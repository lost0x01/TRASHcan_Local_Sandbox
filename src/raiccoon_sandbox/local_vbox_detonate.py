#!/usr/bin/env python3
"""
Local VirtualBox malware detonation runner.

This is the REMnux + Windows path for the local RAIccoon lab:
  - restore/start the host-only Windows VM for detonation
  - stage run artifacts into REMnux for static/network artifact analysis
  - provide wildcard DNS on the host-only gateway
  - provide fake HTTP/HTTPS services
  - capture vboxnet0 with tshark
  - detonate via mounted ISO and keyboard injection
  - parse PCAP/DNS/static artifacts via REMnux when configured
  - power off and restore the clean snapshot
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import http.server
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from pathlib import Path
import xml.etree.ElementTree as ET


DEFAULT_VM = "win-malware-lab"
DEFAULT_SNAPSHOT = "clean-guestadditions-sysmon"
DEFAULT_INTERFACE = "vboxnet0"
DEFAULT_HOST_IP = "192.168.56.254"
DEFAULT_GUEST_IP = "192.168.56.20"
DEFAULT_PASSWORD = "infected"
DEFAULT_GUEST_USER = "analyst"
DEFAULT_GUEST_PASSWORD = "MalwareLab!2026"
DEFAULT_RUN_ROOT = Path("/home/lost0x01/obsidian/05 Security Research/Malware Analysis/Runs")
DEFAULT_ANALYSIS_VM = "remnux"
DEFAULT_ANALYSIS_VM_USER = "remnux"
DEFAULT_ANALYSIS_VM_PASSWORD = "malware"
DEFAULT_ANALYSIS_SHARE_HOST = Path("/home/lost0x01/vm-shares/remnux-transfer")
DEFAULT_ANALYSIS_SHARE_GUEST = "/media/sf_remnux_transfer"
DEFAULT_ANALYSIS_SERVICE_IP = "192.168.56.1"
DEFAULT_ANALYSIS_INTERFACE = "enp0s3"
DEFAULT_HTTP_BODY_LIMIT = 1024 * 1024
PRIVILEGED_HELPER_PATH = Path(os.getenv("TRASHCAN_PRIV_HELPER", "/usr/local/libexec/trashcan/trashcan-net-helper.py"))


IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
    "url": re.compile(r"https?://[^\s\"'<>]{4,200}", re.IGNORECASE),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"),
    "registry_key": re.compile(r"(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\[^\x00\n\r]{4,200}", re.IGNORECASE),
    "windows_path": re.compile(r"(?:[A-Za-z]:\\|\\\\)[^\x00\n\r\"*?<>|]{4,200}"),
}

BENIGN_DOMAIN_SUFFIXES = (
    ".microsoft.com", ".windows.com", ".msn.com", ".bing.com",
    ".skype.com", ".onenote.net", ".live.com", ".msftconnecttest.com",
    ".windowsupdate.com", ".in-addr.arpa", ".ip6.arpa", ".local",
)
BENIGN_EXACT_DOMAINS = {
    "_googlecast._tcp.local",
    "ctldl.windowsupdate.com",
    "www.msftconnecttest.com",
}


def normalize_domain(value: object) -> str:
    domain = str(value or "").strip().lower().rstrip(".")
    if domain.startswith("[") and "]" in domain:
        domain = domain[1:domain.index("]")]
    elif domain.count(":") == 1:
        host, port = domain.rsplit(":", 1)
        if port.isdigit():
            domain = host
    return domain


def is_suspicious_domain(value: object) -> bool:
    domain = normalize_domain(value)
    if not domain or "." not in domain:
        return False
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass
    if domain in BENIGN_EXACT_DOMAINS:
        return False
    if any(domain.endswith(suffix) for suffix in BENIGN_DOMAIN_SUFFIXES):
        return False
    return True


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class FakeHandler(http.server.BaseHTTPRequestHandler):
    server_version = "RAIccoonFakeHTTP/1.0"

    def _record(self) -> None:
        log_path: Path = self.server.log_path  # type: ignore[attr-defined]
        body_limit: int = self.server.body_limit  # type: ignore[attr-defined]
        body_sha256 = ""
        body_preview = ""
        content_length = int(self.headers.get("Content-Length", "0") or "0")
        if content_length:
            body = self.rfile.read(min(content_length, body_limit))
            body_sha256 = hashlib.sha256(body).hexdigest()
            body_preview = body[:256].hex()
        row = {
            "ts": dt.datetime.now(dt.UTC).isoformat(),
            "client": self.client_address[0],
            "method": self.command,
            "path": self.path,
            "host": self.headers.get("Host", ""),
            "user_agent": self.headers.get("User-Agent", ""),
            "content_length": content_length,
            "body_sha256": body_sha256,
            "body_preview_hex": body_preview,
        }
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")

    def _reply(self) -> None:
        self._record()
        body = b"OK\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._reply()

    def do_POST(self) -> None:
        self._reply()

    def do_HEAD(self) -> None:
        self._record()
        self.send_response(200)
        self.end_headers()

    def log_message(self, fmt: str, *args: object) -> None:
        return


def run(cmd: list[str], *, check: bool = True, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=cwd)


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def privileged_helper_cmd(*args: str) -> list[str]:
    return ["sudo", "-n", str(PRIVILEGED_HELPER_PATH), *args]


def start(cmd: list[str], log_path: Path, *, cwd: Path | None = None, env: dict[str, str] | None = None) -> subprocess.Popen:
    log = log_path.open("ab")
    return subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, cwd=cwd, env=env, start_new_session=True)


def stop_process(proc: subprocess.Popen | None, timeout: float = 5.0) -> None:
    if not proc or proc.poll() is not None:
        return

    def signal_proc(sig: signal.Signals) -> None:
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            return
        except PermissionError:
            subprocess.run(["sudo", "-n", "kill", f"-{sig.name}", f"-{proc.pid}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        signal_proc(signal.SIGINT)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=timeout)
        return
    except subprocess.TimeoutExpired:
        signal_proc(signal.SIGTERM)
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        signal_proc(signal.SIGKILL)
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return


def port_is_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((host, port)) != 0


def find_interface_capture_pids(interface: str) -> list[str]:
    result = run(["pgrep", "-af", f"(tshark|dumpcap).*{re.escape(interface)}"], check=False)
    pids = []
    for line in result.stdout.splitlines():
        parts = line.split(maxsplit=1)
        if parts and parts[0].isdigit() and str(os.getpid()) != parts[0]:
            pids.append(parts[0])
    return pids


def preflight(args: argparse.Namespace, run_dir: Path | None = None) -> dict[str, object]:
    required = ["VBoxManage", "7z", "xorriso"]
    if not analysis_vm_enabled(args):
        required.extend(["tshark", "capinfos", "dnsmasq"])
    missing = [name for name in required if not command_exists(name)]
    if missing:
        raise RuntimeError(f"Missing required host tools: {', '.join(missing)}")
    if args.suricata and not analysis_vm_enabled(args) and not command_exists("suricata"):
        raise RuntimeError("Suricata was requested but is not installed")

    snapshot_list = run(["VBoxManage", "snapshot", args.vm, "list", "--machinereadable"], check=False).stdout
    if args.snapshot not in snapshot_list:
        raise RuntimeError(f"Snapshot '{args.snapshot}' was not found on VM '{args.vm}'")
    if analysis_vm_enabled(args):
        analysis_vm_info = run(["VBoxManage", "showvminfo", args.analysis_vm, "--machinereadable"], check=False)
        if analysis_vm_info.returncode != 0:
            raise RuntimeError(f"Analysis VM '{args.analysis_vm}' was not found")
        args.analysis_share_host.expanduser().resolve().mkdir(parents=True, exist_ok=True)
        busy_ports: list[int] = []
        stale_capture_pids: list[str] = []
    else:
        busy_ports = [p for p in (53, 80, 443, 8080) if not port_is_free(args.host_ip, p)]
        stale_capture_pids = find_interface_capture_pids(args.interface)
        if stale_capture_pids and args.kill_stale_capture:
            for pid in stale_capture_pids:
                run(["sudo", "-n", "kill", "-TERM", pid], check=False)
            time.sleep(1)
            stale_capture_pids = find_interface_capture_pids(args.interface)
    details = {
        "ts": dt.datetime.now(dt.UTC).isoformat(),
        "vm": args.vm,
        "snapshot": args.snapshot,
        "interface": args.interface,
        "host_ip": args.host_ip,
        "analysis_vm": args.analysis_vm if analysis_vm_enabled(args) else "",
        "analysis_service_ip": args.analysis_service_ip if analysis_vm_enabled(args) else "",
        "analysis_interface": args.analysis_interface if analysis_vm_enabled(args) else "",
        "busy_ports_before_host_conflict_stop": busy_ports,
        "stale_capture_pids": stale_capture_pids,
        "suricata_available": command_exists("suricata"),
        "zeek_available": command_exists("zeek"),
        "volatility_available": command_exists("vol") or command_exists("volatility3"),
    }
    if run_dir:
        (run_dir / "preflight.json").write_text(json.dumps(details, indent=2, sort_keys=True), encoding="utf-8")
    if stale_capture_pids and not args.allow_stale_capture:
        raise RuntimeError(f"Stale capture processes remain on {args.interface}: {', '.join(stale_capture_pids)}")
    return details


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def service_is_active(service: str) -> bool:
    if not shutil.which("systemctl"):
        return False
    return run(["systemctl", "is-active", "--quiet", service], check=False).returncode == 0


def stop_host_conflicts(run_dir: Path, stop_apache: bool) -> dict[str, bool]:
    state = {"apache2_was_active": False}
    if stop_apache and service_is_active("apache2"):
        state["apache2_was_active"] = True
        out = run(privileged_helper_cmd("apache", "stop"), check=False).stdout
        (run_dir / "host_services.log").write_text(f"Stopped apache2 before run:\n{out}\n", encoding="utf-8")
    return state


def restore_host_conflicts(state: dict[str, bool], run_dir: Path | None) -> None:
    if state.get("apache2_was_active"):
        out = run(privileged_helper_cmd("apache", "start"), check=False).stdout
        if run_dir:
            with (run_dir / "host_services.log").open("a", encoding="utf-8") as fh:
                fh.write(f"\nRestored apache2 after run:\n{out}\n")


def extract_strings(sample: Path, min_len: int = 6) -> list[str]:
    data = sample.read_bytes()
    ascii_strings = [m.group(0).decode("ascii", errors="ignore") for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data)]
    utf16_strings = [
        m.group(0).decode("utf-16-le", errors="ignore")
        for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data)
    ]
    strings = sorted(set(ascii_strings + utf16_strings), key=lambda s: (-len(s), s))
    return strings


def static_triage(sample: Path, run_dir: Path) -> dict[str, object]:
    data = sample.read_bytes()
    strings = extract_strings(sample)
    (run_dir / "strings.txt").write_text("\n".join(strings) + "\n", encoding="utf-8", errors="replace")
    triage: dict[str, object] = {
        "size": len(data),
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "file": run(["file", str(sample)], check=False).stdout.strip() if shutil.which("file") else "",
        "rabin2_info": run(["rabin2", "-I", str(sample)], check=False).stdout if shutil.which("rabin2") else "",
        "rabin2_sections": run(["rabin2", "-S", str(sample)], check=False).stdout if shutil.which("rabin2") else "",
        "rabin2_imports": run(["rabin2", "-i", str(sample)], check=False).stdout if shutil.which("rabin2") else "",
    }
    static_iocs: dict[str, list[str]] = {}
    blob = "\n".join(strings)
    for kind, pattern in IOC_PATTERNS.items():
        values = sorted(set(pattern.findall(blob)))
        if kind == "domain":
            values = [
                v for v in values
                if "." in v
                and len(v) < 200
                and not v.lower().endswith(".dll")
                and len(v.rsplit(".", 1)[-1]) > 2
            ]
        static_iocs[kind] = values[:200]
    triage["static_iocs"] = static_iocs
    (run_dir / "static_triage.json").write_text(json.dumps(triage, indent=2, sort_keys=True), encoding="utf-8")
    return triage


def make_rules(run_dir: Path, sample_sha256: str, summary: dict[str, object], triage: dict[str, object]) -> None:
    suspicious_domains = summary.get("suspicious_domains", [])
    strings_path = run_dir / "strings.txt"
    strings = strings_path.read_text(encoding="utf-8", errors="replace").splitlines() if strings_path.exists() else []
    interesting = []
    for value in strings:
        low = value.lower()
        if len(value) >= 10 and any(token in low for token in ("user-agent", ".pw", "createprocess", "mozilla", "windows nt")):
            interesting.append(value)
        if len(interesting) >= 12:
            break
    yara_strings = []
    for idx, value in enumerate(interesting, 1):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        yara_strings.append(f'        $s{idx} = "{escaped}" ascii wide')
    yara_condition = "uint16(0) == 0x5a4d and 2 of them"
    if not yara_strings:
        yara_strings.append('        $mz = { 4D 5A }')
        yara_condition = "uint16(0) == 0x5a4d"
    yara_body = "\n".join(yara_strings)
    yara_rule = f"""rule RAIccoon_{sample_sha256[:12]}_Triage
{{
    meta:
        description = "Auto-generated triage rule for local sandbox run"
        sha256 = "{sample_sha256}"
        author = "RAIccoon local sandbox"
    strings:
{yara_body}
    condition:
        {yara_condition}
}}
"""
    (run_dir / "rule.yar").write_text(yara_rule, encoding="utf-8")
    sigma_domains = suspicious_domains if isinstance(suspicious_domains, list) else []
    if sigma_domains:
        sigma_domain_lines = "\n".join(f"      - '{d}'" for d in sigma_domains)
        sigma_rule = f"""title: Suspicious DNS From RAIccoon Sandbox Sample {sample_sha256[:12]}
id: 00000000-0000-4000-8000-{sample_sha256[:12]}
status: experimental
description: Detects DNS queries observed during local sandbox detonation.
references:
  - local-sandbox-run:{sample_sha256}
author: RAIccoon local sandbox
date: {dt.date.today().isoformat()}
tags:
  - attack.command-and-control
  - attack.t1071
logsource:
  category: dns
detection:
  selection:
    query|endswith:
{sigma_domain_lines}
  condition: selection
falsepositives:
  - Domain reuse or sinkhole testing
level: medium
"""
        (run_dir / "sigma_dns.yml").write_text(sigma_rule, encoding="utf-8")
    else:
        (run_dir / "sigma_dns.skipped").write_text("No suspicious DNS domains were observed; DNS Sigma rule not generated.\n", encoding="utf-8")

    behaviors = summary.get("behaviors", [])
    if isinstance(behaviors, list) and behaviors:
        behavior_rule = f"""title: Sandbox Observed Autorun Persistence To User Writable Path {sample_sha256[:12]}
id: {uuid.uuid5(uuid.NAMESPACE_DNS, sample_sha256 + '-autorun-persistence')}
status: experimental
description: Detects Run or RunOnce persistence pointing at Temp, AppData, ProgramData, or Startup paths.
references:
  - local-sandbox-run:{sample_sha256}
author: RAIccoon local sandbox
date: {dt.date.today().isoformat()}
tags:
  - attack.persistence
  - attack.t1547.001
logsource:
  product: windows
  service: sysmon
detection:
  selection_event:
    EventID:
      - 12
      - 13
      - 14
    TargetObject|contains:
      - '\\Run'
      - '\\RunOnce'
      - '\\StartupApproved'
  selection_path:
    Details|contains:
      - '\\Temp\\'
      - '\\AppData\\'
      - '\\ProgramData\\'
      - '\\Startup\\'
  condition: selection_event and selection_path
falsepositives:
  - Legitimate software updaters using per-user autoruns
level: high
"""
        (run_dir / "sigma_behavior.yml").write_text(behavior_rule, encoding="utf-8")


def extract_sample(input_path: Path, work_dir: Path, password: str) -> Path:
    if input_path.suffix.lower() == ".7z":
        out_dir = work_dir / "extracted"
        out_dir.mkdir()
        run(["7z", "x", f"-p{password}", f"-o{out_dir}", str(input_path)])
        files = [p for p in out_dir.iterdir() if p.is_file()]
        if len(files) != 1:
            raise RuntimeError(f"Expected one extracted file, found {len(files)}")
        sample = files[0]
    else:
        sample = work_dir / "sample.bin"
        shutil.copy2(input_path, sample)
    sample.chmod(0o644)
    return sample


def make_runner_iso(sample: Path, run_dir: Path) -> Path:
    iso_src = run_dir / "iso"
    iso_src.mkdir(exist_ok=True)
    shutil.copy2(sample, iso_src / "sample.exe")
    (iso_src / "run.bat").write_text(
        "@echo off\r\n"
        "mkdir C:\\Analysis 2>NUL\r\n"
        "echo started %DATE% %TIME% > C:\\Analysis\\runner.txt\r\n"
        "cd /d %~dp0\r\n"
        "start \"\" /wait sample.exe\r\n"
        "echo finished %DATE% %TIME% >> C:\\Analysis\\runner.txt\r\n"
        "timeout /t 20 /nobreak >NUL\r\n",
        encoding="ascii",
    )
    iso_path = run_dir / "runner.iso"
    run(["xorriso", "-as", "mkisofs", "-J", "-R", "-o", str(iso_path), str(iso_src)])
    return iso_path


def make_tls_cert(run_dir: Path) -> tuple[Path, Path] | None:
    if not shutil.which("openssl"):
        return None
    cert = run_dir / "fake_https.crt"
    key = run_dir / "fake_https.key"
    run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-subj", "/CN=raiccoon.local", "-days", "1",
            "-keyout", str(key), "-out", str(cert),
        ]
    )
    return cert, key


def serve_http(host_ip: str, port: int, log_path: Path, cert_pair: tuple[Path, Path] | None = None) -> None:
    httpd = ThreadingHTTPServer((host_ip, port), FakeHandler)
    httpd.log_path = log_path  # type: ignore[attr-defined]
    httpd.body_limit = DEFAULT_HTTP_BODY_LIMIT  # type: ignore[attr-defined]
    if cert_pair:
        cert, key = cert_pair
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()


def start_fake_services(args: argparse.Namespace, run_dir: Path) -> list[subprocess.Popen]:
    procs: list[subprocess.Popen] = []
    dns_log = run_dir / "dnsmasq.log"
    dns_cmd = privileged_helper_cmd("dnsmasq", "--interface", args.interface, "--host-ip", args.host_ip)
    procs.append(start(dns_cmd, dns_log))
    time.sleep(1)
    if procs[-1].poll() is not None:
        raise RuntimeError(f"dnsmasq failed to start; see {dns_log}")

    for port in (80, 8080):
        log_json = run_dir / f"http_{port}.jsonl"
        if port < 1024:
            cmd = privileged_helper_cmd(
                "http",
                "--host-ip", args.host_ip,
                "--port", str(port),
                "--log-path", str(log_json),
            )
            procs.append(start(cmd, run_dir / f"http_{port}.log"))
        else:
            procs.append(
                start(
                    [
                        sys.executable,
                        "-u",
                        "-c",
                        (
                            "import importlib.util; "
                            f"p={str(Path(__file__).resolve())!r}; "
                            "s=importlib.util.spec_from_file_location('runner', p); "
                            "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
                            f"m.serve_http({args.host_ip!r}, {port}, m.Path({str(log_json)!r}), None)"
                        ),
                    ],
                    run_dir / f"http_{port}.log",
                )
            )

    cert_pair = make_tls_cert(run_dir)
    if cert_pair:
        cmd = privileged_helper_cmd(
            "http",
            "--host-ip", args.host_ip,
            "--port", "443",
            "--log-path", str(run_dir / "https_443.jsonl"),
            "--cert", str(cert_pair[0]),
            "--key", str(cert_pair[1]),
        )
        procs.append(start(cmd, run_dir / "https_443.log"))
    time.sleep(1)
    return procs


def start_suricata(args: argparse.Namespace, run_dir: Path) -> subprocess.Popen | None:
    if not args.suricata or not shutil.which("suricata"):
        (run_dir / "suricata.status").write_text(
            "suricata disabled or not installed\n",
            encoding="utf-8",
        )
        return None
    eve = run_dir / "suricata_eve.json"
    log_dir = run_dir / "suricata"
    log_dir.mkdir(exist_ok=True)
    rules = run_dir / "suricata_local.rules"
    rules.write_text(
        "\n".join([
            'alert dns any any -> any any (msg:"RAIccoon suspicious .pw DNS query"; dns.query; content:".pw"; nocase; endswith; sid:9000001; rev:1;)',
            'alert tls any any -> any any (msg:"RAIccoon suspicious .pw TLS SNI"; tls.sni; content:".pw"; nocase; endswith; sid:9000002; rev:1;)',
            "",
        ]),
        encoding="ascii",
    )
    cmd = privileged_helper_cmd(
        "suricata-run",
        "--interface", args.interface,
        "--log-dir", str(log_dir),
        "--rules", str(rules),
        "--eve", str(eve),
    )
    validation = run(privileged_helper_cmd("suricata-test", "--rules", str(rules)), check=False)
    (run_dir / "suricata_rule_test.log").write_text(validation.stdout, encoding="utf-8", errors="replace")
    if validation.returncode != 0:
        (run_dir / "suricata.status").write_text("suricata rule validation failed; see suricata_rule_test.log\n", encoding="utf-8")
        return None
    proc = start(cmd, run_dir / "suricata.log")
    time.sleep(2)
    if proc.poll() is not None:
        (run_dir / "suricata.status").write_text("suricata failed to start; see suricata.log\n", encoding="utf-8")
        return None
    (run_dir / "suricata.status").write_text("suricata started\n", encoding="utf-8")
    return proc


def write_guest_scripts(run_dir: Path) -> None:
    setup = r'''# RAIccoon Windows guest setup
# Run as Administrator inside the clean snapshot, then create/refresh the snapshot.
$ErrorActionPreference = "Continue"
$Tools = "C:\Tools"
$Analysis = "C:\Analysis"
New-Item -ItemType Directory -Force -Path "$Tools\Sysmon","$Tools\Sysinternals","$Analysis\Sample","$Analysis\Output","$Analysis\Logs" | Out-Null
Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableScriptScanning $true
$Sysmon = "$Tools\Sysmon\Sysmon64.exe"
$SysmonCfg = "$Tools\Sysmon\sysmonconfig.xml"
if (!(Test-Path $Sysmon)) { Invoke-WebRequest -Uri "https://live.sysinternals.com/Sysmon64.exe" -OutFile $Sysmon -UseBasicParsing }
@'
<Sysmon schemaversion="4.82">
  <HashAlgorithms>sha256,md5</HashAlgorithms>
  <EventFiltering>
    <ProcessCreate onmatch="include" />
    <NetworkConnect onmatch="include" />
    <ImageLoad onmatch="include">
      <ImageLoaded condition="contains">\Temp\</ImageLoaded>
      <ImageLoaded condition="contains">\AppData\</ImageLoaded>
      <ImageLoaded condition="contains">\ProgramData\</ImageLoaded>
    </ImageLoad>
    <CreateRemoteThread onmatch="include" />
    <ProcessAccess onmatch="include">
      <GrantedAccess condition="contains">0x1f0fff</GrantedAccess>
      <GrantedAccess condition="contains">0x1f1fff</GrantedAccess>
      <GrantedAccess condition="contains">0x143a</GrantedAccess>
    </ProcessAccess>
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">\Temp\</TargetFilename>
      <TargetFilename condition="contains">\AppData\</TargetFilename>
      <TargetFilename condition="contains">\ProgramData\</TargetFilename>
      <TargetFilename condition="contains">\Startup\</TargetFilename>
    </FileCreate>
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">Run</TargetObject>
      <TargetObject condition="contains">RunOnce</TargetObject>
      <TargetObject condition="contains">Winlogon</TargetObject>
      <TargetObject condition="contains">Services</TargetObject>
      <TargetObject condition="contains">Explorer\StartupApproved</TargetObject>
      <TargetObject condition="contains">WMI</TargetObject>
    </RegistryEvent>
    <DnsQuery onmatch="include" />
  </EventFiltering>
</Sysmon>
'@ | Out-File -Encoding UTF8 $SysmonCfg
if (Test-Path $Sysmon) {
  & $Sysmon -accepteula -i $SysmonCfg
  if ($LASTEXITCODE -ne 0) { & $Sysmon -accepteula -c $SysmonCfg }
}
wevtutil sl Microsoft-Windows-PowerShell/Operational /e:true
wevtutil sl Microsoft-Windows-Sysmon/Operational /e:true
'''
    collector = r'''# RAIccoon Windows artifact collector
$Out = "C:\Analysis\Output"
New-Item -ItemType Directory -Force -Path $Out | Out-Null
Remove-Item -Path "$Out\*" -Recurse -Force -ErrorAction SilentlyContinue
Get-Date -Format o | Out-File "$Out\collection_time.txt"
Get-Process | Select-Object Name,Id,Path,StartTime,Company,ProductVersion -ErrorAction SilentlyContinue | ConvertTo-Json -Depth 4 | Out-File "$Out\processes.json"
Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate | ConvertTo-Json -Depth 4 | Out-File "$Out\process_tree_raw.json"
Get-NetTCPConnection | ConvertTo-Json -Depth 4 | Out-File "$Out\tcp_connections.json"
Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,StartName | ConvertTo-Json -Depth 4 | Out-File "$Out\services.json"
Get-ScheduledTask | Select-Object TaskName,TaskPath,State,Actions,Triggers | ConvertTo-Json -Depth 8 | Out-File "$Out\scheduled_tasks.json"
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | ConvertTo-Json -Depth 6 | Out-File "$Out\wmi_event_filters.json"
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue | ConvertTo-Json -Depth 6 | Out-File "$Out\wmi_commandline_consumers.json"
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | ConvertTo-Json -Depth 6 | Out-File "$Out\wmi_filter_bindings.json"
reg export HKCU\Software\Microsoft\Windows\CurrentVersion\Run "$Out\hkcu_run.reg" /y 2>$null
reg export HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce "$Out\hkcu_runonce.reg" /y 2>$null
reg export HKLM\Software\Microsoft\Windows\CurrentVersion\Run "$Out\hklm_run.reg" /y 2>$null
reg export HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce "$Out\hklm_runonce.reg" /y 2>$null
reg export HKLM\SYSTEM\CurrentControlSet\Services "$Out\services.reg" /y 2>$null
$RecentRoots = @(
  "$env:TEMP",
  "$env:APPDATA",
  "$env:LOCALAPPDATA",
  "$env:PROGRAMDATA",
  "$env:USERPROFILE\Desktop",
  "$env:USERPROFILE\Downloads",
  "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
  "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\Startup"
) | Where-Object { $_ -and (Test-Path $_) }
$Since = (Get-Date).AddHours(-4)
$Dropped = foreach ($Root in $RecentRoots) {
  Get-ChildItem -Path $Root -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -ge $Since } |
    Select-Object FullName,Length,CreationTimeUtc,LastWriteTimeUtc
}
$Dropped | ConvertTo-Json -Depth 4 | Out-File "$Out\recent_files.json"
$Hashes = foreach ($Item in $Dropped) {
  try {
    $Hash = Get-FileHash -Algorithm SHA256 -Path $Item.FullName -ErrorAction Stop
    [PSCustomObject]@{ Path=$Item.FullName; Size=$Item.Length; SHA256=$Hash.Hash.ToLowerInvariant(); LastWriteTimeUtc=$Item.LastWriteTimeUtc }
  } catch {}
}
$Hashes | ConvertTo-Json -Depth 4 | Out-File "$Out\recent_file_hashes.json"
if (Test-Path "$env:TEMP") {
  New-Item -ItemType Directory -Force -Path "$Out\dropped_files" | Out-Null
  foreach ($Item in $Dropped | Where-Object { $_.Length -le 52428800 } | Select-Object -First 100) {
    try {
      $Safe = ($Item.FullName -replace '[:\\\/]','_')
      Copy-Item -Path $Item.FullName -Destination "$Out\dropped_files\$Safe" -Force -ErrorAction Stop
    } catch {}
  }
}
wevtutil epl Microsoft-Windows-Sysmon/Operational "$Out\sysmon.evtx" /ow:true
wevtutil epl Microsoft-Windows-PowerShell/Operational "$Out\powershell_operational.evtx" /ow:true
wevtutil epl Security "$Out\security.evtx" /ow:true
wevtutil epl Application "$Out\application.evtx" /ow:true
wevtutil epl System "$Out\system.evtx" /ow:true
if (Test-Path "C:\Tools\WinPmem\winpmem_mini_x64_rc2.exe") {
  if (Test-Path "C:\Analysis\request_memory_dump.flag") {
    & "C:\Tools\WinPmem\winpmem_mini_x64_rc2.exe" "$Out\memory.raw"
  }
}
Compress-Archive -Path "$Out\*" -DestinationPath "C:\Analysis\artifacts.zip" -Force
'''
    (run_dir / "guest_setup.ps1").write_text(setup, encoding="utf-8")
    (run_dir / "guest_collect.ps1").write_text(collector, encoding="utf-8")


def vm_state(vm: str) -> str:
    out = run(["VBoxManage", "showvminfo", vm, "--machinereadable"], check=False).stdout
    for line in out.splitlines():
        if line.startswith("VMState="):
            return line.split("=", 1)[1].strip('"')
    return "unknown"


def restore_and_start_vm(args: argparse.Namespace) -> None:
    state = vm_state(args.vm)
    if state == "running":
        run(["VBoxManage", "controlvm", args.vm, "poweroff"], check=False)
        time.sleep(3)
    run(["VBoxManage", "snapshot", args.vm, "restore", args.snapshot])
    run(["VBoxManage", "startvm", args.vm, "--type", "headless"])
    time.sleep(args.boot_wait)


def guest_args(args: argparse.Namespace) -> list[str]:
    return ["--username", args.guest_user, "--password", args.guest_password]


def guest_run(args: argparse.Namespace, exe: str, guest_argv: list[str], *, timeout: int = 120, check: bool = True) -> subprocess.CompletedProcess:
    cmd = [
        "VBoxManage", "guestcontrol", args.vm, "run",
        *guest_args(args),
        "--exe", exe,
        "--wait-stdout", "--wait-stderr",
        "--timeout", str(timeout * 1000),
        "--",
        *guest_argv,
    ]
    return run(cmd, check=check)


def guest_ready(args: argparse.Namespace) -> bool:
    result = guest_run(
        args,
        r"C:\Windows\System32\cmd.exe",
        ["cmd.exe", "/c", "whoami"],
        timeout=20,
        check=False,
    )
    return result.returncode == 0 and args.guest_user.lower() in result.stdout.lower()


def wait_guest_ready(args: argparse.Namespace, timeout: int = 180) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if guest_ready(args):
            return
        time.sleep(5)
    raise RuntimeError("Guest Control did not become ready")


def guest_copyto(args: argparse.Namespace, src: Path, dst: str) -> None:
    run(["VBoxManage", "guestcontrol", args.vm, "copyto", str(src), dst, *guest_args(args)])


def guest_copyfrom(args: argparse.Namespace, src: str, dst: Path, *, check: bool = True) -> subprocess.CompletedProcess:
    return run(["VBoxManage", "guestcontrol", args.vm, "copyfrom", src, str(dst), *guest_args(args)], check=check)


def guest_mkdir(args: argparse.Namespace, path: str) -> None:
    run(["VBoxManage", "guestcontrol", args.vm, "mkdir", path, *guest_args(args), "--parents"], check=False)


def analysis_vm_enabled(args: argparse.Namespace) -> bool:
    return bool(str(getattr(args, "analysis_vm", "")).strip()) and not bool(getattr(args, "local_analysis_only", False))


def analysis_vm_state(args: argparse.Namespace) -> str:
    return vm_state(args.analysis_vm)


def analysis_guest_args(args: argparse.Namespace) -> list[str]:
    return ["--username", args.analysis_vm_user, "--password", args.analysis_vm_password]


def analysis_guest_run(args: argparse.Namespace, exe: str, guest_argv: list[str], *, timeout: int = 120, check: bool = True) -> subprocess.CompletedProcess:
    cmd = [
        "VBoxManage", "guestcontrol", args.analysis_vm, "run",
        *analysis_guest_args(args),
        "--exe", exe,
        "--wait-stdout", "--wait-stderr",
        "--timeout", str(timeout * 1000),
        "--",
        *guest_argv,
    ]
    return run(cmd, check=check)


def analysis_guest_ready(args: argparse.Namespace) -> bool:
    result = analysis_guest_run(
        args,
        "/bin/sh",
        ["-lc", "whoami"],
        timeout=20,
        check=False,
    )
    return result.returncode == 0 and args.analysis_vm_user.lower() in result.stdout.lower()


def wait_analysis_guest_ready(args: argparse.Namespace, timeout: int = 180) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if analysis_guest_ready(args):
            return
        time.sleep(5)
    raise RuntimeError(f"Analysis VM '{args.analysis_vm}' Guest Control did not become ready")


def ensure_analysis_vm_running(args: argparse.Namespace) -> bool:
    was_running = analysis_vm_state(args) == "running"
    if not was_running:
        run(["VBoxManage", "startvm", args.analysis_vm, "--type", "headless"])
    wait_analysis_guest_ready(args)
    return was_running


def stop_analysis_vm_if_started(args: argparse.Namespace, was_running: bool) -> None:
    if was_running:
        return
    if analysis_vm_state(args) == "running":
        run(["VBoxManage", "controlvm", args.analysis_vm, "acpipowerbutton"], check=False)
        deadline = time.time() + 180
        while time.time() < deadline:
            if analysis_vm_state(args) == "poweroff":
                return
            time.sleep(2)
        run(["VBoxManage", "controlvm", args.analysis_vm, "poweroff"], check=False)


def stage_analysis_run_dir(args: argparse.Namespace, run_dir: Path) -> tuple[Path, str]:
    host_root = args.analysis_share_host.expanduser().resolve()
    guest_root = args.analysis_share_guest.rstrip("/")
    host_root.mkdir(parents=True, exist_ok=True)
    stage_root = host_root / "analysis-runs"
    stage_root.mkdir(parents=True, exist_ok=True)
    staged_run_dir = stage_root / run_dir.name
    if staged_run_dir.exists():
        shutil.rmtree(staged_run_dir)
    shutil.copytree(run_dir, staged_run_dir)
    guest_run_dir = f"{guest_root}/analysis-runs/{run_dir.name}"
    return staged_run_dir, guest_run_dir


def sync_analysis_outputs(staged_run_dir: Path, run_dir: Path) -> None:
    shutil.copytree(staged_run_dir, run_dir, dirs_exist_ok=True)


def shell_join(argv: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in argv)


def prepare_analysis_stage(args: argparse.Namespace, run_dir: Path) -> tuple[Path, str]:
    host_root = args.analysis_share_host.expanduser().resolve()
    guest_root = args.analysis_share_guest.rstrip("/")
    host_root.mkdir(parents=True, exist_ok=True)
    stage_root = host_root / "analysis-runs"
    stage_root.mkdir(parents=True, exist_ok=True)
    staged_run_dir = stage_root / run_dir.name
    if staged_run_dir.exists():
        shutil.rmtree(staged_run_dir)
    shutil.copytree(run_dir, staged_run_dir)
    guest_run_dir = f"{guest_root}/analysis-runs/{run_dir.name}"
    return staged_run_dir, guest_run_dir


def sync_host_run_to_stage(run_dir: Path, staged_run_dir: Path) -> None:
    shutil.copytree(run_dir, staged_run_dir, dirs_exist_ok=True)


def start_analysis_gateway(args: argparse.Namespace, run_dir: Path) -> dict[str, object]:
    staged_run_dir, guest_run_dir = prepare_analysis_stage(args, run_dir)
    guest_log_dir = f"{guest_run_dir}/inetsim-logs"
    guest_report_dir = f"{guest_run_dir}/inetsim-report"
    guest_pcap = f"{guest_run_dir}/capture.pcapng"
    guest_tshark_log = f"{guest_run_dir}/tshark.log"
    guest_tshark_pid = f"{guest_run_dir}/tshark.pid"
    guest_inetsim_pid = f"{guest_run_dir}/inetsim.pid"
    guest_inetsim_stdout = f"{guest_run_dir}/inetsim.stdout"
    guest_dnsmasq_pid = f"{guest_run_dir}/dnsmasq.pid"
    guest_dnsmasq_log = f"{guest_run_dir}/dnsmasq.log"
    guest_dnsmasq_stdout = f"{guest_run_dir}/dnsmasq.stdout"
    analysis_vm_was_running = ensure_analysis_vm_running(args)
    bootstrap = "\n".join([
        "set -euo pipefail",
        f"mkdir -p {shlex.quote(guest_run_dir)} {shlex.quote(guest_log_dir)} {shlex.quote(guest_report_dir)}",
        f"rm -f {shlex.quote(guest_pcap)} {shlex.quote(guest_tshark_log)} {shlex.quote(guest_tshark_pid)} {shlex.quote(guest_inetsim_pid)} {shlex.quote(guest_inetsim_stdout)} {shlex.quote(guest_dnsmasq_pid)} {shlex.quote(guest_dnsmasq_log)} {shlex.quote(guest_dnsmasq_stdout)}",
        "sudo -n pkill -x inetsim_main >/dev/null 2>&1 || true",
        "sudo -n pkill -f '^inetsim_' >/dev/null 2>&1 || true",
        "sudo -n pkill -x tshark >/dev/null 2>&1 || true",
        "sudo -n pkill dnsmasq >/dev/null 2>&1 || true",
        (
            f"sudo -n bash -lc {shlex.quote(f'nohup tshark -i {shlex.quote(args.analysis_interface)} -a duration:{args.duration + 120} -w {shlex.quote(guest_pcap)} > {shlex.quote(guest_tshark_log)} 2>&1 < /dev/null & echo $! > {shlex.quote(guest_tshark_pid)}')}"
        ),
        (
            f"sudo -n bash -lc {shlex.quote(f'nohup dnsmasq --no-daemon --keep-in-foreground --no-resolv --log-queries --log-facility={shlex.quote(guest_dnsmasq_log)} --interface={shlex.quote(args.analysis_interface)} --listen-address={shlex.quote(args.analysis_service_ip)} --bind-interfaces --address=/#/{shlex.quote(args.analysis_service_ip)} > {shlex.quote(guest_dnsmasq_stdout)} 2>&1 < /dev/null & echo $! > {shlex.quote(guest_dnsmasq_pid)}')}"
        ),
        (
            f"sudo -n bash -lc {shlex.quote(f'nohup inetsim --bind-address={args.analysis_service_ip} --user=root --log-dir={shlex.quote(guest_log_dir)} --report-dir={shlex.quote(guest_report_dir)} --session={shlex.quote(run_dir.name)} > {shlex.quote(guest_inetsim_stdout)} 2>&1 < /dev/null & echo $! > {shlex.quote(guest_inetsim_pid)}')}"
        ),
        "sleep 5",
        f"test -f {shlex.quote(guest_inetsim_pid)}",
        f"test -f {shlex.quote(guest_tshark_pid)}",
        f"test -f {shlex.quote(guest_dnsmasq_pid)}",
        f"cat {shlex.quote(guest_inetsim_pid)} {shlex.quote(guest_tshark_pid)} {shlex.quote(guest_dnsmasq_pid)}",
        f"ss -ltnup | grep -E ':(53|80|443|8080)\\b' || true",
    ])
    result = analysis_guest_run(args, "/bin/bash", ["-lc", bootstrap], timeout=180, check=False)
    (run_dir / "analysis_gateway_start.log").write_text(result.stdout, encoding="utf-8", errors="replace")
    if result.returncode != 0:
        stop_analysis_vm_if_started(args, analysis_vm_was_running)
        raise RuntimeError(f"Failed to start REMnux gateway services; see {run_dir / 'analysis_gateway_start.log'}")
    gateway_state = {
        "analysis_vm_was_running": analysis_vm_was_running,
        "staged_run_dir": staged_run_dir,
        "guest_run_dir": guest_run_dir,
        "guest_inetsim_pid": guest_inetsim_pid,
        "guest_tshark_pid": guest_tshark_pid,
        "guest_dnsmasq_pid": guest_dnsmasq_pid,
    }
    (run_dir / "analysis_gateway_state.json").write_text(json.dumps({
        "analysis_vm": args.analysis_vm,
        "analysis_service_ip": args.analysis_service_ip,
        "analysis_interface": args.analysis_interface,
        "guest_run_dir": guest_run_dir,
    }, indent=2, sort_keys=True), encoding="utf-8")
    return gateway_state


def stop_analysis_gateway(args: argparse.Namespace, run_dir: Path, gateway_state: dict[str, object]) -> None:
    staged_run_dir = Path(str(gateway_state["staged_run_dir"]))
    guest_run_dir = str(gateway_state["guest_run_dir"])
    guest_inetsim_pid = str(gateway_state["guest_inetsim_pid"])
    guest_tshark_pid = str(gateway_state["guest_tshark_pid"])
    guest_dnsmasq_pid = str(gateway_state["guest_dnsmasq_pid"])
    shutdown = "\n".join([
        "set -euo pipefail",
        f"sudo -n pkill -F {shlex.quote(guest_inetsim_pid)} >/dev/null 2>&1 || true",
        f"sudo -n pkill -F {shlex.quote(guest_tshark_pid)} >/dev/null 2>&1 || true",
        f"sudo -n pkill -F {shlex.quote(guest_dnsmasq_pid)} >/dev/null 2>&1 || true",
        "sleep 2",
        f"ls -la {shlex.quote(guest_run_dir)} || true",
    ])
    result = analysis_guest_run(args, "/bin/bash", ["-lc", shutdown], timeout=120, check=False)
    (run_dir / "analysis_gateway_stop.log").write_text(result.stdout, encoding="utf-8", errors="replace")
    sync_analysis_outputs(staged_run_dir, run_dir)
    stop_analysis_vm_if_started(args, bool(gateway_state.get("analysis_vm_was_running", False)))


def run_analysis_in_analysis_vm(args: argparse.Namespace, run_dir: Path) -> Path:
    staged_run_dir, guest_run_dir = stage_analysis_run_dir(args, run_dir)
    guest_script = f"{args.analysis_share_guest.rstrip('/')}/local_vbox_detonate.py"
    run_dir_hint = staged_run_dir / "analysis_vm_stage.json"
    run_dir_hint.write_text(json.dumps({
        "analysis_vm": args.analysis_vm,
        "guest_run_dir": guest_run_dir,
        "guest_script": guest_script,
    }, indent=2, sort_keys=True), encoding="utf-8")
    shutil.copy2(Path(__file__), args.analysis_share_host / "local_vbox_detonate.py")
    analysis_vm_was_running = ensure_analysis_vm_running(args)
    try:
        result = analysis_guest_run(
            args,
            "/bin/sh",
            [
                "-lc",
                " ".join([
                    "python3",
                    guest_script,
                    "--parse-only",
                    "--retriage",
                    "--run-dir",
                    shlex.quote(guest_run_dir),
                    "--vm",
                    shlex.quote(args.vm),
                    "--snapshot",
                    shlex.quote(args.snapshot),
                    "--interface",
                    shlex.quote(args.interface),
                    "--host-ip",
                    shlex.quote(args.host_ip),
                    "--guest-ip",
                    shlex.quote(args.guest_ip),
                ]),
            ],
            timeout=max(300, args.duration + 180),
            check=False,
        )
        (run_dir / "analysis_vm.log").write_text(result.stdout, encoding="utf-8", errors="replace")
        if result.returncode != 0:
            raise RuntimeError(f"Analysis VM parse run failed; see {run_dir / 'analysis_vm.log'}")
    finally:
        stop_analysis_vm_if_started(args, analysis_vm_was_running)
    sync_analysis_outputs(staged_run_dir, run_dir)
    return run_dir / "analysis.md"


def launch_with_guestcontrol(args: argparse.Namespace, sample: Path, run_dir: Path) -> bool:
    if not args.guestcontrol:
        return False
    if not guest_ready(args):
        return False
    guest_mkdir(args, r"C:\Analysis\Sample")
    guest_mkdir(args, r"C:\Analysis\Output")
    guest_copyto(args, sample, r"C:\Analysis\Sample\sample.exe")
    guest_copyto(args, run_dir / "guest_collect.ps1", r"C:\Analysis\guest_collect.ps1")
    if args.memory_dump:
        flag_path = run_dir / "request_memory_dump.flag"
        flag_path.write_text("requested\n", encoding="ascii")
        guest_copyto(args, flag_path, r"C:\Analysis\request_memory_dump.flag")
    launcher_path = run_dir / "guest_run.ps1"
    launcher_path.write_text(
        "\n".join([
            "$ErrorActionPreference = 'Continue'",
            "Set-Content -Path 'C:\\Analysis\\runner.txt' -Value ('started ' + (Get-Date -Format o))",
            *([
                "$LabIf = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -and $_.InterfaceAlias -ne 'Loopback Pseudo-Interface 1' } | Select-Object -First 1",
                f"if ($LabIf) {{ Set-DnsClientServerAddress -InterfaceAlias $LabIf.InterfaceAlias -ServerAddresses @('{args.analysis_service_ip}') -ErrorAction SilentlyContinue; ipconfig /flushdns | Out-Null; Add-Content -Path 'C:\\Analysis\\runner.txt' -Value ('dns ' + $LabIf.InterfaceAlias + ' -> {args.analysis_service_ip}') }}",
            ] if analysis_vm_enabled(args) else []),
            "$p = Start-Process -FilePath 'C:\\Analysis\\Sample\\sample.exe' -PassThru",
            f"Wait-Process -Id $p.Id -Timeout {max(5, args.duration)} -ErrorAction SilentlyContinue",
            "Add-Content -Path 'C:\\Analysis\\runner.txt' -Value ('finished ' + (Get-Date -Format o))",
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\\Analysis\\guest_collect.ps1'",
            "",
        ]),
        encoding="utf-8",
    )
    guest_copyto(args, launcher_path, r"C:\Analysis\guest_run.ps1")
    result = guest_run(
        args,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", r"C:\Analysis\guest_run.ps1"],
        timeout=args.duration + 90,
        check=False,
    )
    (run_dir / "guestcontrol_run.log").write_text(result.stdout, encoding="utf-8", errors="replace")
    guest_copyfrom(args, r"C:\Analysis\runner.txt", run_dir / "guest_runner.txt", check=False)
    guest_copyfrom(args, r"C:\Analysis\artifacts.zip", run_dir / "guest_artifacts.zip", check=False)
    return True


def mount_and_launch(args: argparse.Namespace, iso_path: Path, run_dir: Path) -> None:
    run([
        "VBoxManage", "storageattach", args.vm,
        "--storagectl", "IDE", "--port", "1", "--device", "0",
        "--type", "dvddrive", "--medium", str(iso_path),
    ])
    time.sleep(2)
    run(["VBoxManage", "controlvm", args.vm, "screenshotpng", str(run_dir / "before_launch.png")], check=False)
    # Win+R, type D:\run.bat, Enter.
    run(["VBoxManage", "controlvm", args.vm, "keyboardputscancode", "e0", "5b", "13", "93", "e0", "db"])
    time.sleep(1)
    run(["VBoxManage", "controlvm", args.vm, "keyboardputstring", "D:\\run.bat"])
    run(["VBoxManage", "controlvm", args.vm, "keyboardputscancode", "1c", "9c"])


def parse_artifacts(run_dir: Path, pcap: Path) -> dict[str, object]:
    summary: dict[str, object] = {
        "dns_queries": [],
        "suspicious_domains": [],
        "tls_sni": [],
        "http_requests": [],
        "suspicious_http_requests": [],
        "http_events": [],
        "suspicious_http_events": [],
        "suricata_alerts": [],
    }
    if pcap.exists():
        parse_pcap = Path(tempfile.mkdtemp(prefix="raiccoon_pcap_parse_")) / pcap.name
        shutil.copy2(pcap, parse_pcap)
        parse_pcap.chmod(0o644)
        run(["capinfos", str(parse_pcap)], check=False).stdout
        dns_out = run(
            [
                "tshark", "-r", str(parse_pcap), "-Y", "dns.qry.name",
                "-T", "fields", "-e", "dns.qry.name",
            ],
            check=False,
        ).stdout
        domains = sorted({
            line.strip()
            for line in dns_out.splitlines()
            if line.strip() and not line.startswith("tshark:")
        })
        summary["dns_queries"] = domains
        summary["suspicious_domains"] = [
            d for d in domains
            if is_suspicious_domain(d)
        ]
        sni_out = run(
            [
                "tshark", "-r", str(parse_pcap), "-Y", "tls.handshake.extensions_server_name",
                "-T", "fields", "-e", "tls.handshake.extensions_server_name",
            ],
            check=False,
        ).stdout
        summary["tls_sni"] = sorted({
            line.strip()
            for line in sni_out.splitlines()
            if line.strip() and not line.startswith("tshark:")
        })
        http_out = run(
            [
                "tshark", "-r", str(parse_pcap), "-Y", "http.request",
                "-T", "fields", "-e", "http.host", "-e", "http.request.method", "-e", "http.request.uri",
            ],
            check=False,
        ).stdout
        requests = []
        for line in http_out.splitlines():
            if not line.strip() or line.startswith("tshark:"):
                continue
            host, method, uri = (line.split("\t") + ["", "", ""])[:3]
            requests.append({"host": host, "method": method, "uri": uri})
        summary["http_requests"] = requests
        summary["suspicious_http_requests"] = [
            r for r in requests
            if is_suspicious_domain(r.get("host"))
        ]
        summary["capinfos"] = run(["capinfos", str(parse_pcap)], check=False).stdout
        summary["protocols"] = run(["tshark", "-r", str(parse_pcap), "-q", "-z", "io,phs"], check=False).stdout
    for path in sorted(run_dir.glob("http_*.jsonl")) + sorted(run_dir.glob("https_*.jsonl")):
        if path.exists():
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip():
                    summary["http_events"].append(json.loads(line))  # type: ignore[index]
    summary["suspicious_http_events"] = [
        e for e in summary["http_events"]  # type: ignore[index]
        if is_suspicious_domain(e.get("host"))
    ]
    for eve in sorted(run_dir.glob("suricata*/eve.json")) + sorted(run_dir.glob("suricata_eve.json")):
        if eve.exists():
            for line in eve.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("event_type") == "alert":
                    summary["suricata_alerts"].append(event)  # type: ignore[index]
                if event.get("event_type") == "dns":
                    for query in event.get("dns", {}).get("queries", []):
                        name = query.get("rrname", "").rstrip(".")
                        if name and name not in summary["dns_queries"]:  # type: ignore[operator]
                            summary["dns_queries"].append(name)  # type: ignore[index]
                if event.get("event_type") == "tls":
                    sni = event.get("tls", {}).get("sni", "").rstrip(".")
                    if sni and sni not in summary["tls_sni"]:  # type: ignore[operator]
                        summary["tls_sni"].append(sni)  # type: ignore[index]
    summary["dns_queries"] = sorted(set(summary["dns_queries"]))  # type: ignore[arg-type]
    summary["tls_sni"] = sorted(set(summary["tls_sni"]))  # type: ignore[arg-type]
    summary["suspicious_domains"] = sorted({
        normalize_domain(d) for d in [*summary["dns_queries"], *summary["tls_sni"]]  # type: ignore[list-item]
        if is_suspicious_domain(d)
    })
    guest_summary = parse_guest_artifacts(run_dir)
    summary.update(guest_summary)
    return summary


def load_json_file(path: Path) -> object:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
    except json.JSONDecodeError:
        return None


def ensure_list(value: object) -> list[object]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def parse_reg_values(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    values: list[dict[str, str]] = []
    key = ""
    for raw in path.read_text(encoding="utf-16", errors="ignore").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            key = line.strip("[]")
            continue
        if "=" in line and key:
            name, data = line.split("=", 1)
            values.append({"key": key, "name": name.strip('"'), "data": data})
    return values


def parse_evtx_sample(evtx_path: Path, output_path: Path, limit: int = 500) -> list[dict[str, object]]:
    try:
        from Evtx.Evtx import Evtx  # type: ignore
    except Exception:
        return []
    events: list[dict[str, object]] = []
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    try:
        with Evtx(str(evtx_path)) as log:
            for record in log.records():
                if len(events) >= limit:
                    break
                root = ET.fromstring(record.xml())
                system = root.find("e:System", ns)
                event_id = ""
                provider = ""
                timestamp = ""
                if system is not None:
                    event_id_node = system.find("e:EventID", ns)
                    provider_node = system.find("e:Provider", ns)
                    time_node = system.find("e:TimeCreated", ns)
                    event_id = event_id_node.text if event_id_node is not None else ""
                    provider = provider_node.attrib.get("Name", "") if provider_node is not None else ""
                    timestamp = time_node.attrib.get("SystemTime", "") if time_node is not None else ""
                data: dict[str, str] = {}
                for node in root.findall(".//e:Data", ns):
                    name = node.attrib.get("Name", "")
                    if name:
                        data[name] = node.text or ""
                events.append({"event_id": event_id, "provider": provider, "timestamp": timestamp, "data": data})
    except Exception:
        return []
    output_path.write_text(json.dumps(events, indent=2, sort_keys=True), encoding="utf-8")
    return events


def parse_guest_artifacts(run_dir: Path) -> dict[str, object]:
    artifacts_zip = run_dir / "guest_artifacts.zip"
    if not artifacts_zip.exists():
        return {"guest_artifacts_present": False, "behaviors": [], "dropped_files": [], "autoruns": []}
    extract_dir = run_dir / "guest_artifacts"
    extract_dir.mkdir(exist_ok=True)
    try:
        with zipfile.ZipFile(artifacts_zip) as zf:
            zf.extractall(extract_dir)
    except zipfile.BadZipFile:
        return {"guest_artifacts_present": False, "guest_artifacts_error": "guest_artifacts.zip is not a valid zip"}

    process_tree = ensure_list(load_json_file(extract_dir / "process_tree_raw.json"))
    recent_hashes = ensure_list(load_json_file(extract_dir / "recent_file_hashes.json"))
    recent_files = ensure_list(load_json_file(extract_dir / "recent_files.json"))
    services = ensure_list(load_json_file(extract_dir / "services.json"))
    scheduled_tasks = ensure_list(load_json_file(extract_dir / "scheduled_tasks.json"))
    autoruns: list[dict[str, str]] = []
    for reg_name in ("hkcu_run.reg", "hkcu_runonce.reg", "hklm_run.reg", "hklm_runonce.reg"):
        autoruns.extend(parse_reg_values(extract_dir / reg_name))

    sysmon_events = parse_evtx_sample(extract_dir / "sysmon.evtx", run_dir / "sysmon_sample_events.json")
    process_events = [
        e for e in sysmon_events
        if str(e.get("event_id")) == "1"
    ]
    file_events = [
        e for e in sysmon_events
        if str(e.get("event_id")) == "11"
    ]
    registry_events = [
        e for e in sysmon_events
        if str(e.get("event_id")) in {"12", "13", "14"}
    ]
    dns_events = [
        e for e in sysmon_events
        if str(e.get("event_id")) == "22"
    ]

    behaviors: list[dict[str, object]] = []
    for item in autoruns:
        data = item.get("data", "")
        if re.search(r"\\(temp|appdata|programdata)\\", data, re.IGNORECASE):
            behaviors.append({
                "type": "persistence",
                "technique": "T1060/T1547.001",
                "description": "Autorun registry value points to a user-writable path",
                "evidence": item,
                "severity": "high",
            })
    for item in recent_hashes:
        if isinstance(item, dict) and re.search(r"\\(temp|appdata|programdata|startup)\\", str(item.get("Path", "")), re.IGNORECASE):
            behaviors.append({
                "type": "dropped_file",
                "technique": "T1105/T1204",
                "description": "Recently written file in a common malware staging path",
                "evidence": item,
                "severity": "medium",
            })
    for event in registry_events:
        data = event.get("data", {})
        if isinstance(data, dict) and re.search(r"\\Run|\\RunOnce|\\StartupApproved", str(data.get("TargetObject", "")), re.IGNORECASE):
            behaviors.append({
                "type": "registry_persistence",
                "technique": "T1547.001",
                "description": "Sysmon observed a persistence-oriented registry modification",
                "evidence": data,
                "severity": "high",
            })

    derived = {
        "guest_artifacts_present": True,
        "artifact_files": sorted(str(p.relative_to(extract_dir)) for p in extract_dir.rglob("*") if p.is_file()),
        "autoruns": autoruns,
        "dropped_files": recent_hashes if recent_hashes else recent_files,
        "process_tree": process_tree,
        "services_observed_count": len(services),
        "scheduled_tasks_observed_count": len(scheduled_tasks),
        "sysmon_event_sample_count": len(sysmon_events),
        "sysmon_process_events": process_events[:100],
        "sysmon_file_create_events": file_events[:100],
        "sysmon_registry_events": registry_events[:100],
        "sysmon_dns_events": dns_events[:100],
        "behaviors": behaviors,
    }
    (run_dir / "behavior_summary.json").write_text(json.dumps(derived, indent=2, sort_keys=True), encoding="utf-8")
    return derived


def write_report(args: argparse.Namespace, run_dir: Path, sample: Path, sample_sha256: str, summary: dict[str, object]) -> Path:
    report = run_dir / "analysis.md"
    dns_queries = summary.get("dns_queries", [])
    suspicious_domains = summary.get("suspicious_domains", [])
    tls_sni = summary.get("tls_sni", [])
    http_requests = summary.get("http_requests", [])
    suspicious_http_requests = summary.get("suspicious_http_requests", [])
    http_events = summary.get("http_events", [])
    suspicious_http_events = summary.get("suspicious_http_events", [])
    suricata_alerts = summary.get("suricata_alerts", [])
    static_iocs = summary.get("static_iocs", {})
    behaviors = summary.get("behaviors", [])
    dropped_files = summary.get("dropped_files", [])
    autoruns = summary.get("autoruns", [])
    artifact_files = summary.get("artifact_files", [])
    generated = ["rule.yar"]
    if (run_dir / "sigma_dns.yml").exists():
        generated.append("sigma_dns.yml")
    if (run_dir / "sigma_behavior.yml").exists():
        generated.append("sigma_behavior.yml")
    suspicious_domains_text = chr(10).join(f'- `{d}`' for d in suspicious_domains) if suspicious_domains else '- None observed'
    dns_queries_text = chr(10).join(f'- `{d}`' for d in dns_queries) if dns_queries else '- None observed'
    tls_sni_text = chr(10).join(f'- `{d}`' for d in tls_sni) if tls_sni else '- None observed'
    suspicious_http_requests_text = (
        chr(10).join(f"- `{r.get('method')} {r.get('host')}{r.get('uri')}`" for r in suspicious_http_requests)
        if suspicious_http_requests else '- None observed'
    )
    suspicious_http_events_text = (
        chr(10).join(f"- `{e.get('method')} {e.get('host')}{e.get('path')}` from `{e.get('client')}` UA `{e.get('user_agent')}`" for e in suspicious_http_events)
        if suspicious_http_events else '- None observed'
    )
    suricata_alerts_text = (
        chr(10).join(f"- `{a.get('alert', {}).get('signature')}` severity `{a.get('alert', {}).get('severity')}`" for a in suricata_alerts)
        if suricata_alerts else '- None observed'
    )
    behaviors_text = (
        chr(10).join(f"- `{b.get('type')}` {b.get('description')} severity `{b.get('severity')}`" for b in behaviors)
        if isinstance(behaviors, list) and behaviors else '- None observed'
    )
    autoruns_text = (
        chr(10).join(f"- `{a.get('key')}\\{a.get('name')}` -> `{a.get('data')}`" for a in autoruns[:50])
        if isinstance(autoruns, list) and autoruns else '- None observed'
    )
    dropped_files_text = (
        chr(10).join(f"- `{d.get('Path')}` sha256 `{d.get('SHA256', 'n/a')}`" for d in dropped_files[:50] if isinstance(d, dict))
        if isinstance(dropped_files, list) and dropped_files else '- None observed'
    )
    static_iocs_text = json.dumps(static_iocs, indent=2) if static_iocs else '{}'
    generated_text = chr(10).join(f'- `{name}`' for name in generated)
    artifact_files_text = (
        chr(10).join(f'- `{name}`' for name in artifact_files[:100])
        if isinstance(artifact_files, list) and artifact_files else '- No guest artifact archive was parsed'
    )
    body = f"""# Local Sandbox Run - {sample_sha256[:12]}

- Timestamp: {dt.datetime.now(dt.UTC).isoformat()}
- VM: `{args.vm}`
- Snapshot restored after run: `{args.snapshot}`
- Interface: `{args.interface}`
- Host-only gateway/DNS: `{args.analysis_service_ip if analysis_vm_enabled(args) else args.host_ip}`
- Analysis VM: `{args.analysis_vm if analysis_vm_enabled(args) else 'local-host'}`
- Analysis interface: `{args.analysis_interface if analysis_vm_enabled(args) else args.interface}`
- Guest IP: `{args.guest_ip}`
- Sample SHA256: `{sample_sha256}`
- Sample file: `{sample.name}`
- PCAP: `{(run_dir / 'capture.pcapng').name}`

## Suspicious Domains

{suspicious_domains_text}

## DNS Queries

{dns_queries_text}

## TLS SNI

{tls_sni_text}

## HTTP Requests

{suspicious_http_requests_text}

Full HTTP request count: `{len(http_requests)}`

## Fake HTTP/HTTPS Hits

{suspicious_http_events_text}

Full fake-service hit count: `{len(http_events)}`

## Suricata Alerts

{suricata_alerts_text}

## Behavioral Findings

{behaviors_text}

## Autoruns

{autoruns_text}

## Dropped / Recently Modified Files

{dropped_files_text}

## Static IOC Summary

{static_iocs_text}

## Generated Detections

{generated_text}

## Guest Artifact Inventory

{artifact_files_text}

## Guest Telemetry Setup

- `guest_setup.ps1` prepares Sysmon/Defender settings inside the clean Windows snapshot.
- `guest_collect.ps1` exports EVTX/process/network/registry artifacts once Guest Control is available or when run manually in the guest.
- `behavior_summary.json` contains parsed guest-side persistence, dropped-file, and Sysmon summaries when artifacts are available.

## Notes

- DNS is wildcarded to `{args.host_ip}` by `dnsmasq`.
- HTTP ports 80/8080 and HTTPS port 443 are simulated locally when available.
- Guest Control is used when available; mounted ISO and keyboard injection remain as fallback.
"""
    report.write_text(body, encoding="utf-8")
    return report


def derive_sample_sha_from_run_dir(run_dir: Path) -> str:
    for path in run_dir.glob("*.sample"):
        return path.stem
    match = re.search(r"_([0-9a-f]{12})$", run_dir.name)
    return match.group(1) if match else "unknown"


def parse_existing_run(args: argparse.Namespace) -> int:
    run_dir = args.run_dir.expanduser().resolve()
    if not run_dir.exists():
        raise RuntimeError(f"Run directory not found: {run_dir}")
    sample_sha256 = derive_sample_sha_from_run_dir(run_dir)
    sample = next(run_dir.glob("*.sample"), run_dir / "sample.unknown")
    triage: dict[str, object] = {}
    if args.retriage and sample.exists():
        triage = static_triage(sample, run_dir)
    pcap = run_dir / "capture.pcapng"
    summary = parse_artifacts(run_dir, pcap)
    static_path = run_dir / "static_triage.json"
    if static_path.exists():
        triage = json.loads(static_path.read_text(encoding="utf-8", errors="replace"))
        summary["static_iocs"] = triage.get("static_iocs", {})
    elif triage:
        summary["static_iocs"] = triage.get("static_iocs", {})
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    make_rules(run_dir, sample_sha256, summary, triage)
    report = write_report(args, run_dir, sample, sample_sha256, summary)
    print(report)
    return 0


def cleanup_vm(args: argparse.Namespace) -> None:
    state = vm_state(args.vm)
    if state == "running":
        run(["VBoxManage", "controlvm", args.vm, "poweroff"], check=False)
        time.sleep(3)
    run(["VBoxManage", "snapshot", args.vm, "restore", args.snapshot], check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a sample in the local VirtualBox malware lab.")
    parser.add_argument("sample", type=Path, nargs="?", help="Sample file or password-protected .7z archive")
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    parser.add_argument("--guest-user", default=DEFAULT_GUEST_USER)
    parser.add_argument("--guest-password", default=DEFAULT_GUEST_PASSWORD)
    parser.add_argument("--guestcontrol", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--vm", default=DEFAULT_VM)
    parser.add_argument("--snapshot", default=DEFAULT_SNAPSHOT)
    parser.add_argument("--interface", default=DEFAULT_INTERFACE)
    parser.add_argument("--host-ip", default=DEFAULT_HOST_IP)
    parser.add_argument("--guest-ip", default=DEFAULT_GUEST_IP)
    parser.add_argument("--duration", type=int, default=180)
    parser.add_argument("--boot-wait", type=int, default=90)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--stop-apache", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--suricata", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--kill-stale-capture", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--allow-stale-capture", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--memory-dump", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--analysis-vm", default=DEFAULT_ANALYSIS_VM)
    parser.add_argument("--analysis-vm-user", default=DEFAULT_ANALYSIS_VM_USER)
    parser.add_argument("--analysis-vm-password", default=DEFAULT_ANALYSIS_VM_PASSWORD)
    parser.add_argument("--analysis-share-host", type=Path, default=DEFAULT_ANALYSIS_SHARE_HOST)
    parser.add_argument("--analysis-share-guest", default=DEFAULT_ANALYSIS_SHARE_GUEST)
    parser.add_argument("--analysis-service-ip", default=DEFAULT_ANALYSIS_SERVICE_IP)
    parser.add_argument("--analysis-interface", default=DEFAULT_ANALYSIS_INTERFACE)
    parser.add_argument("--local-analysis-only", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--parse-only", action="store_true", help="Re-parse an existing run directory and regenerate detections/report")
    parser.add_argument("--report-only", action="store_true", help="Alias for --parse-only")
    parser.add_argument("--retriage", action="store_true", help="Re-run static triage before parsing/report generation")
    parser.add_argument("--run-dir", type=Path, help="Existing run directory for --parse-only/--report-only")
    args = parser.parse_args()

    if args.parse_only or args.report_only:
        if not args.run_dir:
            parser.error("--run-dir is required with --parse-only/--report-only")
        return parse_existing_run(args)

    if not args.sample:
        parser.error("sample is required unless --parse-only/--report-only is used")
    args.sample = args.sample.expanduser().resolve()
    args.run_root.mkdir(parents=True, exist_ok=True)
    work_dir = Path(tempfile.mkdtemp(prefix="raiccoon_local_"))
    service_procs: list[subprocess.Popen] = []
    host_service_state: dict[str, bool] = {}
    suricata: subprocess.Popen | None = None
    tshark: subprocess.Popen | None = None
    gateway_state: dict[str, object] | None = None
    run_dir: Path | None = None
    try:
        sample = extract_sample(args.sample, work_dir, args.password)
        sample_sha256 = sha256_file(sample)
        run_dir = args.run_root / f"{dt.datetime.now().strftime('%Y-%m-%d_%H%M%S')}_{sample_sha256[:12]}"
        run_dir.mkdir(parents=True)
        assert run_dir is not None
        current_run_dir: Path = run_dir
        shutil.copy2(sample, run_dir / f"{sample_sha256}.sample")
        preflight(args, current_run_dir)
        if not analysis_vm_enabled(args):
            host_service_state = stop_host_conflicts(current_run_dir, args.stop_apache)
        triage: dict[str, object] = {}
        if not analysis_vm_enabled(args):
            triage = static_triage(sample, current_run_dir)
        write_guest_scripts(current_run_dir)
        iso_path = make_runner_iso(sample, current_run_dir)

        if analysis_vm_enabled(args):
            gateway_state = start_analysis_gateway(args, current_run_dir)
        else:
            service_procs = start_fake_services(args, current_run_dir)
            suricata = start_suricata(args, current_run_dir)
        restore_and_start_vm(args)

        pcap = current_run_dir / "capture.pcapng"
        if not analysis_vm_enabled(args):
            capture_duration = str(args.duration + 120)
            tshark = start(
                privileged_helper_cmd(
                    "capture",
                    "--interface", args.interface,
                    "--duration", capture_duration,
                    "--output", str(pcap),
                ),
                current_run_dir / "tshark.log",
            )
            time.sleep(2)
            if tshark.poll() is not None:
                raise RuntimeError(f"tshark failed to start; see {current_run_dir / 'tshark.log'}")

        launched_with_guestcontrol = False
        if args.guestcontrol:
            wait_guest_ready(args)
            launched_with_guestcontrol = launch_with_guestcontrol(args, sample, current_run_dir)
        if not launched_with_guestcontrol:
            mount_and_launch(args, iso_path, current_run_dir)
            for second in range(0, args.duration, 30):
                time.sleep(min(30, args.duration - second))
                run(["VBoxManage", "controlvm", args.vm, "screenshotpng", str(current_run_dir / f"screenshot_{second + 30:03d}s.png")], check=False)
        else:
            run(["VBoxManage", "controlvm", args.vm, "screenshotpng", str(current_run_dir / "after_guestcontrol_launch.png")], check=False)

        if tshark:
            try:
                tshark.wait(timeout=30)
            except subprocess.TimeoutExpired:
                stop_process(tshark)
            tshark = None
        if suricata:
            stop_process(suricata)
            suricata = None
        for proc in reversed(service_procs):
            stop_process(proc)
        service_procs = []
        if gateway_state is not None:
            sync_host_run_to_stage(current_run_dir, Path(str(gateway_state["staged_run_dir"])))
            stop_analysis_gateway(args, current_run_dir, gateway_state)
            gateway_state = None
        run(privileged_helper_cmd("fix-run-dir", "--run-dir", str(current_run_dir)), check=False)
        if pcap.exists():
            pcap.chmod(0o644)
        if analysis_vm_enabled(args):
            report = run_analysis_in_analysis_vm(args, current_run_dir)
        else:
            summary = parse_artifacts(current_run_dir, pcap)
            summary["static_iocs"] = triage.get("static_iocs", {})
            summary_path = current_run_dir / "summary.json"
            summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
            make_rules(current_run_dir, sample_sha256, summary, triage)
            report = write_report(args, current_run_dir, sample, sample_sha256, summary)
        print(report)
        return 0
    finally:
        if tshark:
            stop_process(tshark)
        if suricata:
            stop_process(suricata)
        for proc in reversed(service_procs):
            stop_process(proc)
        if gateway_state is not None and run_dir is not None:
            try:
                sync_host_run_to_stage(run_dir, Path(str(gateway_state["staged_run_dir"])))
                stop_analysis_gateway(args, run_dir, gateway_state)
            except Exception:
                pass
        cleanup_vm(args)
        restore_host_conflicts(host_service_state, run_dir)
        shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
