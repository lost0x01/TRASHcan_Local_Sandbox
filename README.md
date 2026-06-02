# RAIccoon Malware Sandbox

RAIccoon Malware Sandbox is a local-first VirtualBox detonation lab for controlled Windows malware triage. It restores a clean Windows snapshot, starts host-only DNS/HTTP/HTTPS simulation, captures traffic, runs a sample through VirtualBox Guest Control, collects Windows artifacts, parses behavior, and generates triage detections.

This repository is designed for defenders and researchers who want a reproducible sandbox without sending samples to public services.

## Capabilities

- VirtualBox snapshot restore and post-run cleanup
- Host-only DNS wildcarding with `dnsmasq`
- Fake HTTP on `80/8080` and HTTPS on `443`
- PCAP capture with `tshark`
- Per-run Suricata validation and capture
- Windows guest collection for processes, services, tasks, WMI, autoruns, recent files, EVTX logs, and optional memory dumps
- Sysmon-oriented behavior parsing
- Auto-generated `summary.json`, `behavior_summary.json`, `analysis.md`, YARA, and Sigma detections
- `--parse-only` / `--report-only` mode for reprocessing completed runs

## Safety Model

Use a dedicated host-only VirtualBox network. Do not bridge the malware VM to your production network. Treat every run artifact as potentially malicious.

Recommended defaults:

- VM name: `win-malware-lab`
- Snapshot: `clean-guestadditions-sysmon`
- Host-only interface: `vboxnet0`
- Host-only gateway: `192.168.56.1`
- Guest IP: `192.168.56.20`
- Sample archive password: `infected`

## Quick Start

```bash
git clone <your-repo-url> raiccoon-malware-sandbox
cd raiccoon-malware-sandbox
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m raiccoon_sandbox.local_vbox_detonate --help
```

Run a password-protected sample archive:

```bash
PYTHONPATH=src python3 -m raiccoon_sandbox.local_vbox_detonate \
  /path/to/sample.7z \
  --password infected \
  --duration 180
```

Re-parse a completed run:

```bash
PYTHONPATH=src python3 -m raiccoon_sandbox.local_vbox_detonate \
  --parse-only \
  --run-dir /path/to/runs/2026-06-02_110358_deadbeefcafe
```

## Repository Layout

```text
src/raiccoon_sandbox/       Python runner and parser
scripts/                    Guest/host setup helpers
configs/                    Example local configuration
docs/                       Rebuild, operations, and safety docs
tests/                      Unit tests for parser and rule behavior
examples/                   Non-malicious example outputs/templates
```

## Required Host Tools

- `VirtualBox` / `VBoxManage`
- `tshark` and `capinfos`
- `dnsmasq`
- `xorriso`
- `7z`
- `openssl`
- `suricata` recommended
- `python-evtx` optional for Sysmon EVTX parsing
- `zeek` optional for future protocol enrichment
- `volatility3` optional for memory analysis

## Legal and Ethical Use

Only analyze samples you are authorized to handle. Keep the VM isolated, use host-only networking, and never upload live malware or generated run artifacts to a public repository.

