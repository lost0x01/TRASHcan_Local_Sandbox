# Recreate the Lab

This guide describes the baseline needed for another researcher to recreate the local sandbox.

## 1. Host Preparation

Install the required tools on a Linux host:

```bash
sudo apt update
sudo apt install -y virtualbox tshark wireshark-common dnsmasq xorriso p7zip-full openssl suricata python3-venv
```

Allow capture on the host-only interface. On some distributions this means adding your user to the `wireshark` group and logging out/in:

```bash
sudo usermod -aG wireshark "$USER"
```

## 2. VirtualBox Network

Create a host-only network with:

- Host IP: `192.168.56.1`
- Guest IP: `192.168.56.20`
- Interface: `vboxnet0`

Disable bridged/NAT adapters before detonation unless you intentionally route traffic through a controlled gateway.

## 3. Windows Guest

Create a Windows analysis VM named:

```text
win-malware-lab
```

Install:

- VirtualBox Guest Additions
- PowerShell 5+
- Sysmon
- Optional WinPmem at `C:\Tools\WinPmem\winpmem_mini_x64_rc2.exe`

Create a local analysis user. The default runner expects:

```text
analyst / MalwareLab!2026
```

Adjust the username/password with `--guest-user` and `--guest-password` if needed.

## 4. Guest Baseline Script

Copy `src/raiccoon_sandbox/local_vbox_detonate.py` generated `guest_setup.ps1` from a run directory or adapt `scripts/setup_flarevm.ps1`.

The important baseline features are:

- Sysmon ProcessCreate, NetworkConnect, FileCreate, Registry, DNS, ProcessAccess, and targeted ImageLoad events
- PowerShell Operational logging enabled
- Defender reduced or disabled inside the isolated lab snapshot
- `analyst` able to read event logs

## 5. Snapshot

Power off the VM and create the clean snapshot:

```bash
VBoxManage snapshot win-malware-lab take clean-guestadditions-sysmon
```

## 6. Test

Use a benign executable first:

```bash
PYTHONPATH=src python3 -m raiccoon_sandbox.local_vbox_detonate /path/to/benign.exe --duration 60
```

Review the generated run folder before detonating malware.

