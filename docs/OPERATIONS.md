# Operations

## Normal Run

```bash
PYTHONPATH=src python3 -m raiccoon_sandbox.local_vbox_detonate sample.7z --password infected --duration 180
```

The runner will:

1. Extract the sample into a temporary working directory.
2. Hash and statically triage the file.
3. Stop Apache if it would conflict with fake HTTP services.
4. Start DNS, fake HTTP/HTTPS, Suricata, and `tshark`.
5. Restore and boot the VM snapshot.
6. Launch the sample through Guest Control.
7. Collect guest artifacts.
8. Parse PCAP, Suricata, HTTP, registry, file, and EVTX artifacts.
9. Generate summary, behavior, YARA, Sigma, and markdown report outputs.
10. Power off and restore the snapshot.

## Useful Flags

```text
--duration N              Sample observation time in seconds
--memory-dump             Ask the guest collector to capture memory when WinPmem is installed
--no-suricata             Disable per-run Suricata
--no-stop-apache          Do not stop/restore Apache
--parse-only --run-dir X  Reparse an existing run directory
--report-only --run-dir X Alias for parse-only
```

## Outputs

```text
analysis.md
summary.json
behavior_summary.json
static_triage.json
strings.txt
capture.pcapng
suricata_eve.json
guest_artifacts.zip
guest_artifacts/
rule.yar
sigma_dns.yml or sigma_dns.skipped
sigma_behavior.yml when behavior supports it
```

## Hygiene Checks

Before running malware, verify:

- The VM only has host-only networking.
- The clean snapshot exists.
- `VBoxManage guestcontrol ... whoami` works.
- No stale `tshark` or `dumpcap` process is bound to `vboxnet0`.
- Ports `53`, `80`, `443`, and `8080` are free or expected to be reclaimed.
- Apache can be stopped and restored if installed.

