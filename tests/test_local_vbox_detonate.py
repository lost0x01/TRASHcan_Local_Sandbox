import argparse
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from raiccoon_sandbox import local_vbox_detonate as runner


class LocalVBoxDetonateTests(unittest.TestCase):
    def test_domain_filtering_rejects_common_noise(self):
        self.assertFalse(runner.is_suspicious_domain("www.msftconnecttest.com"))
        self.assertFalse(runner.is_suspicious_domain("192.168.56.20"))
        self.assertTrue(runner.is_suspicious_domain("example-c2.invalid"))

    def test_make_rules_skips_dns_placeholder(self):
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            (tmp_path / "strings.txt").write_text("MZ\n", encoding="utf-8")
            summary = {"suspicious_domains": [], "behaviors": []}
            runner.make_rules(tmp_path, "a" * 64, summary, {})

            self.assertTrue((tmp_path / "rule.yar").exists())
            self.assertFalse((tmp_path / "sigma_dns.yml").exists())
            self.assertTrue((tmp_path / "sigma_dns.skipped").exists())
            self.assertNotIn("example.invalid", (tmp_path / "sigma_dns.skipped").read_text(encoding="utf-8"))

    def test_build_host_suricata_rules_includes_repo_rules(self):
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            rules_path = runner.build_host_suricata_rules(tmp_path)
            content = rules_path.read_text(encoding="utf-8")
            self.assertIn("TRASHcan Suspicious Malware Staging Or C2 DNS Query", content)
            self.assertIn("RAIccoon suspicious .pw DNS query", content)
            self.assertIn("TRASHcan Stealer Exfiltration Pattern", content)

    def test_run_bundled_yara_triage_scans_sample_and_guest_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            sample = tmp_path / "sample.bin"
            sample.write_text(
                "powershell -enc\nFromBase64String(\nIEX(\nDownloadString(\n",
                encoding="utf-8",
            )
            guest_dir = tmp_path / "guest_artifacts"
            guest_dir.mkdir()
            (guest_dir / "rat.txt").write_text("AnyDesk\nRustDesk\n", encoding="utf-8")

            result = runner.run_bundled_yara_triage(tmp_path, sample)

            self.assertGreaterEqual(result["match_count"], 2)
            self.assertIn("TRASHcan_PowerShell_EncodedCommand_Artifacts", result["matched_rules"])
            self.assertIn("TRASHcan_Remote_Access_Tool_Artifacts", result["matched_rules"])
            self.assertTrue((tmp_path / "yara_triage_summary.json").exists())
            self.assertTrue((tmp_path / "yara_triage_hits.txt").exists())

    def test_stage_analysis_support_files_copies_bundled_yara_assets(self):
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            runner.stage_analysis_support_files(tmp_path)

            staged_rules = tmp_path / "bundled_support" / "rules" / "yara" / "trashcan_static_triage.yar"
            staged_helper = tmp_path / "bundled_support" / "scripts" / "run_yara_triage.sh"

            self.assertTrue(staged_rules.exists())
            self.assertTrue(staged_helper.exists())
            self.assertEqual(staged_rules.read_text(encoding="utf-8"), runner.BUNDLED_YARA_RULESET.read_text(encoding="utf-8"))

    def test_make_rules_generates_sigma_and_kql_for_family_hits(self):
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            (tmp_path / "strings.txt").write_text("MZ\nAnyDesk\n", encoding="utf-8")
            summary = {
                "suspicious_domains": ["evil-c2.invalid"],
                "behaviors": [{
                    "type": "autorun",
                    "description": "Run key points at AppData dropper",
                    "severity": "high",
                }],
                "yara_triage": {
                    "matched_rules": [
                        "TRASHcan_Loader_Stager_Artifacts",
                        "TRASHcan_Remote_Access_Tool_Artifacts",
                    ]
                },
            }

            runner.make_rules(tmp_path, "b" * 64, summary, {})

            sigma_family = tmp_path / "sigma_yara_family.yml"
            kql_family = tmp_path / "kql_triage_hunts.kql"
            self.assertTrue(sigma_family.exists())
            self.assertTrue(kql_family.exists())
            self.assertIn("TRASHcan_Loader_Stager_Artifacts", sigma_family.read_text(encoding="utf-8"))
            self.assertIn("DeviceProcessEvents", kql_family.read_text(encoding="utf-8"))
            self.assertIn("AnyDesk", kql_family.read_text(encoding="utf-8"))

    def test_parse_guest_artifacts_handles_recent_files(self):
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            artifact_dir = tmp_path / "artifact_src"
            artifact_dir.mkdir()
            (artifact_dir / "recent_file_hashes.json").write_text(
                json.dumps([
                    {
                        "Path": r"C:\Users\analyst\AppData\Local\Temp\drop.exe",
                        "Size": 1234,
                        "SHA256": "b" * 64,
                    }
                ]),
                encoding="utf-8",
            )
            with zipfile.ZipFile(tmp_path / "guest_artifacts.zip", "w") as zf:
                zf.write(artifact_dir / "recent_file_hashes.json", "recent_file_hashes.json")

            parsed = runner.parse_guest_artifacts(tmp_path)
            self.assertTrue(parsed["guest_artifacts_present"])
            self.assertTrue(parsed["behaviors"])

    def test_parse_existing_run_retriage_generates_static_triage(self):
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td) / "2026-06-13_abcdefabcdef"
            run_dir.mkdir()
            (run_dir / ("a" * 64 + ".sample")).write_text(
                "powershell -enc\nFromBase64String(\nIEX(\nDownloadString(\n",
                encoding="utf-8",
            )
            args = argparse.Namespace(
                run_dir=run_dir,
                retriage=True,
                vm="win-malware-lab",
                snapshot="clean-guestadditions-sysmon",
                interface="vboxnet0",
                host_ip="192.168.56.1",
                guest_ip="192.168.56.20",
                analysis_service_ip="192.168.56.1",
                analysis_vm="remnux",
                analysis_interface="enp0s3",
                local_analysis_only=True,
            )

            rc = runner.parse_existing_run(args)
            self.assertEqual(rc, 0)
            self.assertTrue((run_dir / "static_triage.json").exists())
            self.assertTrue((run_dir / "summary.json").exists())
            self.assertTrue((run_dir / "analysis.md").exists())
            self.assertTrue((run_dir / "yara_triage_summary.json").exists())
            self.assertTrue((run_dir / "kql_triage_hunts.kql").exists())
            self.assertTrue((run_dir / "iocs_full.csv").exists())
            self.assertTrue((run_dir / "process_tree_summary.md").exists())
            report_text = (run_dir / "analysis.md").read_text(encoding="utf-8")
            self.assertIn("## 3. Static Analysis", report_text)
            self.assertIn("## 4. Code Analysis and Embedded Artefacts", report_text)
            self.assertIn("## 5. Dynamic Analysis", report_text)
            self.assertIn("## 6. Process Tree and Execution Chain", report_text)
            self.assertIn("## 8. Full IOC Summary", report_text)
            self.assertIn("## 9. Detection Engineering", report_text)
            self.assertIn("## 10. Threat Hunting", report_text)
            ioc_csv = (run_dir / "iocs_full.csv").read_text(encoding="utf-8")
            self.assertIn("type,value,source,context", ioc_csv)
            self.assertIn("TRASHcan_PowerShell_EncodedCommand_Artifacts", report_text)
            yara_summary = json.loads((run_dir / "yara_triage_summary.json").read_text(encoding="utf-8"))
            self.assertIn("TRASHcan_PowerShell_EncodedCommand_Artifacts", yara_summary["matched_rules"])


if __name__ == "__main__":
    unittest.main()
