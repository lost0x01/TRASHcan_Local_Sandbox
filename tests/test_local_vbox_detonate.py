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

    def test_service_level_profiles_define_triage_standard_and_deep_dive(self):
        triage = runner.service_level_profile("rapid-triage")
        standard = runner.service_level_profile("standard")
        deep_dive = runner.service_level_profile("deep-dive")

        self.assertEqual(triage["required_sections"], ["Executive Summary", "Sample Metadata", "IOC"])
        self.assertIn("Detection Engineering", standard["required_sections"])
        self.assertTrue(deep_dive["memory_analysis_required"])
        self.assertGreater(deep_dive["minimum_score_for_client_ready"], triage["minimum_score_for_client_ready"])

    def test_report_preflight_identifies_ready_and_missing_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td)
            required = [
                "analysis.md", "summary.json", "static_analysis.json", "dynamic_analysis.json",
                "process_tree.json", "network_summary.json", "iocs_full.csv", "verdict_score.json",
                "mitre_attack_mapping.json", "run_manifest.json", "chain_of_custody.json",
            ]
            for name in required:
                (run_dir / name).write_text("{}" if name.endswith(".json") else "Executive Summary\nSample Metadata\nStatic Analysis\nDynamic Analysis\nProcess Tree\nIOC\nDetection Engineering\nThreat Hunting\n", encoding="utf-8")
            for dirname in ("reports", "static", "dynamic", "network", "detections", "evidence"):
                (run_dir / dirname).mkdir()
            (run_dir / "reports" / "analysis.md").write_text("report", encoding="utf-8")
            manifest = {"privacy_guardrails": {"allow_public_enrichment": False, "public_uploads_allowed": False}}
            (run_dir / "run_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            (run_dir / "verdict_score.json").write_text(json.dumps({"score": 90, "verdict": "suspicious"}), encoding="utf-8")

            result = runner.report_preflight(run_dir, service_level="standard")
            self.assertTrue(result["client_ready"])
            self.assertEqual(result["missing_required_artifacts"], [])

            (run_dir / "verdict_score.json").write_text(json.dumps({"score": 10, "verdict": "inconclusive"}), encoding="utf-8")
            low_score = runner.report_preflight(run_dir, service_level="standard")
            self.assertFalse(low_score["client_ready"])
            self.assertTrue(low_score["score_errors"])
            (run_dir / "verdict_score.json").write_text(json.dumps({"score": 90, "verdict": "suspicious"}), encoding="utf-8")

            (run_dir / "process_tree.json").unlink()
            failed = runner.report_preflight(run_dir, service_level="standard")
            self.assertFalse(failed["client_ready"])
            self.assertIn("process_tree.json", failed["missing_required_artifacts"])

    def test_workflow_status_and_handoff_builder(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            run_dir = root / "run"
            run_dir.mkdir()
            final_dir = root / "RAIccoon_Reports"
            for name in ("analysis.md", "summary.json", "static_analysis.json", "dynamic_analysis.json", "process_tree.json", "network_summary.json", "iocs_full.csv", "verdict_score.json", "mitre_attack_mapping.json", "run_manifest.json", "chain_of_custody.json"):
                (run_dir / name).write_text("{}" if name.endswith(".json") else "Executive Summary\nSample Metadata\nStatic Analysis\nDynamic Analysis\nProcess Tree\nIOC\nDetection Engineering\nThreat Hunting\n", encoding="utf-8")
            for dirname in ("reports", "static", "dynamic", "network", "detections", "evidence"):
                (run_dir / dirname).mkdir()
            (run_dir / "reports" / "analysis.md").write_text("report", encoding="utf-8")
            (run_dir / "reports" / "client_report.pdf").write_bytes(b"%PDF-1.4\n% test pdf\n")
            (run_dir / "run_manifest.json").write_text(json.dumps({"privacy_guardrails": {"allow_public_enrichment": False, "public_uploads_allowed": False}}), encoding="utf-8")
            (run_dir / "verdict_score.json").write_text(json.dumps({"score": 90, "verdict": "suspicious"}), encoding="utf-8")

            status = runner.update_workflow_status(run_dir, "qa", "ready for final handoff")
            self.assertEqual(status["current_status"], "qa")
            self.assertEqual(status["history"][-1]["note"], "ready for final handoff")

            handoff = runner.build_client_handoff(run_dir, final_dir, service_level="standard")
            self.assertTrue(handoff["client_ready"])
            self.assertTrue(Path(handoff["final_pdf"]).exists())
            self.assertEqual(Path(handoff["final_pdf"]).parent, final_dir)
            self.assertTrue((run_dir / "client_handoff.json").exists())

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
            expected_artifacts = [
                "iocs_full.csv",
                "process_tree_summary.md",
                "static_analysis.json",
                "string_iocs.json",
                "packer_assessment.json",
                "static_findings.md",
                "dynamic_analysis.json",
                "process_tree.json",
                "behavior_timeline.json",
                "network_summary.json",
                "c2_candidates.json",
                "memory_analysis.json",
                "verdict_score.json",
                "mitre_attack_mapping.json",
                "run_manifest.json",
                "chain_of_custody.json",
                "tool_versions.json",
            ]
            for artifact in expected_artifacts:
                self.assertTrue((run_dir / artifact).exists(), artifact)
            report_bundle = run_dir / "reports"
            self.assertTrue((report_bundle / "analysis.md").exists())
            self.assertTrue((run_dir / "static" / "static_analysis.json").exists())
            self.assertTrue((run_dir / "dynamic" / "dynamic_analysis.json").exists())
            self.assertTrue((run_dir / "network" / "network_summary.json").exists())
            self.assertTrue((run_dir / "detections" / "rule.yar").exists())
            self.assertTrue((run_dir / "evidence" / "chain_of_custody.json").exists())
            process_tree = json.loads((run_dir / "process_tree.json").read_text(encoding="utf-8"))
            self.assertIn("processes", process_tree)
            verdict = json.loads((run_dir / "verdict_score.json").read_text(encoding="utf-8"))
            self.assertIn(verdict["verdict"], {"benign", "suspicious", "malicious", "inconclusive"})
            manifest = json.loads((run_dir / "run_manifest.json").read_text(encoding="utf-8"))
            self.assertFalse(manifest["privacy_guardrails"]["allow_public_enrichment"])
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
