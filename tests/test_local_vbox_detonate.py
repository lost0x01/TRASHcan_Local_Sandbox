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
            (run_dir / ("a" * 64 + ".sample")).write_bytes(b"MZ" + b"\x00" * 64)
            args = argparse.Namespace(
                run_dir=run_dir,
                retriage=True,
                vm="win-malware-lab",
                snapshot="clean-guestadditions-sysmon",
                interface="vboxnet0",
                host_ip="192.168.56.1",
                guest_ip="192.168.56.20",
            )

            rc = runner.parse_existing_run(args)
            self.assertEqual(rc, 0)
            self.assertTrue((run_dir / "static_triage.json").exists())
            self.assertTrue((run_dir / "summary.json").exists())
            self.assertTrue((run_dir / "analysis.md").exists())


if __name__ == "__main__":
    unittest.main()

