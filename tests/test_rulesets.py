import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SURICATA_RULESET = REPO_ROOT / "rules" / "suricata" / "trashcan-local.rules"
YARA_RULESET = REPO_ROOT / "rules" / "yara" / "trashcan_static_triage.yar"
SETUP_REMNUX = REPO_ROOT / "scripts" / "setup_remnux.sh"
YARA_HELPER = REPO_ROOT / "scripts" / "run_yara_triage.sh"


class RulesetTests(unittest.TestCase):
    def test_custom_suricata_ruleset_exists_and_compiles(self):
        self.assertTrue(SURICATA_RULESET.exists(), f"missing {SURICATA_RULESET}")
        self.assertTrue(shutil.which("suricata"), "suricata binary is required for validation")
        with tempfile.TemporaryDirectory() as td:
            log_dir = Path(td) / "log"
            log_dir.mkdir()
            result = subprocess.run(
                ["suricata", "-T", "-S", str(SURICATA_RULESET), "-l", str(log_dir)],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_custom_suricata_ruleset_includes_expanded_patterns(self):
        content = SURICATA_RULESET.read_text(encoding="utf-8")
        self.assertIn("pastebin\\.com", content)
        self.assertIn("discord(?:app)?\\.com", content)
        self.assertIn("curl/", content)
        self.assertIn("TelegramBot", content)
        self.assertIn("rustdesk\\.com", content)

    def test_custom_suricata_ruleset_includes_family_focused_patterns(self):
        content = SURICATA_RULESET.read_text(encoding="utf-8")
        self.assertIn("TRASHcan Stealer Exfiltration Pattern", content)
        self.assertIn("TRASHcan Loader Staging URI Pattern", content)
        self.assertIn("TRASHcan Ransomware Leaksite Or Negotiation DNS Query", content)
        self.assertIn("\\/gate\\.php", content)

    def test_custom_yara_ruleset_exists_and_compiles(self):
        self.assertTrue(YARA_RULESET.exists(), f"missing {YARA_RULESET}")
        self.assertTrue(shutil.which("yarac"), "yarac binary is required for validation")
        with tempfile.TemporaryDirectory() as td:
            compiled = Path(td) / "compiled.yarc"
            result = subprocess.run(
                ["yarac", str(YARA_RULESET), str(compiled)],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_custom_yara_ruleset_includes_expanded_triage_rules(self):
        content = YARA_RULESET.read_text(encoding="utf-8")
        self.assertIn("TRASHcan_Remote_Access_Tool_Artifacts", content)
        self.assertIn("TRASHcan_Credential_Access_Artifacts", content)
        self.assertIn("Mimikatz", content)
        self.assertIn("AnyDesk", content)

    def test_custom_yara_ruleset_includes_family_focused_rules(self):
        content = YARA_RULESET.read_text(encoding="utf-8")
        self.assertIn("TRASHcan_Stealer_Exfil_Artifacts", content)
        self.assertIn("TRASHcan_Loader_Stager_Artifacts", content)
        self.assertIn("TRASHcan_Ransomware_Note_Artifacts", content)
        self.assertIn("wallet.dat", content)
        self.assertIn("README.txt", content)

    def test_setup_remnux_references_custom_suricata_ruleset(self):
        content = SETUP_REMNUX.read_text(encoding="utf-8")
        self.assertIn("trashcan-local.rules", content)
        self.assertIn("run_yara_triage.sh", content)
        self.assertIn("trashcan_static_triage.yar", content)

    def test_yara_helper_script_exists_and_reports_matches(self):
        self.assertTrue(YARA_HELPER.exists(), f"missing {YARA_HELPER}")
        self.assertTrue(shutil.which("yara"), "yara binary is required for helper validation")
        with tempfile.TemporaryDirectory() as td:
            sample_dir = Path(td) / "samples"
            sample_dir.mkdir()
            suspicious = sample_dir / "suspicious.ps1"
            suspicious.write_text(
                "powershell -enc AAAA\nFromBase64String(\nIEX(\nDownloadString(\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [str(YARA_HELPER), str(sample_dir)],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("TRASHcan_PowerShell_EncodedCommand_Artifacts", result.stdout)
        self.assertIn("suspicious.ps1", result.stdout)


if __name__ == "__main__":
    unittest.main()
