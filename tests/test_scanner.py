import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from webguardian.scanner import Scanner


FIXTURES = Path(__file__).parent / "fixtures"


class ScannerTests(unittest.TestCase):
    def test_detects_known_backdoor_filename_and_reports_progress(self):
        root = FIXTURES / "detected"
        payload = root / "shell.php"
        progress = []
        result = Scanner(root, progress_callback=progress.append).run()
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["stats"]["files_scanned"], 1)
        self.assertEqual(len(result["scanned_files"]), 1)
        self.assertEqual(result["scanned_files"][0]["status"], "threat")
        self.assertEqual(result["scanned_files"][0]["detections"], result["summary"]["total"])
        self.assertGreater(result["summary"]["critical"], 0)
        self.assertTrue(any(item["percent"] == 100 for item in progress))
        matching = [item for item in result["findings"] if item.get("rule_id") == "backdoor_filename"]
        self.assertEqual(len(matching), 1)
        self.assertTrue(matching[0].get("sha256"))

    def test_exclusion_skips_matching_directory(self):
        root = FIXTURES / "excluded"
        result = Scanner(root, exclusions=["generated/**"]).run()
        self.assertEqual(result["stats"]["files_scanned"], 0)
        self.assertEqual(result["summary"]["total"], 0)

    def test_pre_cancelled_scan_finishes_as_cancelled(self):
        event = threading.Event()
        event.set()
        result = Scanner(FIXTURES, cancel_event=event).run()
        self.assertEqual(result["status"], "cancelled")

    def test_permission_scan_is_opt_in(self):
        scanner = Scanner(FIXTURES / "detected")
        with patch.object(scanner, "_check_permissions") as check:
            scanner.run()
            check.assert_not_called()

        scanner = Scanner(FIXTURES / "detected", check_permissions=True)
        with patch.object(scanner, "_check_permissions") as check:
            scanner.run()
            check.assert_called_once()


if __name__ == "__main__":
    unittest.main()
