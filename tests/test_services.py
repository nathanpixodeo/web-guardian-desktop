import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from webguardian.quarantine import QuarantineManager
from webguardian.scanner.version import SignatureVersion
from webguardian.storage import HistoryStore

TEMP_ROOT = Path(__file__).parent / ".tmp"
TEMP_ROOT.mkdir(exist_ok=True)


class ServiceTests(unittest.TestCase):
    @unittest.skipIf(os.environ.get("WEBGUARDIAN_READONLY_TESTS"), "requires filesystem mutation")
    def test_quarantine_and_restore_preserve_content(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as temp:
            root = Path(temp)
            source = root / "project" / "bad.php"
            source.parent.mkdir()
            source.write_text("malicious-content", encoding="utf-8")
            manager = QuarantineManager(root / "data")
            record = manager.quarantine(str(source), {"message": "test", "severity": "critical"})
            self.assertFalse(source.exists())
            self.assertEqual(len(manager.list()), 1)
            manager.restore(record["id"])
            self.assertEqual(source.read_text(encoding="utf-8"), "malicious-content")

    @unittest.skipIf(os.environ.get("WEBGUARDIAN_READONLY_TESTS"), "requires filesystem mutation")
    def test_history_round_trip(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as temp:
            store = HistoryStore(Path(temp))
            report = {
                "scan_id": "scan-1",
                "completed_at": "2026-06-19T12:00:00+00:00",
                "scanned_path": "C:/project",
                "summary": {"total": 1},
                "stats": {"files_scanned": 4},
            }
            store.save(report)
            self.assertEqual(store.list()[0]["scan_id"], "scan-1")
            self.assertEqual(store.get("scan-1")["summary"]["total"], 1)

    @unittest.skipIf(os.environ.get("WEBGUARDIAN_READONLY_TESTS"), "requires filesystem mutation")
    def test_verified_signature_update_install(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as temp:
            root = Path(temp)
            remote = root / "remote"
            remote.mkdir()
            database = {
                "version": "9.0.0",
                "build": 99,
                "published_at": "2026-06-19T00:00:00Z",
                "rules": [{
                    "id": "test-rule",
                    "category": "test",
                    "severity": "high",
                    "extensions": [".php"],
                    "pattern": "evil_test_pattern",
                    "description": "Test signature",
                }],
                "hashes": [],
                "filenames": [],
            }
            raw = json.dumps(database).encode("utf-8")
            database_path = remote / "signatures.json"
            database_path.write_bytes(raw)
            manifest = {
                "version": "9.0.0",
                "build": 99,
                "database_url": database_path.as_uri(),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
            manifest_path = remote / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            updater = SignatureVersion(manifest_path.as_uri(), root / "data")
            self.assertEqual(updater.check_for_updates()["status"], "update_available")
            self.assertEqual(updater.install_update()["status"], "installed")
            self.assertEqual(updater.build, 99)

    def test_bundled_signature_hash_matches_manifest(self):
        root = Path(__file__).parents[1]
        database = (root / "assets" / "signatures.json").read_bytes()
        manifest = json.loads((root / "assets" / "signatures_manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(hashlib.sha256(database).hexdigest(), manifest["sha256"])
        parsed = SignatureVersion._validate_database(database)
        self.assertGreater(len(parsed["rules"]), 0)


if __name__ == "__main__":
    unittest.main()
