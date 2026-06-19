"""Verified malware-signature database updates."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from webguardian.storage import atomic_write_json, get_data_dir
from .signatures import SIGNATURES


PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUNDLED_DATABASE = PROJECT_ROOT / "assets" / "signatures.json"
DEFAULT_MANIFEST_URL = (
    "https://raw.githubusercontent.com/nathanpixodeo/web-guardian-desktop/"
    "master/assets/signatures_manifest.json"
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _utc_label() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


class SignatureUpdateError(RuntimeError):
    pass


class SignatureVersion:
    """Reports current signature metadata and installs verified updates.

    The remote manifest provides ``database_url`` and the expected SHA-256.
    Installation is atomic and keeps one rollback copy.
    """

    def __init__(self, manifest_url: str | None = None, data_dir: Path | None = None):
        self.data_dir = Path(data_dir) if data_dir else get_data_dir()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.installed_file = self.data_dir / "signatures.json"
        self.backup_file = self.data_dir / "signatures.previous.json"
        self.state_file = self.data_dir / "signature_state.json"
        self.manifest_url = (
            manifest_url
            or os.environ.get("WEBGUARDIAN_UPDATE_URL")
            or DEFAULT_MANIFEST_URL
        )
        self.last_checked = ""
        self.last_updated = ""
        self._pending_manifest: dict | None = None
        self._load_state()
        self._refresh_metadata()

    @property
    def active_file(self) -> Path:
        return self.installed_file if self.installed_file.is_file() else BUNDLED_DATABASE

    def _load_state(self) -> None:
        try:
            state = json.loads(self.state_file.read_text(encoding="utf-8"))
            self.last_checked = str(state.get("last_checked", ""))
            self.last_updated = str(state.get("last_updated", ""))
        except (OSError, json.JSONDecodeError):
            pass

    def _save_state(self) -> None:
        atomic_write_json(self.state_file, {
            "last_checked": self.last_checked,
            "last_updated": self.last_updated,
            "manifest_url": self.manifest_url,
        })

    def _refresh_metadata(self) -> None:
        try:
            raw = self.active_file.read_bytes()
            data = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            raw, data = b"", {}
        self.version = str(data.get("version", "builtin"))
        self.build = int(data.get("build", 0))
        self.date = str(data.get("published_at", ""))[:10]
        self.dynamic_patterns = len(data.get("rules", []))
        self.patterns = self.dynamic_patterns + sum(len(rules) for rules in SIGNATURES.values())
        dynamic_categories = {row.get("category") for row in data.get("rules", []) if row.get("category")}
        self.categories = len(set(SIGNATURES) | dynamic_categories)
        self.hashes = len(data.get("hashes", []))
        self.file_hash = _sha256(raw) if raw else ""

    @staticmethod
    def _read_url(url: str, timeout: int = 15) -> bytes:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"https", "file"}:
            raise SignatureUpdateError("Update URL must use HTTPS")
        request = urllib.request.Request(url, headers={"User-Agent": "WebGuardian/1.1"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()

    @staticmethod
    def _validate_database(raw: bytes) -> dict:
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SignatureUpdateError("Signature database is not valid UTF-8 JSON") from exc
        if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
            raise SignatureUpdateError("Signature database schema is invalid")
        if not data.get("version") or not isinstance(data.get("build"), int):
            raise SignatureUpdateError("Signature database metadata is incomplete")
        valid_rules = 0
        for rule in data["rules"]:
            if not isinstance(rule, dict) or not rule.get("id") or not rule.get("pattern"):
                raise SignatureUpdateError("Signature database contains an invalid rule")
            try:
                re.compile(rule["pattern"], re.IGNORECASE)
            except (re.error, TypeError) as exc:
                raise SignatureUpdateError(f"Invalid regular expression in rule {rule.get('id')}") from exc
            valid_rules += 1
        if valid_rules == 0:
            raise SignatureUpdateError("Signature database contains no rules")
        return data

    def _fetch_manifest(self) -> dict:
        try:
            raw = self._read_url(self.manifest_url)
            manifest = json.loads(raw.decode("utf-8"))
        except (urllib.error.URLError, TimeoutError) as exc:
            raise SignatureUpdateError("Cannot reach the signature update server") from exc
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SignatureUpdateError("Update manifest is invalid") from exc
        required = {"version", "build", "database_url", "sha256"}
        if not isinstance(manifest, dict) or not required.issubset(manifest):
            raise SignatureUpdateError("Update manifest is missing required fields")
        if not isinstance(manifest["build"], int) or isinstance(manifest["build"], bool) or manifest["build"] < 0:
            raise SignatureUpdateError("Update manifest has an invalid build number")
        if not isinstance(manifest["database_url"], str) or not manifest["database_url"].strip():
            raise SignatureUpdateError("Update manifest has an invalid database URL")
        if not re.fullmatch(r"[a-fA-F0-9]{64}", str(manifest["sha256"])):
            raise SignatureUpdateError("Update manifest has an invalid SHA-256")
        return manifest

    def check_for_updates(self, callback=None) -> dict:
        if callback:
            callback({"phase": "Đang kết nối máy chủ cập nhật", "pct": 15})
        try:
            manifest = self._fetch_manifest()
            self._pending_manifest = manifest
            self.last_checked = _utc_label()
            self._save_state()
            if callback:
                callback({"phase": "Đã xác minh thông tin phiên bản", "pct": 100})
            available = int(manifest["build"]) > self.build
            return {
                "status": "update_available" if available else "up_to_date",
                "message": "Có CSDL nhận diện mới" if available else "CSDL nhận diện đã mới nhất",
                "current_version": self.version,
                "current_build": self.build,
                "remote_version": str(manifest["version"]),
                "remote_build": int(manifest["build"]),
                "published_at": str(manifest.get("published_at", "")),
            }
        except SignatureUpdateError as exc:
            return {"status": "error", "message": str(exc)}

    def install_update(self, callback=None) -> dict:
        try:
            manifest = self._pending_manifest or self._fetch_manifest()
            if int(manifest["build"]) <= self.build:
                return {"status": "up_to_date", "message": "CSDL nhận diện đã mới nhất"}
            if callback:
                callback({"phase": "Đang tải CSDL nhận diện", "pct": 30})
            database_url = urllib.parse.urljoin(self.manifest_url, str(manifest["database_url"]))
            raw = self._read_url(database_url)
            if callback:
                callback({"phase": "Đang xác minh SHA-256", "pct": 65})
            actual_hash = _sha256(raw)
            if actual_hash.lower() != str(manifest["sha256"]).lower():
                raise SignatureUpdateError("SHA-256 mismatch; update was rejected")
            data = self._validate_database(raw)
            if int(data["build"]) != int(manifest["build"]):
                raise SignatureUpdateError("Database build does not match the manifest")

            if self.installed_file.exists():
                shutil.copy2(self.installed_file, self.backup_file)
            fd, temp_name = tempfile.mkstemp(prefix="signatures.", suffix=".tmp", dir=self.data_dir)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temp_name, self.installed_file)
            finally:
                if os.path.exists(temp_name):
                    os.unlink(temp_name)

            self.last_updated = _utc_label()
            self.last_checked = self.last_updated
            self._save_state()
            self._refresh_metadata()
            if callback:
                callback({"phase": "Cập nhật hoàn tất", "pct": 100})
            return {
                "status": "installed",
                "message": f"Đã cài CSDL nhận diện {self.version} (build {self.build})",
                **self.to_dict(),
            }
        except (SignatureUpdateError, urllib.error.URLError, TimeoutError) as exc:
            return {"status": "error", "message": str(exc)}

    def rollback(self) -> dict:
        if not self.backup_file.is_file():
            return {"status": "error", "message": "Không có bản CSDL trước để khôi phục"}
        os.replace(self.backup_file, self.installed_file)
        self._refresh_metadata()
        return {"status": "rolled_back", "message": f"Đã khôi phục CSDL {self.version}"}

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "build": self.build,
            "date": self.date,
            "patterns": self.patterns,
            "dynamic_patterns": self.dynamic_patterns,
            "categories": self.categories,
            "hashes": self.hashes,
            "file_hash": self.file_hash,
            "last_checked": self.last_checked,
            "last_updated": self.last_updated,
            "source": "installed" if self.installed_file.is_file() else "bundled",
        }
