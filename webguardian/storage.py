"""Persistent application data for WebGuardian.

All writes are kept outside the installation directory so packaged builds can run
from read-only locations.  Tests may pass an explicit ``data_dir``.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


APP_NAME = "WebGuardian"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_data_dir() -> Path:
    override = os.environ.get("WEBGUARDIAN_DATA_DIR")
    if override:
        root = Path(override).expanduser()
    elif os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / APP_NAME
    else:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / APP_NAME.lower()
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError:
        # Restricted/portable environments may not expose the profile folder.
        root = Path(tempfile.gettempdir()) / APP_NAME.lower()
        root.mkdir(parents=True, exist_ok=True)
    return root


def atomic_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


class SettingsStore:
    DEFAULTS = {
        "theme": "dark",
        "language": "vi",
        "check_permissions": True,
        "scan_archives": False,
        "max_file_size_mb": 10,
        "auto_update": True,
        "update_url": "",
        "exclusions": [],
        "last_scan_path": "",
    }

    def __init__(self, data_dir: Path | None = None):
        self.data_dir = Path(data_dir) if data_dir else get_data_dir()
        self.path = self.data_dir / "settings.json"
        self._data = dict(self.DEFAULTS)
        self.reload()

    def reload(self) -> dict:
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    self._data.update(raw)
            except (OSError, json.JSONDecodeError):
                pass
        return dict(self._data)

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value
        self.save()

    def update(self, values: dict) -> None:
        self._data.update(values)
        self.save()

    def save(self) -> None:
        atomic_write_json(self.path, self._data)

    def to_dict(self) -> dict:
        return dict(self._data)


class HistoryStore:
    """Stores compact scan reports as individual JSON files."""

    def __init__(self, data_dir: Path | None = None):
        self.root = (Path(data_dir) if data_dir else get_data_dir()) / "reports"
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, result: dict) -> str:
        scan_id = result.get("scan_id") or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        result["scan_id"] = scan_id
        atomic_write_json(self.root / f"{scan_id}.json", result)
        return scan_id

    def list(self, limit: int = 100) -> list[dict]:
        reports = []
        for path in sorted(self.root.glob("*.json"), reverse=True):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            reports.append({
                "scan_id": data.get("scan_id", path.stem),
                "started_at": data.get("started_at", ""),
                "completed_at": data.get("completed_at", ""),
                "scanned_path": data.get("scanned_path", ""),
                "scan_mode": data.get("scan_mode", "smart"),
                "status": data.get("status", "complete"),
                "summary": data.get("summary", {}),
                "stats": data.get("stats", {}),
            })
            if len(reports) >= limit:
                break
        return reports

    def get(self, scan_id: str) -> dict | None:
        safe_id = Path(scan_id).name
        path = self.root / f"{safe_id}.json"
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def delete(self, scan_id: str) -> bool:
        path = self.root / f"{Path(scan_id).name}.json"
        try:
            path.unlink()
            return True
        except OSError:
            return False
