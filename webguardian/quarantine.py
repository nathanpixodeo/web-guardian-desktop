"""Safe local quarantine with integrity metadata and restore support."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import uuid
from pathlib import Path

from .storage import atomic_write_json, get_data_dir, utc_now


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class QuarantineManager:
    def __init__(self, data_dir: Path | None = None):
        self.root = (Path(data_dir) if data_dir else get_data_dir()) / "quarantine"
        self.files = self.root / "files"
        self.index_path = self.root / "index.json"
        self.files.mkdir(parents=True, exist_ok=True)

    def _load(self) -> list[dict]:
        try:
            data = json.loads(self.index_path.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    def _save(self, records: list[dict]) -> None:
        atomic_write_json(self.index_path, records)

    def list(self) -> list[dict]:
        return sorted(self._load(), key=lambda row: row.get("quarantined_at", ""), reverse=True)

    def quarantine(self, source: str, finding: dict | None = None) -> dict:
        src = Path(source).resolve()
        if not src.is_file():
            raise FileNotFoundError(f"File not found: {src}")

        item_id = uuid.uuid4().hex
        payload = self.files / f"{item_id}.wgq"
        digest = sha256_file(src)
        size = src.stat().st_size
        shutil.move(str(src), str(payload))
        try:
            payload.chmod(0o600)
        except OSError:
            pass

        record = {
            "id": item_id,
            "original_path": str(src),
            "payload": payload.name,
            "sha256": digest,
            "size": size,
            "quarantined_at": utc_now(),
            "detection": (finding or {}).get("message", "Manual quarantine"),
            "severity": (finding or {}).get("severity", "high"),
        }
        records = self._load()
        records.append(record)
        try:
            self._save(records)
        except Exception:
            # Do not orphan a payload when metadata persistence fails.
            if payload.exists() and not src.exists():
                shutil.move(str(payload), str(src))
            raise
        return record

    def restore(self, item_id: str, overwrite: bool = False) -> Path:
        records = self._load()
        record = next((row for row in records if row.get("id") == item_id), None)
        if not record:
            raise KeyError("Quarantine item not found")
        payload = self.files / record["payload"]
        if not payload.is_file() or sha256_file(payload) != record.get("sha256"):
            raise ValueError("Quarantined payload failed integrity verification")

        destination = Path(record["original_path"])
        if destination.exists() and not overwrite:
            raise FileExistsError(f"Restore destination already exists: {destination}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            destination.unlink()
        shutil.move(str(payload), str(destination))
        records.remove(record)
        self._save(records)
        return destination

    def delete(self, item_id: str) -> bool:
        records = self._load()
        record = next((row for row in records if row.get("id") == item_id), None)
        if not record:
            return False
        payload = self.files / record.get("payload", "")
        try:
            if payload.is_file():
                payload.unlink()
        finally:
            records.remove(record)
            self._save(records)
        return True
