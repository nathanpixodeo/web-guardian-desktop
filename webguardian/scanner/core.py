"""Malware and insecure-code scanning engine."""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import stat
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .cms import check_laravel, check_prestashop, check_wordpress, detect_cms_type
from .signatures import (
    BACKUP_FILE_PATTERNS,
    SCAN_EXTENSIONS,
    SIGNATURES,
    SKIP_DIRECTORIES,
    SignatureDatabase,
)


SEVERITIES = ("critical", "high", "medium", "low", "info")
ALWAYS_SKIP = {".git", ".svn", ".hg", "__pycache__"}
QUICK_EXTENSIONS = {".php", ".phtml", ".inc", ".js", ".py", ".sh", ".htaccess", ".env"}


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Scanner:
    def __init__(
        self,
        root_path,
        progress_callback=None,
        threat_callback=None,
        *,
        cancel_event: threading.Event | None = None,
        scan_mode: str = "smart",
        exclusions: list[str] | None = None,
        check_permissions: bool = True,
        max_file_size_mb: int = 10,
        signature_database: SignatureDatabase | None = None,
    ):
        self.root_path = os.path.abspath(os.path.expanduser(str(root_path)))
        self.progress_callback = progress_callback
        self.threat_callback = threat_callback
        self.cancel_event = cancel_event or threading.Event()
        self.scan_mode = scan_mode if scan_mode in {"quick", "smart", "full"} else "smart"
        self.exclusions = [str(value).replace("\\", "/").strip() for value in (exclusions or []) if str(value).strip()]
        self.check_permissions = check_permissions
        self.max_file_size = max(1, int(max_file_size_mb)) * 1024 * 1024
        self.database = signature_database or SignatureDatabase()
        self._seen: set[tuple] = set()
        self._compiled_builtin = {
            category: [(re.compile(pattern, re.IGNORECASE), pattern, description) for pattern, description in rules]
            for category, rules in SIGNATURES.items()
        }
        self.results = {
            "scan_id": uuid.uuid4().hex,
            "started_at": _iso_now(),
            "completed_at": "",
            "status": "running",
            "findings": [],
            "stats": {
                "files_discovered": 0,
                "files_scanned": 0,
                "files_skipped": 0,
                "dirs_skipped": 0,
                "bytes_scanned": 0,
                "read_errors": 0,
                "elapsed_ms": 0,
            },
            "summary": {**{severity: 0 for severity in SEVERITIES}, "total": 0},
            "cms_type": "unknown",
            "scan_mode": self.scan_mode,
            "scanned_path": self.root_path,
            "signature_version": self.database.version,
            "signature_build": self.database.build,
        }

    def cancel(self) -> None:
        self.cancel_event.set()

    def _progress(self, phase: str, current_file: str = "", percent: int = 0) -> None:
        if self.progress_callback:
            self.progress_callback({
                "phase": phase,
                "current_file": current_file,
                "percent": max(0, min(100, int(percent))),
                "files_total": self.results["stats"]["files_discovered"],
                "files_scanned": self.results["stats"]["files_scanned"],
                "files_skipped": self.results["stats"]["files_skipped"],
                "findings_count": self.results["summary"]["total"],
            })

    def _add_finding(
        self,
        severity: str,
        message: str,
        file_path: str = "",
        line: int = 0,
        pattern: str = "",
        rule_id: str = "",
        sha256: str = "",
    ) -> None:
        severity = severity if severity in SEVERITIES else "info"
        identity = (file_path, line, rule_id or pattern or message)
        if identity in self._seen:
            return
        self._seen.add(identity)
        finding = {
            "id": uuid.uuid4().hex,
            "file": file_path,
            "line": line,
            "severity": severity,
            "message": message,
            "pattern": pattern,
            "rule_id": rule_id,
            "sha256": sha256,
            "action": "none",
        }
        self.results["findings"].append(finding)
        self.results["summary"][severity] += 1
        self.results["summary"]["total"] += 1
        if self.threat_callback:
            self.threat_callback(dict(finding))

    def _relative(self, path: str) -> str:
        try:
            return os.path.relpath(path, self.root_path).replace("\\", "/")
        except ValueError:
            return path.replace("\\", "/")

    def _is_excluded(self, path: str) -> bool:
        rel = self._relative(path)
        absolute = os.path.abspath(path).replace("\\", "/")
        for pattern in self.exclusions:
            normalized = pattern.rstrip("/")
            if fnmatch.fnmatch(rel, normalized) or fnmatch.fnmatch(absolute, normalized):
                return True
            if rel == normalized or rel.startswith(normalized + "/"):
                return True
        return False

    def _should_skip_dir(self, full_path: str, name: str) -> bool:
        lower = name.lower()
        if self._is_excluded(full_path) or lower in ALWAYS_SKIP:
            return True
        if self.scan_mode != "full" and (name.startswith(".") or lower in SKIP_DIRECTORIES):
            return True
        return False

    def _is_candidate(self, path: str, name: str) -> bool:
        ext = Path(name).suffix.lower()
        lower = name.lower()
        if lower in self.database.filenames or any(re.search(pattern, lower, re.IGNORECASE) for pattern in BACKUP_FILE_PATTERNS):
            return True
        if lower == ".env" or ext in SCAN_EXTENSIONS:
            return self.scan_mode != "quick" or ext in QUICK_EXTENSIONS or lower in {"wp-config.php", "composer.json"}
        return self.scan_mode == "full"

    def _discover(self) -> list[str]:
        candidates: list[str] = []
        self._progress("Đang lập danh sách tệp", self.root_path, 1)
        for root, dirs, files in os.walk(self.root_path, followlinks=False):
            if self.cancel_event.is_set():
                break
            kept = []
            for name in dirs:
                full = os.path.join(root, name)
                if self._should_skip_dir(full, name) or os.path.islink(full):
                    self.results["stats"]["dirs_skipped"] += 1
                else:
                    kept.append(name)
            dirs[:] = kept
            for name in files:
                path = os.path.join(root, name)
                if self._is_excluded(path) or os.path.islink(path):
                    self.results["stats"]["files_skipped"] += 1
                    continue
                try:
                    size = os.path.getsize(path)
                except OSError:
                    self.results["stats"]["read_errors"] += 1
                    self.results["stats"]["files_skipped"] += 1
                    continue
                if size > self.max_file_size or not self._is_candidate(path, name):
                    self.results["stats"]["files_skipped"] += 1
                    continue
                candidates.append(path)
        self.results["stats"]["files_discovered"] = len(candidates)
        return candidates

    @staticmethod
    def _file_hash(path: str) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _scan_file(self, file_path: str) -> None:
        ext = Path(file_path).suffix.lower()
        base = os.path.basename(file_path)
        lower = base.lower()
        try:
            size = os.path.getsize(file_path)
            digest = self._file_hash(file_path)
            raw = Path(file_path).read_bytes()
        except (OSError, PermissionError):
            self.results["stats"]["read_errors"] += 1
            return
        self.results["stats"]["bytes_scanned"] += size

        known = self.database.hashes.get(digest)
        if known:
            self._add_finding(
                str(known.get("severity", "critical")),
                str(known.get("description", "Known malicious file hash")),
                file_path,
                rule_id="known_hash",
                sha256=digest,
            )

        if lower in self.database.filenames:
            self._add_finding(
                "critical", f"Tên tệp trùng mẫu backdoor đã biết: {base}", file_path,
                rule_id="backdoor_filename", sha256=digest,
            )
        for pattern in BACKUP_FILE_PATTERNS:
            if re.search(pattern, lower, re.IGNORECASE):
                severity = "high" if ext in {".php", ".sql", ".env"} else "medium"
                self._add_finding(severity, f"Phát hiện tệp sao lưu nhạy cảm: {base}", file_path,
                                  rule_id="backup_file", sha256=digest)
                break
        if lower == ".env":
            self._add_finding("medium", "Tệp cấu hình .env chứa dữ liệu nhạy cảm; cần bảo đảm không public",
                              file_path, rule_id="sensitive_env", sha256=digest)

        if b"\x00" in raw[:4096]:
            return
        content = raw.decode("utf-8", errors="ignore")
        lines = content.splitlines()
        for category, rules in self._compiled_builtin.items():
            severity = "critical" if category == "malware" else "high"
            for regex, source_pattern, description in rules:
                for number, line_text in enumerate(lines, 1):
                    if regex.search(line_text):
                        self._add_finding(severity, description, file_path, number, source_pattern,
                                          f"builtin:{category}", digest)
                        break
        for rule in self.database.rules_for(ext):
            for number, line_text in enumerate(lines, 1):
                if rule["regex"].search(line_text):
                    self._add_finding(rule["severity"], rule["description"], file_path, number,
                                      rule["regex"].pattern, rule["id"], digest)
                    break

    def _check_permissions(self, file_path: str) -> None:
        try:
            mode = os.stat(file_path).st_mode
            base = os.path.basename(file_path)
            if bool(mode & stat.S_IWOTH) and base.lower().endswith((".php", ".phtml", ".inc")):
                self._add_finding("high", f"Tệp PHP cho phép mọi người ghi: {base}", file_path,
                                  rule_id="world_writable")
            if bool(mode & stat.S_IROTH) and base.lower() in {".env", "wp-config.php", "config.php", "settings.inc.php"}:
                self._add_finding("high", f"Tệp nhạy cảm cho phép mọi người đọc: {base}", file_path,
                                  rule_id="world_readable")
        except OSError:
            pass

    def _check_project_configuration(self) -> None:
        git_dir = os.path.join(self.root_path, ".git")
        if os.path.isdir(git_dir):
            self._add_finding("medium", "Có thư mục .git; không được public trên máy chủ web", git_dir,
                              rule_id="git_exposure")
        composer = os.path.join(self.root_path, "composer.json")
        if os.path.isfile(composer):
            try:
                import json
                data = json.loads(Path(composer).read_text(encoding="utf-8"))
                stability = data.get("minimum-stability")
                if stability and stability != "stable":
                    self._add_finding("medium", f"Composer minimum-stability đang là '{stability}'", composer,
                                      rule_id="unstable_dependencies")
            except (OSError, json.JSONDecodeError):
                self._add_finding("medium", "composer.json không phải JSON hợp lệ", composer,
                                  rule_id="invalid_composer")
        for filename in ("php.ini", ".user.ini"):
            path = os.path.join(self.root_path, filename)
            if not os.path.isfile(path):
                continue
            try:
                content = Path(path).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            checks = [
                (r"^display_errors\s*=\s*On", "display_errors đang bật", "high"),
                (r"^allow_url_include\s*=\s*On", "allow_url_include đang bật", "critical"),
                (r"^expose_php\s*=\s*On", "expose_php đang bật", "medium"),
            ]
            for pattern, message, severity in checks:
                if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                    self._add_finding(severity, message, path, rule_id=f"php_ini:{pattern}")

    def run(self) -> dict:
        start = time.monotonic()
        if not os.path.isdir(self.root_path):
            raise ValueError(f"Scan path is not a directory: {self.root_path}")
        self.results["cms_type"] = detect_cms_type(self.root_path)
        self._check_project_configuration()
        if self.results["cms_type"] == "wordpress":
            cms_findings = check_wordpress(self.root_path)
        elif self.results["cms_type"] == "laravel":
            cms_findings = check_laravel(self.root_path)
        elif self.results["cms_type"] == "prestashop":
            cms_findings = check_prestashop(self.root_path)
        else:
            cms_findings = []
        for finding in cms_findings:
            self._add_finding(finding["severity"], finding["message"], finding.get("file", ""),
                              finding.get("line", 0), rule_id="cms_configuration")

        candidates = self._discover()
        total = len(candidates)
        for index, file_path in enumerate(candidates, 1):
            if self.cancel_event.is_set():
                break
            self._scan_file(file_path)
            if self.check_permissions:
                self._check_permissions(file_path)
            self.results["stats"]["files_scanned"] += 1
            percent = 5 + int((index / max(total, 1)) * 94)
            if index == 1 or index == total or index % 10 == 0:
                self._progress("Đang phân tích mã nguồn", file_path, percent)

        self.results["status"] = "cancelled" if self.cancel_event.is_set() else "complete"
        self.results["completed_at"] = _iso_now()
        self.results["stats"]["elapsed_ms"] = int((time.monotonic() - start) * 1000)
        self._progress("Đã hủy quét" if self.cancel_event.is_set() else "Quét hoàn tất", "", 100)
        return self.results
