"""Versioned, bounded analysis snapshots; user annotations never live here."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .decompiler import DecompilationReport, DecompilerError, MAX_REPORT_BYTES, SCHEMA, parse_report


CACHE_SCHEMA = "hextrail.cache.v1"
MAX_IDENTITY_BYTES = 16 * 1024
MAX_ENTRY_BYTES = MAX_REPORT_BYTES + MAX_IDENTITY_BYTES + 4096
DEFAULT_MAX_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_ENTRIES = 128
_DIGEST = re.compile(r"[0-9a-f]{64}")
_ENTRY_NAME = re.compile(r"[0-9a-f]{64}-[0-9a-f]{64}\.json")


class CacheError(ValueError):
    """Cache failure that should not prevent fresh analysis."""


def _json_bytes(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def default_cache_root() -> Path:
    configured = os.environ.get("HEXTRAIL_CACHE_DIR")
    if configured:
        return Path(configured).expanduser()
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg).expanduser() / "hextrail" / "decompilation"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "hextrail" / "decompilation"
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "HexTrail" / "cache"
    return Path.home() / ".cache" / "hextrail" / "decompilation"


@dataclass(frozen=True)
class CacheIdentity:
    """An immutable canonical description, hashed into a filesystem-safe name."""
    canonical: str

    @classmethod
    def create(cls, sha256: str, profile: dict) -> CacheIdentity:
        if not _DIGEST.fullmatch(sha256):
            raise CacheError("Invalid binary digest for analysis cache.")
        if not isinstance(profile, dict):
            raise CacheError("Provider analysis profile must be an object.")
        for field in ("provider", "provider_version", "architecture", "language", "compiler",
                      "adapter_revision", "exporter_sha256"):
            value = profile.get(field)
            if not isinstance(value, str) or not value or len(value) > 4096:
                raise CacheError(f"Invalid analysis profile field: {field}.")
        if not isinstance(profile.get("options"), dict):
            raise CacheError("Analysis profile options must be an object.")
        try:
            raw = _json_bytes({"binary_sha256": sha256, "report_schema": SCHEMA, "profile": profile})
        except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
            raise CacheError(f"Invalid analysis profile: {exc}") from exc
        if len(raw) > MAX_IDENTITY_BYTES:
            raise CacheError("Analysis profile exceeds the cache identity limit.")
        return cls(raw.decode("utf-8"))

    @property
    def data(self) -> dict:
        return json.loads(self.canonical)

    @property
    def sha256(self) -> str:
        return self.data["binary_sha256"]

    @property
    def filename(self) -> str:
        key = hashlib.sha256(self.canonical.encode("utf-8")).hexdigest()
        return f"{self.sha256}-{key}.json"

    def validate_report(self, report: DecompilationReport | dict) -> DecompilationReport:
        validated = parse_report(report if isinstance(report, dict) else report.to_dict(), self.sha256)
        profile = self.data["profile"]
        if (validated.provider, validated.provider_version, validated.architecture) != (
                profile["provider"], profile["provider_version"], profile["architecture"]):
            raise DecompilerError("Decompiler result does not match the analysis profile.")
        return validated


@dataclass(frozen=True)
class CachedReport:
    report: DecompilationReport
    created_at: str
    size_bytes: int


class AnalysisCache:
    def __init__(self, root: Path | None = None, *, max_bytes=DEFAULT_MAX_BYTES,
                 max_entries=DEFAULT_MAX_ENTRIES):
        if max_bytes <= 0 or max_entries <= 0:
            raise ValueError("Cache storage limits must be positive.")
        self.root = (Path(root) if root is not None else default_cache_root()).resolve()
        self.max_bytes = max_bytes
        self.max_entries = max_entries

    def path_for(self, identity: CacheIdentity) -> Path:
        return self.root / identity.filename

    def load(self, identity: CacheIdentity) -> CachedReport | None:
        path = self.path_for(identity)
        try:
            if not stat.S_ISREG(path.lstat().st_mode):
                raise CacheError("Cached analysis is not a regular file.")
            with path.open("rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise CacheError("Cached analysis is not a regular file.")
                raw = stream.read(min(MAX_ENTRY_BYTES, self.max_bytes) + 1)
            if len(raw) > min(MAX_ENTRY_BYTES, self.max_bytes):
                raise CacheError("Cached analysis exceeds the entry size limit.")
            payload = json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict) or payload.get("schema") != CACHE_SCHEMA:
                raise CacheError("Unsupported analysis cache schema.")
            if payload.get("identity") != identity.data:
                raise CacheError("Cached analysis identity does not match this request.")
            report_bytes = _json_bytes(payload.get("report"))
            if len(report_bytes) > MAX_REPORT_BYTES:
                raise CacheError("Cached decompiler report exceeds the report size limit.")
            if hashlib.sha256(report_bytes).hexdigest() != payload.get("report_sha256"):
                raise CacheError("Cached analysis checksum does not match.")
            report = identity.validate_report(payload["report"])
            created_at = payload.get("created_at")
            if not isinstance(created_at, str) or len(created_at) > 80:
                raise CacheError("Cached analysis timestamp is invalid.")
            timestamp = datetime.fromisoformat(created_at)
            if timestamp.tzinfo is None:
                raise CacheError("Cached analysis timestamp has no timezone.")
        except FileNotFoundError:
            return None
        except (OSError, ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise CacheError(f"Cached analysis ignored: {exc}") from exc
        try:
            os.utime(path, None)  # Update recency without recreating a concurrently removed entry.
        except OSError:
            pass  # A readable cache remains useful on a read-only filesystem.
        return CachedReport(report, created_at, len(raw))

    def save(self, identity: CacheIdentity, report: DecompilationReport,
             cancelled: Callable[[], bool] = lambda: False) -> Path:
        _check_cancelled(cancelled)
        validated = identity.validate_report(report)
        try:
            report_payload = validated.to_dict()
            report_bytes = _json_bytes(report_payload)
            if len(report_bytes) > MAX_REPORT_BYTES:
                raise CacheError("Decompiler report exceeds the cache report size limit.")
            raw = _json_bytes({
                "schema": CACHE_SCHEMA, "identity": identity.data,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
                "report": report_payload,
            })
            if len(raw) > min(MAX_ENTRY_BYTES, self.max_bytes):
                raise CacheError("Analysis result exceeds the cache storage limit.")
            _check_cancelled(cancelled)
            self.root.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix=".cache-", suffix=".tmp", dir=self.root)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                _check_cancelled(cancelled)
                path = self.path_for(identity)
                self._prune(path, len(raw))
                _check_cancelled(cancelled)
                os.replace(temporary, path)
                return path
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        except (OSError, UnicodeError) as exc:
            raise CacheError(f"Analysis could not be cached: {exc}") from exc

    def _entries(self):
        if not self.root.exists():
            return
        for path in self.root.iterdir():
            if _ENTRY_NAME.fullmatch(path.name):
                info = path.lstat()
                if stat.S_ISREG(info.st_mode):
                    yield path, info

    def _prune(self, keep: Path, incoming_bytes: int):
        entries = sorted((entry for entry in self._entries() if entry[0] != keep),
                         key=lambda entry: entry[1].st_mtime_ns)
        size = sum(info.st_size for _, info in entries) + incoming_bytes
        count = len(entries) + 1
        for path, info in entries:
            if size <= self.max_bytes and count <= self.max_entries:
                break
            path.unlink(missing_ok=True)
            size -= info.st_size
            count -= 1
        # Interrupted processes may leave temporary files. Never read them as
        # reports; remove old ones after the maximum normal job lifetime.
        for path in self.root.glob(".cache-*.tmp"):
            info = path.lstat()
            if stat.S_ISREG(info.st_mode) and time.time() - info.st_mtime > 3600:
                path.unlink(missing_ok=True)

    def clear(self, sha256: str, cancelled: Callable[[], bool] = lambda: False) -> int:
        if not _DIGEST.fullmatch(sha256):
            raise CacheError("Invalid binary digest for cache removal.")
        count = 0
        try:
            for path, _ in self._entries():
                _check_cancelled(cancelled)
                if path.name.startswith(sha256 + "-"):
                    path.unlink(missing_ok=True)
                    count += 1
        except OSError as exc:
            raise CacheError(f"Cached analysis could not be removed: {exc}") from exc
        return count


@dataclass(frozen=True)
class AnalysisResult:
    report: DecompilationReport | None
    cache_status: str
    detail: str
    elapsed_seconds: float


def _check_cancelled(cancelled):
    if cancelled():
        raise DecompilerError("Decompilation cancelled.")


def _verify_input(path, sha256, cancelled):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            _check_cancelled(cancelled)
            digest.update(chunk)
    if digest.hexdigest() != sha256:
        raise DecompilerError("The binary changed after the initial HexTrail analysis.")


def run_analysis(provider, path, sha256, cache: AnalysisCache, *, force=False,
                 cache_only=False, cancelled=lambda: False, progress=lambda message: None) -> AnalysisResult:
    """Read a matching snapshot or run the provider, preserving cache failures as diagnostics."""
    start = time.monotonic()
    _check_cancelled(cancelled)
    _verify_input(path, sha256, cancelled)
    identity = CacheIdentity.create(sha256, provider.analysis_profile())
    detail = "Cache bypassed for an explicit rerun." if force else "No matching cached analysis."
    if not force:
        progress("Checking cached analysis…")
        try:
            cached = cache.load(identity)
            _check_cancelled(cancelled)
            if cached:
                return AnalysisResult(cached.report, "hit",
                    f"Saved {cached.created_at} · {cached.size_bytes:,} bytes · {cache.path_for(identity)}",
                    time.monotonic() - start)
        except CacheError as exc:
            detail = str(exc)
    if cache_only:
        return AnalysisResult(None, "miss", detail, time.monotonic() - start)
    _check_cancelled(cancelled)
    progress(f"Analysing with {identity.data['profile']['provider']}…")
    report = provider.decompile(path, sha256, cancelled)
    _check_cancelled(cancelled)
    progress("Importing decompiler results…")
    if report.binary_sha256 != sha256:
        raise DecompilerError("Decompiler report belongs to a different binary.")
    if report.architecture != "AArch64":
        raise DecompilerError("Decompiler report is not for AArch64.")
    report = identity.validate_report(report)
    _check_cancelled(cancelled)
    progress("Saving analysis cache…")
    try:
        saved = cache.save(identity, report, cancelled)
        status = "refreshed" if force else "stored"
        detail += f" Saved to {saved}."
    except CacheError as exc:
        status = "unavailable"
        detail += f" {exc} Results remain available in this session."
    return AnalysisResult(report, status, detail, time.monotonic() - start)
