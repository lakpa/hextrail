"""Hash-scoped annotations, kept separately from the input binary."""
from __future__ import annotations
import json
import os
import tempfile
from pathlib import Path


class AnnotationStore:
    def __init__(self, sha256: str, root: Path | None = None):
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise ValueError("Invalid binary digest")
        self.sha256 = sha256
        self.path = (root or Path.home() / ".hextrail" / "projects") / f"{sha256}.json"
        self.items = {}
        self.error = ""
        source_path = self.path
        if root is None and not source_path.exists():
            legacy = Path.home() / ".nativescope" / "projects" / f"{sha256}.json"
            if legacy.exists():
                source_path = legacy
        if source_path.exists():
            try:
                raw = json.loads(source_path.read_text())
                if raw.get("sha256") != sha256 or not isinstance(raw.get("annotations"), dict):
                    raise ValueError("Project metadata does not match this binary")
                for key, value in raw["annotations"].items():
                    if isinstance(value, dict) and isinstance(value.get("alias", ""), str) and isinstance(value.get("note", ""), str):
                        self.items[key] = {"alias": value.get("alias", "")[:160], "note": value.get("note", "")[:20000]}
            except (OSError, ValueError, TypeError) as exc:
                self.error = f"Annotations could not be read: {exc}. Existing file will not be overwritten."

    def get(self, address: int) -> dict:
        return self.items.get(hex(address), {"alias": "", "note": ""})

    def set(self, address: int, alias: str, note: str):
        if self.error:
            raise OSError(self.error)
        self.items[hex(address)] = {"alias": alias[:160], "note": note[:20000]}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"schema": "hextrail.notes.v1", "sha256": self.sha256, "annotations": self.items}
        fd, temporary = tempfile.mkstemp(prefix=".notes-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w") as stream:
                json.dump(payload, stream, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
