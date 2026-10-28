"""Provider-neutral contract for importing decompiler results.

Decompiler processes are intentionally kept outside the UI and the ELF parser.
Their JSON output is treated as untrusted input and validated before HexTrail
uses it. Phase 1 defines this boundary; a Ghidra provider can implement the
``Decompiler`` protocol without coupling Ghidra to the desktop application.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Protocol


SCHEMA = "hextrail.decompilation.v1"
MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_FUNCTIONS = 100_000
MAX_PSEUDOCODE_CHARS = 2_000_000
MAX_TOTAL_PSEUDOCODE_CHARS = 24_000_000
_SHA256 = re.compile(r"[0-9a-f]{64}")


class DecompilerError(ValueError):
    """A decompiler provider failed or returned an invalid result."""


@dataclass(frozen=True)
class DecompiledFunction:
    address: int
    size: int
    name: str
    signature: str
    pseudocode: str
    boundary_source: str


@dataclass(frozen=True)
class DecompilationReport:
    binary_sha256: str
    provider: str
    provider_version: str
    architecture: str
    functions: tuple[DecompiledFunction, ...]
    warnings: tuple[str, ...] = ()

    def function_at(self, address: int) -> DecompiledFunction | None:
        """Return a function containing an address, preferring exact starts."""
        exact = next((fn for fn in self.functions if fn.address == address), None)
        if exact:
            return exact
        return next((fn for fn in self.functions
                     if fn.size and fn.address < address < fn.address + fn.size), None)

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "binary": {"sha256": self.binary_sha256, "architecture": self.architecture},
            "provider": {"name": self.provider, "version": self.provider_version},
            "functions": [asdict(fn) for fn in self.functions],
            "warnings": list(self.warnings),
        }


class Decompiler(Protocol):
    """Interface implemented by out-of-process decompiler providers."""

    @property
    def name(self) -> str: ...

    def analysis_profile(self) -> dict:
        """Describe provider/version, architecture, configuration and code revisions for caching."""
        ...

    def decompile(
        self,
        path: str | Path,
        binary_sha256: str,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> DecompilationReport: ...


def load_report(
    path: str | Path,
    expected_sha256: str | None = None,
) -> DecompilationReport:
    """Load a bounded JSON report produced by a decompiler worker."""
    path = Path(path)
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_REPORT_BYTES + 1)
        if len(raw) > MAX_REPORT_BYTES:
            raise DecompilerError("Decompiler report exceeds the 32 MiB limit.")
        payload = json.loads(raw.decode("utf-8"))
    except DecompilerError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DecompilerError(f"Could not read decompiler report: {exc}") from exc
    return parse_report(payload, expected_sha256)


def parse_report(payload: object, expected_sha256: str | None = None) -> DecompilationReport:
    """Validate provider JSON and convert it into immutable model objects."""
    root = _mapping(payload, "report")
    if root.get("schema") != SCHEMA:
        raise DecompilerError(f"Unsupported decompiler report schema; expected {SCHEMA}.")

    binary = _mapping(root.get("binary"), "binary")
    sha256 = _text(binary.get("sha256"), "binary.sha256", maximum=64)
    if not _SHA256.fullmatch(sha256):
        raise DecompilerError("binary.sha256 must be a lowercase SHA-256 digest.")
    if expected_sha256 and sha256 != expected_sha256:
        raise DecompilerError("Decompiler report belongs to a different binary.")
    architecture = _text(binary.get("architecture"), "binary.architecture", maximum=80)

    provider = _mapping(root.get("provider"), "provider")
    provider_name = _text(provider.get("name"), "provider.name", maximum=120)
    provider_version = _text(provider.get("version"), "provider.version", maximum=120)

    raw_functions = root.get("functions")
    if not isinstance(raw_functions, list):
        raise DecompilerError("functions must be a list.")
    if len(raw_functions) > MAX_FUNCTIONS:
        raise DecompilerError("Decompiler report exceeds the 100,000-function limit.")

    functions = []
    addresses = set()
    total_pseudocode = 0
    for index, value in enumerate(raw_functions):
        item = _mapping(value, f"functions[{index}]")
        address = _integer(item.get("address"), f"functions[{index}].address")
        size = _integer(item.get("size"), f"functions[{index}].size")
        if address in addresses:
            raise DecompilerError(f"Duplicate function address 0x{address:x}.")
        addresses.add(address)
        pseudocode = _text(
            item.get("pseudocode"), f"functions[{index}].pseudocode",
            maximum=MAX_PSEUDOCODE_CHARS, allow_empty=True,
        )
        total_pseudocode += len(pseudocode)
        if total_pseudocode > MAX_TOTAL_PSEUDOCODE_CHARS:
            raise DecompilerError("Decompiler report contains too much pseudocode.")
        functions.append(DecompiledFunction(
            address=address,
            size=size,
            name=_text(item.get("name"), f"functions[{index}].name", maximum=4096),
            signature=_text(
                item.get("signature"), f"functions[{index}].signature",
                maximum=32_768, allow_empty=True,
            ),
            pseudocode=pseudocode,
            boundary_source=_text(
                item.get("boundary_source"), f"functions[{index}].boundary_source",
                maximum=240,
            ),
        ))

    raw_warnings = root.get("warnings", [])
    if not isinstance(raw_warnings, list) or len(raw_warnings) > 10_000:
        raise DecompilerError("warnings must be a list with at most 10,000 entries.")
    warnings = tuple(_text(value, f"warnings[{index}]", maximum=4096)
                     for index, value in enumerate(raw_warnings))
    return DecompilationReport(
        binary_sha256=sha256,
        provider=provider_name,
        provider_version=provider_version,
        architecture=architecture,
        functions=tuple(sorted(functions, key=lambda fn: fn.address)),
        warnings=warnings,
    )


def _mapping(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise DecompilerError(f"{label} must be an object.")
    return value


def _text(value: object, label: str, maximum: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise DecompilerError(f"{label} must be a non-empty string.")
    if len(value) > maximum:
        raise DecompilerError(f"{label} exceeds its length limit.")
    return value


def _integer(value: object, label: str) -> int:
    # bool is an int subclass, but is never a valid address or byte count.
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise DecompilerError(f"{label} must be a non-negative integer.")
    return value
