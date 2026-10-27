"""Bounded, out-of-process Ghidra decompiler provider."""
from __future__ import annotations

import hashlib
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile

from .decompiler import DecompilationReport, DecompilerError, load_report


SCRIPT_NAME = "HexTrailExport.java"
MAX_PROPERTIES_BYTES = 1024 * 1024
MAX_CAPTURE_BYTES = 256 * 1024
POLL_SECONDS = 0.1
STOP_GRACE_SECONDS = 2.0


@dataclass(frozen=True)
class GhidraInstallation:
    home: Path
    analyze_headless: Path
    version: str
    source: str


def discover_ghidra(
    explicit: str | Path | None = None,
    environ: Mapping[str, str] | None = None,
    which: Callable[[str], str | None] = shutil.which,
) -> GhidraInstallation:
    """Discover and validate a Ghidra installation without launching it."""
    environment = os.environ if environ is None else environ
    if explicit is not None:
        return _installation(Path(explicit), "explicit configuration")

    configured = environment.get("GHIDRA_HOME")
    if configured:
        try:
            return _installation(Path(configured), "GHIDRA_HOME")
        except DecompilerError as exc:
            raise DecompilerError(f"GHIDRA_HOME is invalid: {exc}") from exc

    discovered = which("analyzeHeadless")
    if discovered:
        return _installation(Path(discovered), "PATH")
    if os.name == "nt":
        discovered = which("analyzeHeadless.bat")
        if discovered:
            return _installation(Path(discovered), "PATH")

    raise DecompilerError(
        "Ghidra was not found. Configure its installation directory or set GHIDRA_HOME."
    )


def _installation(candidate: Path, source: str) -> GhidraInstallation:
    candidate = candidate.expanduser().resolve()
    if candidate.is_file():
        launcher = candidate
        home = launcher.parent.parent
    else:
        home = candidate
        launcher_name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
        launcher = home / "support" / launcher_name
        if not launcher.is_file() and os.name != "nt":
            alternate = home / "support" / "analyzeHeadless.bat"
            if alternate.is_file():
                launcher = alternate

    if not launcher.is_file():
        raise DecompilerError(f"analyzeHeadless was not found under {home}.")
    if os.name != "nt" and not os.access(launcher, os.X_OK):
        raise DecompilerError(f"analyzeHeadless is not executable: {launcher}.")

    properties = home / "Ghidra" / "application.properties"
    version = _application_version(properties)
    return GhidraInstallation(home, launcher.resolve(), version, source)


def _application_version(path: Path) -> str:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_PROPERTIES_BYTES + 1)
        if len(raw) > MAX_PROPERTIES_BYTES:
            raise DecompilerError("Ghidra application.properties is unexpectedly large.")
        for line in raw.decode("utf-8").splitlines():
            if line.startswith("application.version="):
                version = line.partition("=")[2].strip()
                if version and len(version) <= 120:
                    return version
                break
    except DecompilerError:
        raise
    except (OSError, UnicodeError) as exc:
        raise DecompilerError(f"Could not read Ghidra version metadata: {exc}") from exc
    raise DecompilerError(f"Ghidra version is missing from {path}.")


class _BoundedCapture(threading.Thread):
    def __init__(self, stream, limit: int = MAX_CAPTURE_BYTES):
        super().__init__(daemon=True)
        self.stream = stream
        self.limit = limit
        self.data = bytearray()
        self.truncated = False

    def run(self) -> None:
        try:
            while True:
                chunk = self.stream.read(8192)
                if not chunk:
                    return
                room = self.limit - len(self.data)
                if room > 0:
                    self.data.extend(chunk[:room])
                if len(chunk) > room:
                    self.truncated = True
        finally:
            self.stream.close()

    def text(self) -> str:
        value = bytes(self.data).decode("utf-8", errors="replace").strip()
        if self.truncated:
            value += "\n[output truncated]"
        return value


class GhidraDecompiler:
    name = "Ghidra"

    def __init__(
        self,
        installation: GhidraInstallation,
        *,
        timeout_seconds: float = 600,
        analysis_timeout_seconds: int = 480,
        function_timeout_seconds: int = 30,
        temporary_root: str | Path | None = None,
        script_directory: str | Path | None = None,
    ):
        if timeout_seconds <= 0 or analysis_timeout_seconds <= 0 or function_timeout_seconds <= 0:
            raise ValueError("Decompiler timeouts must be positive.")
        self.installation = installation
        self.timeout_seconds = timeout_seconds
        self.analysis_timeout_seconds = analysis_timeout_seconds
        self.function_timeout_seconds = function_timeout_seconds
        self.temporary_root = Path(temporary_root).resolve() if temporary_root else None
        self.script_directory = (
            Path(script_directory).resolve()
            if script_directory
            else Path(__file__).with_name("ghidra_scripts").resolve()
        )
        if not (self.script_directory / SCRIPT_NAME).is_file():
            raise DecompilerError(f"HexTrail's Ghidra export script is missing: {SCRIPT_NAME}.")

    def command(
        self,
        binary_path: str | Path,
        project_directory: str | Path,
        report_path: str | Path,
        binary_sha256: str,
    ) -> list[str]:
        """Build a shell-free analyzeHeadless invocation."""
        return [
            str(self.installation.analyze_headless),
            str(Path(project_directory).resolve()),
            "HexTrail",
            "-import",
            str(Path(binary_path).resolve()),
            "-loader",
            "ElfLoader",
            "-loader-imagebase",
            f"{_elf_image_base(Path(binary_path)):x}",
            "-scriptPath",
            str(self.script_directory),
            "-analysisTimeoutPerFile",
            str(self.analysis_timeout_seconds),
            "-postScript",
            SCRIPT_NAME,
            str(Path(report_path).resolve()),
            binary_sha256,
            str(self.function_timeout_seconds),
            "-deleteProject",
        ]

    def decompile(
        self,
        path: str | Path,
        binary_sha256: str,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> DecompilationReport:
        binary_path = Path(path).resolve()
        if not binary_path.is_file():
            raise DecompilerError(f"Binary does not exist: {binary_path}.")
        if cancelled():
            raise DecompilerError("Decompilation cancelled.")
        if _sha256(binary_path, cancelled) != binary_sha256:
            raise DecompilerError("The binary changed after the initial HexTrail analysis.")

        if self.temporary_root:
            self.temporary_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="hextrail-ghidra-",
            dir=self.temporary_root,
        ) as temporary:
            root = Path(temporary)
            project = root / "project"
            project.mkdir()
            report_path = root / "decompilation.json"
            command = self.command(binary_path, project, report_path, binary_sha256)
            stdout, stderr, returncode = self._run(command, cancelled)
            if returncode != 0:
                detail = _diagnostic(stdout, stderr)
                suffix = f"\n{detail}" if detail else ""
                raise DecompilerError(
                    f"Ghidra headless analysis exited with status {returncode}.{suffix}"
                )
            if not report_path.is_file():
                detail = _diagnostic(stdout, stderr)
                suffix = f"\n{detail}" if detail else ""
                raise DecompilerError(f"Ghidra did not produce a decompiler report.{suffix}")
            result = load_report(report_path, binary_sha256)
            if result.provider != self.name:
                raise DecompilerError(f"Unexpected decompiler provider: {result.provider}.")
            if result.provider_version != self.installation.version:
                raise DecompilerError(
                    "Decompiler report version does not match the configured Ghidra installation."
                )
            return result

    def _run(
        self,
        command: list[str],
        cancelled: Callable[[], bool],
    ) -> tuple[str, str, int]:
        options = {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "shell": False,
        }
        if os.name == "nt":
            options["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        else:
            options["start_new_session"] = True
        try:
            process = subprocess.Popen(command, **options)
        except OSError as exc:
            raise DecompilerError(f"Could not start Ghidra: {exc}") from exc

        stdout = _BoundedCapture(process.stdout)
        stderr = _BoundedCapture(process.stderr)
        stdout.start()
        stderr.start()
        deadline = time.monotonic() + self.timeout_seconds
        failure: DecompilerError | None = None
        try:
            while process.poll() is None:
                if cancelled():
                    failure = DecompilerError("Decompilation cancelled.")
                    break
                if time.monotonic() >= deadline:
                    failure = DecompilerError(
                        f"Ghidra analysis exceeded the {self.timeout_seconds:g}-second limit."
                    )
                    break
                time.sleep(POLL_SECONDS)
            if failure:
                _stop_process(process)
        finally:
            if process.poll() is None:
                _stop_process(process)
            stdout.join(STOP_GRACE_SECONDS)
            stderr.join(STOP_GRACE_SECONDS)
        if failure:
            raise failure
        return stdout.text(), stderr.text(), int(process.returncode)


def _elf_image_base(path: Path) -> int:
    """Keep Ghidra addresses in the ELF's original link-time address space.

    Ghidra defaults zero-based shared objects to an artificial nonzero base.
    Explicitly using the lowest PT_LOAD address also preserves nonzero bases
    in linked executables and prelinked libraries.
    """
    try:
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            if elf.num_segments() > 65_536:
                raise DecompilerError("ELF program-header count exceeds the import limit.")
            return min((segment["p_vaddr"] for segment in elf.iter_segments()
                        if segment["p_type"] == "PT_LOAD"), default=0)
    except (OSError, ELFError) as exc:
        raise DecompilerError(f"Could not determine the ELF image base: {exc}") from exc


def _sha256(path: Path, cancelled: Callable[[], bool]) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                if cancelled():
                    raise DecompilerError("Decompilation cancelled.")
                digest.update(chunk)
    except DecompilerError:
        raise
    except OSError as exc:
        raise DecompilerError(f"Could not read the binary for decompilation: {exc}") from exc
    return digest.hexdigest()


def _stop_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            process.terminate()
        else:
            os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=STOP_GRACE_SECONDS)
        return
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        if os.name == "nt":
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=STOP_GRACE_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _diagnostic(stdout: str, stderr: str) -> str:
    combined = "\n".join(value for value in (stderr, stdout) if value)
    if len(combined) > 4096:
        # Headless startup can fill the beginning of the log before an export
        # failure is reported. Preserve the end as well as the initial context.
        return combined[:1024] + "\n[diagnostic truncated]\n" + combined[-3072:]
    return combined
