import hashlib
import os
import sys
import struct
import time
from pathlib import Path

import pytest

from hextrail.decompiler import DecompilerError
from hextrail.ghidra import GhidraDecompiler, discover_ghidra
from hextrail.cache import AnalysisCache, CacheIdentity, run_analysis


SAMPLE = Path(__file__).parents[1] / "hextrail/samples/libnative_demo.so"
SHA256 = hashlib.sha256(SAMPLE.read_bytes()).hexdigest()


def fake_installation(tmp_path, program="pass"):
    home = tmp_path / "ghidra"
    support = home / "support"
    metadata = home / "Ghidra"
    support.mkdir(parents=True)
    metadata.mkdir()
    launcher = support / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    if os.name == "nt":
        fake = support / "fake_headless.py"
        fake.write_text(program + "\n")
        launcher.write_text(f'@"{sys.executable}" "{fake}" %*\n')
    else:
        launcher.write_text(f"#!{sys.executable}\n{program}\n")
    launcher.chmod(0o755)
    (metadata / "application.properties").write_text(
        "application.name=Ghidra\napplication.version=12.3\n"
    )
    return home, launcher


SUCCESS_PROGRAM = r'''
import json
import sys
from pathlib import Path

index = sys.argv.index("-postScript")
output = Path(sys.argv[index + 2])
sha256 = sys.argv[index + 3]
payload = {
    "schema": "hextrail.decompilation.v1",
    "binary": {"sha256": sha256, "architecture": "AArch64"},
    "provider": {"name": "Ghidra", "version": "12.3"},
    "functions": [{
        "address": 0x1054c,
        "size": 64,
        "name": "calculate_total",
        "signature": "int calculate_total(int quantity, int price)",
        "pseudocode": "return quantity * price;",
        "boundary_source": "Ghidra analysis",
    }],
    "warnings": [],
}
output.write_text(json.dumps(payload))
'''


def test_discovery_uses_explicit_home_environment_and_path(tmp_path):
    home, launcher = fake_installation(tmp_path)

    explicit = discover_ghidra(home, environ={}, which=lambda name: None)
    assert explicit.home == home.resolve()
    assert explicit.version == "12.3"
    assert explicit.source == "explicit configuration"

    configured = discover_ghidra(environ={"GHIDRA_HOME": str(home)}, which=lambda name: None)
    assert configured.analyze_headless == launcher.resolve()
    assert configured.source == "GHIDRA_HOME"

    on_path = discover_ghidra(environ={}, which=lambda name: str(launcher))
    assert on_path.source == "PATH"


def test_discovery_rejects_invalid_installations(tmp_path):
    with pytest.raises(DecompilerError, match="analyzeHeadless"):
        discover_ghidra(tmp_path / "missing", environ={}, which=lambda name: None)
    with pytest.raises(DecompilerError, match="not found"):
        discover_ghidra(environ={}, which=lambda name: None)


def test_command_is_argument_list_with_controlled_script_directory(tmp_path):
    home, _ = fake_installation(tmp_path)
    provider = GhidraDecompiler(discover_ghidra(home))
    project = tmp_path / "project"
    report = tmp_path / "report.json"

    command = provider.command(SAMPLE, project, report, SHA256)

    assert command[0] == str(provider.installation.analyze_headless)
    assert command[1:3] == [str(project.resolve()), "HexTrail"]
    assert command[command.index("-import") + 1] == str(SAMPLE.resolve())
    assert command[command.index("-loader") + 1] == "ElfLoader"
    assert command[command.index("-loader-imagebase") + 1] == "0"
    assert command[command.index("-scriptPath") + 1] == str(provider.script_directory)
    script = command.index("-postScript")
    assert command[script + 1:script + 5] == [
        "HexTrailExport.java", str(report.resolve()), SHA256, "30"
    ]
    assert "-deleteProject" in command


def test_command_preserves_nonzero_elf_image_base(tmp_path):
    home, _ = fake_installation(tmp_path)
    provider = GhidraDecompiler(discover_ghidra(home))
    data = bytearray(SAMPLE.read_bytes())
    struct.pack_into("<H", data, 16, 2)  # ET_EXEC
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    for index in range(phnum):
        offset = phoff + index * phentsize
        if struct.unpack_from("<I", data, offset)[0] == 1:  # PT_LOAD
            address = struct.unpack_from("<Q", data, offset + 16)[0]
            struct.pack_into("<Q", data, offset + 16, address + 0x400000)
    binary = tmp_path / "nonzero-base.elf"
    binary.write_bytes(data)
    command = provider.command(binary, tmp_path / "project", tmp_path / "report.json", SHA256)
    assert command[command.index("-loader-imagebase") + 1] == "400000"


def test_fake_headless_provider_imports_validated_report_and_cleans_up(tmp_path):
    home, _ = fake_installation(tmp_path, SUCCESS_PROGRAM)
    runs = tmp_path / "runs"
    provider = GhidraDecompiler(discover_ghidra(home), temporary_root=runs)

    report = provider.decompile(SAMPLE, SHA256)

    assert report.provider == "Ghidra"
    assert report.provider_version == "12.3"
    assert report.function_at(0x1054C).name == "calculate_total"
    assert list(runs.iterdir()) == []


def test_provider_rejects_changed_binary_before_launch(tmp_path):
    home, _ = fake_installation(tmp_path, SUCCESS_PROGRAM)
    provider = GhidraDecompiler(discover_ghidra(home))

    with pytest.raises(DecompilerError, match="binary changed"):
        provider.decompile(SAMPLE, "b" * 64)


def test_nonzero_exit_captures_bounded_diagnostics_and_cleans_up(tmp_path):
    program = "import sys\nsys.stderr.write('failure ' + 'x' * 300000)\nsys.exit(7)"
    home, _ = fake_installation(tmp_path, program)
    runs = tmp_path / "runs"
    provider = GhidraDecompiler(discover_ghidra(home), temporary_root=runs)

    with pytest.raises(DecompilerError, match="status 7") as failure:
        provider.decompile(SAMPLE, SHA256)

    assert "failure" in str(failure.value)
    assert len(str(failure.value)) < 5000
    assert list(runs.iterdir()) == []


def test_missing_report_is_a_structured_error(tmp_path):
    home, _ = fake_installation(tmp_path, "print('completed without export')")
    provider = GhidraDecompiler(discover_ghidra(home))

    with pytest.raises(DecompilerError, match="did not produce"):
        provider.decompile(SAMPLE, SHA256)


def test_export_failure_after_long_startup_log_remains_visible(tmp_path):
    program = "print('startup ' * 1000)\nprint('ERROR: native decompiler is missing')"
    home, _ = fake_installation(tmp_path, program)
    provider = GhidraDecompiler(discover_ghidra(home))

    with pytest.raises(DecompilerError, match="native decompiler is missing") as failure:
        provider.decompile(SAMPLE, SHA256)
    assert "diagnostic truncated" in str(failure.value)
    assert len(str(failure.value)) < 5000


def test_whole_analysis_timeout_stops_process_and_cleans_up(tmp_path):
    home, _ = fake_installation(tmp_path, "import time\ntime.sleep(10)")
    runs = tmp_path / "runs"
    provider = GhidraDecompiler(
        discover_ghidra(home), timeout_seconds=0.2, temporary_root=runs
    )

    with pytest.raises(DecompilerError, match="exceeded"):
        provider.decompile(SAMPLE, SHA256)

    assert list(runs.iterdir()) == []


def test_cancellation_stops_process_and_cleans_up(tmp_path):
    home, _ = fake_installation(tmp_path, "import time\ntime.sleep(10)")
    runs = tmp_path / "runs"
    provider = GhidraDecompiler(
        discover_ghidra(home), timeout_seconds=5, temporary_root=runs
    )
    started = time.monotonic()

    with pytest.raises(DecompilerError, match="cancelled"):
        provider.decompile(SAMPLE, SHA256, lambda: time.monotonic() - started > 0.2)

    assert list(runs.iterdir()) == []


def test_provider_rejects_report_from_another_ghidra_version(tmp_path):
    program = SUCCESS_PROGRAM.replace('"version": "12.3"', '"version": "12.2"')
    home, _ = fake_installation(tmp_path, program)
    provider = GhidraDecompiler(discover_ghidra(home))

    with pytest.raises(DecompilerError, match="version"):
        provider.decompile(SAMPLE, SHA256)


def test_warm_cache_skips_headless_process_and_profile_tracks_exporter_and_options(tmp_path, monkeypatch):
    home, _ = fake_installation(tmp_path, SUCCESS_PROGRAM)
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    exporter = scripts / "HexTrailExport.java"
    exporter.write_text("// owned test exporter")
    installation = discover_ghidra(home)
    provider = GhidraDecompiler(installation, script_directory=scripts)
    cache = AnalysisCache(tmp_path / "cache")
    cold = run_analysis(provider, SAMPLE, SHA256, cache)

    def unexpected(*args):
        pytest.fail("A valid cache hit launched analyzeHeadless")

    fresh = GhidraDecompiler(installation, script_directory=scripts)
    monkeypatch.setattr(fresh, "_run", unexpected)
    warm = run_analysis(fresh, SAMPLE, SHA256, cache)
    assert warm.cache_status == "hit"
    assert warm.report == cold.report
    original = CacheIdentity.create(SHA256, fresh.analysis_profile())
    exporter.write_text("// revised owned test exporter")
    assert cache.load(CacheIdentity.create(SHA256, fresh.analysis_profile())) is None
    exporter.write_text("// owned test exporter")
    fresh.function_timeout_seconds += 1
    assert cache.load(CacheIdentity.create(SHA256, fresh.analysis_profile())) is None
    assert cache.load(original) is not None
