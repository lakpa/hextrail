"""Opt-in acceptance tests against a real, user-installed Ghidra."""
import os
from pathlib import Path

import pytest

from hextrail.engine import analyse
from hextrail.ghidra import GhidraDecompiler, discover_ghidra
from hextrail.cache import AnalysisCache, run_analysis


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("HEXTRAIL_TEST_GHIDRA") != "1",
        reason="Set HEXTRAIL_TEST_GHIDRA=1 to run real Ghidra acceptance tests",
    ),
]
SAMPLES = Path(__file__).parents[1] / "hextrail" / "samples"


@pytest.mark.parametrize("filename", ["libnative_demo.so", "libnative_demo_stripped.so"])
def test_real_ghidra_decompiles_source_backed_and_stripped_samples(filename, tmp_path, monkeypatch):
    installation = discover_ghidra()
    binary = analyse(SAMPLES / filename)
    reference = analyse(SAMPLES / "libnative_demo.so")
    runs = tmp_path / "runs"
    provider = GhidraDecompiler(installation, temporary_root=runs)
    cache = AnalysisCache(tmp_path / "cache")
    cold = run_analysis(provider, binary.path, binary.sha256, cache)
    report = cold.report
    assert cold.cache_status == "stored"

    assert report.binary_sha256 == binary.sha256
    assert report.provider == "Ghidra"
    assert report.provider_version == installation.version
    assert report.architecture == "AArch64"
    by_address = {function.address: function for function in report.functions}
    for name in ("calculate_total", "validate_quantity", "checksum_bytes"):
        expected = next(function for function in reference.functions if function.name == name)
        recovered = by_address[expected.address]
        assert recovered.pseudocode.strip(), f"No pseudocode for {name}: {report.warnings}"
        section = binary.section_at(recovered.address)
        assert section and "X" in section.flags

    if "stripped" in filename:
        symbol_addresses = {function.address for function in binary.functions}
        local = next(function for function in reference.functions if function.name == "validate_quantity")
        assert local.address not in symbol_addresses
        assert local.address in by_address
    fresh = GhidraDecompiler(installation, temporary_root=runs)

    def unexpected(*args):
        pytest.fail("Warm analysis launched a Ghidra process")

    monkeypatch.setattr(fresh, "_run", unexpected)
    warm = run_analysis(fresh, binary.path, binary.sha256, AnalysisCache(cache.root))
    assert warm.cache_status == "hit"
    assert warm.report == report
    assert not list(runs.iterdir()), "Ghidra temporary project was not removed"
