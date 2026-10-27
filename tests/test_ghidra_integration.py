"""Opt-in acceptance tests against a real, user-installed Ghidra."""
import os
from pathlib import Path

import pytest

from hextrail.engine import analyse
from hextrail.ghidra import GhidraDecompiler, discover_ghidra


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("HEXTRAIL_TEST_GHIDRA") != "1",
        reason="Set HEXTRAIL_TEST_GHIDRA=1 to run real Ghidra acceptance tests",
    ),
]
SAMPLES = Path(__file__).parents[1] / "hextrail" / "samples"


@pytest.mark.parametrize("filename", ["libnative_demo.so", "libnative_demo_stripped.so"])
def test_real_ghidra_decompiles_source_backed_and_stripped_samples(filename, tmp_path):
    installation = discover_ghidra()
    binary = analyse(SAMPLES / filename)
    reference = analyse(SAMPLES / "libnative_demo.so")
    provider = GhidraDecompiler(installation, temporary_root=tmp_path)
    report = provider.decompile(binary.path, binary.sha256)

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
    assert not list(tmp_path.iterdir()), "Ghidra temporary project was not removed"
