import io
import struct
from pathlib import Path

import pytest
from elftools.elf.elffile import ELFFile

from hextrail.engine import analyse, disassemble, control_flow, AnalysisError, MAX_FILE
from hextrail.storage import AnnotationStore

SAMPLE = Path(__file__).parents[1] / "hextrail/samples/libnative_demo.so"
STRIPPED = SAMPLE.with_name("libnative_demo_stripped.so")


def test_compiled_arm64_sample_has_expected_exports_and_imports():
    binary = analyse(SAMPLE)
    assert binary.elf_type == "ET_DYN"
    assert {f.name for f in binary.functions} == {
        "validate_quantity", "calculate_total", "checksum_bytes", "build_label",
        "Java_org_hextrail_demo_NativeBridge_quote", "Java_org_hextrail_demo_NativeBridge_logReady",
    }
    assert any(i["name"] == "__android_log_write" for i in binary.imports)
    assert any("Native library ready for inspection" in s.text for s in binary.strings)


def test_virtual_address_maps_to_file_bytes_and_real_call_target():
    binary = analyse(SAMPLE)
    fn = next(f for f in binary.functions if f.name == "calculate_total")
    target = next(f for f in binary.functions if f.name == "validate_quantity")
    # Independent baseline from the included compiled fixture and readelf output.
    assert fn.address == 0x1054c
    assert binary.bytes_at(fn.address, 4) == bytes.fromhex("fd7bbea9")
    assert binary.data[fn.address:fn.address + 4] != binary.bytes_at(fn.address, 4)
    instructions = disassemble(binary, fn)
    assert instructions[0].mnemonic == "stp"
    assert instructions[-1].mnemonic == "ret"
    call = next(i for i in instructions if i.flow == "call")
    assert call.target == target.address
    assert call.symbol == target.name
    assert any(c.address == call.address and c.target == target.address for c in binary.calls)


def test_control_flow_preserves_conditional_edges_and_loop():
    binary = analyse(SAMPLE)
    fn = next(f for f in binary.functions if f.name == "calculate_total")
    blocks = control_flow(disassemble(binary, fn))
    assert len(blocks) == 6
    conditional = [b for b in blocks if b.instructions[-1].flow == "conditional"]
    assert conditional
    assert all({kind for _, kind in b.edges} == {"taken", "fallthrough"} for b in conditional)
    assert not blocks[-1].edges  # return does not flow into adjacent bytes
    loop_fn = next(f for f in binary.functions if f.name == "checksum_bytes")
    loop_blocks = control_flow(disassemble(binary, loop_fn))
    assert any(target <= b.address for b in loop_blocks for target, _ in b.edges)


def test_stripped_library_does_not_invent_missing_local_functions():
    binary = analyse(STRIPPED)
    assert len(binary.functions) == 5
    assert "validate_quantity" not in {f.name for f in binary.functions}
    assert any("stripped" in warning for warning in binary.warnings)
    assert binary.regions and all(r.is_region for r in binary.regions)


def test_no_function_symbols_still_exposes_regions(tmp_path):
    data = bytearray(SAMPLE.read_bytes())
    elf = ELFFile(io.BytesIO(data))
    for sec in elf.iter_sections():
        if sec["sh_type"] in ("SHT_SYMTAB", "SHT_DYNSYM"):
            for index, sym in enumerate(sec.iter_symbols()):
                if sym["st_info"]["type"] == "STT_FUNC":
                    position = sec["sh_offset"] + index * sec["sh_entsize"] + 4
                    data[position] &= 0xf0  # valid STT_NOTYPE, name does not prove a function
    path = tmp_path / "untyped.so"
    path.write_bytes(data)
    binary = analyse(path)
    assert binary.functions == []
    assert binary.regions
    assert disassemble(binary, binary.regions[0])
    assert any("No named function" in warning for warning in binary.warnings)


@pytest.mark.parametrize("payload", [b"not an ELF", b"\x7fELF\x02", SAMPLE.read_bytes()[:100]])
def test_malformed_inputs_fail_cleanly(tmp_path, payload):
    path = tmp_path / "broken.so"
    path.write_bytes(payload)
    with pytest.raises(AnalysisError):
        analyse(path)


def test_wrong_architecture_is_rejected(tmp_path):
    data = bytearray(SAMPLE.read_bytes())
    struct.pack_into("<H", data, 18, 62)  # EM_X86_64
    path = tmp_path / "x64.so"
    path.write_bytes(data)
    with pytest.raises(AnalysisError, match="ARM64"):
        analyse(path)


def test_out_of_bounds_section_is_rejected(tmp_path):
    data = bytearray(SAMPLE.read_bytes())
    elf = ELFFile(io.BytesIO(data))
    index = next(i for i, s in enumerate(elf.iter_sections()) if s.name == ".text")
    section_header = elf["e_shoff"] + index * elf["e_shentsize"]
    struct.pack_into("<Q", data, section_header + 24, len(data) + 4096)
    path = tmp_path / "bad-offset.so"
    path.write_bytes(data)
    with pytest.raises(AnalysisError, match="beyond"):
        analyse(path)


def test_file_size_limit_is_checked_before_reading(tmp_path):
    path = tmp_path / "large.so"
    with path.open("wb") as f:
        f.truncate(MAX_FILE + 1)
    with pytest.raises(AnalysisError, match="128 MiB"):
        analyse(path)


def test_cancellation_and_missing_address():
    with pytest.raises(AnalysisError, match="cancelled"):
        analyse(SAMPLE, lambda: True)
    binary = analyse(SAMPLE)
    assert binary.bytes_at(0xffffffffffff, 16) == b""


def test_notes_persist_per_binary_without_modifying_input(tmp_path):
    before = SAMPLE.read_bytes()
    binary = analyse(SAMPLE)
    store = AnnotationStore(binary.sha256, tmp_path)
    store.set(0x1054c, "quote_total", "10% discount for members at >= 1000")
    restored = AnnotationStore(binary.sha256, tmp_path)
    assert restored.get(0x1054c)["alias"] == "quote_total"
    assert "discount" in restored.get(0x1054c)["note"]
    assert AnnotationStore("0" * 64, tmp_path).get(0x1054c)["note"] == ""
    assert SAMPLE.read_bytes() == before


def test_corrupt_notes_are_not_overwritten(tmp_path):
    store = AnnotationStore("0" * 64, tmp_path)
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text("broken JSON")
    restored = AnnotationStore("0" * 64, tmp_path)
    with pytest.raises(OSError):
        restored.set(1, "name", "note")
    assert restored.path.read_text() == "broken JSON"
