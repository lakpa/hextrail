import json

import pytest

from hextrail.decompiler import (
    DecompilerError,
    MAX_REPORT_BYTES,
    SCHEMA,
    load_report,
    parse_report,
)


SHA256 = "a" * 64


def report_payload():
    return {
        "schema": SCHEMA,
        "binary": {"sha256": SHA256, "architecture": "AArch64"},
        "provider": {"name": "Test provider", "version": "1.0"},
        "functions": [
            {
                "address": 0x1054C,
                "size": 64,
                "name": "calculate_total",
                "signature": "int calculate_total(int quantity, int price)",
                "pseudocode": "return quantity * price;",
                "boundary_source": "provider analysis",
            },
            {
                "address": 0x104F0,
                "size": 24,
                "name": "validate_quantity",
                "signature": "bool validate_quantity(int quantity)",
                "pseudocode": "return quantity > 0;",
                "boundary_source": "ELF symbol",
            },
        ],
        "warnings": ["Example warning"],
    }


def test_report_contract_round_trip_and_address_lookup(tmp_path):
    path = tmp_path / "decompilation.json"
    path.write_text(json.dumps(report_payload()))
    report = load_report(path, SHA256)

    assert report.provider == "Test provider"
    assert [fn.name for fn in report.functions] == ["validate_quantity", "calculate_total"]
    assert report.function_at(0x1054C).name == "calculate_total"
    assert report.function_at(0x10550).name == "calculate_total"
    assert parse_report(report.to_dict()) == report


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda value: value.update(schema="other.v1"), "schema"),
        (lambda value: value["binary"].update(sha256="not-a-digest"), "SHA-256"),
        (lambda value: value["functions"][0].update(address=-1), "non-negative"),
        (lambda value: value["functions"].append(value["functions"][0].copy()), "Duplicate"),
        (lambda value: value.update(warnings="warning"), "warnings"),
    ],
)
def test_invalid_provider_output_is_rejected(change, message):
    payload = report_payload()
    change(payload)
    with pytest.raises(DecompilerError, match=message):
        parse_report(payload)


def test_report_must_match_the_open_binary():
    with pytest.raises(DecompilerError, match="different binary"):
        parse_report(report_payload(), "b" * 64)


def test_report_file_size_is_bounded(tmp_path):
    path = tmp_path / "oversized.json"
    with path.open("wb") as stream:
        stream.truncate(MAX_REPORT_BYTES + 1)
    with pytest.raises(DecompilerError, match="32 MiB"):
        load_report(path)
