import copy
import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from hextrail.cache import AnalysisCache, CacheError, CacheIdentity, run_analysis
from hextrail.decompiler import DecompilationReport, DecompiledFunction, DecompilerError


@pytest.fixture
def provider(tmp_path):
    binary = tmp_path / "input.bin"
    binary.write_bytes(b"source-backed test input")
    sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()

    class Provider:
        def __init__(self):
            self.calls = 0
            self.failure = None
            self.profile = {
                "provider": "Test provider", "provider_version": "1.0",
                "architecture": "AArch64", "language": "AARCH64:LE:64:v8A",
                "compiler": "default", "adapter_revision": "revision-1",
                "exporter_sha256": "a" * 64, "options": {"timeout": 30},
            }
            self.report = DecompilationReport(sha256, "Test provider", "1.0", "AArch64", (
                DecompiledFunction(0x1000, 8, "sample", "int sample(void)",
                                   "return 42;", "Test analysis"),), ("sample warning",))

        def analysis_profile(self):
            return copy.deepcopy(self.profile)

        def decompile(self, path, digest, cancelled):
            self.calls += 1
            if self.failure:
                raise DecompilerError(self.failure)
            return self.report

    return Provider(), binary, sha256


def identity_for(provider):
    instance, _, digest = provider
    return CacheIdentity.create(digest, instance.analysis_profile())


def test_cache_survives_restart_and_warm_request_never_calls_provider(provider, tmp_path):
    instance, binary, digest = provider
    cache = AnalysisCache(tmp_path / "cache")
    cold = run_analysis(instance, binary, digest, cache)
    assert cold.cache_status == "stored"
    instance.failure = "Ghidra must not start on a cache hit"
    warm = run_analysis(instance, binary, digest, AnalysisCache(cache.root))
    assert warm.cache_status == "hit"
    assert warm.report == cold.report
    assert instance.calls == 1
    assert "Saved" in warm.detail


@pytest.mark.parametrize("change", [
    {"provider": "Other provider"}, {"provider_version": "2.0"},
    {"architecture": "other"}, {"language": "other-language"},
    {"compiler": "other-compiler"}, {"adapter_revision": "revision-2"},
    {"exporter_sha256": "b" * 64}, {"options": {"timeout": 60}},
])
def test_profile_changes_miss_existing_entry(provider, tmp_path, change):
    instance, _, _ = provider
    cache = AnalysisCache(tmp_path)
    cache.save(identity_for(provider), instance.report)
    instance.profile.update(change)
    assert cache.load(identity_for(provider)) is None


def test_binary_digest_and_report_schema_are_part_of_identity(provider, tmp_path, monkeypatch):
    import hextrail.cache as module
    instance, _, digest = provider
    cache = AnalysisCache(tmp_path)
    identity = identity_for(provider)
    cache.save(identity, instance.report)
    other = CacheIdentity.create("b" * 64, instance.profile)
    assert cache.load(other) is None
    monkeypatch.setattr(module, "SCHEMA", "hextrail.decompilation.future")
    assert cache.load(CacheIdentity.create(digest, instance.profile)) is None


def test_profile_key_order_is_irrelevant_and_profile_is_snapshotted(provider):
    instance, _, digest = provider
    identity = identity_for(provider)
    reversed_profile = dict(reversed(list(instance.profile.items())))
    assert CacheIdentity.create(digest, reversed_profile).filename == identity.filename
    instance.profile["options"]["timeout"] = 999
    assert identity.data["profile"]["options"]["timeout"] == 30


def test_changed_input_is_rejected_even_when_cache_exists(provider, tmp_path):
    instance, binary, digest = provider
    cache = AnalysisCache(tmp_path / "cache")
    run_analysis(instance, binary, digest, cache)
    binary.write_bytes(b"rebuilt binary")
    with pytest.raises(DecompilerError, match="binary changed"):
        run_analysis(instance, binary, digest, cache)
    assert instance.calls == 1


@pytest.mark.parametrize("damage", ["truncated", "identity", "checksum", "report", "schema", "oversized"])
def test_corruption_is_a_miss_and_success_replaces_bad_entry(provider, tmp_path, damage):
    instance, binary, digest = provider
    cache = AnalysisCache(tmp_path / "cache", max_bytes=16_384)
    identity = identity_for(provider)
    path = cache.save(identity, instance.report)
    if damage == "truncated":
        path.write_text('{"schema":')
    elif damage == "oversized":
        with path.open("wb") as stream:
            stream.truncate(16_385)
    else:
        value = json.loads(path.read_text())
        if damage == "identity":
            value["identity"]["profile"]["provider_version"] = "stale"
        elif damage == "checksum":
            value["report"]["functions"][0]["pseudocode"] = "changed but well-formed"
        elif damage == "schema":
            value["schema"] = "other.cache"
        else:
            value["report"]["functions"][0]["address"] = -1
            raw = json.dumps(value["report"], sort_keys=True, separators=(",", ":")).encode()
            value["report_sha256"] = hashlib.sha256(raw).hexdigest()
        path.write_text(json.dumps(value))
    result = run_analysis(instance, binary, digest, cache)
    assert result.cache_status == "stored"
    assert "ignored" in result.detail
    assert cache.load(identity).report == instance.report
    assert instance.calls == 1


def test_unwritable_cache_is_nonfatal_for_fresh_analysis(provider, tmp_path):
    instance, binary, digest = provider
    blocked = tmp_path / "not-a-directory"
    blocked.write_text("unrelated data")
    result = run_analysis(instance, binary, digest, AnalysisCache(blocked))
    assert result.report == instance.report
    assert result.cache_status == "unavailable"
    assert "Results remain available" in result.detail
    assert blocked.read_text() == "unrelated data"


def test_force_rerun_replaces_success_but_failure_preserves_previous_entry(provider, tmp_path):
    instance, binary, digest = provider
    cache = AnalysisCache(tmp_path)
    original = run_analysis(instance, binary, digest, cache).report
    instance.failure = "Provider failed"
    with pytest.raises(DecompilerError, match="Provider failed"):
        run_analysis(instance, binary, digest, cache, force=True)
    assert cache.load(identity_for(provider)).report == original
    instance.failure = None
    instance.report = replace(original, warnings=("refreshed warning",))
    refreshed = run_analysis(instance, binary, digest, cache, force=True)
    assert refreshed.cache_status == "refreshed"
    assert cache.load(identity_for(provider)).report.warnings == ("refreshed warning",)
    assert instance.calls == 3


def test_cache_only_miss_never_launches_provider(provider, tmp_path):
    instance, binary, digest = provider
    result = run_analysis(instance, binary, digest, AnalysisCache(tmp_path), cache_only=True)
    assert result.report is None
    assert result.cache_status == "miss"
    assert instance.calls == 0


def test_atomic_replace_failure_retains_previous_report_and_cleans_temporary(provider, tmp_path, monkeypatch):
    import hextrail.cache as module
    instance, _, _ = provider
    cache = AnalysisCache(tmp_path)
    identity = identity_for(provider)
    cache.save(identity, instance.report)

    def interrupted(source, target):
        raise OSError("simulated interrupted replacement")

    monkeypatch.setattr(module.os, "replace", interrupted)
    with pytest.raises(CacheError, match="interrupted replacement"):
        cache.save(identity, replace(instance.report, warnings=("new",)))
    assert cache.load(identity).report == instance.report
    assert not list(tmp_path.glob(".cache-*.tmp"))


def test_cancellation_during_write_preserves_previous_entry(provider, tmp_path, monkeypatch):
    import hextrail.cache as module
    instance, _, _ = provider
    cache = AnalysisCache(tmp_path)
    identity = identity_for(provider)
    cache.save(identity, instance.report)
    stopped = False
    original_fsync = module.os.fsync

    def stop_after_write(fd):
        nonlocal stopped
        original_fsync(fd)
        stopped = True

    monkeypatch.setattr(module.os, "fsync", stop_after_write)
    with pytest.raises(DecompilerError, match="cancelled"):
        cache.save(identity, replace(instance.report, warnings=("new",)), lambda: stopped)
    assert cache.load(identity).report == instance.report
    assert not list(tmp_path.glob(".cache-*.tmp"))


def test_failed_or_cancelled_analysis_does_not_create_cache(provider, tmp_path):
    instance, binary, digest = provider
    cache = AnalysisCache(tmp_path / "cache")
    instance.failure = "cancelled by provider"
    with pytest.raises(DecompilerError):
        run_analysis(instance, binary, digest, cache)
    with pytest.raises(DecompilerError, match="cancelled"):
        run_analysis(instance, binary, digest, cache, cancelled=lambda: True)
    assert not cache.root.exists()


def test_clear_removes_all_profiles_for_binary_and_keeps_notes_and_other_binaries(provider, tmp_path):
    instance, _, digest = provider
    cache = AnalysisCache(tmp_path)
    cache.save(identity_for(provider), instance.report)
    instance.profile["options"]["timeout"] = 60
    cache.save(identity_for(provider), instance.report)
    other = CacheIdentity.create("b" * 64, instance.profile)
    cache.save(other, replace(instance.report, binary_sha256="b" * 64))
    notes = tmp_path / f"{digest}.json"
    notes.write_text("user notes")
    assert cache.clear(digest) == 2
    assert cache.load(other) is not None
    assert notes.read_text() == "user notes"


@pytest.mark.parametrize("limit", ["count", "bytes"])
def test_storage_budget_evicts_old_entries(provider, tmp_path, limit):
    instance, _, digest = provider
    cache = AnalysisCache(tmp_path, max_entries=2)
    first = identity_for(provider)
    first_path = cache.save(first, instance.report)
    entry_size = first_path.stat().st_size
    if limit == "bytes":
        cache.max_entries = 100
        cache.max_bytes = entry_size * 2 + 64
    instance.profile["options"]["timeout"] = 40
    second = identity_for(provider)
    cache.save(second, instance.report)
    os.utime(first_path, ns=(1, 1))
    instance.profile["options"]["timeout"] = 50
    third = identity_for(provider)
    cache.save(third, instance.report)
    assert cache.load(first) is None
    assert cache.load(second) is not None
    assert cache.load(third) is not None


def test_nonregular_cache_entry_is_never_followed(provider, tmp_path):
    instance, _, _ = provider
    cache = AnalysisCache(tmp_path)
    path = cache.path_for(identity_for(provider))
    outside = tmp_path / "notes.json"
    outside.write_text("notes")
    path.symlink_to(outside)
    with pytest.raises(CacheError, match="regular file"):
        cache.load(identity_for(provider))
    cache.clear(instance.report.binary_sha256)
    assert outside.read_text() == "notes"


def test_eviction_failure_does_not_replace_existing_result(provider, tmp_path, monkeypatch):
    instance, _, _ = provider
    cache = AnalysisCache(tmp_path)
    identity = identity_for(provider)
    cache.save(identity, instance.report)

    def interrupted(*args):
        raise OSError("eviction denied")

    monkeypatch.setattr(cache, "_prune", interrupted)
    with pytest.raises(CacheError, match="eviction denied"):
        cache.save(identity, replace(instance.report, warnings=("new",)))
    assert cache.load(identity).report == instance.report
    assert not list(tmp_path.glob(".cache-*.tmp"))


def test_recency_update_does_not_recreate_entry_cleared_by_another_session(provider, tmp_path, monkeypatch):
    import hextrail.cache as module
    instance, _, _ = provider
    cache = AnalysisCache(tmp_path)
    identity = identity_for(provider)
    path = cache.save(identity, instance.report)
    original_utime = module.os.utime

    def remove_before_touch(target, values):
        Path(target).unlink()
        original_utime(target, values)

    monkeypatch.setattr(module.os, "utime", remove_before_touch)
    assert cache.load(identity).report == instance.report
    assert not path.exists()


def test_abandoned_temporary_files_are_not_loaded_and_stale_ones_are_cleaned(provider, tmp_path):
    instance, _, _ = provider
    cache = AnalysisCache(tmp_path)
    old = tmp_path / ".cache-abandoned.tmp"
    recent = tmp_path / ".cache-running.tmp"
    old.write_text("incomplete abandoned write")
    recent.write_text("another session's current write")
    os.utime(old, ns=(1, 1))
    assert cache.load(identity_for(provider)) is None
    cache.save(identity_for(provider), instance.report)
    assert not old.exists()
    assert recent.exists()
