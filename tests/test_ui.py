import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import time
import threading
from dataclasses import replace
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QFileDialog

from hextrail.app import MainWindow, STYLE, SAMPLE
from hextrail.engine import analyse
from hextrail.storage import AnnotationStore
from hextrail.decompiler import DecompilationReport, DecompiledFunction, DecompilerError


@pytest.fixture(scope="module")
def app():
    instance = QApplication.instance() or QApplication([])
    instance.setStyle("Fusion")
    instance.setStyleSheet(STYLE)
    return instance


@pytest.fixture
def window(app, tmp_path):
    win = MainWindow(tmp_path, cache_root=tmp_path / "cache")
    win.show()
    win.set_binary(analyse(SAMPLE))
    app.processEvents()
    yield win
    win.close()
    app.processEvents()


def test_ui_load_filter_jump_graph_and_hex(window, app):
    assert window.current_fn.name == "calculate_total"
    assert window.assembly_model.rowCount() == 26
    QTest.keyClicks(window.function_filter, "checksum")
    assert window.functions_model.rowCount() == 1
    window.functions_view.setCurrentIndex(window.functions_model.index(0, 0))
    assert window.current_fn.name == "checksum_bytes"
    window.function_filter.clear()
    QTest.keyClicks(window.jump_input, "1054c")
    QTest.keyClick(window.jump_input, Qt.Key.Key_Return)
    assert window.current_fn.name == "calculate_total"
    assert window.graph.scene().items()
    assert "fd 7b be a9" in window.hex_view.toPlainText()
    row = next(i for i, item in enumerate(window.instructions) if item.flow == "call")
    index = window.assembly_model.index(row, 0)
    # Exercise the real Qt signal/slot path for double-click navigation.
    window.assembly_view.doubleClicked.emit(index)
    assert window.current_fn.name == "validate_quantity"


def test_ui_notes_survive_function_navigation(window, app, tmp_path):
    QTest.keyClicks(window.alias_input, "quote_total")
    QTest.keyClicks(window.note_editor, "Member discount applies at 1000.")
    QTest.qWait(450)
    assert window.note_status.text() == "Saved locally"
    address = window.current_fn.address
    window.jump_to(next(f.address for f in window.binary.functions if f.name == "validate_quantity"))
    window.jump_to(address)
    assert window.alias_input.text() == "quote_total"
    assert "discount" in window.note_editor.toPlainText()
    restored = AnnotationStore(window.binary.sha256, tmp_path)
    assert restored.get(address)["alias"] == "quote_total"


def test_strings_imports_clipboard_and_export(window, app, tmp_path, monkeypatch):
    QTest.keyClicks(window.string_filter, "ready for inspection")
    assert window.strings_model.rowCount() == 1
    window.strings_view.doubleClicked.emit(window.strings_model.index(0, 0))
    assert window.tabs.currentIndex() == 2
    assert "File offset" in window.hex_view.toPlainText()
    QTest.keyClicks(window.import_filter, "android_log")
    assert window.imports_model.rowCount() == 1
    window.copy_context()
    assert "0x1054c" in QApplication.clipboard().text()
    assert "static disassembly" in QApplication.clipboard().text()
    out = tmp_path / "analysis.json"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *args, **kwargs: (str(out), "JSON"))
    window.export_report()
    import json
    report = json.loads(out.read_text())
    assert report["sha256"] == window.binary.sha256
    assert len(report["functions"]) == 6


def test_background_analysis_completes(app, tmp_path):
    window = MainWindow(tmp_path, cache_root=tmp_path / "cache")
    window.show()
    window.load_binary(SAMPLE)
    deadline = time.monotonic() + 10
    while window.worker.isRunning() and time.monotonic() < deadline:
        app.processEvents()
        QTest.qWait(10)
    app.processEvents()
    assert window.binary is not None
    assert window.current_fn.name == "calculate_total"
    wait_for(app, lambda: window.deep_worker is None)
    assert window.open_button.isEnabled()
    window.close()


def wait_for(app, predicate):
    deadline = time.monotonic() + 5
    while not predicate() and time.monotonic() < deadline:
        app.processEvents()
        QTest.qWait(10)
    app.processEvents()
    assert predicate(), "Timed out waiting for the Qt worker"


@pytest.fixture
def deep_provider(window, app):
    """A controllable provider exercises the real Qt thread/signal boundary."""
    class Provider:
        def __init__(self):
            self.started = threading.Event()
            self.release = threading.Event()
            self.error = None
            self.received_home = None
            self.thread_id = None
            self.result = None
            self.calls = 0

        def factory(self, home):
            self.received_home = home
            return self

        def analysis_profile(self):
            return {"provider": "Ghidra", "provider_version": "test-version",
                    "architecture": "AArch64", "language": "auto", "compiler": "auto",
                    "adapter_revision": "test-v1", "exporter_sha256": "a" * 64,
                    "options": {"analysis": "default"}}

        def decompile(self, path, sha256, cancelled):
            self.calls += 1
            self.thread_id = threading.get_ident()
            self.started.set()
            while not self.release.wait(0.01):
                if cancelled():
                    raise DecompilerError("Decompilation cancelled.")
            if self.error:
                raise DecompilerError(self.error)
            if self.result:
                return self.result
            functions = analyse(SAMPLE).functions
            total = next(f for f in functions if f.name == "calculate_total")
            local = next(f for f in functions if f.name == "validate_quantity")
            return DecompilationReport(sha256, "Ghidra", "test-version", "AArch64", (
                DecompiledFunction(total.address, total.size, total.name,
                                   "int calculate_total(int quantity, int price)",
                                   "return quantity * price;", "Ghidra analysis"),
                DecompiledFunction(local.address, local.size, local.name,
                                   "int validate_quantity(int quantity)", "", "Ghidra analysis"),
            ), ("<b>Provider warning: sample only</b>",))

    provider = Provider()
    window.provider_factory = provider.factory
    yield provider
    provider.release.set()
    if window.deep_worker:
        window.cancel_deep_analysis()
        wait_for(app, lambda: window.deep_worker is None)


def test_deep_analysis_is_responsive_and_synchronizes_pseudocode(window, app, deep_provider):
    window.ghidra_home.setText("/chosen/ghidra")
    window.deep_button.click()
    wait_for(app, deep_provider.started.is_set)
    assert deep_provider.thread_id != threading.get_ident()
    assert deep_provider.received_home == "/chosen/ghidra"
    assert not window.open_button.isEnabled()
    assert window.deep_progress.isVisible()
    # Navigation still responds while the provider is waiting.
    window.jump_to(next(f.address for f in window.binary.functions if f.name == "checksum_bytes"))
    assert window.current_fn.name == "checksum_bytes"
    deep_provider.release.set()
    wait_for(app, lambda: window.deep_worker is None)
    assert "No pseudocode matches" in window.pseudocode_view.toPlainText()
    window.jump_to(next(f.address for f in window.binary.functions if f.name == "calculate_total"))
    assert window.pseudocode_view.toPlainText() == "return quantity * price;"
    assert "Ghidra test-version" in window.pseudocode_origin.text()
    assert "int calculate_total" in window.pseudocode_origin.text()
    assert "<b>Provider warning" in window.decompiler_warnings.toPlainText()
    assert window.pseudocode_view.isReadOnly()
    assert window.open_button.isEnabled()
    assert not window.deep_progress.isVisible()
    assert "Completed" in window.deep_status.text()


def test_recovered_function_navigation_on_stripped_binary(window, app, deep_provider):
    window.set_binary(analyse(SAMPLE.with_name("libnative_demo_stripped.so")))
    assert not any(f.name == "validate_quantity" for f in window.binary.functions)
    deep_provider.release.set()
    window.run_deep_analysis()
    wait_for(app, lambda: window.deep_worker is None)
    completer = window.recovered_selector.completer()
    completer.setCompletionPrefix("validate_quantity")
    assert completer.completionCount() == 1
    index = next(i for i, f in enumerate(window.recovered_model.rows) if f.name == "validate_quantity")
    address = window.recovered_model.rows[index].address
    completer.setCompletionPrefix(f"{address:08x}")
    assert completer.completionCount() == 1
    window.recovered_selector.setCurrentIndex(index)
    window.recovered_selector.activated.emit(index)
    assert window.tabs.currentWidget() == window.pseudocode_page
    assert window.current_fn.is_region
    assert window.pseudocode_address == address
    assert "validate_quantity" in window.recovered_selector.currentText()
    assert f"{address:08x}" in window.recovered_selector.currentText()
    assert "no pseudocode" in window.pseudocode_view.toPlainText()
    assert "validate_quantity" in window.pseudocode_origin.text()
    window.pseudocode_assembly.click()
    assert window.tabs.currentIndex() == 0
    assert window.assembly_view.currentIndex().data(Qt.ItemDataRole.UserRole).address == address
    assert window.pseudocode_address == address
    window.tabs.setCurrentWidget(window.pseudocode_page)
    assert "validate_quantity" in window.pseudocode_origin.text()
    # A byte count must not be interpreted as proof of a contiguous function range.
    window.update_pseudocode(address + 4)
    assert "No pseudocode matches" in window.pseudocode_view.toPlainText()


def test_missing_provider_failure_and_retry(window, app, deep_provider, monkeypatch):
    from hextrail.app import ghidra_provider
    import hextrail.app as ui

    def absent(home):
        raise DecompilerError("Ghidra was not found. Set GHIDRA_HOME.")

    monkeypatch.setattr(ui, "discover_ghidra", absent)
    window.provider_factory = ghidra_provider
    window.run_deep_analysis()
    wait_for(app, lambda: window.deep_worker is None)
    assert "GHIDRA_HOME" in window.deep_status.text()
    assert window.decompilation is None
    assert window.assembly_model.rowCount() == 26
    assert window.deep_button.isEnabled()
    window.provider_factory = deep_provider.factory
    deep_provider.release.set()
    window.deep_button.click()
    wait_for(app, lambda: window.deep_worker is None)
    assert window.decompilation is not None


def test_cancellation_preserves_session_and_allows_retry(window, app, deep_provider):
    window.rerun_deep_analysis()
    wait_for(app, deep_provider.started.is_set)
    original = window.binary
    # File-menu and drag/drop paths cannot replace the binary while analysis runs.
    window.load_binary(SAMPLE.with_name("libnative_demo_stripped.so"))
    assert window.binary is original
    assert window.worker is None
    window.deep_cancel.click()
    wait_for(app, lambda: window.deep_worker is None)
    assert "cancelled" in window.deep_status.text()
    assert window.decompilation is None
    assert window.current_fn.name == "calculate_total"
    deep_provider.release.set()
    window.run_deep_analysis()
    wait_for(app, lambda: window.deep_worker is None)
    assert window.decompilation is not None


@pytest.mark.parametrize("change, message", [
    ({"binary_sha256": "0" * 64}, "different binary"),
    ({"architecture": "x86"}, "not for AArch64"),
])
def test_mismatched_decompiler_result_is_rejected(window, app, deep_provider, change, message):
    deep_provider.result = replace(DecompilationReport(
        window.binary.sha256, "Ghidra", "test", "AArch64", ()), **change)
    deep_provider.release.set()
    window.run_deep_analysis()
    wait_for(app, lambda: window.deep_worker is None)
    assert message in window.deep_status.text()
    assert window.decompilation is None


def test_failed_rerun_retains_previous_results_and_new_binary_clears_them(window, app, deep_provider):
    deep_provider.release.set()
    window.run_deep_analysis()
    wait_for(app, lambda: window.deep_worker is None)
    report = window.decompilation
    deep_provider.release.clear()
    deep_provider.started.clear()
    window.rerun_deep_analysis()
    wait_for(app, deep_provider.started.is_set)
    window.cancel_deep_analysis()
    wait_for(app, lambda: window.deep_worker is None)
    assert window.decompilation is report
    assert "Previous results remain displayed" in window.deep_status.text()
    deep_provider.release.set()
    deep_provider.error = "Provider process failed"
    window.rerun_deep_analysis()
    wait_for(app, lambda: window.deep_worker is None)
    assert "Previous results remain displayed" in window.deep_status.text()
    assert window.decompilation is report
    assert window.pseudocode_view.toPlainText() == "return quantity * price;"
    window.load_binary(SAMPLE.with_name("libnative_demo_stripped.so"))
    wait_for(app, lambda: window.worker is not None and not window.worker.isRunning())
    assert window.decompilation is None
    assert window.recovered_model.rowCount() == 0
    assert not window.decompiler_warnings.isVisible()
    assert "Run deep analysis" in window.pseudocode_view.toPlainText()


def test_close_cancels_deep_analysis_before_destroying_window(window, app, deep_provider):
    window.run_deep_analysis()
    wait_for(app, deep_provider.started.is_set)
    assert not window.close()
    wait_for(app, lambda: window.deep_worker is None and not window.isVisible())


def test_reopening_binary_automatically_restores_cache_without_provider_run(window, app, deep_provider):
    deep_provider.release.set()
    window.run_deep_analysis()
    wait_for(app, lambda: window.deep_worker is None)
    window.alias_input.setText("saved_name")
    window.note_editor.setPlainText("Annotations survive cache restore.")
    assert window.save_notes()
    expected = window.pseudocode_view.toPlainText()
    deep_provider.error = "Provider must not run"
    reopened = MainWindow(window.notes_root, provider_factory=deep_provider.factory,
                          cache_root=window.analysis_cache.root)
    try:
        reopened.show()
        reopened.load_binary(SAMPLE)
        wait_for(app, lambda: reopened.decompilation is not None and reopened.deep_worker is None)
        assert reopened.cache_status.text() == "Cache hit"
        assert "Loaded cached analysis" in reopened.deep_status.text()
        assert reopened.pseudocode_view.toPlainText() == expected
        assert reopened.alias_input.text() == "saved_name"
        assert "Annotations survive" in reopened.note_editor.toPlainText()
        assert deep_provider.calls == 1
    finally:
        reopened.close()
        if reopened.deep_worker:
            wait_for(app, lambda: reopened.deep_worker is None)


def test_cache_clear_is_scoped_and_keeps_displayed_results_and_annotations(window, app, deep_provider):
    deep_provider.release.set()
    window.run_deep_analysis()
    wait_for(app, lambda: window.deep_worker is None)
    report = window.decompilation
    window.note_editor.setPlainText("Keep this note")
    assert window.save_notes()
    stored_notes = window.store.path.read_bytes()

    def unavailable(home):
        raise AssertionError("Clearing cache must not discover or launch Ghidra")

    window.provider_factory = unavailable
    window.cache_clear.click()
    wait_for(app, lambda: window.deep_worker is None)
    assert window.cache_status.text() == "Cache cleared"
    assert window.decompilation is report
    assert window.pseudocode_view.toPlainText() == "return quantity * price;"
    assert window.store.path.read_bytes() == stored_notes
    assert not list(window.analysis_cache.root.glob("*.json"))
    window.provider_factory = deep_provider.factory
    window.run_deep_analysis()
    wait_for(app, lambda: window.deep_worker is None)
    assert deep_provider.calls == 2


def test_ui_corrupt_cache_regenerates_and_rerun_bypasses_good_cache(window, app, deep_provider):
    deep_provider.release.set()
    window.run_deep_analysis()
    wait_for(app, lambda: window.deep_worker is None)
    entry = next(window.analysis_cache.root.glob("*.json"))
    entry.write_text("incomplete cache write")
    window.deep_button.click()
    wait_for(app, lambda: window.deep_worker is None)
    assert "Cache miss" in window.cache_status.text()
    assert "ignored" in window.cache_status.toolTip()
    assert deep_provider.calls == 2
    window.deep_rerun.click()
    wait_for(app, lambda: window.deep_worker is None)
    assert window.cache_status.text() == "Cache refreshed"
    assert deep_provider.calls == 3
