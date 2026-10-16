import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import time
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QFileDialog

from hextrail.app import MainWindow, STYLE, SAMPLE
from hextrail.engine import analyse
from hextrail.storage import AnnotationStore


@pytest.fixture(scope="module")
def app():
    instance = QApplication.instance() or QApplication([])
    instance.setStyle("Fusion")
    instance.setStyleSheet(STYLE)
    return instance


@pytest.fixture
def window(app, tmp_path):
    win = MainWindow(tmp_path)
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
    window = MainWindow(tmp_path)
    window.show()
    window.load_binary(SAMPLE)
    deadline = time.monotonic() + 10
    while window.worker.isRunning() and time.monotonic() < deadline:
        app.processEvents()
        QTest.qWait(10)
    app.processEvents()
    assert window.binary is not None
    assert window.current_fn.name == "calculate_total"
    assert window.open_button.isEnabled()
    window.close()
