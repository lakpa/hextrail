"""Native Qt desktop UI; the analysis engine has no dependency on this module."""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
from collections import defaultdict, deque
from pathlib import Path

from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex, QThread, Signal, QTimer
from PySide6.QtGui import QColor, QFont, QFontDatabase, QPainter, QPainterPath, QPen, QPolygonF, QAction, QKeySequence
from PySide6.QtCore import QPointF
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QSplitter, QTabWidget, QTableView, QHeaderView, QAbstractItemView,
    QPlainTextEdit, QFileDialog, QMessageBox, QFrame, QGraphicsView, QGraphicsScene,
    QGraphicsRectItem, QSizePolicy, QProgressBar, QComboBox,
)

from . import __version__
from .engine import Binary, Function, Instruction, analyse, disassemble, control_flow, ai_context, PAGE_BYTES
from .storage import AnnotationStore
from .ghidra import GhidraDecompiler, discover_ghidra
from .cache import AnalysisCache, AnalysisResult, run_analysis

SAMPLE = Path(__file__).parent / "samples" / "libnative_demo.so"
ACCENT = "#73e3b1"
STYLE = """
QWidget { background: #101722; color: #dce5f1; font-size: 13px; }
QMainWindow { background: #101722; }
QLabel#Brand { font-size: 22px; font-weight: 700; color: #f0f6ff; }
QLabel#Logo { background: #73e3b1; color: #112a24; border-radius: 9px; font-size: 20px; font-weight: 800; }
QLabel#Muted { color: #91a2b9; }
QLabel#Badge { color: #73e3b1; background: #17352f; border: 1px solid #2b5148; border-radius: 5px; padding: 5px 10px; }
QLabel#SectionTitle { color: #93a8c2; font-size: 11px; font-weight: 700; }
QLabel#FileName { font-size: 18px; font-weight: 600; }
QPushButton { background: #1c293b; border: 1px solid #33435c; border-radius: 6px; padding: 8px 13px; }
QPushButton:hover { background: #283b52; border-color: #6482a7; }
QPushButton:pressed { background: #162234; }
QPushButton:disabled { color: #5b6b7e; border-color: #253247; }
QPushButton#Primary { background: #73e3b1; color: #10281f; border-color: #73e3b1; font-weight: 700; }
QPushButton#Primary:hover { background: #94efc9; }
QLineEdit, QPlainTextEdit, QComboBox { background: #0c121d; border: 1px solid #2b3a50; border-radius: 5px; padding: 7px; selection-background-color: #285949; }
QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus { border-color: #73e3b1; }
QComboBox QLineEdit { border: none; padding: 0; }
QTabWidget::pane { border: 1px solid #29374c; background: #0e1520; border-radius: 4px; }
QTabBar::tab { background: #121c2b; color: #92a4bc; padding: 11px 16px; border-bottom: 2px solid transparent; }
QTabBar::tab:selected { color: #eaf6ff; border-bottom: 2px solid #73e3b1; background: #182538; }
QTableView { background: #101824; alternate-background-color: #131e2d; border: none; gridline-color: #1c2a3d; selection-background-color: #214535; selection-color: #e8fff5; }
QTableView::item { padding: 3px 7px; border: none; }
QHeaderView::section { background: #172233; color: #8fa6c3; border: none; border-bottom: 1px solid #2e3e54; padding: 7px 8px; font-size: 11px; }
QSplitter::handle { background: #243247; width: 1px; }
QFrame#Card { background: #141f2d; border: 1px solid #2a3a50; border-radius: 7px; }
QFrame#Card QLabel { background: transparent; }
QLabel#Metric { font-size: 23px; font-weight: 600; color: #edf6ff; }
QStatusBar { background: #0a111b; color: #93a8bf; border-top: 1px solid #27354a; }
QScrollBar:vertical { background: #101722; width: 10px; }
QScrollBar::handle:vertical { background: #3c4f68; border-radius: 4px; min-height: 30px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { background: #101722; height: 10px; }
QScrollBar::handle:horizontal { background: #3c4f68; border-radius: 4px; min-width: 30px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QToolTip { background: #233249; color: #e8f1ff; border: 1px solid #50647d; padding: 5px; }
QMenu { background: #172233; border: 1px solid #35475f; }
QMenu::item:selected { background: #284334; }
"""


def hx(value):
    return f"0x{value:08x}" if value is not None else "—"


def readable_size(value):
    return f"{value / 1024 / 1024:.1f} MiB" if value >= 1048576 else f"{value / 1024:.1f} KiB"


def label(text, kind="", word_wrap=False):
    item = QLabel(text)
    item.setTextFormat(Qt.TextFormat.PlainText)
    if kind:
        item.setObjectName(kind)
    item.setWordWrap(word_wrap)
    return item


def button(text, slot, primary=False):
    item = QPushButton(text)
    if primary:
        item.setObjectName("Primary")
    item.clicked.connect(slot)
    return item


class Rows(QAbstractTableModel):
    def __init__(self, columns, rows=None, parent=None):
        super().__init__(parent)
        self.columns = columns
        self.rows = rows or []

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.columns)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or index.row() >= len(self.rows):
            return None
        row = self.rows[index.row()]
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole, Qt.ItemDataRole.EditRole):
            return str(self.columns[index.column()][1](row))
        if role == Qt.ItemDataRole.UserRole:
            return row
        if role == Qt.ItemDataRole.ForegroundRole and isinstance(row, Instruction):
            if index.column() == 2:
                return QColor({"call": "#d1b0ff", "conditional": "#f2cb7d", "branch": "#f2cb7d",
                               "return": "#73e3b1"}.get(row.flow, "#8fc7ef"))
            if index.column() == 0:
                return QColor("#7f95ae")
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.columns[section][0]
        return None

    def replace(self, rows):
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()


def table(model, mono=False):
    view = QTableView()
    view.setModel(model)
    view.setAlternatingRowColors(True)
    view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    view.setWordWrap(False)
    view.verticalHeader().hide()
    view.verticalHeader().setDefaultSectionSize(28)
    view.setShowGrid(False)
    view.horizontalHeader().setStretchLastSection(True)
    view.horizontalHeader().setDefaultSectionSize(150)
    if mono:
        view.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
    return view


class AnalyseWorker(QThread):
    ready = Signal(object)
    failed = Signal(str)

    def __init__(self, path, parent=None):
        super().__init__(parent)
        self.path = path

    def run(self):
        try:
            self.ready.emit(analyse(self.path, self.isInterruptionRequested))
        except Exception as exc:
            self.failed.emit(str(exc))


def ghidra_provider(home):
    return GhidraDecompiler(discover_ghidra(home))


class DecompileWorker(QThread):
    ready = Signal(object)
    failed = Signal(str)
    cancelled = Signal()
    progress = Signal(str)
    cleared = Signal(int)

    def __init__(self, binary, home, provider_factory, cache, operation, parent=None):
        super().__init__(parent)
        self.path = binary.path
        self.sha256 = binary.sha256
        self.home = home
        self.provider_factory = provider_factory
        self.cache = cache
        self.operation = operation

    def run(self):
        try:
            if self.operation == "clear":
                self.progress.emit("Clearing saved analysis…")
                self.cleared.emit(self.cache.clear(self.sha256, self.isInterruptionRequested))
                return
            self.progress.emit("Checking analysis provider…")
            provider = self.provider_factory(self.home)
            if self.isInterruptionRequested():
                self.cancelled.emit()
                return
            result = run_analysis(provider, self.path, self.sha256, self.cache,
                force=self.operation == "rerun", cache_only=self.operation == "restore",
                cancelled=self.isInterruptionRequested, progress=self.progress.emit)
            if self.isInterruptionRequested():
                self.cancelled.emit()
                return
            self.ready.emit(result)
        except Exception as exc:
            if self.isInterruptionRequested():
                self.cancelled.emit()
            else:
                self.failed.emit(str(exc))


class GraphNode(QGraphicsRectItem):
    def __init__(self, x, y, width, height, address, callback):
        super().__init__(x, y, width, height)
        self.address, self.callback = address, callback
        self.setBrush(QColor("#172334"))
        self.setPen(QPen(QColor("#435975"), 1.3))
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def mouseDoubleClickEvent(self, event):
        self.callback(self.address)
        event.accept()


class FlowView(QGraphicsView):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback
        self.scene_data = QGraphicsScene(self)
        self.setScene(self.scene_data)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setBackgroundBrush(QColor("#0c131e"))
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)

    def draw(self, instructions):
        scene = self.scene_data
        scene.clear()
        blocks = control_flow(instructions)
        if not blocks:
            return
        if len(blocks) > 60:
            text = scene.addText("This page has more than 60 basic blocks. Use disassembly or a smaller function.")
            text.setDefaultTextColor(QColor("#dce5f1"))
            return
        by_addr = {b.address: b for b in blocks}
        levels, queue = {blocks[0].address: 0}, deque([blocks[0].address])
        while queue:
            address = queue.popleft()
            for target, _ in by_addr[address].edges:
                if target not in levels:
                    levels[target] = levels[address] + 1
                    queue.append(target)
        tail = max(levels.values()) + 1
        for b in blocks:
            if b.address not in levels:
                levels[b.address] = tail
                tail += 1
        grouped = defaultdict(list)
        for b in blocks:
            grouped[levels[b.address]].append(b)
        positions = {}
        row = 0
        for level in sorted(grouped):
            for index, b in enumerate(grouped[level]):
                positions[b.address] = (30 + (index % 3) * 345, 30 + (row + index // 3) * 225)
            row += math.ceil(len(grouped[level]) / 3)
        node_width, node_height = 315, 170
        for b in blocks:
            x, y = positions[b.address]
            for target, kind in b.edges:
                tx, ty = positions[target]
                colour = QColor("#73cda9" if kind == "taken" else "#6684ad")
                start, end = QPointF(x + node_width / 2, y + node_height), QPointF(tx + node_width / 2, ty)
                path = QPainterPath(start)
                if ty <= y:
                    side = x + node_width + 20
                    path.cubicTo(QPointF(side + 90, y + node_height + 50), QPointF(side + 90, ty - 40), end)
                else:
                    middle = (start.y() + end.y()) / 2
                    path.cubicTo(QPointF(start.x(), middle), QPointF(end.x(), middle), end)
                line = scene.addPath(path, QPen(colour, 1.6))
                line.setZValue(-1)
                arrow = QPolygonF([end, QPointF(end.x() - 4, end.y() - 8), QPointF(end.x() + 4, end.y() - 8)])
                scene.addPolygon(arrow, QPen(colour), colour)
            node = GraphNode(x, y, node_width, node_height, b.address, self.callback)
            node.setToolTip("Double-click to jump to disassembly.\n" + "\n".join(f"{i.mnemonic} {i.operands}" for i in b.instructions))
            scene.addItem(node)
            title = scene.addText(hx(b.address), QFont("Monospace", 10, QFont.Weight.Bold))
            title.setDefaultTextColor(QColor(ACCENT))
            title.setPos(x + 10, y + 6)
            formatted = [f"{i.mnemonic:<7} {i.operands}" for i in b.instructions]
            lines = formatted if len(formatted) <= 8 else formatted[:4] + [f"… {len(formatted) - 7} more instructions"] + formatted[-3:]
            body = scene.addText("\n".join(line[:43] for line in lines), QFont("Monospace", 9))
            body.setDefaultTextColor(QColor("#c6d5e7"))
            body.setPos(x + 10, y + 34)
        scene.setSceneRect(scene.itemsBoundingRect().adjusted(-20, -20, 20, 20))
        self.resetTransform()
        self.centerOn(positions[blocks[0].address][0] + 160, 180)

    def wheelEvent(self, event):
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            factor = 1.12 if event.angleDelta().y() > 0 else 1 / 1.12
            scale = self.transform().m11() * factor
            if 0.3 <= scale <= 2.8:
                self.scale(factor, factor)
            event.accept()
        else:
            super().wheelEvent(event)


class MainWindow(QMainWindow):
    def __init__(self, notes_root=None, *, provider_factory=ghidra_provider, cache_root=None):
        super().__init__()
        self.binary = None
        self.current_fn = None
        self.store = None
        self.worker = None
        self.deep_worker = None
        self.decompilation = None
        self.pseudocode_address = None
        self.provider_factory = provider_factory
        self.analysis_cache = AnalysisCache(cache_root)
        self._restore_cache_pending = False
        self._close_pending = False
        self.page = 0
        self.instructions = []
        self.notes_root = notes_root
        self._editing = False
        self._dirty = False
        self.setWindowTitle("HexTrail — Android native analysis")
        self.resize(1440, 920)
        self.setMinimumSize(1050, 700)
        self.setAcceptDrops(True)
        self.notes_timer = QTimer(self)
        self.notes_timer.setSingleShot(True)
        self.notes_timer.timeout.connect(self.save_notes)
        self._build_ui()
        self._menus()

    def _menus(self):
        menu = self.menuBar().addMenu("File")
        for title, shortcut, action in [
            ("Open ARM64 library…", QKeySequence.StandardKey.Open, self.choose_file),
            ("Export analysis…", QKeySequence.StandardKey.SaveAs, self.export_report),
            ("Quit", QKeySequence.StandardKey.Quit, self.close),
        ]:
            item = QAction(title, self)
            item.setShortcut(shortcut)
            item.triggered.connect(action)
            menu.addAction(item)
        navigate = self.menuBar().addMenu("Navigate")
        item = QAction("Go to virtual address", self)
        item.setShortcut(QKeySequence("Ctrl+G"))
        item.triggered.connect(lambda: self.jump_input.setFocus())
        navigate.addAction(item)
        analysis = self.menuBar().addMenu("Analysis")
        self.deep_action = QAction("Run deep analysis", self)
        self.deep_action.setEnabled(False)
        self.deep_action.triggered.connect(self.run_deep_analysis)
        analysis.addAction(self.deep_action)

    def _build_ui(self):
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(20, 18, 20, 12)
        layout.setSpacing(16)
        self.setCentralWidget(root)
        bar = QHBoxLayout()
        mark = label("H", "Logo")
        mark.setFixedSize(40, 40)
        mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bar.addWidget(mark)
        title = QVBoxLayout()
        title.setSpacing(1)
        title.addWidget(label("HexTrail", "Brand"))
        title.addWidget(label("Understand your Android native code", "Muted"))
        bar.addLayout(title)
        bar.addStretch()
        bar.addWidget(label("LOCAL  /  ARM64", "Badge"))
        self.demo_button = button("Load demo", lambda: self.load_binary(SAMPLE))
        self.export_button = button("Export JSON", self.export_report)
        self.open_button = button("Open .so", self.choose_file, True)
        for btn in [self.demo_button, self.export_button, self.open_button]:
            bar.addWidget(btn)
        layout.addLayout(bar)

        info = QHBoxLayout()
        file_box = QVBoxLayout()
        self.file_title = label("Open a library to begin", "FileName")
        self.file_detail = label("ELF64 · AArch64 · Static analysis", "Muted")
        file_box.addWidget(self.file_title)
        file_box.addWidget(self.file_detail)
        info.addLayout(file_box)
        info.addStretch()
        self.metrics = {}
        for key, name in [("functions", "FUNCTIONS"), ("imports", "IMPORTS"), ("strings", "STRINGS")]:
            box = QFrame()
            box.setObjectName("Card")
            box.setFixedWidth(112)
            v = QVBoxLayout(box)
            v.setContentsMargins(12, 8, 12, 8)
            value = label("—", "Metric")
            self.metrics[key] = value
            v.addWidget(value)
            v.addWidget(label(name, "SectionTitle"))
            info.addWidget(box)
        layout.addLayout(info)

        self.workspace = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(self.workspace, 1)
        left = QWidget()
        side = QVBoxLayout(left)
        side.setContentsMargins(0, 0, 12, 0)
        side.addWidget(label("FUNCTIONS & REGIONS", "SectionTitle"))
        self.function_filter = QLineEdit()
        self.function_filter.setPlaceholderText("Filter names or addresses…")
        self.function_filter.setClearButtonEnabled(True)
        self.function_filter.textChanged.connect(self.filter_functions)
        side.addWidget(self.function_filter)
        self.functions_model = Rows([
            ("NAME", lambda f: self.function_name(f)),
            ("ADDRESS", lambda f: hx(f.address)),
        ])
        self.functions_view = table(self.functions_model)
        self.functions_view.setColumnWidth(0, 159)
        self.functions_view.setColumnWidth(1, 104)
        self.functions_view.selectionModel().currentRowChanged.connect(self._function_selected)
        side.addWidget(self.functions_view, 1)
        self.function_count = label("Symbol functions + executable sections", "Muted", True)
        side.addWidget(self.function_count)
        self.workspace.addWidget(left)

        center = QWidget()
        middle = QVBoxLayout(center)
        middle.setContentsMargins(12, 0, 12, 0)
        navigation = QHBoxLayout()
        self.location = label("DISASSEMBLY", "SectionTitle")
        navigation.addWidget(self.location)
        navigation.addStretch()
        self.jump_input = QLineEdit()
        self.jump_input.setPlaceholderText("Go to hex address")
        self.jump_input.setMaximumWidth(185)
        self.jump_input.returnPressed.connect(self.jump_from_input)
        navigation.addWidget(self.jump_input)
        middle.addLayout(navigation)
        self.tabs = QTabWidget()
        middle.addWidget(self.tabs, 1)
        disassembly_page = QWidget()
        assembly_layout = QVBoxLayout(disassembly_page)
        assembly_layout.setContentsMargins(0, 0, 0, 8)
        self.assembly_model = Rows([
            ("ADDRESS", lambda i: hx(i.address)), ("BYTES", lambda i: i.raw),
            ("OP", lambda i: i.mnemonic), ("OPERANDS", lambda i: i.operands),
            ("TARGET SYMBOL", lambda i: i.symbol),
        ])
        self.assembly_view = table(self.assembly_model, True)
        for i, width in enumerate([118, 120, 74, 205, 180]):
            self.assembly_view.setColumnWidth(i, width)
        self.assembly_view.doubleClicked.connect(self.follow_instruction)
        assembly_layout.addWidget(self.assembly_view, 1)
        page_bar = QHBoxLayout()
        self.previous_button = button("‹ Previous", lambda: self.change_page(-1))
        self.next_button = button("Next ›", lambda: self.change_page(1))
        self.page_label = label("", "Muted")
        page_bar.addWidget(self.previous_button)
        page_bar.addWidget(self.page_label, 1)
        page_bar.addWidget(self.next_button)
        assembly_layout.addLayout(page_bar)
        self.tabs.addTab(disassembly_page, "Disassembly")
        flow_page = QWidget()
        flow_layout = QVBoxLayout(flow_page)
        flow_layout.setContentsMargins(0, 0, 0, 8)
        self.graph = FlowView(self.jump_to)
        flow_layout.addWidget(self.graph, 1)
        flow_layout.addWidget(label("Current page · green: taken, blue: fallthrough/jump · drag to pan · Ctrl + wheel to zoom", "Muted", True))
        self.tabs.addTab(flow_page, "Control flow")
        self.hex_view = QPlainTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.hex_view.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.tabs.addTab(self.hex_view, "Hex")

        self.strings_model = Rows([
            ("FILE OFFSET", lambda s: hx(s.offset)), ("VIRTUAL ADDRESS", lambda s: hx(s.address)),
            ("SECTION", lambda s: s.section), ("ASCII STRING", lambda s: s.text),
        ])
        strings_page, self.strings_view, self.string_filter = self.filtered_page(
            self.strings_model, "Filter ASCII strings…", self.filter_strings)
        self.strings_view.setColumnWidth(0, 110)
        self.strings_view.setColumnWidth(1, 130)
        self.strings_view.setColumnWidth(2, 110)
        self.strings_view.doubleClicked.connect(self.show_string)
        self.tabs.addTab(strings_page, "Strings")
        self.imports_model = Rows([
            ("SYMBOL", lambda x: x["name"]), ("TYPE", lambda x: x["type"]), ("BINDING", lambda x: x["binding"]),
        ])
        imports_page, self.imports_view, self.import_filter = self.filtered_page(
            self.imports_model, "Filter imported symbols…", self.filter_imports)
        self.imports_view.setColumnWidth(0, 350)
        self.tabs.addTab(imports_page, "Imports")
        self.sections_model = Rows([
            ("SECTION", lambda s: s.name or "(null)"), ("ADDRESS", lambda s: hx(s.address)),
            ("OFFSET", lambda s: hx(s.offset)), ("SIZE", lambda s: f"{s.size:,}"), ("FLAGS", lambda s: s.flags),
        ])
        self.sections_view = table(self.sections_model)
        self.sections_view.setColumnWidth(0, 165)
        self.sections_view.setColumnWidth(1, 115)
        self.sections_view.setColumnWidth(2, 115)
        self.sections_view.setColumnWidth(3, 100)
        self.sections_view.doubleClicked.connect(self.show_section)
        self.tabs.addTab(self.sections_view, "Sections")
        self.details_view = QPlainTextEdit()
        self.details_view.setReadOnly(True)
        self.tabs.addTab(self.details_view, "Details")
        self._build_pseudocode_ui()
        self.workspace.addWidget(center)

        right = QWidget()
        right.setMaximumWidth(330)
        right.setMinimumWidth(240)
        inspector = QVBoxLayout(right)
        inspector.setContentsMargins(12, 0, 0, 0)
        inspector.addWidget(label("INSPECTOR", "SectionTitle"))
        self.function_title = label("Select a function", "FileName", True)
        self.function_title.setMinimumWidth(0)
        self.function_title.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        inspector.addWidget(self.function_title)
        self.function_details = label("", "Muted", True)
        inspector.addWidget(self.function_details)
        inspector.addSpacing(10)
        inspector.addWidget(label("LOCAL ALIAS", "SectionTitle"))
        self.alias_input = QLineEdit()
        self.alias_input.setMaxLength(160)
        self.alias_input.setPlaceholderText("Your name for this function")
        self.alias_input.textChanged.connect(self.notes_changed)
        inspector.addWidget(self.alias_input)
        inspector.addWidget(label("NOTES", "SectionTitle"))
        self.note_editor = QPlainTextEdit()
        self.note_editor.setPlaceholderText("Record observations and questions.\nSaved locally for this binary.")
        self.note_editor.textChanged.connect(self.notes_changed)
        self.note_editor.setMinimumHeight(100)
        self.note_editor.setMaximumHeight(200)
        inspector.addWidget(self.note_editor, 1)
        self.note_status = label("Annotations stay separate from the binary", "Muted", True)
        inspector.addWidget(self.note_status)
        inspector.addSpacing(10)
        inspector.addWidget(label("DIRECT CALL REFERENCES", "SectionTitle"))
        self.xrefs_model = Rows([
            ("FROM / TO", lambda x: x["label"]), ("ADDRESS", lambda x: hx(x["address"])),
        ])
        self.xrefs_view = table(self.xrefs_model, True)
        self.xrefs_view.setMaximumHeight(190)
        self.xrefs_view.setMinimumHeight(100)
        self.xrefs_view.setColumnWidth(0, 135)
        self.xrefs_view.doubleClicked.connect(self.follow_xref)
        inspector.addWidget(self.xrefs_view, 1)
        inspector.addWidget(label("Static BL candidates; indirect calls are unresolved.", "Muted", True))
        self.context_button = button("Copy AI context", self.copy_context)
        inspector.addWidget(self.context_button)
        inspector.addWidget(label("Copies evidence to clipboard. No model is connected.", "Muted", True))
        inspector.addStretch()
        self.workspace.addWidget(right)
        self.workspace.setSizes([285, 850, 270])
        self.statusBar().showMessage("Ready · Open an ARM64 ELF library or load the included demo")

    def _build_pseudocode_ui(self):
        self.pseudocode_page = QWidget()
        layout = QVBoxLayout(self.pseudocode_page)
        configuration = QHBoxLayout()
        self.ghidra_home = QLineEdit()
        self.ghidra_home.setPlaceholderText("Ghidra directory (or use GHIDRA_HOME / PATH)")
        configuration.addWidget(self.ghidra_home, 1)
        self.ghidra_browse = button("Browse…", self.choose_ghidra)
        configuration.addWidget(self.ghidra_browse)
        layout.addLayout(configuration)
        controls = QHBoxLayout()
        self.deep_button = button("Run deep analysis", self.run_deep_analysis)
        self.deep_button.setEnabled(False)
        self.deep_cancel = button("Cancel", self.cancel_deep_analysis)
        self.deep_cancel.setEnabled(False)
        controls.addWidget(self.deep_button)
        controls.addWidget(self.deep_cancel)
        self.deep_progress = QProgressBar()
        self.deep_progress.setRange(0, 0)
        self.deep_progress.setTextVisible(False)
        self.deep_progress.hide()
        controls.addWidget(self.deep_progress, 1)
        layout.addLayout(controls)
        cache_controls = QHBoxLayout()
        self.deep_rerun = button("Rerun analysis", self.rerun_deep_analysis)
        self.cache_clear = button("Clear cache", self.clear_analysis_cache)
        self.deep_rerun.setEnabled(False)
        self.cache_clear.setEnabled(False)
        cache_controls.addWidget(self.deep_rerun)
        cache_controls.addWidget(self.cache_clear)
        self.cache_status = label("Cache not checked.", "Muted", True)
        self.cache_status.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.cache_status.setToolTip(f"Cache directory: {self.analysis_cache.root}")
        cache_controls.addWidget(self.cache_status, 1)
        layout.addLayout(cache_controls)
        self.deep_status = label("Open a library, then run deep analysis to generate pseudocode.", "Muted", True)
        self.deep_status.setMaximumHeight(72)
        self.deep_status.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.deep_status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.deep_status)
        self.recovered_model = Rows([
            ("GHIDRA FUNCTION", lambda f: f"{f.name} · {hx(f.address)}"),
        ])
        recovered = QHBoxLayout()
        recovered.addWidget(label("Recovered functions", "Muted"))
        self.recovered_selector = QComboBox()
        self.recovered_selector.setEditable(True)
        self.recovered_selector.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.recovered_selector.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.recovered_selector.setMinimumContentsLength(12)
        self.recovered_selector.setModel(self.recovered_model)
        self.recovered_selector.lineEdit().setPlaceholderText("Search names or addresses…")
        self.recovered_selector.completer().setCompletionRole(Qt.ItemDataRole.DisplayRole)
        self.recovered_selector.completer().setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.recovered_selector.completer().setFilterMode(Qt.MatchFlag.MatchContains)
        self.recovered_selector.activated.connect(self.select_recovered_function)
        recovered.addWidget(self.recovered_selector, 1)
        layout.addLayout(recovered)
        self.pseudocode_origin = label("No decompiler result loaded.", "Muted", True)
        self.pseudocode_origin.setMaximumHeight(80)
        self.pseudocode_origin.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.pseudocode_origin.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.pseudocode_origin)
        self.pseudocode_view = QPlainTextEdit()
        self.pseudocode_view.setReadOnly(True)
        self.pseudocode_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.pseudocode_view.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.pseudocode_view.setPlainText("Run deep analysis to inspect C-like pseudocode for the selected function.")
        layout.addWidget(self.pseudocode_view, 1)
        self.pseudocode_assembly = button("Show function in disassembly", self.show_pseudocode_assembly)
        self.pseudocode_assembly.setEnabled(False)
        layout.addWidget(self.pseudocode_assembly)
        self.decompiler_warnings = QPlainTextEdit()
        self.decompiler_warnings.setReadOnly(True)
        self.decompiler_warnings.setMaximumHeight(90)
        self.decompiler_warnings.hide()
        layout.addWidget(self.decompiler_warnings)
        layout.addWidget(label("Generated pseudocode is an interpretation, not original source. Navigation uses function addresses.", "Muted", True))
        self.tabs.addTab(self.pseudocode_page, "Pseudocode")

    def choose_ghidra(self):
        path = QFileDialog.getExistingDirectory(self, "Select Ghidra installation", self.ghidra_home.text())
        if path:
            self.ghidra_home.setText(path)

    def run_deep_analysis(self):
        self._start_deep_analysis("normal")

    def rerun_deep_analysis(self):
        self._start_deep_analysis("rerun")

    def clear_analysis_cache(self):
        self._start_deep_analysis("clear")

    def _start_deep_analysis(self, operation):
        if not self.binary or self.deep_worker or (self.worker and self.worker.isRunning()):
            return
        self._restore_cache_pending = False
        if operation != "restore":
            self.tabs.setCurrentWidget(self.pseudocode_page)
        self.deep_worker = DecompileWorker(
            self.binary, self.ghidra_home.text().strip() or None, self.provider_factory,
            self.analysis_cache, operation, self)
        self.deep_worker.progress.connect(self.deep_analysis_progress)
        self.deep_worker.ready.connect(self.deep_analysis_ready)
        self.deep_worker.failed.connect(self.deep_analysis_failed)
        self.deep_worker.cancelled.connect(self.deep_analysis_cancelled)
        self.deep_worker.cleared.connect(self.analysis_cache_cleared)
        self.deep_worker.finished.connect(self.deep_analysis_finished)
        self._deep_controls(True)
        self.deep_status.setText("Clearing saved analysis…" if operation == "clear" else "Checking analysis…")
        self.deep_status.setToolTip("")
        self.deep_worker.start()

    def _deep_controls(self, busy):
        loading = bool(self.worker and self.worker.isRunning())
        self.deep_button.setEnabled(not busy and not loading and self.binary is not None)
        self.deep_action.setEnabled(self.deep_button.isEnabled())
        self.deep_rerun.setEnabled(self.deep_button.isEnabled())
        self.cache_clear.setEnabled(self.deep_button.isEnabled())
        self.deep_cancel.setEnabled(busy)
        self.deep_progress.setVisible(busy)
        self.ghidra_home.setEnabled(not busy)
        self.ghidra_browse.setEnabled(not busy)
        self.open_button.setEnabled(not busy and not loading)
        self.demo_button.setEnabled(not busy and not loading)

    def cancel_deep_analysis(self):
        if self.deep_worker:
            self.deep_worker.requestInterruption()
            self.deep_cancel.setEnabled(False)
            self.deep_status.setText("Cancelling deep analysis…")

    def deep_analysis_progress(self, message):
        if self.deep_worker and not self.deep_worker.isInterruptionRequested():
            self.deep_status.setText(message)

    def deep_analysis_ready(self, result: AnalysisResult):
        if not self.deep_worker or self.deep_worker.isInterruptionRequested():
            return
        labels = {"hit": "Cache hit", "miss": "Cache miss", "stored": "Cache miss · saved",
                  "refreshed": "Cache refreshed", "unavailable": "Result not cached"}
        self.cache_status.setText(labels[result.cache_status])
        self.cache_status.setToolTip(f"{result.detail}\nCache directory: {self.analysis_cache.root}")
        report = result.report
        if report is None:
            self.deep_status.setText("No matching saved analysis. Run deep analysis to generate pseudocode.")
            return
        if not self.binary or self.binary.sha256 != report.binary_sha256:
            self.deep_analysis_failed("Discarded results for a library that is no longer open.")
            return
        self.decompilation = report
        self.populate_recovered_functions()
        self.decompiler_warnings.setPlainText("Provider warnings:\n" + "\n".join(report.warnings))
        self.decompiler_warnings.setVisible(bool(report.warnings))
        self.update_pseudocode(self.pseudocode_address)
        self.deep_status.setText(
            f"{'Loaded cached analysis' if result.cache_status == 'hit' else 'Completed'} · "
            f"{report.provider} {report.provider_version} · {len(report.functions):,} functions · "
            f"{len(report.warnings):,} warning(s) · {result.elapsed_seconds:.2f}s")

    def analysis_cache_cleared(self, count):
        self.cache_status.setText("Cache cleared")
        self.cache_status.setToolTip(f"Cache directory: {self.analysis_cache.root}")
        self.deep_status.setText(
            f"Removed {count} saved result(s) for this binary. Displayed analysis and notes are unchanged.")

    def deep_analysis_failed(self, message):
        suffix = " Previous results remain displayed." if self.decompilation else ""
        restoring = self.deep_worker and self.deep_worker.operation == "restore"
        self.deep_status.setText(
            f"{'Cached analysis could not be restored' if restoring else 'Deep analysis failed'}: {message}{suffix}")
        self.deep_status.setToolTip(message)

    def deep_analysis_cancelled(self):
        suffix = " Previous results remain displayed." if self.decompilation else ""
        self.deep_status.setText("Deep analysis cancelled." + suffix)

    def deep_analysis_finished(self):
        worker = self.deep_worker
        if worker and worker.isInterruptionRequested():
            self.deep_analysis_cancelled()
        self.deep_worker = None
        self._deep_controls(False)
        if worker:
            worker.deleteLater()
        if self._close_pending:
            QTimer.singleShot(0, self.close)

    def populate_recovered_functions(self):
        self.recovered_model.replace(list(self.decompilation.functions) if self.decompilation else [])
        self.recovered_selector.setCurrentIndex(-1)
        self.recovered_selector.clearEditText()

    def select_recovered_function(self, index):
        function = self.recovered_model.index(index, 0).data(Qt.ItemDataRole.UserRole)
        if function and self.save_notes():
            self.jump_to(function.address)
            self.update_pseudocode(function.address)
            self.tabs.setCurrentWidget(self.pseudocode_page)

    def update_pseudocode(self, address=None):
        self.pseudocode_address = address
        self.pseudocode_assembly.setEnabled(False)
        self.pseudocode_origin.setToolTip("")
        report = self.decompilation
        if not report:
            self.pseudocode_origin.setText("No decompiler result loaded.")
            self.pseudocode_view.setPlainText("Run deep analysis to inspect C-like pseudocode for the selected function.")
            return
        origin = f"{report.provider} {report.provider_version} · {report.architecture}"
        # Schema v1 reports body byte counts, not discontiguous address ranges.
        # Only exact entry addresses establish a reliable function association.
        index = next((i for i, f in enumerate(report.functions) if f.address == address), -1)
        function = report.functions[index] if index >= 0 else None
        self.recovered_selector.setCurrentIndex(index)
        if not function:
            self.recovered_selector.clearEditText()
            self.pseudocode_origin.setText(origin)
            self.pseudocode_view.setPlainText(
                "No pseudocode matches this function entry. Select a recovered function above; "
                "ELF and Ghidra function boundaries may differ.")
            return
        self.pseudocode_origin.setText(
            f"{origin}\n{hx(function.address)} · {function.boundary_source}\n{function.signature or function.name}")
        self.pseudocode_origin.setToolTip(self.pseudocode_origin.text())
        self.pseudocode_view.setPlainText(function.pseudocode or
            "The provider returned no pseudocode for this function. Check the provider warnings below.")
        self.pseudocode_assembly.setEnabled(self.binary.section_at(function.address) is not None)

    def show_pseudocode_assembly(self):
        if self.pseudocode_address is not None and self.save_notes():
            address = self.pseudocode_address
            self.jump_to(address)
            self.update_pseudocode(address)

    def filtered_page(self, model, placeholder, callback):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
        search = QLineEdit()
        search.setPlaceholderText(placeholder)
        search.setClearButtonEnabled(True)
        search.textChanged.connect(callback)
        layout.addWidget(search)
        view = table(model)
        layout.addWidget(view, 1)
        return page, view, search

    def choose_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open ARM64 ELF library", "", "Shared libraries (*.so);;All files (*)")
        if path:
            self.load_binary(path)

    def load_binary(self, path):
        if self.deep_worker:
            self.statusBar().showMessage("Cancel deep analysis before opening another library.")
            return
        if self.worker and self.worker.isRunning():
            return
        if not self.save_notes():
            return
        self.workspace.setEnabled(False)
        self.open_button.setEnabled(False)
        self.demo_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.deep_button.setEnabled(False)
        self.deep_action.setEnabled(False)
        self.deep_rerun.setEnabled(False)
        self.cache_clear.setEnabled(False)
        self.statusBar().showMessage(f"Analysing {Path(path).name}…")
        self.worker = AnalyseWorker(str(path), self)
        self.worker.ready.connect(self.set_binary)
        self.worker.failed.connect(self.analysis_failed)
        self.worker.finished.connect(self.analysis_finished)
        self.worker.start()

    def analysis_finished(self):
        self.workspace.setEnabled(True)
        self.open_button.setEnabled(True)
        self.demo_button.setEnabled(True)
        self.export_button.setEnabled(True)
        self._deep_controls(bool(self.deep_worker))
        if self._restore_cache_pending:
            self._restore_cache_pending = False
            self._start_deep_analysis("restore")

    def analysis_failed(self, message):
        self.statusBar().showMessage(message)
        QMessageBox.warning(self, "Unable to open library", message)

    def set_binary(self, binary: Binary):
        self.notes_timer.stop()
        self.binary, self.current_fn = binary, None
        self._restore_cache_pending = True
        self.decompilation = None
        self.update_pseudocode()
        self.populate_recovered_functions()
        self.decompiler_warnings.clear()
        self.decompiler_warnings.hide()
        self.deep_status.setText("Ready · Run deep analysis to generate pseudocode for this library.")
        self.deep_status.setToolTip("")
        self.cache_status.setText("Cache not checked.")
        self.cache_status.setToolTip(f"Cache directory: {self.analysis_cache.root}")
        self._deep_controls(bool(self.deep_worker))
        self.store = AnnotationStore(binary.sha256, self.notes_root)
        self._dirty = False
        name = Path(binary.path).name
        self.file_title.setText(name + ("  ·  included demo" if Path(binary.path) == SAMPLE.resolve() else ""))
        self.file_title.setToolTip(binary.path)
        self.file_detail.setText(f"ELF64 / AArch64     {readable_size(len(binary.data))}     SHA-256 {binary.sha256[:14]}…")
        for key in self.metrics:
            self.metrics[key].setText(f"{len(getattr(binary, key)):,}")
        for field in [self.function_filter, self.string_filter, self.import_filter]:
            field.blockSignals(True)
            field.clear()
            field.blockSignals(False)
        self.filter_functions()
        self.filter_strings()
        self.filter_imports()
        self.sections_model.replace(binary.sections)
        details = [f"File: {binary.path}", f"SHA-256: {binary.sha256}", "Architecture: AArch64 / ELF64 / little-endian",
                   f"ELF type: {binary.elf_type}", f"ELF OS ABI: {binary.osabi}",
                   "Note: AArch64 ELF alone does not prove a file was built for Android.",
                   f"Needed libraries: {', '.join(binary.libraries) or '(none declared)'}", "",
                   "ANALYSIS COVERAGE", f"Direct-call scan: {binary.call_scan_bytes:,} of {binary.executable_bytes:,} executable bytes",
                   "Functions come from ELF symbols. Zero-sized symbols use an estimated extent.",
                   "Executable regions are section ranges, not recovered functions.",
                   "The direct-call index scans aligned BL encodings; embedded data may create false candidates.",
                   "Indirect calls, PLT target resolution, exceptions and runtime behaviour are not modelled.",
                   "Disassembly and control flow show one page (up to 4 KiB) at a time.",
                   "Addresses are link-time virtual addresses. No ASLR load base is applied.",
                   "Strings are printable ASCII, not decoded Java, Kotlin or Dart objects.", "",
                   "LIMITS", *(["• " + w for w in binary.warnings] or ["No additional warnings for this file."]), "",
                   "Optional Ghidra deep analysis generates C-like pseudocode in the Pseudocode tab.",
                   "This prototype does not debug, patch, execute or recover original source code.",
                   "It has no network or AI provider connection. Copy AI context is an explicit clipboard action.",
                   f"Annotation file: {self.store.path}"]
        self.details_view.setPlainText("\n".join(details))
        selected = next((i for i, f in enumerate(self.functions_model.rows) if f.name == "calculate_total"), 0)
        if self.functions_model.rows:
            self.functions_view.setCurrentIndex(self.functions_model.index(selected, 0))
        else:
            self.assembly_model.replace([])
            self.graph.draw([])
            self.hex_view.clear()
            self.alias_input.clear()
            self.note_editor.clear()
            self.xrefs_model.replace([])
            self.function_title.setText("No executable code")
            self.function_details.setText("Inspect metadata, sections and strings.")
            self.tabs.setCurrentIndex(6)
        self.statusBar().showMessage(f"Loaded {name} · static analysis · {len(binary.warnings)} coverage note(s) in Details")
        if self.store.error:
            self.note_status.setText(self.store.error)

    def function_name(self, fn):
        alias = self.store.get(fn.address)["alias"] if self.store else ""
        return ("▤ " if fn.is_region else "ƒ ") + (alias or fn.name)

    def filter_functions(self, *_):
        if not self.binary:
            return
        query = self.function_filter.text().lower().strip()
        rows = self.binary.functions + self.binary.regions
        filtered = [f for f in rows if query in f.name.lower() or query in hx(f.address) or
                    (self.store and query in self.store.get(f.address)["alias"].lower())]
        self.functions_model.replace(filtered)
        self.function_count.setText(f"{len(filtered):,} entries · ƒ symbol function · ▤ section region")

    def filter_strings(self, *_):
        if self.binary:
            query = self.string_filter.text().lower()
            self.strings_model.replace([s for s in self.binary.strings if query in s.text.lower()])

    def filter_imports(self, *_):
        if self.binary:
            query = self.import_filter.text().lower()
            self.imports_model.replace([i for i in self.binary.imports if query in i["name"].lower()])

    def _function_selected(self, index, previous):
        if index.isValid():
            self.show_function(index.data(Qt.ItemDataRole.UserRole))

    def show_function(self, fn, page=0):
        if not self.save_notes():
            return
        self.current_fn, self.page = fn, page
        self.instructions = disassemble(self.binary, fn, page)
        self.assembly_model.replace(self.instructions)
        self.graph.draw(self.instructions)
        total_pages = max(1, math.ceil(fn.size / PAGE_BYTES))
        self.page_label.setText(f"Page {page + 1} / {total_pages}  ·  {len(self.instructions)} instructions")
        self.previous_button.setEnabled(page > 0)
        self.next_button.setEnabled(page + 1 < total_pages)
        self.location.setText(f"{hx(fn.address)}  /  {fn.section}")
        self.function_title.setText(fn.name)
        self.function_title.setToolTip(fn.name)
        self.function_details.setText(f"{hx(fn.address)}\n{fn.size:,} bytes · {fn.source}" +
                                     ("\nEstimated extent" if fn.estimated_size else ""))
        self._editing = True
        stored = self.store.get(fn.address)
        self.alias_input.setText(stored["alias"])
        self.note_editor.setPlainText(stored["note"])
        self._editing = False
        self._dirty = False
        self.note_status.setText(self.store.error or ("Saved locally" if stored["note"] or stored["alias"] else "Notes save automatically"))
        refs = []
        for call in self.binary.calls:
            if call.target == fn.address:
                refs.append({"label": "← " + call.caller, "address": call.address})
            if fn.address <= call.address < fn.address + fn.size:
                target_fn = self.binary.function_at(call.target)
                refs.append({"label": "→ " + (target_fn.name if target_fn and target_fn.address == call.target else "target"),
                             "address": call.target})
        self.xrefs_model.replace(refs)
        start = fn.address + page * PAGE_BYTES
        self.set_hex(self.binary.bytes_at(start, min(PAGE_BYTES, max(0, fn.size - page * PAGE_BYTES))), start, "Virtual address")
        self.update_pseudocode(fn.address)

    def change_page(self, delta):
        if self.current_fn:
            self.show_function(self.current_fn, self.page + delta)

    def jump_from_input(self):
        try:
            self.jump_to(int(self.jump_input.text().strip(), 16))
        except ValueError:
            self.statusBar().showMessage("Enter a hexadecimal virtual address, for example 0x1040.")

    def jump_to(self, address):
        if not self.binary or not self.save_notes():
            return
        fn = self.binary.function_at(address)
        if not fn:
            fn = next((r for r in self.binary.regions if r.address <= address < r.address + r.size), None)
        if not fn:
            section = self.binary.section_at(address)
            if section:
                self.set_hex(self.binary.bytes_at(address, 1024), address, "Virtual address")
                self.tabs.setCurrentIndex(2)
            else:
                self.statusBar().showMessage(f"{hx(address)} does not map to stored bytes in this ELF.")
            return
        self.show_function(fn, (address - fn.address) // PAGE_BYTES)
        self.update_pseudocode(address if fn.is_region else fn.address)
        self.tabs.setCurrentIndex(0)
        for row, instruction in enumerate(self.instructions):
            if instruction.address <= address < instruction.address + instruction.size:
                index = self.assembly_model.index(row, 0)
                self.assembly_view.setCurrentIndex(index)
                self.assembly_view.scrollTo(index, QAbstractItemView.ScrollHint.PositionAtCenter)
                break

    def follow_instruction(self, index):
        instruction = index.data(Qt.ItemDataRole.UserRole)
        if instruction.target is not None:
            self.jump_to(instruction.target)
        else:
            self.statusBar().showMessage("This instruction has no direct branch or call target.")

    def follow_xref(self, index):
        self.jump_to(index.data(Qt.ItemDataRole.UserRole)["address"])

    def set_hex(self, data, start, kind):
        lines = [f"{kind} · {len(data):,} bytes shown", ""]
        for offset in range(0, len(data), 16):
            chunk = data[offset:offset + 16]
            ascii_text = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{start + offset:08x}  {chunk.hex(' '):47}  {ascii_text}")
        self.hex_view.setPlainText("\n".join(lines))

    def show_string(self, index):
        string = index.data(Qt.ItemDataRole.UserRole)
        offset = string.offset
        self.set_hex(self.binary.data[offset:offset + 256], offset, "File offset")
        self.tabs.setCurrentIndex(2)

    def show_section(self, index):
        section = index.data(Qt.ItemDataRole.UserRole)
        if "X" in section.flags and section.file_size:
            self.jump_to(section.address)
        else:
            self.set_hex(self.binary.data[section.offset:section.offset + min(section.file_size, PAGE_BYTES)],
                         section.offset, "File offset")
            self.tabs.setCurrentIndex(2)

    def notes_changed(self, *_):
        if self._editing or not self.current_fn:
            return
        self._dirty = True
        self.note_status.setText("Saving…")
        self.notes_timer.start(400)

    def save_notes(self):
        self.notes_timer.stop()
        if not self._dirty or not self.current_fn or not self.store:
            return True
        try:
            text = self.note_editor.toPlainText()
            if len(text) > 20000:
                self.note_status.setText("Notes are limited to 20,000 characters. Shorten this note to save it.")
                return False
            self.store.set(self.current_fn.address, self.alias_input.text(), text)
            self._dirty = False
            self.note_status.setText("Saved locally")
            if self.functions_model.rows:
                self.functions_model.dataChanged.emit(self.functions_model.index(0, 0),
                    self.functions_model.index(len(self.functions_model.rows) - 1, 0))
            return True
        except OSError as exc:
            self.note_status.setText(f"Not saved: {exc}")
            return False

    def copy_context(self):
        if self.binary and self.current_fn:
            QApplication.clipboard().setText(ai_context(self.binary, self.current_fn, self.instructions))
            self.statusBar().showMessage("Function evidence copied to clipboard. Nothing was sent to a model.")

    def export_report(self):
        if not self.binary or not self.save_notes():
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export analysis", Path(self.binary.path).stem + "-analysis.json", "JSON (*.json)")
        if path:
            try:
                target = Path(path)
                if target.resolve() == Path(self.binary.path).resolve() or (target.exists() and os.path.samefile(target, self.binary.path)):
                    raise OSError("Choose a different filename; the input binary cannot be overwritten.")
                report = self.binary.report()
                report["annotations"] = self.store.items
                target.write_text(json.dumps(report, indent=2), encoding="utf-8")
                self.statusBar().showMessage(f"Analysis exported to {target.name}")
            except OSError as exc:
                QMessageBox.warning(self, "Export failed", str(exc))

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls() and len(event.mimeData().urls()) == 1 and event.mimeData().urls()[0].isLocalFile():
            event.acceptProposedAction()

    def dropEvent(self, event):
        self.load_binary(event.mimeData().urls()[0].toLocalFile())

    def closeEvent(self, event):
        if not self.save_notes():
            choice = QMessageBox.question(self, "Notes are not saved", self.note_status.text() + "\n\nClose without saving these changes?",
                QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel)
            if choice != QMessageBox.StandardButton.Discard:
                event.ignore()
                return
        if self.deep_worker:
            self._close_pending = True
            self.cancel_deep_analysis()
            self.statusBar().showMessage("Cancelling deep analysis before closing…")
            event.ignore()
            return
        if self.worker and self.worker.isRunning():
            self.worker.requestInterruption()
            if not self.worker.wait(2000):
                self.statusBar().showMessage("Finishing analysis cancellation; close again in a moment.")
                event.ignore()
                return
        event.accept()


def main():
    parser = argparse.ArgumentParser(description="Local ARM64 ELF analysis workbench")
    parser.add_argument("file", nargs="?", help="ARM64 ELF shared library; defaults to the included demo")
    parser.add_argument("--json", action="store_true", help="Print analysis JSON without opening a window")
    args = parser.parse_args()
    if args.json:
        try:
            print(json.dumps(analyse(args.file or SAMPLE).report(), indent=2))
        except Exception as exc:
            parser.exit(1, f"Error: {exc}\n")
        return
    app = QApplication(sys.argv[:1])
    app.setApplicationName("HexTrail")
    app.setApplicationVersion(__version__)
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    data_dir = os.getenv("HEXTRAIL_DATA_DIR") or os.getenv("NATIVESCOPE_DATA_DIR")
    root = Path(data_dir) if data_dir else None
    window = MainWindow(root)
    window.show()
    QTimer.singleShot(0, lambda: window.load_binary(args.file or SAMPLE))
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
