"""Professional PyQt6 security dashboard for WebGuardian."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from PyQt6.QtCore import QObject, Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QPainter, QPen
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QAbstractScrollArea,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QStackedWidget,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from webguardian.quarantine import QuarantineManager
from webguardian.scanner import Scanner
from webguardian.scanner.version import SignatureVersion
from webguardian.storage import HistoryStore, SettingsStore


APP_VERSION = "1.1.0"
GREEN = "#19b394"
GREEN_DARK = "#10977d"
RED = "#ed5a5a"
SEVERITY_COLORS = {
    "critical": "#ed5a5a",
    "high": "#f28b45",
    "medium": "#f2b84b",
    "low": "#5d9cec",
    "info": "#8b98a8",
}
MODE_LABELS = {"Quét nhanh": "quick", "Quét thông minh": "smart", "Quét toàn bộ": "full"}


def font(size: int = 10, bold: bool = False, mono: bool = False) -> QFont:
    family = "Cascadia Mono" if mono else "Segoe UI"
    return QFont(family, size, QFont.Weight.DemiBold if bold else QFont.Weight.Normal)


def section_title(title: str, subtitle: str) -> QVBoxLayout:
    block = QVBoxLayout()
    block.setSpacing(3)
    heading = QLabel(title)
    heading.setObjectName("pageTitle")
    heading.setFont(font(22, True))
    description = QLabel(subtitle)
    description.setObjectName("muted")
    description.setFont(font(10))
    description.setWordWrap(True)
    description.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
    block.addWidget(heading)
    block.addWidget(description)
    return block


def card() -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setObjectName("card")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(20, 18, 20, 18)
    layout.setSpacing(10)
    return frame, layout


def configure_table(table: QTableWidget) -> None:
    table.setSizeAdjustPolicy(QAbstractScrollArea.SizeAdjustPolicy.AdjustIgnored)
    table.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Expanding)
    table.setMinimumWidth(0)
    table.setWordWrap(False)
    table.setTextElideMode(Qt.TextElideMode.ElideMiddle)
    table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
    table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
    table.setAlternatingRowColors(True)
    table.setShowGrid(False)


def show_empty_state(table: QTableWidget, columns: int, message: str) -> None:
    table.clearSpans()
    table.setRowCount(1)
    table.setSpan(0, 0, 1, columns)
    item = QTableWidgetItem(message)
    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
    item.setForeground(QColor("#8fa0b3"))
    item.setFlags(Qt.ItemFlag.ItemIsEnabled)
    table.setItem(0, 0, item)
    table.setRowHeight(0, 56)


class ElidedLabel(QLabel):
    """Single-line label that never forces its parent wider than the viewport."""

    def __init__(self, text: str = "", parent=None):
        super().__init__(parent)
        self._full_text = ""
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.setText(text)

    def setText(self, text: str) -> None:
        self._full_text = str(text or "")
        self.setToolTip(self._full_text)
        self._update_elision()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._update_elision()

    def _update_elision(self):
        available = max(20, self.width() - 4)
        super().setText(self.fontMetrics().elidedText(self._full_text, Qt.TextElideMode.ElideMiddle, available))


class RingProgress(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.value = 0
        self.color = GREEN
        self.setFixedSize(124, 124)

    def set_value(self, value: int, color: str | None = None) -> None:
        self.value = max(0, min(100, int(value)))
        if color:
            self.color = color
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect().adjusted(10, 10, -10, -10)
        painter.setPen(QPen(QColor("#293544"), 9, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(rect, 0, 360 * 16)
        painter.setPen(QPen(QColor(self.color), 9, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(rect, 90 * 16, -int(360 * 16 * self.value / 100))
        painter.setPen(QColor(self.color))
        painter.setFont(font(18, True))
        painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, f"{self.value}%")


class ScanWorker(QObject):
    progress = pyqtSignal(dict)
    threat = pyqtSignal(dict)
    finished = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(self, path: str, options: dict):
        super().__init__()
        self.path = path
        self.options = options
        self.cancel_event = threading.Event()

    def cancel(self) -> None:
        self.cancel_event.set()

    def run(self) -> None:
        try:
            scanner = Scanner(
                self.path,
                progress_callback=self.progress.emit,
                threat_callback=self.threat.emit,
                cancel_event=self.cancel_event,
                **self.options,
            )
            self.finished.emit(scanner.run())
        except Exception as exc:
            self.failed.emit(str(exc))


class UpdateWorker(QObject):
    progress = pyqtSignal(dict)
    finished = pyqtSignal(dict)

    def __init__(self, updater: SignatureVersion, action: str):
        super().__init__()
        self.updater = updater
        self.action = action

    def run(self) -> None:
        if self.action == "install":
            result = self.updater.install_update(self.progress.emit)
        else:
            result = self.updater.check_for_updates(self.progress.emit)
        self.finished.emit(result)


class DashboardPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        root = QVBoxLayout(self)
        root.setContentsMargins(32, 28, 32, 28)
        root.setSpacing(18)
        root.addLayout(section_title("Tổng quan bảo vệ", "Trạng thái an toàn của mã nguồn và CSDL nhận diện"))

        hero = QFrame()
        hero.setObjectName("hero")
        hero_layout = QHBoxLayout(hero)
        hero_layout.setContentsMargins(28, 24, 28, 24)
        self.shield = QLabel("✓")
        self.shield.setObjectName("shield")
        self.shield.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.shield.setFixedSize(76, 76)
        hero_layout.addWidget(self.shield)
        hero_layout.addSpacing(16)
        text = QVBoxLayout()
        text.setSpacing(3)
        self.status_title = QLabel("Đang kiểm tra trạng thái")
        self.status_title.setFont(font(18, True))
        self.status_title.setWordWrap(True)
        self.status_title.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.status_detail = QLabel("")
        self.status_detail.setObjectName("muted")
        self.status_detail.setWordWrap(True)
        self.status_detail.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        text.addWidget(self.status_title)
        text.addWidget(self.status_detail)
        hero_layout.addLayout(text, 1)
        scan = QPushButton("Quét thông minh")
        scan.setObjectName("primary")
        scan.setFixedHeight(40)
        scan.clicked.connect(self.quick_scan)
        hero_layout.addWidget(scan)
        root.addWidget(hero)

        metrics = QHBoxLayout()
        metrics.setSpacing(12)
        self.metric_values = {}
        for key, title, icon in [
            ("database", "CSDL nhận diện", "DB"),
            ("quarantine", "Đang cách ly", "Q"),
            ("last_scan", "Lần quét gần nhất", "S"),
        ]:
            frame, layout = card()
            row = QHBoxLayout()
            badge = QLabel(icon)
            badge.setObjectName("metricIcon")
            badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            badge.setFixedSize(38, 38)
            row.addWidget(badge)
            row.addStretch()
            layout.addLayout(row)
            value = QLabel("—")
            value.setFont(font(17, True))
            label = QLabel(title)
            label.setObjectName("muted")
            layout.addWidget(value)
            layout.addWidget(label)
            self.metric_values[key] = value
            metrics.addWidget(frame, 1)
        root.addLayout(metrics)

        recent, recent_layout = card()
        header = QHBoxLayout()
        title = QLabel("Hoạt động gần đây")
        title.setFont(font(13, True))
        header.addWidget(title)
        header.addStretch()
        all_reports = QPushButton("Xem báo cáo")
        all_reports.setObjectName("ghost")
        all_reports.clicked.connect(lambda: self.main.navigate(3))
        header.addWidget(all_reports)
        recent_layout.addLayout(header)
        self.recent_table = QTableWidget(0, 4)
        configure_table(self.recent_table)
        self.recent_table.setHorizontalHeaderLabels(["Thời gian", "Thư mục", "Tệp đã quét", "Phát hiện"])
        self.recent_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.recent_table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.recent_table.verticalHeader().setVisible(False)
        self.recent_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.recent_table.setMaximumHeight(190)
        recent_layout.addWidget(self.recent_table)
        root.addWidget(recent, 1)

    def quick_scan(self):
        last_path = self.main.settings.get("last_scan_path", "")
        path = last_path if os.path.isdir(last_path) else QFileDialog.getExistingDirectory(self, "Chọn thư mục mã nguồn")
        if path:
            self.main.navigate(1)
            self.main.scan_page.start_external(path, "smart")

    def refresh(self):
        reports = self.main.history.list(5)
        quarantine_count = len(self.main.quarantine.list())
        self.metric_values["database"].setText(f"v{self.main.updater.version} · {self.main.updater.patterns} mẫu")
        self.metric_values["quarantine"].setText(str(quarantine_count))
        if reports:
            latest = reports[0]
            stamp = latest.get("completed_at", "").replace("T", " ")[:16]
            self.metric_values["last_scan"].setText(stamp or "—")
            threats = latest.get("summary", {}).get("total", 0)
            if threats:
                self.status_title.setText("Cần xử lý phát hiện bảo mật")
                self.status_detail.setText(f"Lần quét gần nhất có {threats} phát hiện. Hãy xem báo cáo và cách ly tệp đáng ngờ.")
                self.shield.setText("!")
                self.shield.setProperty("alert", True)
            else:
                self.status_title.setText("Mã nguồn đang được bảo vệ")
                self.status_detail.setText("Lần quét gần nhất không phát hiện mối đe dọa.")
                self.shield.setText("✓")
                self.shield.setProperty("alert", False)
        else:
            self.metric_values["last_scan"].setText("Chưa quét")
            self.status_title.setText("Sẵn sàng bảo vệ mã nguồn")
            self.status_detail.setText("Chạy quét thông minh để thiết lập trạng thái an toàn ban đầu.")
            self.shield.setText("✓")
            self.shield.setProperty("alert", False)
        self.shield.style().unpolish(self.shield)
        self.shield.style().polish(self.shield)

        self.recent_table.clearSpans()
        if not reports:
            show_empty_state(self.recent_table, 4, "Chưa có hoạt động · Chạy Quét thông minh để tạo báo cáo đầu tiên")
            return
        self.recent_table.setRowCount(len(reports))
        for row, report in enumerate(reports):
            values = [
                report.get("completed_at", "").replace("T", " ")[:19],
                report.get("scanned_path", ""),
                str(report.get("stats", {}).get("files_scanned", 0)),
                str(report.get("summary", {}).get("total", 0)),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                if column == 3 and int(value or 0) > 0:
                    item.setForeground(QColor(RED))
                self.recent_table.setItem(row, column, item)


class ScanPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        self.result: dict | None = None
        root = QVBoxLayout(self)
        root.setContentsMargins(32, 28, 32, 28)
        root.setSpacing(14)
        root.addLayout(section_title("Quét mã độc", "Phân tích mã nguồn, cấu hình, backdoor và hành vi nguy hiểm"))

        controls, controls_layout = card()
        top = QHBoxLayout()
        self.mode = QComboBox()
        self.mode.addItems(MODE_LABELS.keys())
        self.mode.setCurrentText("Quét thông minh")
        self.mode.setFixedWidth(160)
        top.addWidget(self.mode)
        self.path = QLineEdit()
        self.path.setPlaceholderText("Chọn thư mục dự án cần quét")
        self.path.returnPressed.connect(self.start)
        top.addWidget(self.path, 1)
        browse = QPushButton("Chọn thư mục")
        browse.clicked.connect(self.browse)
        top.addWidget(browse)
        self.start_button = QPushButton("Bắt đầu quét")
        self.start_button.setObjectName("primary")
        self.start_button.clicked.connect(self.start)
        top.addWidget(self.start_button)
        self.stop_button = QPushButton("Dừng")
        self.stop_button.setObjectName("danger")
        self.stop_button.setVisible(False)
        self.stop_button.clicked.connect(self.main.cancel_scan)
        top.addWidget(self.stop_button)
        controls_layout.addLayout(top)
        scan_options = QHBoxLayout()
        self.mode_help = QLabel("Cân bằng tốc độ và độ bao phủ; bỏ qua thư viện và tệp sinh tự động.")
        self.mode_help.setObjectName("muted")
        scan_options.addWidget(self.mode_help, 1)
        self.permission_scan = QCheckBox("Kiểm tra quyền tệp")
        self.permission_scan.setChecked(bool(main.settings.get("check_permissions", False)))
        self.permission_scan.setToolTip("Bật để phát hiện tệp nhạy cảm có quyền đọc/ghi quá rộng")
        scan_options.addWidget(self.permission_scan)
        controls_layout.addLayout(scan_options)
        self.mode.currentTextChanged.connect(self.update_mode_help)
        root.addWidget(controls)

        self.progress_card, progress_layout = card()
        self.progress_card.setVisible(False)
        body = QHBoxLayout()
        self.ring = RingProgress()
        body.addWidget(self.ring)
        body.addSpacing(16)
        details = QVBoxLayout()
        self.phase = QLabel("Đang chuẩn bị")
        self.phase.setFont(font(14, True))
        self.current_file = ElidedLabel("")
        self.current_file.setObjectName("monoMuted")
        details.addWidget(self.phase)
        details.addWidget(self.current_file)
        details.addSpacing(8)
        stats = QHBoxLayout()
        self.stats = {}
        for key, label in [("files", "Đã quét"), ("total", "Tổng tệp"), ("threats", "Phát hiện"), ("skipped", "Bỏ qua")]:
            block = QVBoxLayout()
            value = QLabel("0")
            value.setFont(font(16, True))
            caption = QLabel(label)
            caption.setObjectName("muted")
            block.addWidget(value)
            block.addWidget(caption)
            stats.addLayout(block)
            stats.addSpacing(28)
            self.stats[key] = value
        stats.addStretch()
        details.addLayout(stats)
        body.addLayout(details, 1)
        progress_layout.addLayout(body)
        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setTextVisible(False)
        progress_layout.addWidget(self.bar)
        root.addWidget(self.progress_card)

        results, results_layout = card()
        result_header = QHBoxLayout()
        self.result_title = QLabel("Kết quả quét")
        self.result_title.setFont(font(13, True))
        result_header.addWidget(self.result_title)
        result_header.addStretch()
        self.quarantine_button = QPushButton("Cách ly tệp đã chọn")
        self.quarantine_button.setEnabled(False)
        self.quarantine_button.clicked.connect(self.quarantine_selected)
        result_header.addWidget(self.quarantine_button)
        self.export_button = QPushButton("Xuất JSON")
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self.export_report)
        result_header.addWidget(self.export_button)
        results_layout.addLayout(result_header)
        self.result_tabs = QTabWidget()
        self.result_tabs.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Expanding)
        self.result_tabs.setMinimumWidth(0)
        finding_tab = QWidget()
        finding_layout = QVBoxLayout(finding_tab)
        finding_layout.setContentsMargins(0, 8, 0, 0)
        finding_layout.setSpacing(10)
        self.findings = QTableWidget(0, 5)
        configure_table(self.findings)
        self.findings.setHorizontalHeaderLabels(["Mức độ", "Tệp", "Dòng", "Vấn đề", "Xử lý"])
        self.findings.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.findings.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.findings.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.findings.verticalHeader().setVisible(False)
        self.findings.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.findings.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.findings.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.findings.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.findings.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.findings.itemSelectionChanged.connect(self.show_finding_details)
        finding_layout.addWidget(self.findings, 1)
        detail_box = QFrame()
        detail_box.setObjectName("softBox")
        detail_layout = QVBoxLayout(detail_box)
        detail_layout.setContentsMargins(14, 10, 14, 10)
        detail_title = QLabel("Chi tiết phát hiện")
        detail_title.setFont(font(11, True))
        self.finding_detail = QPlainTextEdit("Chọn một phát hiện để xem rule, SHA-256 và khuyến nghị xử lý.")
        self.finding_detail.setObjectName("findingDetail")
        self.finding_detail.setReadOnly(True)
        self.finding_detail.setMinimumHeight(82)
        self.finding_detail.setMaximumHeight(126)
        detail_layout.addWidget(detail_title)
        detail_layout.addWidget(self.finding_detail)
        finding_layout.addWidget(detail_box)

        file_tab = QWidget()
        file_layout = QVBoxLayout(file_tab)
        file_layout.setContentsMargins(0, 8, 0, 0)
        self.scanned_files = QTableWidget(0, 6)
        configure_table(self.scanned_files)
        self.scanned_files.setHorizontalHeaderLabels(["Trạng thái", "Tệp đã quét", "Loại", "Kích thước", "Phát hiện", "SHA-256"])
        self.scanned_files.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.scanned_files.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.scanned_files.verticalHeader().setVisible(False)
        self.scanned_files.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.scanned_files.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.scanned_files.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.scanned_files.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.scanned_files.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.scanned_files.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        file_layout.addWidget(self.scanned_files)
        self.result_tabs.addTab(finding_tab, "Phát hiện (0)")
        self.result_tabs.addTab(file_tab, "Tệp đã quét (0)")
        results_layout.addWidget(self.result_tabs)
        root.addWidget(results, 1)

    def update_mode_help(self, text):
        descriptions = {
            "Quét nhanh": "Ưu tiên tệp có rủi ro cao để cho kết quả sớm.",
            "Quét thông minh": "Cân bằng tốc độ và độ bao phủ; bỏ qua thư viện và tệp sinh tự động.",
            "Quét toàn bộ": "Kiểm tra mọi tệp đủ kích thước, bao gồm cả thư mục dependency.",
        }
        self.mode_help.setText(descriptions[text])

    def browse(self):
        path = QFileDialog.getExistingDirectory(self, "Chọn thư mục mã nguồn", self.path.text())
        if path:
            self.path.setText(path)

    def start(self):
        path = self.path.text().strip()
        if not os.path.isdir(path):
            QMessageBox.warning(self, "Đường dẫn không hợp lệ", "Hãy chọn một thư mục mã nguồn tồn tại.")
            return
        self.start_external(path, MODE_LABELS[self.mode.currentText()])

    def start_external(self, path: str, mode: str):
        self.path.setText(path)
        for label, value in MODE_LABELS.items():
            if value == mode:
                self.mode.setCurrentText(label)
                break
        self.main.start_scan(path, mode)

    def begin(self):
        self.result = None
        self.findings.clearSpans()
        self.scanned_files.clearSpans()
        self.findings.setRowCount(0)
        self.scanned_files.setRowCount(0)
        self.result_tabs.setTabText(0, "Phát hiện (0)")
        self.result_tabs.setTabText(1, "Tệp đã quét (0)")
        self.finding_detail.setPlainText("Chọn một phát hiện để xem rule, SHA-256 và khuyến nghị xử lý.")
        self.progress_card.setVisible(True)
        self.start_button.setVisible(False)
        self.stop_button.setVisible(True)
        self.export_button.setEnabled(False)
        self.quarantine_button.setEnabled(False)
        self.ring.set_value(0)
        self.bar.setValue(0)
        self.phase.setText("Đang chuẩn bị bộ máy quét")
        self.current_file.setText("")
        for value in self.stats.values():
            value.setText("0")

    def on_progress(self, data: dict):
        pct = data.get("percent", 0)
        self.ring.set_value(pct)
        self.bar.setValue(pct)
        self.phase.setText(data.get("phase", "Đang quét"))
        self.current_file.setText(data.get("current_file", ""))
        self.stats["files"].setText(str(data.get("files_scanned", 0)))
        self.stats["total"].setText(str(data.get("files_total", 0)))
        self.stats["threats"].setText(str(data.get("findings_count", 0)))
        self.stats["skipped"].setText(str(data.get("files_skipped", 0)))

    def on_threat(self, finding: dict):
        self.add_finding(finding)

    def add_finding(self, finding: dict):
        row = self.findings.rowCount()
        self.findings.insertRow(row)
        severity = finding.get("severity", "info")
        severity_item = QTableWidgetItem(severity.upper())
        severity_item.setForeground(QColor(SEVERITY_COLORS.get(severity, "#8b98a8")))
        severity_item.setData(Qt.ItemDataRole.UserRole, finding)
        file_path = finding.get("file", "")
        file_item = QTableWidgetItem(file_path)
        file_item.setToolTip(file_path)
        category = finding.get("category", "security")
        self.findings.setItem(row, 0, severity_item)
        self.findings.setItem(row, 1, file_item)
        self.findings.setItem(row, 2, QTableWidgetItem(str(finding.get("line") or "—")))
        issue = f"{category} · {finding.get('message', '')}"
        issue_item = QTableWidgetItem(issue)
        issue_item.setToolTip(issue)
        self.findings.setItem(row, 3, issue_item)
        action = {"none": "Chưa xử lý", "quarantined": "Đã cách ly"}.get(
            finding.get("action", "none"), finding.get("action", "Chưa xử lý")
        )
        self.findings.setItem(row, 4, QTableWidgetItem(action))
        self.result_tabs.setTabText(0, f"Phát hiện ({self.findings.rowCount()})")

    def on_complete(self, result: dict):
        self.result = result
        if self.findings.rowCount() == 0:
            for finding in result.get("findings", []):
                self.add_finding(finding)
        self.start_button.setVisible(True)
        self.stop_button.setVisible(False)
        self.export_button.setEnabled(True)
        self.ring.set_value(100, RED if result["summary"]["total"] else GREEN)
        self.bar.setValue(100)
        status = "Đã hủy quét" if result.get("status") == "cancelled" else "Quét hoàn tất"
        total = result.get("summary", {}).get("total", 0)
        self.phase.setText(f"{status} · {total} phát hiện")
        files = result.get("scanned_files", [])
        self.result_title.setText(f"Kết quả quét · {len(files)} tệp · {total} phát hiện")
        self.result_tabs.setTabText(0, f"Phát hiện ({total})")
        self.result_tabs.setTabText(1, f"Tệp đã quét ({len(files)})")
        self.scanned_files.setRowCount(len(files))
        status_labels = {"clean": "Sạch", "threat": "Có vấn đề", "binary": "Tệp nhị phân"}
        for row, record in enumerate(files):
            status_key = record.get("status", "clean")
            status_item = QTableWidgetItem(status_labels.get(status_key, status_key))
            status_item.setForeground(QColor(RED if status_key == "threat" else GREEN))
            path_item = QTableWidgetItem(record.get("file", ""))
            path_item.setToolTip(record.get("file", ""))
            size = record.get("size", 0)
            size_text = f"{size / 1024:.1f} KB" if size < 1024 * 1024 else f"{size / (1024 * 1024):.1f} MB"
            values = [
                status_item,
                path_item,
                QTableWidgetItem(record.get("extension", "")),
                QTableWidgetItem(size_text),
                QTableWidgetItem(str(record.get("detections", 0))),
                QTableWidgetItem(record.get("sha256", "")),
            ]
            for column, item in enumerate(values):
                item.setToolTip(item.text())
                self.scanned_files.setItem(row, column, item)
        if total == 0:
            show_empty_state(self.findings, 5, "Không có phát hiện · Xem tab Tệp đã quét để kiểm tra inventory")
            self.finding_detail.setPlainText("Không phát hiện mã độc hoặc cấu hình nguy hiểm. Xem tab “Tệp đã quét” để kiểm tra danh sách tệp cụ thể.")
        elif self.findings.rowCount():
            self.findings.setCurrentCell(0, 0)
        if not files:
            show_empty_state(self.scanned_files, 6, "Không có tệp phù hợp phạm vi quét · Kiểm tra exclusion và chế độ quét")

    def on_error(self, message: str):
        self.start_button.setVisible(True)
        self.stop_button.setVisible(False)
        self.phase.setText("Không thể hoàn tất quét")
        QMessageBox.critical(self, "Lỗi quét", message)

    def show_report(self, result: dict):
        self.path.setText(result.get("scanned_path", ""))
        self.progress_card.setVisible(False)
        self.findings.clearSpans()
        self.scanned_files.clearSpans()
        self.findings.setRowCount(0)
        self.scanned_files.setRowCount(0)
        self.finding_detail.setPlainText("Chọn một phát hiện để xem rule, SHA-256 và khuyến nghị xử lý.")
        self.on_complete(result)

    def selected_finding(self) -> tuple[int, dict] | tuple[None, None]:
        row = self.findings.currentRow()
        if row < 0:
            return None, None
        return row, self.findings.item(row, 0).data(Qt.ItemDataRole.UserRole)

    def show_finding_details(self):
        row, finding = self.selected_finding()
        self.quarantine_button.setEnabled(bool(finding and os.path.isfile(finding.get("file", ""))))
        if not finding:
            return
        recommendations = {
            "critical": "Cách ly tệp ngay, đối chiếu commit tạo tệp và thay toàn bộ secret liên quan.",
            "high": "Kiểm tra luồng dữ liệu vào hàm nguy hiểm; cách ly nếu không phải hành vi có chủ đích.",
            "medium": "Rà soát cấu hình và giới hạn khả năng truy cập trước khi triển khai production.",
            "low": "Đánh giá trong đợt hardening tiếp theo.",
            "info": "Thông tin tham khảo; chưa cần hành động khẩn cấp.",
        }
        self.finding_detail.setPlainText(
            f"Loại: {finding.get('category', 'security')}\n"
            f"Rule: {finding.get('rule_id') or 'built-in'}\n"
            f"Tệp: {finding.get('file') or 'Không gắn với tệp'}\n"
            f"Dòng: {finding.get('line') or 'Không xác định'}\n"
            f"SHA-256: {finding.get('sha256') or 'Không có'}\n"
            f"Vấn đề: {finding.get('message', '')}\n"
            f"Khuyến nghị: {recommendations.get(finding.get('severity', 'info'), recommendations['info'])}"
        )

    def quarantine_selected(self):
        row, finding = self.selected_finding()
        if not finding:
            return
        path = finding.get("file", "")
        if not os.path.isfile(path):
            QMessageBox.warning(self, "Không thể cách ly", "Tệp không còn tồn tại hoặc phát hiện này không gắn với tệp.")
            return
        answer = QMessageBox.question(self, "Xác nhận cách ly", f"Di chuyển tệp ra khỏi dự án?\n\n{path}")
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            self.main.quarantine.quarantine(path, finding)
            finding["action"] = "quarantined"
            if self.result:
                for stored in self.result.get("findings", []):
                    if stored.get("id") == finding.get("id"):
                        stored["action"] = "quarantined"
                        break
                self.main.history.save(self.result)
            self.findings.item(row, 4).setText("Đã cách ly")
            self.quarantine_button.setEnabled(False)
            self.main.refresh_pages()
        except Exception as exc:
            QMessageBox.critical(self, "Không thể cách ly", str(exc))

    def export_report(self):
        if not self.result:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Xuất báo cáo", "webguardian-report.json", "JSON (*.json)")
        if path:
            Path(path).write_text(json.dumps(self.result, ensure_ascii=False, indent=2), encoding="utf-8")


class QuarantinePage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        root = QVBoxLayout(self)
        root.setContentsMargins(32, 28, 32, 28)
        root.setSpacing(16)
        root.addLayout(section_title("Khu vực cách ly", "Tệp bị vô hiệu hóa, kiểm tra integrity trước khi khôi phục"))
        frame, layout = card()
        header = QHBoxLayout()
        self.count = QLabel("0 mục")
        self.count.setFont(font(13, True))
        header.addWidget(self.count)
        header.addStretch()
        restore = QPushButton("Khôi phục")
        restore.clicked.connect(self.restore)
        delete = QPushButton("Xóa vĩnh viễn")
        delete.setObjectName("danger")
        delete.clicked.connect(self.delete)
        header.addWidget(restore)
        header.addWidget(delete)
        layout.addLayout(header)
        self.table = QTableWidget(0, 5)
        configure_table(self.table)
        self.table.setHorizontalHeaderLabels(["Thời gian", "Phát hiện", "Đường dẫn gốc", "Kích thước", "SHA-256"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)
        root.addWidget(frame, 1)

    def refresh(self):
        rows = self.main.quarantine.list()
        self.count.setText(f"{len(rows)} mục")
        self.table.clearSpans()
        if not rows:
            show_empty_state(self.table, 5, "Khu vực cách ly đang trống · Chọn một finding trong kết quả quét để cách ly")
            return
        self.table.setRowCount(len(rows))
        for row, item in enumerate(rows):
            values = [item.get("quarantined_at", "").replace("T", " ")[:19], item.get("detection", ""),
                      item.get("original_path", ""), f"{item.get('size', 0) / 1024:.1f} KB", item.get("sha256", "")]
            for column, value in enumerate(values):
                cell = QTableWidgetItem(value)
                cell.setToolTip(value)
                if column == 0:
                    cell.setData(Qt.ItemDataRole.UserRole, item.get("id"))
                self.table.setItem(row, column, cell)

    def selected_id(self):
        row = self.table.currentRow()
        return self.table.item(row, 0).data(Qt.ItemDataRole.UserRole) if row >= 0 else None

    def restore(self):
        item_id = self.selected_id()
        if not item_id:
            return
        try:
            path = self.main.quarantine.restore(item_id)
            QMessageBox.information(self, "Đã khôi phục", f"Tệp đã được khôi phục về:\n{path}")
            self.refresh()
        except FileExistsError as exc:
            if QMessageBox.question(self, "Tệp đã tồn tại", f"{exc}\n\nGhi đè tệp hiện tại?") == QMessageBox.StandardButton.Yes:
                self.main.quarantine.restore(item_id, overwrite=True)
                self.refresh()
        except Exception as exc:
            QMessageBox.critical(self, "Không thể khôi phục", str(exc))

    def delete(self):
        item_id = self.selected_id()
        if not item_id:
            return
        if QMessageBox.warning(self, "Xóa vĩnh viễn", "Thao tác này không thể hoàn tác. Tiếp tục?",
                               QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            self.main.quarantine.delete(item_id)
            self.refresh()


class ReportsPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        root = QVBoxLayout(self)
        root.setContentsMargins(32, 28, 32, 28)
        root.setSpacing(16)
        root.addLayout(section_title("Báo cáo quét", "Lịch sử kiểm tra và kết quả phát hiện theo thời gian"))
        frame, layout = card()
        header = QHBoxLayout()
        title = QLabel("Lịch sử")
        title.setFont(font(13, True))
        header.addWidget(title)
        header.addStretch()
        view = QPushButton("Xem chi tiết")
        view.clicked.connect(self.view)
        remove = QPushButton("Xóa báo cáo")
        remove.clicked.connect(self.delete)
        header.addWidget(view)
        header.addWidget(remove)
        layout.addLayout(header)
        self.table = QTableWidget(0, 6)
        configure_table(self.table)
        self.table.setHorizontalHeaderLabels(["Thời gian", "Chế độ", "Đường dẫn", "Đã quét", "Phát hiện", "Trạng thái"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)
        root.addWidget(frame, 1)

    def refresh(self):
        reports = self.main.history.list()
        self.table.clearSpans()
        if not reports:
            show_empty_state(self.table, 6, "Chưa có báo cáo · Bắt đầu một lượt quét để tạo lịch sử")
            return
        self.table.setRowCount(len(reports))
        for row, report in enumerate(reports):
            values = [report.get("completed_at", "").replace("T", " ")[:19], report.get("scan_mode", "smart"),
                      report.get("scanned_path", ""), str(report.get("stats", {}).get("files_scanned", 0)),
                      str(report.get("summary", {}).get("total", 0)), report.get("status", "complete")]
            for column, value in enumerate(values):
                cell = QTableWidgetItem(value)
                cell.setToolTip(value)
                if column == 0:
                    cell.setData(Qt.ItemDataRole.UserRole, report.get("scan_id"))
                if column == 4 and int(value or 0):
                    cell.setForeground(QColor(RED))
                self.table.setItem(row, column, cell)

    def selected_id(self):
        row = self.table.currentRow()
        return self.table.item(row, 0).data(Qt.ItemDataRole.UserRole) if row >= 0 else None

    def view(self):
        report = self.main.history.get(self.selected_id() or "")
        if not report:
            return
        self.main.navigate(1)
        self.main.scan_page.show_report(report)

    def delete(self):
        report_id = self.selected_id()
        if report_id and QMessageBox.question(self, "Xóa báo cáo", "Xóa báo cáo đã chọn?") == QMessageBox.StandardButton.Yes:
            self.main.history.delete(report_id)
            self.refresh()


class UpdatesPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        root = QVBoxLayout(self)
        root.setContentsMargins(32, 28, 32, 28)
        root.setSpacing(16)
        root.addLayout(section_title("Cập nhật nhận diện", "Cập nhật được xác minh SHA-256 và cài đặt atomically"))
        frame, layout = card()
        head = QHBoxLayout()
        self.icon = QLabel("✓")
        self.icon.setObjectName("updateIcon")
        self.icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon.setFixedSize(52, 52)
        head.addWidget(self.icon)
        texts = QVBoxLayout()
        self.title = QLabel("CSDL nhận diện sẵn sàng")
        self.title.setFont(font(16, True))
        self.detail = QLabel("")
        self.detail.setObjectName("muted")
        self.detail.setWordWrap(True)
        self.detail.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        texts.addWidget(self.title)
        texts.addWidget(self.detail)
        head.addLayout(texts, 1)
        self.check_button = QPushButton("Kiểm tra cập nhật")
        self.check_button.clicked.connect(lambda: self.run_action("check"))
        self.install_button = QPushButton("Tải và cài đặt")
        self.install_button.setObjectName("primary")
        self.install_button.setVisible(False)
        self.install_button.clicked.connect(lambda: self.run_action("install"))
        self.rollback_button = QPushButton("Khôi phục bản trước")
        self.rollback_button.setVisible(False)
        self.rollback_button.clicked.connect(self.rollback)
        head.addWidget(self.check_button)
        head.addWidget(self.install_button)
        head.addWidget(self.rollback_button)
        layout.addLayout(head)
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        info = QGridLayout()
        self.info = {}
        fields = [("version", "Phiên bản"), ("build", "Build"), ("patterns", "Quy tắc động"),
                  ("categories", "Nhóm nhận diện"), ("last_checked", "Kiểm tra gần nhất"), ("source", "Nguồn đang dùng")]
        for index, (key, label) in enumerate(fields):
            box = QFrame()
            box.setObjectName("softBox")
            box_layout = QVBoxLayout(box)
            box_layout.setContentsMargins(14, 10, 14, 10)
            caption = QLabel(label)
            caption.setObjectName("muted")
            value = QLabel("—")
            value.setFont(font(12, True, mono=key in {"version", "build"}))
            box_layout.addWidget(caption)
            box_layout.addWidget(value)
            info.addWidget(box, index // 3, index % 3)
            self.info[key] = value
        layout.addLayout(info)
        root.addWidget(frame)

        note, note_layout = card()
        note_title = QLabel("Chuỗi tin cậy cập nhật")
        note_title.setFont(font(13, True))
        note_layout.addWidget(note_title)
        note_text = QLabel("Manifest HTTPS → xác minh SHA-256 → kiểm tra schema và regex → ghi tệp tạm → thay thế atomically → giữ một bản rollback.")
        note_text.setObjectName("muted")
        note_text.setWordWrap(True)
        note_layout.addWidget(note_text)
        root.addWidget(note)
        root.addStretch()

    def refresh(self):
        data = self.main.updater.to_dict()
        self.detail.setText(f"Phiên bản {data['version']} · build {data['build']} · phát hành {data['date'] or 'bundled'}")
        self.rollback_button.setVisible(self.main.updater.backup_file.is_file())
        for key, label in self.info.items():
            label.setText(str(data.get(key) or "Chưa có"))

    def rollback(self):
        if QMessageBox.question(self, "Khôi phục CSDL", "Khôi phục phiên bản nhận diện trước đó?") != QMessageBox.StandardButton.Yes:
            return
        self.on_result(self.main.updater.rollback())

    def run_action(self, action: str):
        self.check_button.setEnabled(False)
        self.install_button.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setValue(5)
        self.title.setText("Đang xử lý cập nhật")
        self.main.start_update(action, self)

    def on_progress(self, data):
        self.progress.setValue(data.get("pct", 0))
        self.detail.setText(data.get("phase", ""))

    def on_result(self, result):
        self.check_button.setEnabled(True)
        self.install_button.setEnabled(True)
        self.main.updater._refresh_metadata()
        self.refresh()
        status = result.get("status")
        if status == "update_available":
            self.icon.setText("↻")
            self.title.setText("Có CSDL nhận diện mới")
            self.detail.setText(f"Phiên bản {result.get('remote_version')} · build {result.get('remote_build')}")
            self.install_button.setVisible(True)
        elif status in {"up_to_date", "installed", "rolled_back"}:
            self.icon.setText("✓")
            titles = {
                "up_to_date": "CSDL nhận diện đã mới nhất",
                "installed": "Cập nhật hoàn tất",
                "rolled_back": "Đã khôi phục CSDL trước",
            }
            self.title.setText(titles[status])
            self.detail.setText(result.get("message", ""))
            self.install_button.setVisible(False)
        else:
            self.icon.setText("!")
            self.title.setText("Không thể cập nhật")
            self.detail.setText(result.get("message", "Lỗi không xác định"))
        self.progress.setVisible(False)


class SettingsPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        content = QWidget()
        scroll.setWidget(content)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        root = QVBoxLayout(content)
        root.setContentsMargins(32, 28, 32, 28)
        root.setSpacing(16)
        root.addLayout(section_title("Cài đặt", "Điều chỉnh phạm vi quét, cập nhật và giao diện"))

        general, general_layout = card()
        heading = QLabel("Tùy chọn quét")
        heading.setFont(font(13, True))
        general_layout.addWidget(heading)
        options = QGridLayout()
        options.setHorizontalSpacing(14)
        options.setVerticalSpacing(12)
        self.permissions = QCheckBox("Kiểm tra quyền tệp không an toàn")
        self.permissions.setChecked(bool(main.settings.get("check_permissions", False)))
        options.addWidget(self.permissions, 0, 0, 1, 4)
        options.addWidget(QLabel("Kích thước tệp tối đa"), 1, 0)
        self.max_size = QSpinBox()
        self.max_size.setRange(1, 250)
        self.max_size.setSuffix(" MB")
        self.max_size.setValue(int(main.settings.get("max_file_size_mb", 10)))
        self.max_size.setFixedWidth(110)
        options.addWidget(self.max_size, 1, 1)
        options.addWidget(QLabel("Giao diện"), 1, 2)
        self.theme = QComboBox()
        self.theme.addItems(["Tối", "Sáng"])
        self.theme.setCurrentText("Tối" if main.settings.get("theme", "dark") == "dark" else "Sáng")
        self.theme.setFixedWidth(120)
        options.addWidget(self.theme, 1, 3)
        options.setColumnStretch(4, 1)
        general_layout.addLayout(options)
        root.addWidget(general)

        exclusions, exclusions_layout = card()
        ex_head = QHBoxLayout()
        ex_title = QLabel("Loại trừ")
        ex_title.setFont(font(13, True))
        ex_head.addWidget(ex_title)
        ex_head.addStretch()
        exclusions_layout.addLayout(ex_head)
        ex_controls = QHBoxLayout()
        ex_controls.setSpacing(8)
        self.exclusion_input = QLineEdit()
        self.exclusion_input.setPlaceholderText("Ví dụ: storage/cache/**")
        ex_controls.addWidget(self.exclusion_input, 1)
        add = QPushButton("Thêm")
        add.clicked.connect(self.add_exclusion)
        remove = QPushButton("Xóa")
        remove.clicked.connect(self.remove_exclusion)
        ex_controls.addWidget(add)
        ex_controls.addWidget(remove)
        exclusions_layout.addLayout(ex_controls)
        self.exclusions = QListWidget()
        self.exclusions.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.exclusions.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.exclusions.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        self.exclusions.setUniformItemSizes(True)
        for value in main.settings.get("exclusions", []):
            self._append_exclusion(value)
        self.exclusions.setMaximumHeight(150)
        exclusions_layout.addWidget(self.exclusions)
        root.addWidget(exclusions)

        updates, updates_layout = card()
        update_title = QLabel("Máy chủ cập nhật")
        update_title.setFont(font(13, True))
        updates_layout.addWidget(update_title)
        self.auto_update = QCheckBox("Tự động kiểm tra cập nhật khi khởi động")
        self.auto_update.setChecked(bool(main.settings.get("auto_update", True)))
        updates_layout.addWidget(self.auto_update)
        self.update_url = QLineEdit(main.settings.get("update_url", ""))
        self.update_url.setPlaceholderText("Để trống để dùng máy chủ cập nhật chính thức")
        updates_layout.addWidget(self.update_url)
        root.addWidget(updates)

        about, about_layout = card()
        about_title = QLabel(f"WebGuardian {APP_VERSION}")
        about_title.setFont(font(13, True))
        about_layout.addWidget(about_title)
        about_text = QLabel("Bộ quét bảo mật mã nguồn chạy cục bộ. Không tải mã nguồn của bạn lên máy chủ.")
        about_text.setObjectName("muted")
        about_text.setWordWrap(True)
        about_layout.addWidget(about_text)
        root.addWidget(about)

        save = QPushButton("Lưu cài đặt")
        save.setObjectName("primary")
        save.setFixedWidth(150)
        save.clicked.connect(self.save)
        root.addWidget(save, 0, Qt.AlignmentFlag.AlignRight)
        root.addStretch()

    def add_exclusion(self):
        value = self.exclusion_input.text().strip()
        if value and not self.exclusions.findItems(value, Qt.MatchFlag.MatchExactly):
            self._append_exclusion(value)
            self.exclusion_input.clear()

    def _append_exclusion(self, value: str):
        item = QListWidgetItem(str(value))
        item.setToolTip(str(value))
        self.exclusions.addItem(item)

    def remove_exclusion(self):
        for item in self.exclusions.selectedItems():
            self.exclusions.takeItem(self.exclusions.row(item))

    def save(self):
        values = {
            "check_permissions": self.permissions.isChecked(),
            "max_file_size_mb": self.max_size.value(),
            "theme": "dark" if self.theme.currentText() == "Tối" else "light",
            "auto_update": self.auto_update.isChecked(),
            "update_url": self.update_url.text().strip(),
            "exclusions": [self.exclusions.item(i).text() for i in range(self.exclusions.count())],
        }
        self.main.settings.update(values)
        self.main.scan_page.permission_scan.setChecked(values["check_permissions"])
        self.main.apply_theme(values["theme"])
        self.main.updater = SignatureVersion(values["update_url"] or None)
        QMessageBox.information(self, "Đã lưu", "Cài đặt đã được áp dụng.")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = SettingsStore()
        self.history = HistoryStore()
        self.quarantine = QuarantineManager()
        self.updater = SignatureVersion(self.settings.get("update_url") or None)
        self.scan_thread = None
        self.scan_worker = None
        self.update_thread = None
        self.update_worker = None
        self.setWindowTitle("WebGuardian — Code Security")
        self.setMinimumSize(1080, 700)
        self.resize(1240, 790)

        central = QWidget()
        central.setObjectName("appRoot")
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        self.build_sidebar(root)
        self.build_content(root)
        self.apply_theme(self.settings.get("theme", "dark"))
        self.navigate(0)
        if self.settings.get("auto_update", True):
            QTimer.singleShot(1200, self.auto_check_updates)

    def build_sidebar(self, root):
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(224)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(16, 22, 16, 18)
        layout.setSpacing(8)
        brand = QHBoxLayout()
        mark = QLabel("W")
        mark.setObjectName("brandMark")
        mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        mark.setFixedSize(38, 38)
        brand.addWidget(mark)
        names = QVBoxLayout()
        name = QLabel("WebGuardian")
        name.setObjectName("brandName")
        name.setFont(font(13, True))
        edition = QLabel("CODE SECURITY")
        edition.setObjectName("brandEdition")
        edition.setFont(font(7, True))
        names.addWidget(name)
        names.addWidget(edition)
        brand.addLayout(names)
        brand.addStretch()
        layout.addLayout(brand)
        layout.addSpacing(24)
        label = QLabel("BẢO MẬT")
        label.setObjectName("navLabel")
        layout.addWidget(label)
        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        self.nav.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.nav.setFrameShape(QFrame.Shape.NoFrame)
        self.nav.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.nav.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        for text in ["⌂   Tổng quan", "⌕   Quét mã độc", "▣   Cách ly", "≡   Báo cáo", "↻   Cập nhật", "⚙   Cài đặt"]:
            self.nav.addItem(QListWidgetItem(text))
        self.nav.setFixedHeight(6 * 46)
        self.nav.currentRowChanged.connect(self.navigate)
        layout.addWidget(self.nav)
        layout.addStretch()
        protection = QFrame()
        protection.setObjectName("sideStatus")
        status_layout = QHBoxLayout(protection)
        status_layout.setContentsMargins(12, 10, 12, 10)
        dot = QLabel("●")
        dot.setObjectName("greenDot")
        status_layout.addWidget(dot)
        status_text = QVBoxLayout()
        top = QLabel("Engine hoạt động")
        top.setObjectName("sideStatusTitle")
        top.setFont(font(9, True))
        bottom = QLabel(f"Phiên bản {APP_VERSION}")
        bottom.setObjectName("sideStatusSub")
        status_text.addWidget(top)
        status_text.addWidget(bottom)
        status_layout.addLayout(status_text)
        layout.addWidget(protection)
        root.addWidget(sidebar)

    def build_content(self, root):
        content = QFrame()
        content.setObjectName("content")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        topbar = QFrame()
        topbar.setObjectName("topbar")
        topbar.setFixedHeight(56)
        top_layout = QHBoxLayout(topbar)
        top_layout.setContentsMargins(30, 0, 30, 0)
        self.breadcrumb = QLabel("Tổng quan")
        self.breadcrumb.setFont(font(10, True))
        top_layout.addWidget(self.breadcrumb)
        top_layout.addStretch()
        self.global_status = QLabel("●  Sẵn sàng")
        self.global_status.setObjectName("globalStatus")
        top_layout.addWidget(self.global_status)
        layout.addWidget(topbar)
        self.stack = QStackedWidget()
        self.stack.setObjectName("pages")
        self.dashboard_page = DashboardPage(self)
        self.scan_page = ScanPage(self)
        self.quarantine_page = QuarantinePage(self)
        self.reports_page = ReportsPage(self)
        self.updates_page = UpdatesPage(self)
        self.settings_page = SettingsPage(self)
        for page in [self.dashboard_page, self.scan_page, self.quarantine_page, self.reports_page, self.updates_page, self.settings_page]:
            page.setObjectName("page")
            self.stack.addWidget(page)
        layout.addWidget(self.stack, 1)
        root.addWidget(content, 1)

    def navigate(self, index: int):
        if index < 0 or not hasattr(self, "stack"):
            return
        names = ["Tổng quan", "Quét mã độc", "Khu vực cách ly", "Báo cáo", "Cập nhật", "Cài đặt"]
        self.stack.setCurrentIndex(index)
        self.breadcrumb.setText(names[index])
        if self.nav.currentRow() != index:
            self.nav.setCurrentRow(index)
        page = self.stack.widget(index)
        if hasattr(page, "refresh"):
            page.refresh()

    def start_scan(self, path: str, mode: str):
        if self.scan_thread and self.scan_thread.isRunning():
            return
        options = {
            "scan_mode": mode,
            "exclusions": self.settings.get("exclusions", []),
            "check_permissions": self.scan_page.permission_scan.isChecked(),
            "max_file_size_mb": int(self.settings.get("max_file_size_mb", 10)),
        }
        self.settings.set("last_scan_path", path)
        self.scan_page.begin()
        self.global_status.setText("●  Đang quét")
        self.scan_thread = QThread(self)
        self.scan_worker = ScanWorker(path, options)
        self.scan_worker.moveToThread(self.scan_thread)
        self.scan_thread.started.connect(self.scan_worker.run)
        self.scan_worker.progress.connect(self.scan_page.on_progress)
        self.scan_worker.threat.connect(self.scan_page.on_threat)
        self.scan_worker.finished.connect(self.finish_scan)
        self.scan_worker.failed.connect(self.fail_scan)
        self.scan_worker.finished.connect(self.scan_thread.quit)
        self.scan_worker.failed.connect(self.scan_thread.quit)
        self.scan_thread.finished.connect(self.cleanup_scan_thread)
        self.scan_thread.start()

    def cancel_scan(self):
        if self.scan_worker:
            self.scan_worker.cancel()
            self.global_status.setText("●  Đang dừng")

    def finish_scan(self, result: dict):
        self.history.save(result)
        self.scan_page.on_complete(result)
        self.global_status.setText("●  Sẵn sàng")
        self.refresh_pages()

    def fail_scan(self, message: str):
        self.scan_page.on_error(message)
        self.global_status.setText("●  Lỗi")

    def cleanup_scan_thread(self):
        if self.scan_worker:
            self.scan_worker.deleteLater()
        if self.scan_thread:
            self.scan_thread.deleteLater()
        self.scan_worker = None
        self.scan_thread = None

    def start_update(self, action: str, page: UpdatesPage):
        if self.update_thread and self.update_thread.isRunning():
            return
        self.update_thread = QThread(self)
        self.update_worker = UpdateWorker(self.updater, action)
        self.update_worker.moveToThread(self.update_thread)
        self.update_thread.started.connect(self.update_worker.run)
        self.update_worker.progress.connect(page.on_progress)
        self.update_worker.finished.connect(page.on_result)
        self.update_worker.finished.connect(self.update_thread.quit)
        self.update_thread.finished.connect(self.cleanup_update_thread)
        self.update_thread.start()

    def auto_check_updates(self):
        if not self.update_thread:
            self.start_update("check", self.updates_page)

    def cleanup_update_thread(self):
        if self.update_worker:
            self.update_worker.deleteLater()
        if self.update_thread:
            self.update_thread.deleteLater()
        self.update_worker = None
        self.update_thread = None

    def refresh_pages(self):
        self.dashboard_page.refresh()
        self.quarantine_page.refresh()
        self.reports_page.refresh()
        self.updates_page.refresh()

    def apply_theme(self, theme: str):
        dark = theme == "dark"
        bg = "#101722" if dark else "#f3f6f8"
        panel = "#17212e" if dark else "#ffffff"
        soft = "#1d2a39" if dark else "#f4f7f9"
        border = "#2a3949" if dark else "#dfe6eb"
        text = "#eef4f7" if dark else "#17202a"
        muted = "#8fa0b3" if dark else "#6d7b88"
        self.setStyleSheet(f"""
            QMainWindow, QWidget#appRoot, QStackedWidget#pages, QWidget#page {{ background: {bg}; color: {text}; }}
            QWidget {{ color: {text}; background: transparent; font-family: 'Segoe UI'; font-size: 10pt; }}
            QLabel {{ background: transparent; border: none; }}
            QFrame#sidebar {{ background: #101923; border: none; }}
            QLabel#brandMark {{ background: {GREEN}; color: white; border-radius: 11px; font-size: 17px; font-weight: 700; }}
            QLabel#brandName {{ color: #f5fbfd; }}
            QLabel#brandEdition, QLabel#navLabel {{ color: #5d7185; letter-spacing: 1px; font-size: 8px; }}
            QListWidget#nav {{ background: transparent; border: none; outline: none; }}
            QListWidget#nav::item {{ color: #91a0af; border-radius: 7px; padding: 12px 13px; margin: 2px 0; }}
            QListWidget#nav::item:selected {{ background: #193b3b; color: #65ddc4; font-weight: 600; border-left: 3px solid {GREEN}; }}
            QListWidget#nav::item:hover:!selected {{ background: #172532; color: #d6e2e8; }}
            QFrame#sideStatus {{ background: #172532; border: 1px solid #223444; border-radius: 9px; }}
            QLabel#greenDot {{ color: {GREEN}; }} QLabel#sideStatusTitle {{ color: #dbe7ed; }} QLabel#sideStatusSub {{ color: #64798d; font-size: 8px; }}
            QFrame#content {{ background: {bg}; }} QFrame#topbar {{ background: {panel}; border-bottom: 1px solid {border}; }}
            QLabel#globalStatus {{ color: {GREEN}; background: {soft}; border: 1px solid {border}; border-radius: 12px; padding: 5px 12px; }}
            QLabel#pageTitle {{ color: {text}; }} QLabel#muted {{ color: {muted}; }} QLabel#monoMuted {{ color: {muted}; font-family: 'Cascadia Mono'; font-size: 9px; }}
            QFrame#card {{ background: {panel}; border: 1px solid {border}; border-radius: 11px; }}
            QFrame#hero {{ background: {panel}; border: 1px solid #245047; border-radius: 12px; }}
            QLabel#shield {{ background: #163c38; color: #52d6bb; border: 1px solid #235b53; border-radius: 38px; font-size: 34px; font-weight: 700; }}
            QLabel#shield[alert='true'] {{ background: #41272a; color: {RED}; border-color: #684047; }}
            QLabel#metricIcon, QLabel#updateIcon {{ background: #173a37; color: #56d8bd; border-radius: 9px; font-weight: 700; }}
            QFrame#softBox {{ background: {soft}; border: 1px solid {border}; border-radius: 8px; }}
            QPushButton {{ background: {soft}; color: {text}; border: 1px solid {border}; border-radius: 7px; padding: 8px 14px; }}
            QPushButton:hover {{ border-color: {GREEN}; color: {GREEN}; }}
            QPushButton:disabled {{ color: #65717c; border-color: {border}; }}
            QPushButton#primary {{ background: {GREEN}; color: #ffffff; border-color: {GREEN}; font-weight: 600; }}
            QPushButton#primary:hover {{ background: {GREEN_DARK}; border-color: {GREEN_DARK}; color: white; }}
            QPushButton#danger {{ background: transparent; color: {RED}; border-color: #6a3c43; }}
            QPushButton#ghost {{ background: transparent; border: none; color: {GREEN}; }}
            QLineEdit, QComboBox, QSpinBox {{ background: {soft}; color: {text}; border: 1px solid {border}; border-radius: 7px; padding: 8px 10px; min-height: 18px; }}
            QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{ border-color: {GREEN}; }}
            QComboBox::drop-down {{ border: none; width: 24px; }} QComboBox QAbstractItemView {{ background: {panel}; color: {text}; selection-background-color: #1d5148; }}
            QCheckBox {{ color: {text}; spacing: 8px; }} QCheckBox::indicator {{ width: 17px; height: 17px; border: 1px solid {border}; border-radius: 4px; background: {soft}; }}
            QCheckBox::indicator:checked {{ background: {GREEN}; border-color: {GREEN}; }}
            QProgressBar {{ background: {soft}; border: none; border-radius: 4px; height: 8px; }} QProgressBar::chunk {{ background: {GREEN}; border-radius: 4px; }}
            QTabWidget::pane {{ background: transparent; border: none; border-top: 1px solid {border}; top: -1px; }}
            QTabBar::tab {{ background: transparent; color: {muted}; border: none; padding: 9px 14px; margin-right: 4px; }}
            QTabBar::tab:selected {{ color: {GREEN}; border-bottom: 2px solid {GREEN}; font-weight: 600; }}
            QTabBar::tab:hover:!selected {{ color: {text}; }}
            QPlainTextEdit#findingDetail {{ background: transparent; color: {muted}; border: none; padding: 0; font-family: 'Cascadia Mono'; font-size: 9pt; selection-background-color: #1b5048; }}
            QTableWidget, QListWidget {{ background: {panel}; color: {text}; border: 1px solid {border}; border-radius: 8px; gridline-color: {border}; alternate-background-color: {soft}; }}
            QTableWidget::item {{ padding: 7px; border-bottom: 1px solid {border}; }} QTableWidget::item:selected, QListWidget::item:selected {{ background: #1b5048; color: #effbf8; }}
            QHeaderView::section {{ background: {soft}; color: {muted}; border: none; border-bottom: 1px solid {border}; padding: 8px; font-weight: 600; }}
            QScrollArea {{ background: {bg}; border: none; }}
            QScrollBar:vertical {{ background: transparent; width: 9px; margin: 0; }}
            QScrollBar::handle:vertical {{ background: {border}; border-radius: 4px; min-height: 32px; }}
            QScrollBar:horizontal {{ background: transparent; height: 9px; margin: 0; }}
            QScrollBar::handle:horizontal {{ background: {border}; border-radius: 4px; min-width: 32px; }}
            QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; background: transparent; border: none; }}
            QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
            QToolTip {{ background: {panel}; color: {text}; border: 1px solid {border}; padding: 6px; }}
        """)

    def closeEvent(self, event):
        if self.scan_thread and self.scan_thread.isRunning():
            if QMessageBox.question(self, "Đang quét", "Dừng tác vụ quét và thoát?") != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self.cancel_scan()
            if not self.scan_thread.wait(5000):
                QMessageBox.information(self, "Đang dừng", "Bộ máy quét đang hoàn tất tệp hiện tại. Hãy thử thoát lại sau ít giây.")
                event.ignore()
                return
        event.accept()
