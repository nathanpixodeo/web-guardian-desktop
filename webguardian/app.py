"""Application bootstrap."""

import sys

from PyQt6.QtWidgets import QApplication

from .ui.main_window import MainWindow


def run() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("WebGuardian")
    app.setOrganizationName("WebGuardian")
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    raise SystemExit(app.exec())
