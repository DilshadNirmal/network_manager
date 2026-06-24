import sys
import os
import shutil
import subprocess
from datetime import datetime

from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QWidget,
    QLabel,
    QVBoxLayout,
    QGridLayout,
    QFrame,
    QScrollArea,
    QMainWindow,
    QPushButton,
    QMessageBox
)

from scanner import scan_network


# ─────────────────────────────────────────────────────────────────────────────
# Background scan worker
# Running scan_network() on the main thread blocks Qt and freezes the window.
# ScanWorker moves the scan onto a background thread and emits a signal when
# the result is ready so the main thread can update the UI safely.
# ─────────────────────────────────────────────────────────────────────────────

class ScanWorker(QThread):

    # Emitted with the device list when the scan succeeds.
    finished = pyqtSignal(list)
    # Emitted with an error string if the scan raises an exception.
    error    = pyqtSignal(str)

    def run(self):
        try:
            devices = scan_network()
            self.finished.emit(devices)
        except Exception as exc:
            self.error.emit(str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# SSH helper
# ─────────────────────────────────────────────────────────────────────────────

def open_ssh_terminal(
    ip: str,
    username: str
) -> bool:
    """
    Open an SSH session to ip in a new terminal window. Cross-platform:
    Windows (Windows Terminal / cmd), macOS (Terminal.app) and Linux (any of
    the common emulators). Returns True if a process was launched.
    """
    ssh_target = f"{username}@{ip}"

    # ── Windows ────────────────────────────────────────────────────────────
    if sys.platform == "win32":
        # Windows 10+ ships an OpenSSH client (ssh.exe). Prefer Windows
        # Terminal if present, else fall back to a classic cmd window.
        try:
            if shutil.which("wt"):
                subprocess.Popen(["wt", "ssh", ssh_target])
            else:
                # `start` is a cmd builtin, so go through the shell; /k keeps
                # the window open after the session ends.
                subprocess.Popen(
                    f'start "SSH {ssh_target}" cmd /k ssh {ssh_target}',
                    shell=True,
                )
            return True
        except Exception as exc:
            print(f"[SSH] windows launch failed: {exc}")
            return False

    # ── macOS ──────────────────────────────────────────────────────────────
    if sys.platform == "darwin":
        try:
            subprocess.Popen([
                "osascript", "-e",
                f'tell app "Terminal" to do script "ssh {ssh_target}"',
                "-e", 'tell app "Terminal" to activate',
            ])
            return True
        except Exception as exc:
            print(f"[SSH] macOS launch failed: {exc}")
            return False

    # ── Linux / other Unix ───────────────────────────────────────────────────
    terminals = [
        ["gnome-terminal", "--",   "ssh", ssh_target],
        ["xfce4-terminal", "-e",   f"ssh {ssh_target}"],
        ["konsole",        "-e",   "ssh", ssh_target],
        ["tilix",          "-e",   f"ssh {ssh_target}"],
        ["terminator",     "-e",   f"ssh {ssh_target}"],
        ["mate-terminal",  "-e",   f"ssh {ssh_target}"],
        ["lxterminal",     "-e",   f"ssh {ssh_target}"],
        ["alacritty",      "-e",   "ssh", ssh_target],
        ["kitty",                  "ssh", ssh_target],
        ["xterm",          "-e",   "ssh", ssh_target],
    ]

    for cmd in terminals:
        if shutil.which(cmd[0]):
            try:
                subprocess.Popen(cmd)
                return True
            except Exception as exc:
                print(f"[SSH] {cmd[0]} failed: {exc}")

    return False


# ─────────────────────────────────────────────────────────────────────────────
# Device card widget
# ─────────────────────────────────────────────────────────────────────────────

class DeviceCard(QWidget):

    def __init__(self, device):
        super().__init__()
        self.device = device
        self.build_ui()

    def build_ui(self):

        outer = QVBoxLayout()
        outer.setContentsMargins(12, 10, 12, 10) #card margin 
        outer.setSpacing(6)

        # ── Heading ──────────────────────────────────────────────────────────
        title = QLabel(self.device["name"].upper())
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("""
            font-family: Consolas, 'Courier New', monospace;
            font-size: 13px;
            font-weight: bold;
            color: #e8eaed;
            letter-spacing: 2px;
            background: transparent;
            border: none;
        """)
        outer.addWidget(title)

        # ── Divider : heading → fields ────────────────────────────────────────
        outer.addWidget(self._make_divider())

        # ── Fields ───────────────────────────────────────────────────────────
        is_active    = self.device["status"].upper() == "ACTIVE"
        status_color = "#3ddc84" if is_active else "#e05252"

        fields = [
            ("IP Address",  self.device["ip"],                  None),
            ("Status",      self.device["status"],              status_color),
            ("MAC Address", self.device["mac"],                 None),
            ("Vendor",      self.device["vendor"],              None),
            ("Type",        self.device["device_type"],         None),
            ("First Seen",  self.device.get("first_seen", "-"), None),
            ("Last Seen",   self.device["last_seen"],           None),
        ]

        field_grid = QGridLayout()
        field_grid.setHorizontalSpacing(10)
        field_grid.setVerticalSpacing(7)
        field_grid.setColumnStretch(2, 1)

        for row_idx, (label_text, value_text, dot_color) in enumerate(fields):

            lbl = QLabel(label_text)
            lbl.setStyleSheet("""
                font-family: Consolas, 'Courier New', monospace;
                font-size: 12px;
                color: #9aa7b4;
                background: transparent;
                border: none;
            """)

            colon = QLabel(":")
            colon.setStyleSheet("""
                font-family: Consolas, 'Courier New', monospace;
                font-size: 12px;
                color: #9aa7b4;
                background: transparent;
                border: none;
            """)

            display  = f"●  {value_text}" if dot_color else str(value_text)
            v_color  = dot_color if dot_color else "#e8eaed"
            v_weight = "bold" if dot_color else "normal"

            val = QLabel(display)
            val.setStyleSheet(f"""
                font-family: Consolas, 'Courier New', monospace;
                font-size: 12px;
                color: {v_color};
                font-weight: {v_weight};
                background: transparent;
                border: none;
            """)

            field_grid.addWidget(lbl,   row_idx, 0)
            field_grid.addWidget(colon, row_idx, 1)
            field_grid.addWidget(val,   row_idx, 2)

        outer.addLayout(field_grid)

        # ── Divider : fields → SSH button ────────────────────────────────────
        outer.addWidget(self._make_divider())

        # ── SSH button ────────────────────────────────────────────────────────
        ssh_btn = QPushButton("⌨  SSH INTO DEVICE")
        ssh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        ssh_btn.clicked.connect(self._on_ssh_clicked)
        ssh_btn.setStyleSheet("""
            QPushButton {
                font-family: Consolas, 'Courier New', monospace;
                font-size: 12px;
                font-weight: bold;
                color: #3ddc84;
                background-color: transparent;
                border: 1px solid #3ddc84;
                border-radius: 4px;
                padding: 6px 0px;
                letter-spacing: 1px;
            }
            QPushButton:hover {
                background-color: #122010;
                color: #5aeea0;
                border-color: #5aeea0;
            }
            QPushButton:pressed {
                background-color: #0a150a;
                color: #3ddc84;
            }
        """)
        outer.addWidget(ssh_btn)

        self.setLayout(outer)
        self.setMinimumSize(280, 300) #card size
        self.setObjectName("deviceCard")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet("""
            QWidget#deviceCard {
                background-color: #12161c;
                border: 2px solid #5a6b7d;
                border-radius: 6px;
            }
            QWidget#deviceCard:hover {
                background-color: #181d25;
                border: 2px solid #7c8da0;
            }
        """)

    @staticmethod
    def _make_divider() -> QFrame:
        div = QFrame()
        div.setFrameShape(QFrame.Shape.HLine)
        div.setFixedHeight(1)
        div.setStyleSheet("background-color: #5a6b7d; border: none;")
        return div

    def _on_ssh_clicked(self):

        ip = self.device["ip"]

        hostname = self.device["name"].lower()

        username = hostname

        if not open_ssh_terminal(
            ip,
            username
         ):

            box = QMessageBox(self)

            box.setWindowTitle(
            "SSH — No Terminal Found"
            )

            box.setIcon(
            QMessageBox.Icon.Warning
            )

            box.setText(
            f"No terminal emulator found "
            f"to SSH into:\n{ip}"
            )

            box.exec()

# ─────────────────────────────────────────────────────────────────────────────
# Dashboard main window
# ─────────────────────────────────────────────────────────────────────────────

class Dashboard(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Device Dashboard")
        self.resize(1600, 900)

        # Keep a reference to the active worker so Python doesn't GC it mid-run.
        self._worker = None

        self.setup_ui()

        # Timer fires every 30 s; _start_scan() ignores it if a scan is running.
        self.timer = QTimer()
        self.timer.timeout.connect(self._start_scan)
        self.timer.start(30_000) #30 seconds reset

        # Kick off the first scan immediately (runs in background — no freeze).
        self._start_scan()

    # ── scan management ───────────────────────────────────────────────────────

    def _start_scan(self):
        """Launch a background scan. Does nothing if one is already running."""
        if self._worker is not None and self._worker.isRunning():
            return

        self.scan_info.setText("⟳  Scanning network …")

        self._worker = ScanWorker()
        self._worker.finished.connect(self._on_scan_done)
        self._worker.error.connect(self._on_scan_error)
        self._worker.start()

    def _on_scan_done(self, devices):
        """Called on the main thread when the background scan finishes."""
        now = datetime.now().strftime("%H:%M:%S")
        self.scan_info.setText(f"Last Scan: {now}")
        self.device_count.setText(f"Monitoring {len(devices)} Devices")
        self._refresh_cards(devices)

    def _on_scan_error(self, msg):
        """Called on the main thread if the scan raised an exception."""
        self.scan_info.setText("Scan failed — see terminal for details")
        print(f"[Dashboard] Scan error: {msg}")

    # ── card grid ─────────────────────────────────────────────────────────────

    def clear_cards(self):
        while self.grid.count():
            item   = self.grid.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

    def _refresh_cards(self, devices):
        self.clear_cards()
        row, col = 0, 0
        for device in devices:
            card = DeviceCard(device)
            self.grid.addWidget(card, row, col)
            col += 1
            if col == 4:
                col = 0
                row += 1

    # ── UI setup ──────────────────────────────────────────────────────────────

    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        title = QLabel("NETWORK DEVICE DASHBOARD")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("""
            font-family: Consolas, 'Courier New', monospace;
            font-size: 30px;
            font-weight: bold;
            color: #e8eaed;
            letter-spacing: 4px;
            padding: 20px;
        """)
        layout.addWidget(title)

        self.scan_info = QLabel("Initializing …")
        self.scan_info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.scan_info.setStyleSheet("""
            font-family: Consolas, 'Courier New', monospace;
            font-size: 12px;
            color: #9aa7b4;
        """)
        layout.addWidget(self.scan_info)

        self.device_count = QLabel("Monitoring 0 Devices")
        self.device_count.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.device_count.setStyleSheet("""
            font-family: Consolas, 'Courier New', monospace;
            font-size: 12px;
            color: #9aa7b4;
            padding-bottom: 10px;
        """)
        layout.addWidget(self.device_count)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)

        self.container = QWidget()
        self.container.setStyleSheet("background-color: transparent;")

        self.grid = QGridLayout(self.container)
        self.grid.setSpacing(8) #grid spacing
        self.grid.setAlignment(
            Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignCenter
        )

        self.scroll.setWidget(self.container)
        layout.addWidget(self.scroll)

        self.setStyleSheet("""
            QMainWindow {
                background-color: #05080f;
            }
            QScrollArea {
                background-color: #05080f;
                border: none;
            }
        """)


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app    = QApplication(sys.argv)
    window = Dashboard()
    window.show()
    sys.exit(app.exec())
