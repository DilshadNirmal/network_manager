import sys
import os
import shutil
import subprocess
from datetime import datetime

from PyQt6.QtCore import (
     Qt,
     QTimer,
     QThread,
     pyqtSignal,
     QEasingCurve,
     QPropertyAnimation,
     QSequentialAnimationGroup
)
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
    QGraphicsOpacityEffect,
    QMessageBox,
    QSplashScreen,
    QProgressBar
)

from PyQt6.QtGui import (
    QFont,
    QPixmap
)

from scanner import scan_network

class SplashScreen(QWidget):

    def __init__(self):
        super().__init__()

        #Window
        self.setWindowTitle("CUBI-5 Network Manager")
        self.setFixedSize(900, 650)

        self.setStyleSheet("""
            QWidget{
                background-color:#05080F;
                color:#E8EAED;
                font-family:Consolas;
            }
        """)

        #layout
        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.setSpacing(18)

        # ---------------------------------------------------------
        # Title
        # ---------------------------------------------------------

        self.title = QLabel("NETWORK MANAGER")
        self.title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.title.setStyleSheet("""
            QLabel{
                font-size:34px;
                font-weight:bold;
                letter-spacing:4px;
                color:#E8EAED;
            }
        """)

        main_layout.addWidget(self.title)
        # ---------------------------------------------------------
        # Subtitle
        # ---------------------------------------------------------

        self.subtitle = QLabel(
            "Enterprise Network Monitoring System"
        )

        self.subtitle.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )

        self.subtitle.setStyleSheet("""
            QLabel{
                font-size:15px;
                color:#9AA7B4;
            }
        """)

        main_layout.addWidget(self.subtitle)

        # ---------------------------------------------------------
        # Divider
        # ---------------------------------------------------------

        divider = QFrame()

        divider.setFrameShape(QFrame.Shape.HLine)

        divider.setFixedWidth(650)

        divider.setStyleSheet("""
            background:#5A6B7D;
            max-height:1px;
            border:none;
        """)

        main_layout.addWidget(divider)

        # ---------------------------------------------------------
        # Loading Message
        # ---------------------------------------------------------

        self.loading_message = QLabel(
            "Initializing Application..."
        )

        self.loading_message.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )

        self.loading_message.setStyleSheet("""
            QLabel{
                font-size:18px;
                font-weight:bold;
                color:#E8EAED;
            }
        """)

        main_layout.addWidget(self.loading_message)

        # ---------------------------------------------------------
        # Progress Bar
        # ---------------------------------------------------------

        self.progress = QProgressBar()

        self.progress.setFixedWidth(420)

        self.progress.setFixedHeight(12)

        self.progress.setRange(0,100)

        self.progress.setValue(0)

        self.progress.setTextVisible(False)

        self.progress.setStyleSheet("""

            QProgressBar{

                background:#12161C;

                border:1px solid #5A6B7D;

                border-radius:6px;

            }

            QProgressBar::chunk{

                background:#3DDC84;

                border-radius:6px;

            }

        """)

        main_layout.addWidget(
            self.progress,
            alignment=Qt.AlignmentFlag.AlignCenter
        )

        # ---------------------------------------------------------
        # Percentage
        # ---------------------------------------------------------

        self.percent = QLabel("0 %")

        self.percent.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )

        self.percent.setStyleSheet("""
            QLabel{
                font-size:16px;
                font-weight:bold;
                color:#3DDC84;
            }
        """)

        main_layout.addWidget(self.percent)

        # ---------------------------------------------------------
        # Status Checklist
        # ---------------------------------------------------------

        self.checklist = QLabel(
            "○ Loading Scanner\n\n"
            "○ Loading Network Module\n\n"
            "○ Detecting Interfaces\n\n"
            "○ Scanning Network\n\n"
            "○ Creating Dashboard"
        )

        self.checklist.setStyleSheet("""
            QLabel{
                font-size:14px;
                color:#E8EAED;
            }
        """)

        main_layout.addWidget(self.checklist)

        # ---------------------------------------------------------
        # Interface Information
        # ---------------------------------------------------------

        self.interfaces = QLabel(
            "Detected Interfaces\n\n"
            "○ enp45s0\n"
            "○ enp46s0"
        )

        self.interfaces.setStyleSheet("""
            QLabel{
                font-size:14px;
                color:#9AA7B4;
            }
        """)

        main_layout.addWidget(self.interfaces)

        # ---------------------------------------------------------
        # Device Counter
        # ---------------------------------------------------------

        self.device_counter = QLabel(
            "Devices Found : 0"
        )

        self.device_counter.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )

        self.device_counter.setStyleSheet("""
            QLabel{
                font-size:15px;
                color:#3DDC84;
                font-weight:bold;
            }
        """)

        main_layout.addWidget(self.device_counter)

        # ---------------------------------------------------------
        # Status Indicator
        # ---------------------------------------------------------

        self.status = QLabel(
            "🟢 Initializing"
        )

        self.status.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )

        self.status.setStyleSheet("""
            QLabel{
                font-size:15px;
                color:#3DDC84;
                font-weight:bold;
            }
        """)

        main_layout.addWidget(self.status)

        main_layout.addStretch()
        self.detect_interfaces()

        self.fade_in_animation()

        self.start_loading()

        #self.update_loading(10,"Loading Network Scanner...")

        # ---------------------------------------
        # Detect Ethernet Interfaces
        # ---------------------------------------

    def interface_connected(self,interface):
            try:
                with open(f"/sys/class/net/{interface}/operstate", "r") as f:
                   return f.read().strip() == "up"
            except Exception:
                   return False


    def detect_interfaces(self):

        text = "Detected Interfaces\n\n"

        if self.interface_connected("enp45s0"):
           text += "✓ enp45s0\n"
        else:
           text += "⚠ enp45s0 (No Cable)\n"

        if self.interface_connected("enp46s0"):
           text += "✓ enp46s0"
        else:
           text += "⚠ enp46s0 (No Cable)"

        self.interfaces.setText(text)

    def fade_in_animation(self):

       self.opacity_effect = QGraphicsOpacityEffect(self)

       self.setGraphicsEffect(self.opacity_effect)

       self.fade_animation = QPropertyAnimation(
        self.opacity_effect,
        b"opacity"
    )

       self.fade_animation.setDuration(500)

       self.fade_animation.setStartValue(0)

       self.fade_animation.setEndValue(1)

       self.fade_animation.start()

    def start_loading(self):

        self.worker = ScanWorker()

        self.worker.progress.connect(
        self.update_progress
    )

        self.worker.finished.connect(
        self.loading_finished
    )

        self.worker.error.connect(
        self.loading_error
    )

        self.worker.start()

    def loading_finished(self, devices):

        self.worker.quit()
        self.worker.wait()

       # -----------------------------
       # Finish Splash Screen
       # -----------------------------
        self.progress.setValue(100)

        self.percent.setText("100%")

        self.loading_message.setText(
        "✓ Initialization Complete\n\nOpening Dashboard..."
    )

        self.status.setText("🟢 Ready")

        self.checklist.setText(

        "✓ Loading Scanner\n\n"

        "✓ Loading Network Module\n\n"

        "✓ Detecting Interfaces\n\n"

        "✓ Scanning Network\n\n"

        "✓ Creating Dashboard"

    )

        QApplication.processEvents()

        self.dashboard = Dashboard()

        self.dashboard._on_scan_done(devices)

        # Wait 600 ms before opening dashboard
        QTimer.singleShot(600, self.finish_loading)

    def finish_loading(self):

        self.dashboard.show()

        self.close()


    def update_progress(self, progress, message):
        if message.startswith("DEVICE_COUNT:"):

           count = int(message.split(":")[1])

           self.device_counter.setText(

           f"Devices Found : {count}"

        )
           QApplication.processEvents()
           return

        self.progress.setValue(progress)

        self.percent.setText(f"{progress}%")

        self.loading_message.setText(message)

    # --------------------------
    # Status Indicator
    # --------------------------

        if progress < 20:
           self.status.setText("🟢 Initializing")
        elif progress < 90:
           self.status.setText("🟢 Scanning Network")
        else:
           self.status.setText("🟢 Finalizing")


    # --------------------------
    # Detect Interfaces
    # --------------------------
        if progress >= 20:
           self.detect_interfaces()

    # --------------------------
    # Checklist
    # --------------------------

        scanner = "○"
        network = "○"
        interface = "○"
        scan = "○"
        dashboard = "○"

        if progress >= 5:
          scanner = "✓"

        if progress >= 15:
          network = "✓"

        if progress >= 35:
          interface = "✓"

        if progress >= 60:
           scan = "✓"

        if progress >= 95:
           dashboard = "✓"

        self.checklist.setText(

         f"{scanner} Loading Scanner\n\n"

        f"{network} Loading Network Module\n\n"

        f"{interface} Detecting Interfaces\n\n"

        f"{scan} Scanning Network\n\n"

        f"{dashboard} Creating Dashboard"

    )

        QApplication.processEvents()

    def loading_error(self, error):

        QMessageBox.critical(
        self,
        "Scanner Error",
        error
    )
        self.close()


# ─────────────────────────────────────────────────────────────────────────────
# Background scan worker
# Running scan_network() on the main thread blocks Qt and freezes the window.
# ScanWorker moves the scan onto a background thread and emits a signal when
# the result is ready so the main thread can update the UI safely.
# ─────────────────────────────────────────────────────────────────────────────

class ScanWorker(QThread):

    progress = pyqtSignal(int, str)

    finished = pyqtSignal(list)

    error = pyqtSignal(str)

    def run(self):


      print("========== ScanWorker STARTED ==========")

      try:
        devices = scan_network(
            progress_callback=self.progress.emit
        )

        print("========== Scan Complete ==========")
        print(f"Devices = {len(devices)}")

        self.finished.emit(devices)

        print("========== Finished Signal Sent ==========")

      except Exception as e:

        import traceback
        traceback.print_exc()

        self.error.emit(str(e))

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
    print(f"[SSH] Target = {ssh_target}")

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
            print(f"[SSH] Launching {' '.join(cmd)}")
            try:
                subprocess.Popen(cmd)
                return True
            except Exception as e:
                print(e)

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
        status = self.device["status"].upper()

        if status == "ACTIVE":

           status_color = "#3DDC84"

        elif status == "ACTIVE (LOCAL)":

             status_color = "#00FFFF"

        elif status == "SSH AVAILABLE":

             status_color = "#3B82F6"

        elif status == "SSH UNAVAILABLE":

             status_color = "#F59E0B"

        elif status == "OFFLINE":

             status_color = "#FF5555"

        else:

             status_color = "#AAAAAA"


        status_icons = {

             "ACTIVE": "🟢",

             "ACTIVE (LOCAL)": "💻",

             "SSH AVAILABLE": "🔐",

             "SSH UNAVAILABLE": "⚠",

             "OFFLINE": "🔴",

             "UNREACHABLE": "❌"

        }

        display_status = (
             f"{status_icons.get(self.device['status'], '❓')} "
             f"{self.device['status']}"
        )




        fields = [
            ("IP Address",  self.device["ip"],None),
            ("Status",display_status,status_color),
            ("Operating System","🐧 Ubuntu"
              if self.device["os"] == "Ubuntu"
              else
              "🪟 Windows"
              if self.device["os"] == "Windows"
              else
              "⚠ Unknown",

              None),

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
        # --------------------------------------------------
        # Card Colour based on Operating System
        # --------------------------------------------------

        if self.device["os"] == "Ubuntu":

           background = "#10261A"
           border = "#3DDC84"

        elif self.device["os"] == "Windows":

           background = "#11243D"
           border = "#3B82F6"

        else:

           background = "#2A1C12"
           border = "#F59E0B"
        self.setObjectName("deviceCard")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet(f"""
            QWidget#deviceCard {{

            background-color: {background};

            border:2px solid {border};

            border-radius:6px;

            }}

            QWidget#deviceCard:hover {{
            background-color:#181D25;

            border:2px solid {border};

            }}
        """)

    @staticmethod
    def _make_divider() -> QFrame:
        div = QFrame()
        div.setFrameShape(QFrame.Shape.HLine)
        div.setFixedHeight(1)
        div.setStyleSheet("background-color: #5a6b7d; border: none;")
        return div

    def _on_ssh_clicked(self):

        print("SSH Button Clicked")

        ip = self.device["ip"]
        if self.device.get("os") == "Unknown":

            box = QMessageBox()

            box.setWindowTitle("Operating System Detection")

            box.setIcon(QMessageBox.Icon.Warning)

            box.setText("Unable to determine Operating System")

            box.setInformativeText(

            f"Device name : {self.device['name']}\n"
            f"IP Address : {ip}\n\n"
            "This Device cannot be accessed using SSH"
            )

            box.setStandardButtons(QMessageBox.StandardButton.Ok)
            box.exec()
            return


        username = (
        self.device["name"]
        .replace("(THIS DEVICE)", "")
        .strip()
        .lower()
    )

        if not open_ssh_terminal(ip, username):

           box = QMessageBox()

           box.setWindowTitle("SSH")

           box.setIcon(QMessageBox.Icon.Warning)

           box.setText(
            f"Unable to open SSH terminal for\n{username}@{ip}"
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

    # ── scan management ───────────────────────────────────────────────────────

    def _start_scan(self):
        """Launch a background scan. Does nothing if one is already running."""
        if self._worker is not None and self._worker.isRunning():
            return

        self.scan_info.setText("⟳  Scanning network …")

        self._worker = ScanWorker()
        self._worker.progress.connect(self.update_dashboard_progress)
        self._worker.finished.connect(self._on_scan_done)
        self._worker.error.connect(self._on_scan_error)
        self._worker.start()

    def update_dashboard_progress(self, progress, message):

        # Ignore device counter messages
        if message.startswith("DEVICE_COUNT:"):
           return

        self.scan_info.setText(message)

        QApplication.processEvents()

    def _on_scan_done(self, devices):

        now = datetime.now().strftime("%H:%M:%S")

        self.scan_info.setText(
        f"✓ Scan Complete\nLast Scan : {now}"
    )

        self.device_count.setText(
        f"Monitoring {len(devices)} Devices"
    )

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
    splash = SplashScreen()
    splash.show()
    #window = Dashboard()
    #window.show()
    sys.exit(app.exec())
