

# ============================================================
# SPEED TEST PAGE
# Network Traffic Analyzer
# UI ONLY - Backend will be connected later
# ============================================================

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QPushButton,
    QComboBox,
    QProgressBar,
    QFrame,
    QGroupBox,
)


# ============================================================
# COLORS
# ============================================================

COLOR_BG = "#0B1120"
COLOR_PANEL = "#111827"
COLOR_PANEL_2 = "#0F172A"
COLOR_BORDER = "#1F2937"

COLOR_BLUE = "#2563EB"
COLOR_BLUE_HOVER = "#3B82F6"

COLOR_CYAN = "#60A5FA"
COLOR_GREEN = "#22C55E"
COLOR_YELLOW = "#EAB308"
COLOR_RED = "#DC2626"

COLOR_TEXT = "#E5E7EB"
COLOR_SECONDARY = "#94A3B8"
COLOR_MUTED = "#64748B"


# ============================================================
# SPEED TEST PAGE
# ============================================================

class SpeedTestPage(QWidget):

    start_test_requested = Signal(dict)

    stop_test_requested = Signal()

    def __init__(self, parent=None):

        super().__init__(parent)

        self.test_running = False

        self.download_speed = 0.0
        self.upload_speed = 0.0
        self.latency = 0
        self.jitter = 0

        self.setup_ui()

    # ========================================================
    # SETUP UI
    # ========================================================

    def setup_ui(self):

        self.setObjectName(
            "SpeedTestPage"
        )

        # Keep the entire page dark, not only the individual cards.
        # This prevents the white canvas visible in the screenshot.
        self.setStyleSheet(f"""
            QWidget#SpeedTestPage {{
                background-color: {COLOR_BG};
                color: {COLOR_TEXT};
                font-family: "Segoe UI";
                font-size: 10px;
            }}

            QComboBox {{
                background-color: {COLOR_PANEL_2};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 5px;
                padding: 7px 28px 7px 9px;
                min-height: 20px;
                selection-background-color: {COLOR_BLUE};
            }}

            QComboBox:hover {{
                border-color: {COLOR_BLUE_HOVER};
            }}

            QComboBox:focus {{
                border: 1px solid {COLOR_CYAN};
            }}

            QComboBox::drop-down {{
                background-color: {COLOR_PANEL};
                border: none;
                border-left: 1px solid {COLOR_BORDER};
                width: 22px;
                subcontrol-origin: padding;
                subcontrol-position: top right;
                border-top-right-radius: 4px;
                border-bottom-right-radius: 4px;
            }}

            QComboBox::down-arrow {{
                width: 8px;
                height: 8px;
            }}

            QComboBox QAbstractItemView {{
                background-color: {COLOR_PANEL};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
                selection-background-color: {COLOR_BLUE};
                selection-color: #FFFFFF;
                outline: none;
            }}

            QGroupBox {{
                color: {COLOR_CYAN};
            }}
        """)

        main_layout = QVBoxLayout(
            self
        )

        main_layout.setContentsMargins(
            18,
            18,
            18,
            18
        )

        main_layout.setSpacing(
            14
        )

        # ----------------------------------------------------
        # HEADER
        # ----------------------------------------------------

        header = QHBoxLayout()

        title_layout = QVBoxLayout()

        title = QLabel(
            "SPEED TEST"
        )

        title.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT};
                font-size: 22px;
                font-weight: 700;
            }}
            """
        )

        subtitle = QLabel(
            "Test your current internet connection performance"
        )

        subtitle.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 11px;
            }}
            """
        )

        title_layout.addWidget(
            title
        )

        title_layout.addWidget(
            subtitle
        )

        header.addLayout(
            title_layout
        )

        header.addStretch()

        self.status_label = QLabel(
            "● READY"
        )

        self.status_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_GREEN};
                background: #10251A;
                border: 1px solid #1B5E36;
                border-radius: 5px;
                padding: 7px 12px;
                font-size: 10px;
                font-weight: 700;
            }}
            """
        )

        header.addWidget(
            self.status_label
        )

        main_layout.addLayout(
            header
        )

        # ----------------------------------------------------
        # MAIN TEST PANEL
        # ----------------------------------------------------

        test_panel = QFrame()

        test_panel.setObjectName(
            "SpeedTestPanel"
        )

        test_panel.setStyleSheet(
            f"""
            QFrame#SpeedTestPanel {{
                background: {COLOR_PANEL};
                border: 1px solid {COLOR_BORDER};
                border-radius: 8px;
            }}
            """
        )

        test_layout = QVBoxLayout(
            test_panel
        )

        test_layout.setContentsMargins(
            20,
            20,
            20,
            20
        )

        # ----------------------------------------------------
        # GAUGE
        # ----------------------------------------------------

        gauge_container = QFrame()

        gauge_layout = QVBoxLayout(
            gauge_container
        )

        gauge_layout.setAlignment(
            Qt.AlignCenter
        )

        self.speed_value = QLabel(
            "00.00"
        )

        self.speed_value.setAlignment(
            Qt.AlignCenter
        )

        self.speed_value.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_CYAN};
                font-size: 52px;
                font-weight: 700;
            }}
            """
        )

        gauge_layout.addWidget(
            self.speed_value
        )

        self.speed_unit = QLabel(
            "Mbps"
        )

        self.speed_unit.setAlignment(
            Qt.AlignCenter
        )

        self.speed_unit.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 13px;
                font-weight: 600;
            }}
            """
        )

        gauge_layout.addWidget(
            self.speed_unit
        )

        self.test_phase = QLabel(
            "READY TO TEST"
        )

        self.test_phase.setAlignment(
            Qt.AlignCenter
        )

        self.test_phase.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_MUTED};
                font-size: 10px;
                font-weight: 700;
                margin-top: 8px;
            }}
            """
        )

        gauge_layout.addWidget(
            self.test_phase
        )

        test_layout.addWidget(
            gauge_container
        )

        # ----------------------------------------------------
        # PROGRESS
        # ----------------------------------------------------

        self.progress_bar = QProgressBar()

        self.progress_bar.setRange(
            0,
            100
        )

        self.progress_bar.setValue(
            0
        )

        self.progress_bar.setTextVisible(
            False
        )

        self.progress_bar.setFixedHeight(
            6
        )

        self.progress_bar.setStyleSheet(
            f"""
            QProgressBar {{
                background: {COLOR_PANEL_2};
                border: none;
                border-radius: 3px;
            }}

            QProgressBar::chunk {{
                background: {COLOR_BLUE};
                border-radius: 3px;
            }}
            """
        )

        test_layout.addWidget(
            self.progress_bar
        )

        # ----------------------------------------------------
        # START / STOP
        # ----------------------------------------------------

        buttons = QHBoxLayout()

        buttons.setAlignment(
            Qt.AlignCenter
        )

        self.start_button = QPushButton(
            "START TEST"
        )

        self.start_button.setFixedSize(
            150,
            38
        )

        self.start_button.setStyleSheet(
            f"""
            QPushButton {{
                background: {COLOR_BLUE};
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 11px;
                font-weight: 700;
            }}

            QPushButton:hover {{
                background: {COLOR_BLUE_HOVER};
            }}

            QPushButton:disabled {{
                background: #1E3A6F;
                color: #94A3B8;
            }}
            """
        )

        self.start_button.clicked.connect(
            self.start_test
        )

        buttons.addWidget(
            self.start_button
        )

        self.stop_button = QPushButton(
            "STOP"
        )

        self.stop_button.setFixedSize(
            100,
            38
        )

        self.stop_button.setStyleSheet(
            f"""
            QPushButton {{
                background: #2A1111;
                color: {COLOR_RED};
                border: 1px solid #6B1B1B;
                border-radius: 5px;
                font-size: 11px;
                font-weight: 700;
            }}

            QPushButton:hover {{
                background: #3A1515;
            }}
            """
        )

        self.stop_button.clicked.connect(
            self.stop_test
        )

        buttons.addWidget(
            self.stop_button
        )

        test_layout.addLayout(
            buttons
        )

        main_layout.addWidget(
            test_panel
        )

        # ----------------------------------------------------
        # SPEED METRICS
        # ----------------------------------------------------

        metrics = QGridLayout()

        self.download_card = self.create_metric_card(
            "DOWNLOAD",
            "00.00 Mbps",
            COLOR_GREEN
        )

        self.upload_card = self.create_metric_card(
            "UPLOAD",
            "00.00 Mbps",
            COLOR_BLUE
        )

        self.latency_card = self.create_metric_card(
            "LATENCY",
            "00 ms",
            COLOR_CYAN
        )

        self.jitter_card = self.create_metric_card(
            "JITTER",
            "00 ms",
            COLOR_YELLOW
        )

        metrics.addWidget(
            self.download_card,
            0,
            0
        )

        metrics.addWidget(
            self.upload_card,
            0,
            1
        )

        metrics.addWidget(
            self.latency_card,
            0,
            2
        )

        metrics.addWidget(
            self.jitter_card,
            0,
            3
        )

        main_layout.addLayout(
            metrics
        )

        # ----------------------------------------------------
        # TEST DETAILS
        # ----------------------------------------------------

        details = QGroupBox(
            "TEST DETAILS"
        )

        details.setStyleSheet(
            f"""
            QGroupBox {{
                color: {COLOR_CYAN};
                background: {COLOR_PANEL};
                border: 1px solid {COLOR_BORDER};
                border-radius: 7px;
                margin-top: 10px;
                padding-top: 15px;
                font-size: 10px;
                font-weight: 700;
            }}

            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 5px;
            }}
            """
        )

        details_layout = QGridLayout(
            details
        )

        details_layout.setContentsMargins(14, 14, 14, 12)
        details_layout.setHorizontalSpacing(10)
        details_layout.setVerticalSpacing(6)

        # Server

        details_layout.addWidget(
            self.create_detail_label(
                "SERVER"
            ),
            0,
            0
        )

        self.server_combo = QComboBox()

        self.server_combo.addItems(
            [
                "Auto Select",
                "Nearest Server",
                "Custom Server",
            ]
        )

        details_layout.addWidget(
            self.server_combo,
            1,
            0
        )

        # Adapter

        details_layout.addWidget(
            self.create_detail_label(
                "CONNECTION"
            ),
            0,
            1
        )

        self.adapter_combo = QComboBox()

        self.adapter_combo.addItems(
            [
                "Wi-Fi",
                "Ethernet",
                "Auto Select",
            ]
        )

        details_layout.addWidget(
            self.adapter_combo,
            1,
            1
        )

        # Public IP

        details_layout.addWidget(
            self.create_detail_label(
                "PUBLIC IP"
            ),
            0,
            2
        )

        self.public_ip_label = QLabel(
            "Not detected"
        )

        self.public_ip_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT};
                background: {COLOR_PANEL_2};
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                padding: 8px;
            }}
            """
        )

        details_layout.addWidget(
            self.public_ip_label,
            1,
            2
        )

        # ISP

        details_layout.addWidget(
            self.create_detail_label(
                "ISP"
            ),
            0,
            3
        )

        self.isp_label = QLabel(
            "Not detected"
        )

        self.isp_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT};
                background: {COLOR_PANEL_2};
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                padding: 8px;
            }}
            """
        )

        details_layout.addWidget(
            self.isp_label,
            1,
            3
        )

        main_layout.addWidget(
            details
        )

        # ----------------------------------------------------
        # TRANSFER INFORMATION
        # ----------------------------------------------------

        transfer = QFrame()

        transfer.setStyleSheet(
            f"""
            QFrame {{
                background: {COLOR_PANEL};
                border: 1px solid {COLOR_BORDER};
                border-radius: 7px;
            }}
            """
        )

        transfer_layout = QGridLayout(
            transfer
        )

        transfer_layout.setHorizontalSpacing(10)
        transfer_layout.setVerticalSpacing(8)

        transfer_layout.setContentsMargins(
            14,
            12,
            14,
            12
        )

        transfer_title = QLabel(
            "TRANSFER"
        )

        transfer_title.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_CYAN};
                font-size: 10px;
                font-weight: 700;
            }}
            """
        )

        transfer_layout.addWidget(
            transfer_title,
            0,
            0,
            1,
            4
        )

        self.downloaded_label = QLabel(
            "Downloaded: 0 MB"
        )

        self.uploaded_label = QLabel(
            "Uploaded: 0 MB"
        )

        self.duration_label = QLabel(
            "Duration: 0 sec"
        )

        self.server_label = QLabel(
            "Server: Auto Select"
        )

        for index, label in enumerate(
            [
                self.downloaded_label,
                self.uploaded_label,
                self.duration_label,
                self.server_label,
            ]
        ):

            label.setStyleSheet(
                f"""
                QLabel {{
                    color: {COLOR_SECONDARY};
                    font-size: 10px;
                    padding: 5px;
                }}
                """
            )

            transfer_layout.addWidget(
                label,
                1,
                index
            )

        main_layout.addWidget(
            transfer
        )

        main_layout.addStretch()

    # ========================================================
    # METRIC CARD
    # ========================================================

    def create_metric_card(
        self,
        title,
        value,
        color
    ):

        frame = QFrame()

        frame.setMinimumHeight(
            82
        )

        frame.setStyleSheet(
            f"""
            QFrame {{
                background: {COLOR_PANEL};
                border: 1px solid {COLOR_BORDER};
                border-radius: 7px;
            }}
            """
        )

        layout = QVBoxLayout(
            frame
        )

        layout.setContentsMargins(
            12,
            10,
            12,
            10
        )

        title_label = QLabel(
            title
        )

        title_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 9px;
                font-weight: 700;
            }}
            """
        )

        value_label = QLabel(
            value
        )

        value_label.setStyleSheet(
            f"""
            QLabel {{
                color: {color};
                font-size: 21px;
                font-weight: 700;
            }}
            """
        )

        layout.addWidget(
            title_label
        )

        layout.addWidget(
            value_label
        )

        frame.value_label = value_label

        return frame

    # ========================================================
    # DETAIL LABEL
    # ========================================================

    def create_detail_label(
        self,
        text
    ):

        label = QLabel(
            text
        )

        label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 9px;
                font-weight: 700;
            }}
            """
        )

        return label

    # ========================================================
    # START TEST
    # ========================================================

    def start_test(self):

        self.test_running = True

        self.start_button.setEnabled(
            False
        )

        self.status_label.setText(
            "● TESTING"
        )

        self.status_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_YELLOW};
                background: #2A230D;
                border: 1px solid #6B5A13;
                border-radius: 5px;
                padding: 7px 12px;
                font-size: 10px;
                font-weight: 700;
            }}
            """
        )

        self.test_phase.setText(
            "INITIALIZING TEST"
        )

        self.progress_bar.setValue(
            10
        )

        config = {
            "server": self.server_combo.currentText(),
            "adapter": self.adapter_combo.currentText(),
        }

        self.start_test_requested.emit(
            config
        )

    # ========================================================
    # STOP TEST
    # ========================================================

    def stop_test(self):

        self.test_running = False

        self.start_button.setEnabled(
            True
        )

        self.progress_bar.setValue(
            0
        )

        self.test_phase.setText(
            "TEST STOPPED"
        )

        self.status_label.setText(
            "● STOPPED"
        )

        self.status_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_RED};
                background: #2A1111;
                border: 1px solid #6B1B1B;
                border-radius: 5px;
                padding: 7px 12px;
                font-size: 10px;
                font-weight: 700;
            }}
            """
        )

        self.stop_test_requested.emit()

    # ========================================================
    # UPDATE DOWNLOAD
    # ========================================================

    def set_download_speed(
        self,
        value
    ):

        self.download_speed = float(
            value
        )

        self.download_card.value_label.setText(
            f"{self.download_speed:.2f} Mbps"
        )

        self.speed_value.setText(
            f"{self.download_speed:.2f}"
        )

        self.test_phase.setText(
            "DOWNLOAD TEST"
        )

    # ========================================================
    # UPDATE UPLOAD
    # ========================================================

    def set_upload_speed(
        self,
        value
    ):

        self.upload_speed = float(
            value
        )

        self.upload_card.value_label.setText(
            f"{self.upload_speed:.2f} Mbps"
        )

        self.speed_value.setText(
            f"{self.upload_speed:.2f}"
        )

        self.test_phase.setText(
            "UPLOAD TEST"
        )

    # ========================================================
    # UPDATE LATENCY
    # ========================================================

    def set_latency(
        self,
        value
    ):

        self.latency = int(
            value
        )

        self.latency_card.value_label.setText(
            f"{self.latency} ms"
        )

    # ========================================================
    # UPDATE JITTER
    # ========================================================

    def set_jitter(
        self,
        value
    ):

        self.jitter = int(
            value
        )

        self.jitter_card.value_label.setText(
            f"{self.jitter} ms"
        )

    # ========================================================
    # UPDATE PROGRESS
    # ========================================================

    def set_progress(
        self,
        value
    ):

        self.progress_bar.setValue(
            int(value)
        )

    # ========================================================
    # COMPLETE TEST
    # ========================================================

    def set_test_complete(
        self
    ):

        self.test_running = False

        self.start_button.setEnabled(
            True
        )

        self.progress_bar.setValue(
            100
        )

        self.test_phase.setText(
            "TEST COMPLETE"
        )

        self.status_label.setText(
            "● COMPLETE"
        )

        self.status_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_GREEN};
                background: #10251A;
                border: 1px solid #1B5E36;
                border-radius: 5px;
                padding: 7px 12px;
                font-size: 10px;
                font-weight: 700;
            }}
            """

        )

    # ========================================================
    # PUBLIC IP
    # ========================================================

    def set_public_ip(
        self,
        ip
    ):

        self.public_ip_label.setText(
            str(ip)
        )

    # ========================================================
    # ISP
    # ========================================================

    def set_isp(
        self,
        isp
    ):

        self.isp_label.setText(
            str(isp)
        )