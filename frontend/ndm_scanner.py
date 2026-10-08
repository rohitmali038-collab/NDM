

# ==============================================================
# NETWORK TRAFFIC ANALYZER
# NDM SCANNER PAGE
# ==============================================================
#
# PAGE 5
#
# NDM = Network Defense Monitor
#
# Modules:
#   - Network Discovery
#   - Port Scanning
#   - Service Detection
#   - Vulnerability Assessment
#   - Risk Scoring
#   - Threat Intelligence Ready
#   - Security Findings
#   - Scan Report Ready
#
# FRONTEND ONLY
# Backend scanner will be connected later.
#
# ==============================================================

from PySide6.QtCore import Qt, Signal

from PySide6.QtWidgets import (
    QWidget,
    QFrame,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QLineEdit,
    QComboBox,
    QProgressBar,
    QTableWidget,
    QTableWidgetItem,
    QAbstractItemView,
    QHeaderView,
    QTabWidget,
    QMessageBox,
)


# ==============================================================
# SIZE CONFIGURATION
# ==============================================================

PAGE_SPACING = 8

HEADER_HEIGHT = 64

CONTROL_HEIGHT = 58

STATUS_HEIGHT = 96

TABLE_MIN_HEIGHT = 330

TABLE_ROW_HEIGHT = 30

BUTTON_HEIGHT = 32

INPUT_HEIGHT = 32


# ==============================================================
# TABLE COLUMN WIDTHS
# ==============================================================

HOST_IP_WIDTH = 140

HOSTNAME_WIDTH = 150

MAC_WIDTH = 145

VENDOR_WIDTH = 130

STATUS_WIDTH = 90

LATENCY_WIDTH = 100


PORT_HOST_WIDTH = 135

PORT_WIDTH = 75

SERVICE_WIDTH = 120

VERSION_WIDTH = 150

RISK_WIDTH = 100


VULN_HOST_WIDTH = 140

VULN_PORT_WIDTH = 70

VULN_SERVICE_WIDTH = 120

VULN_FINDING_WIDTH = 300

VULN_SEVERITY_WIDTH = 100

VULN_CONFIDENCE_WIDTH = 110


# ==============================================================
# COLORS
# ==============================================================

COLOR_BACKGROUND = "#050B14"

COLOR_PANEL = "#0B1728"

COLOR_PANEL_DARK = "#071321"

COLOR_BORDER = "#17324D"

COLOR_BORDER_LIGHT = "#1D3857"

COLOR_CYAN = "#00E5FF"

COLOR_BLUE = "#1683FF"

COLOR_GREEN = "#00E676"

COLOR_YELLOW = "#FFC107"

COLOR_ORANGE = "#FF9800"

COLOR_RED = "#FF3B4E"

COLOR_PURPLE = "#A78BFA"

COLOR_TEXT = "#F1F5F9"

COLOR_SECONDARY = "#94A3B8"

COLOR_MUTED = "#64748B"


# ==============================================================
# NDM SCANNER PAGE
# ==============================================================


class NDMScannerPage(QWidget):

    # ----------------------------------------------------------
    # Signals
    # ----------------------------------------------------------

    start_scan_requested = Signal(dict)

    stop_scan_requested = Signal()

    host_selected = Signal(dict)

    vulnerability_selected = Signal(dict)

    # ==========================================================
    # CONSTRUCTOR
    # ==========================================================

    def __init__(self):

        super().__init__()

        self.setObjectName(
            "ndmScannerPage"
        )

        self.all_hosts = []

        self.all_ports = []

        self.all_vulnerabilities = []

        self.scan_running = False

        self.setup_ui()

        self.load_demo_data()

    # ==========================================================
    # MAIN UI
    # ==========================================================

    def setup_ui(self):

        main_layout = QVBoxLayout(
            self
        )

        main_layout.setContentsMargins(
            0,
            0,
            0,
            0
        )

        main_layout.setSpacing(
            PAGE_SPACING
        )

        # ------------------------------------------------------
        # Header
        # ------------------------------------------------------

        main_layout.addWidget(
            self.create_page_header()
        )

        # ------------------------------------------------------
        # Scanner controls
        # ------------------------------------------------------

        main_layout.addWidget(
            self.create_scan_controls()
        )

        # ------------------------------------------------------
        # Scan status
        # ------------------------------------------------------

        main_layout.addWidget(
            self.create_scan_status()
        )

        # ------------------------------------------------------
        # Main tabs
        # ------------------------------------------------------

        main_layout.addWidget(
            self.create_tabs(),
            1
        )

    # ==========================================================
    # PAGE HEADER
    # ==========================================================

    def create_page_header(self):

        frame = QFrame()

        frame.setFixedHeight(
            HEADER_HEIGHT
        )

        frame.setStyleSheet(
            f"""
            QFrame {{
                background-color: transparent;
                border: none;
            }}
            """
        )

        layout = QVBoxLayout(
            frame
        )

        layout.setContentsMargins(
            4,
            4,
            4,
            2
        )

        layout.setSpacing(
            2
        )

        # ------------------------------------------------------
        # Title
        # ------------------------------------------------------

        title = QLabel(
            "NDM SCANNER"
        )

        title.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT};
                font-size: 22px;
                font-weight: 700;
                letter-spacing: 1px;
            }}
            """
        )

        layout.addWidget(
            title
        )

        # ------------------------------------------------------
        # Subtitle
        # ------------------------------------------------------

        subtitle = QLabel(
            "Network discovery, service analysis and security assessment"
        )

        subtitle.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 11px;
            }}
            """
        )

        layout.addWidget(
            subtitle
        )

        return frame

    # ==========================================================
    # SCAN CONTROLS
    # ==========================================================

    def create_scan_controls(self):

        frame = QFrame()

        frame.setObjectName(
            "scanControls"
        )

        frame.setFixedHeight(
            CONTROL_HEIGHT
        )

        frame.setStyleSheet(
            f"""
            QFrame#scanControls {{
                background-color: {COLOR_PANEL};
                border: 1px solid {COLOR_BORDER};
                border-radius: 7px;
            }}
            """
        )

        layout = QHBoxLayout(
            frame
        )

        layout.setContentsMargins(
            10,
            8,
            10,
            8
        )

        layout.setSpacing(
            8
        )

        # ======================================================
        # NETWORK LABEL
        # ======================================================

        network_label = QLabel(
            "Network:"
        )

        network_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT};
                font-size: 12px;
                font-weight: 600;
            }}
            """
        )

        layout.addWidget(
            network_label
        )

        # ======================================================
        # NETWORK INPUT
        # ======================================================

        self.network_input = QLineEdit()

        self.network_input.setText(
            "192.168.1.0/24"
        )

        self.network_input.setPlaceholderText(
            "Network / CIDR"
        )

        self.network_input.setFixedHeight(
            INPUT_HEIGHT
        )

        self.network_input.setMinimumWidth(
            180
        )

        self.network_input.setStyleSheet(
            f"""
            QLineEdit {{
                background-color: #081321;
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 5px;
                padding: 0 9px;
                font-size: 11px;
            }}

            QLineEdit:focus {{
                border: 1px solid {COLOR_CYAN};
            }}
            """
        )

        layout.addWidget(
            self.network_input
        )

        # ======================================================
        # AUTO BUTTON
        # ======================================================

        self.auto_button = QPushButton(
            "AUTO"
        )

        self.auto_button.setFixedHeight(
            BUTTON_HEIGHT
        )

        self.auto_button.setStyleSheet(
            self.button_style(
                COLOR_BORDER
            )
        )

        self.auto_button.clicked.connect(
            self.auto_detect_network
        )

        layout.addWidget(
            self.auto_button
        )

        # ======================================================
        # SCAN PROFILE
        # ======================================================

        profile_label = QLabel(
            "Profile:"
        )

        profile_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 11px;
            }}
            """
        )

        layout.addWidget(
            profile_label
        )

        self.scan_profile = QComboBox()

        self.scan_profile.addItems(
            [
                "Quick Discovery",
                "Standard Security",
                "Full Network Audit",
                "Vulnerability Assessment",
                "Custom",
            ]
        )

        self.scan_profile.setFixedHeight(
            INPUT_HEIGHT
        )

        self.scan_profile.setMinimumWidth(
            180
        )

        self.scan_profile.setStyleSheet(
            f"""
            QComboBox {{
                background-color: #081321;
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 5px;
                padding-left: 8px;
                font-size: 11px;
            }}

            QComboBox:hover {{
                border: 1px solid {COLOR_CYAN};
            }}

            QComboBox QAbstractItemView {{
                background-color: {COLOR_PANEL};
                color: {COLOR_TEXT};
                selection-background-color: #12345A;
                border: 1px solid {COLOR_BORDER};
            }}
            """
        )

        layout.addWidget(
            self.scan_profile
        )

        # ======================================================
        # SPACER
        # ======================================================

        layout.addStretch()

        # ======================================================
        # START BUTTON
        # ======================================================

        self.start_button = QPushButton(
            "▶  START SCAN"
        )

        self.start_button.setFixedHeight(
            BUTTON_HEIGHT
        )

        self.start_button.setMinimumWidth(
            125
        )

        self.start_button.setStyleSheet(
            self.button_style(
                COLOR_BLUE,
                hover=COLOR_CYAN
            )
        )

        self.start_button.clicked.connect(
            self.start_scan
        )

        layout.addWidget(
            self.start_button
        )

        # ======================================================
        # STOP BUTTON
        # ======================================================

        self.stop_button = QPushButton(
            "■  STOP"
        )

        self.stop_button.setFixedHeight(
            BUTTON_HEIGHT
        )

        self.stop_button.setMinimumWidth(
            85
        )

        self.stop_button.setEnabled(
            False
        )

        self.stop_button.setStyleSheet(
            self.button_style(
                COLOR_RED
            )
        )

        self.stop_button.clicked.connect(
            self.stop_scan
        )

        layout.addWidget(
            self.stop_button
        )

        return frame

    # ==========================================================
    # BUTTON STYLE
    # ==========================================================

    def button_style(
        self,
        background,
        hover=None
    ):

        if hover is None:
            hover = background

        return f"""
        QPushButton {{
            background-color: {background};
            color: {COLOR_TEXT};
            border: 1px solid {background};
            border-radius: 5px;
            padding: 0 12px;
            font-size: 10px;
            font-weight: 700;
        }}

        QPushButton:hover {{
            background-color: {hover};
        }}

        QPushButton:disabled {{
            background-color: #17263B;
            color: {COLOR_MUTED};
            border: 1px solid {COLOR_BORDER};
        }}
        """

    # ==========================================================
    # SCAN STATUS
    # ==========================================================

    def create_scan_status(self):

        frame = QFrame()

        frame.setFixedHeight(
            STATUS_HEIGHT
        )

        frame.setStyleSheet(
            f"""
            QFrame {{
                background-color: {COLOR_PANEL};
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
            8,
            12,
            8
        )

        layout.setSpacing(
            6
        )

        # ======================================================
        # TOP STATUS
        # ======================================================

        top = QHBoxLayout()

        # ------------------------------------------------------
        # Status
        # ------------------------------------------------------

        self.status_label = QLabel(
            "● READY"
        )

        self.status_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_GREEN};
                font-size: 12px;
                font-weight: 700;
            }}
            """
        )

        top.addWidget(
            self.status_label
        )

        top.addStretch()

        # ------------------------------------------------------
        # Hosts
        # ------------------------------------------------------

        self.host_count_label = QLabel(
            "Hosts: 0"
        )

        top.addWidget(
            self.create_status_counter(
                self.host_count_label
            )
        )

        # ------------------------------------------------------
        # Ports
        # ------------------------------------------------------

        self.port_count_label = QLabel(
            "Open Ports: 0"
        )

        top.addWidget(
            self.create_status_counter(
                self.port_count_label
            )
        )

        # ------------------------------------------------------
        # Findings
        # ------------------------------------------------------

        self.finding_count_label = QLabel(
            "Findings: 0"
        )

        top.addWidget(
            self.create_status_counter(
                self.finding_count_label
            )
        )

        # ------------------------------------------------------
        # Risk
        # ------------------------------------------------------

        self.risk_label = QLabel(
            "Risk: LOW"
        )

        self.risk_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_GREEN};
                font-size: 11px;
                font-weight: 700;
                padding-left: 14px;
            }}
            """
        )

        top.addWidget(
            self.risk_label
        )

        layout.addLayout(
            top
        )

        # ======================================================
        # PROGRESS
        # ======================================================

        self.scan_progress = QProgressBar()

        self.scan_progress.setRange(
            0,
            100
        )

        self.scan_progress.setValue(
            0
        )

        self.scan_progress.setTextVisible(
            False
        )

        self.scan_progress.setFixedHeight(
            8
        )

        self.scan_progress.setStyleSheet(
            f"""
            QProgressBar {{
                background-color: #17263B;
                border: none;
                border-radius: 4px;
            }}

            QProgressBar::chunk {{
                background-color: {COLOR_CYAN};
                border-radius: 4px;
            }}
            """
        )

        layout.addWidget(
            self.scan_progress
        )

        return frame

    # ==========================================================
    # STATUS COUNTER
    # ==========================================================

    def create_status_counter(
        self,
        label
    ):

        label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 11px;
                padding-left: 14px;
            }}
            """
        )

        return label

    # ==========================================================
    # TABS
    # ==========================================================

    def create_tabs(self):

        self.tabs = QTabWidget()

        self.tabs.setObjectName(
            "ndmTabs"
        )

        self.tabs.setStyleSheet(
            f"""
            QTabWidget::pane {{
                background-color: {COLOR_PANEL};
                border: 1px solid {COLOR_BORDER};
                border-radius: 7px;
                top: -1px;
            }}

            QTabBar::tab {{
                background-color: #081321;
                color: {COLOR_SECONDARY};
                border: 1px solid {COLOR_BORDER};
                padding: 8px 15px;
                margin-right: 2px;
                font-size: 10px;
            }}

            QTabBar::tab:selected {{
                background-color: {COLOR_PANEL};
                color: {COLOR_CYAN};
                border-bottom-color: {COLOR_PANEL};
            }}

            QTabBar::tab:hover {{
                color: {COLOR_TEXT};
            }}
            """
        )

        # ------------------------------------------------------
        # Dashboard
        # ------------------------------------------------------

        self.tabs.addTab(
            self.create_dashboard_tab(),
            "Dashboard"
        )

        # ------------------------------------------------------
        # Hosts
        # ------------------------------------------------------

        self.tabs.addTab(
            self.create_hosts_tab(),
            "Hosts"
        )

        # ------------------------------------------------------
        # Ports
        # ------------------------------------------------------

        self.tabs.addTab(
            self.create_ports_tab(),
            "Ports"
        )

        # ------------------------------------------------------
        # Vulnerabilities
        # ------------------------------------------------------

        self.tabs.addTab(
            self.create_vulnerabilities_tab(),
            "Vulnerabilities"
        )

        # ------------------------------------------------------
        # Topology
        # ------------------------------------------------------

        self.tabs.addTab(
            self.create_topology_tab(),
            "Topology"
        )

        # ------------------------------------------------------
        # Reports
        # ------------------------------------------------------

        self.tabs.addTab(
            self.create_reports_tab(),
            "Reports"
        )

        return self.tabs

    # ==========================================================
    # DASHBOARD TAB
    # ==========================================================

    def create_dashboard_tab(self):

        widget = QWidget()

        layout = QVBoxLayout(
            widget
        )

        layout.setContentsMargins(
            12,
            12,
            12,
            12
        )

        layout.setSpacing(
            10
        )

        # ======================================================
        # METRICS
        # ======================================================

        metrics = QHBoxLayout()

        metrics.setSpacing(
            8
        )

        self.device_metric = (
            self.create_metric_card(
                "DEVICES",
                "0",
                COLOR_CYAN
            )
        )

        self.open_port_metric = (
            self.create_metric_card(
                "OPEN PORTS",
                "0",
                COLOR_BLUE
            )
        )

        self.high_metric = (
            self.create_metric_card(
                "HIGH RISK",
                "0",
                COLOR_RED
            )
        )

        self.medium_metric = (
            self.create_metric_card(
                "MEDIUM RISK",
                "0",
                COLOR_YELLOW
            )
        )

        self.score_metric = (
            self.create_metric_card(
                "SECURITY SCORE",
                "100",
                COLOR_GREEN
            )
        )

        metrics.addWidget(
            self.device_metric
        )

        metrics.addWidget(
            self.open_port_metric
        )

        metrics.addWidget(
            self.high_metric
        )

        metrics.addWidget(
            self.medium_metric
        )

        metrics.addWidget(
            self.score_metric
        )

        layout.addLayout(
            metrics
        )

        # ======================================================
        # SECURITY SCORE PANEL
        # ======================================================

        score_panel = QFrame()

        score_panel.setStyleSheet(
            f"""
            QFrame {{
                background-color: {COLOR_PANEL_DARK};
                border: 1px solid {COLOR_BORDER};
                border-radius: 7px;
            }}
            """
        )

        score_layout = QHBoxLayout(
            score_panel
        )

        score_layout.setContentsMargins(
            16,
            12,
            16,
            12
        )

        # ------------------------------------------------------
        # Score
        # ------------------------------------------------------

        score_title = QLabel(
            "NETWORK SECURITY SCORE"
        )

        score_title.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 11px;
                font-weight: 600;
            }}
            """
        )

        score_layout.addWidget(
            score_title
        )

        score_layout.addStretch()

        self.large_score = QLabel(
            "100 / 100"
        )

        self.large_score.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_GREEN};
                font-size: 26px;
                font-weight: 700;
            }}
            """
        )

        score_layout.addWidget(
            self.large_score
        )

        self.large_score_status = QLabel(
            " SAFE"
        )

        self.large_score_status.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_GREEN};
                font-size: 12px;
                font-weight: 700;
            }}
            """
        )

        score_layout.addWidget(
            self.large_score_status
        )

        layout.addWidget(
            score_panel
        )

        # ======================================================
        # FINDINGS SUMMARY
        # ======================================================

        findings_title = QLabel(
            "SECURITY FINDINGS"
        )

        findings_title.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_CYAN};
                font-size: 11px;
                font-weight: 700;
                padding-top: 5px;
            }}
            """
        )

        layout.addWidget(
            findings_title
        )

        self.summary_label = QLabel(
            "No security findings detected."
        )

        self.summary_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 11px;
                padding: 8px;
                background-color: {COLOR_PANEL_DARK};
                border: 1px solid {COLOR_BORDER};
                border-radius: 6px;
            }}
            """
        )

        self.summary_label.setWordWrap(
            True
        )

        layout.addWidget(
            self.summary_label
        )

        layout.addStretch()

        return widget

    # ==========================================================
    # METRIC CARD
    # ==========================================================

    def create_metric_card(
        self,
        title,
        value,
        accent
    ):

        card = QFrame()

        card.setMinimumHeight(
            78
        )

        card.setStyleSheet(
            f"""
            QFrame {{
                background-color: {COLOR_PANEL_DARK};
                border: 1px solid {COLOR_BORDER};
                border-radius: 7px;
            }}
            """
        )

        layout = QVBoxLayout(
            card
        )

        layout.setContentsMargins(
            12,
            8,
            12,
            8
        )

        layout.setSpacing(
            3
        )

        title_label = QLabel(
            title
        )

        title_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 9px;
                font-weight: 600;
            }}
            """
        )

        layout.addWidget(
            title_label
        )

        value_label = QLabel(
            value
        )

        value_label.setStyleSheet(
            f"""
            QLabel {{
                color: {accent};
                font-size: 22px;
                font-weight: 700;
            }}
            """
        )

        layout.addWidget(
            value_label
        )

        card.value_label = value_label

        return card

    # ==========================================================
    # HOSTS TAB
    # ==========================================================

    def create_hosts_tab(self):

        widget = QWidget()

        layout = QVBoxLayout(
            widget
        )

        layout.setContentsMargins(
            10,
            10,
            10,
            10
        )

        title = QLabel(
            "DISCOVERED HOSTS"
        )

        title.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_CYAN};
                font-size: 11px;
                font-weight: 700;
            }}
            """
        )

        layout.addWidget(
            title
        )

        self.host_table = QTableWidget()

        self.host_table.setColumnCount(
            6
        )

        self.host_table.setHorizontalHeaderLabels(
            [
                "IP Address",
                "Hostname",
                "MAC Address",
                "Vendor",
                "Status",
                "Latency",
            ]
        )

        self.configure_table(
            self.host_table
        )

        widths = [
            HOST_IP_WIDTH,
            HOSTNAME_WIDTH,
            MAC_WIDTH,
            VENDOR_WIDTH,
            STATUS_WIDTH,
            LATENCY_WIDTH,
        ]

        for index, width in enumerate(
            widths
        ):

            self.host_table.setColumnWidth(
                index,
                width
            )

        self.host_table.itemSelectionChanged.connect(
            self.on_host_selected
        )

        layout.addWidget(
            self.host_table
        )

        return widget

    # ==========================================================
    # PORTS TAB
    # ==========================================================

    def create_ports_tab(self):

        widget = QWidget()

        layout = QVBoxLayout(
            widget
        )

        layout.setContentsMargins(
            10,
            10,
            10,
            10
        )

        title = QLabel(
            "OPEN SERVICES & PORTS"
        )

        title.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_CYAN};
                font-size: 11px;
                font-weight: 700;
            }}
            """
        )

        layout.addWidget(
            title
        )

        self.port_table = QTableWidget()

        self.port_table.setColumnCount(
            5
        )

        self.port_table.setHorizontalHeaderLabels(
            [
                "Host",
                "Port",
                "Service",
                "Version",
                "Risk",
            ]
        )

        self.configure_table(
            self.port_table
        )

        widths = [
            PORT_HOST_WIDTH,
            PORT_WIDTH,
            SERVICE_WIDTH,
            VERSION_WIDTH,
            RISK_WIDTH,
        ]

        for index, width in enumerate(
            widths
        ):

            self.port_table.setColumnWidth(
                index,
                width
            )

        layout.addWidget(
            self.port_table
        )

        return widget

    # ==========================================================
    # VULNERABILITIES TAB
    # ==========================================================

    def create_vulnerabilities_tab(self):

        widget = QWidget()

        layout = QVBoxLayout(
            widget
        )

        layout.setContentsMargins(
            10,
            10,
            10,
            10
        )

        # ------------------------------------------------------
        # Header
        # ------------------------------------------------------

        header = QHBoxLayout()

        title = QLabel(
            "VULNERABILITY ASSESSMENT"
        )

        title.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_CYAN};
                font-size: 11px;
                font-weight: 700;
            }}
            """
        )

        header.addWidget(
            title
        )

        header.addStretch()

        self.critical_count = QLabel(
            "CRITICAL 0"
        )

        self.high_count = QLabel(
            "HIGH 0"
        )

        self.medium_count = QLabel(
            "MEDIUM 0"
        )

        self.low_count = QLabel(
            "LOW 0"
        )

        self.set_severity_style(
            self.critical_count,
            COLOR_RED
        )

        self.set_severity_style(
            self.high_count,
            COLOR_ORANGE
        )

        self.set_severity_style(
            self.medium_count,
            COLOR_YELLOW
        )

        self.set_severity_style(
            self.low_count,
            COLOR_GREEN
        )

        header.addWidget(
            self.critical_count
        )

        header.addWidget(
            self.high_count
        )

        header.addWidget(
            self.medium_count
        )

        header.addWidget(
            self.low_count
        )

        layout.addLayout(
            header
        )

        # ------------------------------------------------------
        # Vulnerability table
        # ------------------------------------------------------

        self.vulnerability_table = QTableWidget()

        self.vulnerability_table.setColumnCount(
            6
        )

        self.vulnerability_table.setHorizontalHeaderLabels(
            [
                "Host",
                "Port",
                "Service",
                "Finding",
                "Severity",
                "Confidence",
            ]
        )

        self.configure_table(
            self.vulnerability_table
        )

        widths = [
            VULN_HOST_WIDTH,
            VULN_PORT_WIDTH,
            VULN_SERVICE_WIDTH,
            VULN_FINDING_WIDTH,
            VULN_SEVERITY_WIDTH,
            VULN_CONFIDENCE_WIDTH,
        ]

        for index, width in enumerate(
            widths
        ):

            self.vulnerability_table.setColumnWidth(
                index,
                width
            )

        self.vulnerability_table.itemSelectionChanged.connect(
            self.on_vulnerability_selected
        )

        layout.addWidget(
            self.vulnerability_table
        )

        return widget

    # ==========================================================
    # TOPOLOGY TAB
    # ==========================================================

    def create_topology_tab(self):

        widget = QWidget()

        layout = QVBoxLayout(
            widget
        )

        layout.setContentsMargins(
            15,
            15,
            15,
            15
        )

        title = QLabel(
            "NETWORK TOPOLOGY"
        )

        title.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_CYAN};
                font-size: 12px;
                font-weight: 700;
            }}
            """
        )

        layout.addWidget(
            title
        )

        topology = QFrame()

        topology.setStyleSheet(
            f"""
            QFrame {{
                background-color: {COLOR_PANEL_DARK};
                border: 1px solid {COLOR_BORDER};
                border-radius: 8px;
            }}
            """
        )

        topology_layout = QVBoxLayout(
            topology
        )

        topology_layout.setAlignment(
            Qt.AlignCenter
        )

        # ------------------------------------------------------
        # Internet
        # ------------------------------------------------------

        internet = self.create_topology_node(
            "INTERNET",
            COLOR_PURPLE
        )

        topology_layout.addWidget(
            internet,
            alignment=Qt.AlignCenter
        )

        arrow1 = QLabel(
            "│\n▼"
        )

        arrow1.setAlignment(
            Qt.AlignCenter
        )

        arrow1.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_CYAN};
                font-size: 15px;
            }}
            """
        )

        topology_layout.addWidget(
            arrow1
        )

        # ------------------------------------------------------
        # Router
        # ------------------------------------------------------

        router = self.create_topology_node(
            "ROUTER\n192.168.1.1",
            COLOR_CYAN
        )

        topology_layout.addWidget(
            router,
            alignment=Qt.AlignCenter
        )

        arrow2 = QLabel(
            "│\n▼"
        )

        arrow2.setAlignment(
            Qt.AlignCenter
        )

        arrow2.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_CYAN};
                font-size: 15px;
            }}
            """
        )

        topology_layout.addWidget(
            arrow2
        )

        # ------------------------------------------------------
        # Devices
        # ------------------------------------------------------

        devices = QHBoxLayout()

        for name, ip, color in [
            (
                "LAPTOP",
                "192.168.1.10",
                COLOR_GREEN
            ),
            (
                "DESKTOP",
                "192.168.1.12",
                COLOR_BLUE
            ),
            (
                "PRINTER",
                "192.168.1.20",
                COLOR_YELLOW
            ),
        ]:

            devices.addWidget(
                self.create_topology_node(
                    f"{name}\n{ip}",
                    color
                )
            )

        topology_layout.addLayout(
            devices
        )

        layout.addWidget(
            topology,
            1
        )

        return widget

    # ==========================================================
    # TOPOLOGY NODE
    # ==========================================================

    def create_topology_node(
        self,
        text,
        color
    ):

        node = QLabel(
            text
        )

        node.setAlignment(
            Qt.AlignCenter
        )

        node.setMinimumSize(
            150,
            55
        )

        node.setStyleSheet(
            f"""
            QLabel {{
                background-color: #081321;
                color: {color};
                border: 1px solid {color};
                border-radius: 7px;
                font-size: 10px;
                font-weight: 700;
                padding: 8px;
            }}
            """
        )

        return node

    # ==========================================================
    # REPORTS TAB
    # ==========================================================

    def create_reports_tab(self):

        widget = QWidget()

        layout = QVBoxLayout(
            widget
        )

        layout.setContentsMargins(
            15,
            15,
            15,
            15
        )

        title = QLabel(
            "SECURITY REPORT"
        )

        title.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_CYAN};
                font-size: 12px;
                font-weight: 700;
            }}
            """
        )

        layout.addWidget(
            title
        )

        report = QFrame()

        report.setStyleSheet(
            f"""
            QFrame {{
                background-color: {COLOR_PANEL_DARK};
                border: 1px solid {COLOR_BORDER};
                border-radius: 8px;
            }}
            """
        )

        report_layout = QVBoxLayout(
            report
        )

        report_layout.setContentsMargins(
            18,
            18,
            18,
            18
        )

        self.report_text = QLabel()

        self.report_text.setText(
            """
NDM SECURITY ASSESSMENT

Target Network:
192.168.1.0/24

Hosts Discovered:
0

Open Ports:
0

Security Findings:
0

Critical:
0

High:
0

Medium:
0

Low:
0

Security Score:
100 / 100

Status:
SAFE

The final report will be generated after
a real scanner run.
            """
        )

        self.report_text.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT};
                font-size: 12px;
                line-height: 1.5;
            }}
            """
        )

        report_layout.addWidget(
            self.report_text
        )

        report_layout.addStretch()

        # ------------------------------------------------------
        # Export buttons
        # ------------------------------------------------------

        buttons = QHBoxLayout()

        buttons.addStretch()

        pdf_button = QPushButton(
            "EXPORT PDF"
        )

        json_button = QPushButton(
            "EXPORT JSON"
        )

        csv_button = QPushButton(
            "EXPORT CSV"
        )

        for button in [
            pdf_button,
            json_button,
            csv_button,
        ]:

            button.setFixedHeight(
                BUTTON_HEIGHT
            )

            button.setStyleSheet(
                self.button_style(
                    COLOR_BORDER
                )
            )

            buttons.addWidget(
                button
            )

        report_layout.addLayout(
            buttons
        )

        layout.addWidget(
            report,
            1
        )

        return widget

    # ==========================================================
    # TABLE CONFIGURATION
    # ==========================================================

    def configure_table(
        self,
        table
    ):

        table.setMinimumHeight(
            TABLE_MIN_HEIGHT
        )

        table.setEditTriggers(
            QAbstractItemView.NoEditTriggers
        )

        table.setSelectionBehavior(
            QAbstractItemView.SelectRows
        )

        table.setSelectionMode(
            QAbstractItemView.SingleSelection
        )

        table.verticalHeader().setVisible(
            False
        )

        table.verticalHeader().setDefaultSectionSize(
            TABLE_ROW_HEIGHT
        )

        table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Interactive
        )

        table.setVerticalScrollBarPolicy(
            Qt.ScrollBarAsNeeded
        )

        table.setHorizontalScrollBarPolicy(
            Qt.ScrollBarAsNeeded
        )

        table.setStyleSheet(
            f"""
            QTableWidget {{
                background-color: {COLOR_PANEL};
                color: {COLOR_TEXT};
                border: none;
                gridline-color: {COLOR_BORDER};
                font-size: 11px;
                selection-background-color: #12345A;
                selection-color: {COLOR_TEXT};
            }}

            QTableWidget::item {{
                padding-left: 8px;
                padding-right: 8px;
                border-bottom: 1px solid {COLOR_BORDER};
            }}

            QTableWidget::item:selected {{
                background-color: #12345A;
            }}

            QHeaderView::section {{
                background-color: #0A1627;
                color: {COLOR_CYAN};
                border: none;
                border-bottom: 1px solid {COLOR_BORDER};
                padding: 8px;
                font-size: 10px;
                font-weight: 700;
            }}

            QScrollBar:vertical {{
                background: #081321;
                width: 8px;
            }}

            QScrollBar::handle:vertical {{
                background: #214968;
                border-radius: 4px;
                min-height: 35px;
            }}

            QScrollBar:horizontal {{
                background: #081321;
                height: 8px;
            }}

            QScrollBar::handle:horizontal {{
                background: #214968;
                border-radius: 4px;
                min-width: 50px;
            }}

            QScrollBar::add-line,
            QScrollBar::sub-line {{
                width: 0px;
                height: 0px;
            }}
            """
        )

    # ==========================================================
    # SEVERITY STYLE
    # ==========================================================

    def set_severity_style(
        self,
        label,
        color
    ):

        label.setStyleSheet(
            f"""
            QLabel {{
                color: {color};
                font-size: 10px;
                font-weight: 700;
                padding-left: 12px;
            }}
            """
        )

    # ==========================================================
    # AUTO NETWORK DETECTION
    # ==========================================================

    def auto_detect_network(self):

        # ------------------------------------------------------
        # Backend will provide the real CIDR later.
        # ------------------------------------------------------

        self.network_input.setText(
            "192.168.1.0/24"
        )

        self.status_label.setText(
            "● NETWORK DETECTED"
        )

        self.status_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_CYAN};
                font-size: 12px;
                font-weight: 700;
            }}
            """
        )

    # ==========================================================
    # START SCAN
    # ==========================================================

    def start_scan(self):

        target = (
            self.network_input.text()
            .strip()
        )

        profile = (
            self.scan_profile.currentText()
        )

        if not target:

            QMessageBox.warning(
                self,
                "NDM Scanner",
                "Please enter a target network."
            )

            return

        # ------------------------------------------------------
        # UI state
        # ------------------------------------------------------

        self.scan_running = True

        self.start_button.setEnabled(
            False
        )

        self.stop_button.setEnabled(
            True
        )

        self.status_label.setText(
            "● SCANNING"
        )

        self.status_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_CYAN};
                font-size: 12px;
                font-weight: 700;
            }}
            """
        )

        self.scan_progress.setValue(
            5
        )

        # ------------------------------------------------------
        # Send request to backend later.
        # ------------------------------------------------------

        self.start_scan_requested.emit(
            {
                "target": target,
                "profile": profile,
            }
        )

    # ==========================================================
    # STOP SCAN
    # ==========================================================

    def stop_scan(self):

        self.scan_running = False

        self.start_button.setEnabled(
            True
        )

        self.stop_button.setEnabled(
            False
        )

        self.status_label.setText(
            "● SCAN STOPPED"
        )

        self.status_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_YELLOW};
                font-size: 12px;
                font-weight: 700;
            }}
            """
        )

        self.stop_scan_requested.emit()

    # ==========================================================
    # UPDATE SCAN PROGRESS
    # ==========================================================

    def update_progress(
        self,
        value
    ):

        value = max(
            0,
            min(
                100,
                int(value)
            )
        )

        self.scan_progress.setValue(
            value
        )

    # ==========================================================
    # SCAN FINISHED
    # ==========================================================

    def scan_finished(self):

        self.scan_running = False

        self.start_button.setEnabled(
            True
        )

        self.stop_button.setEnabled(
            False
        )

        self.scan_progress.setValue(
            100
        )

        self.status_label.setText(
            "● SCAN COMPLETE"
        )

        self.status_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_GREEN};
                font-size: 12px;
                font-weight: 700;
            }}
            """
        )

    # ==========================================================
    # LOAD HOSTS
    # ==========================================================

    def set_hosts(
        self,
        hosts
    ):

        self.all_hosts = list(
            hosts
        )

        self.host_table.setRowCount(
            0
        )

        for row, host in enumerate(
            self.all_hosts
        ):

            self.host_table.insertRow(
                row
            )

            values = [
                host.get(
                    "ip",
                    "-"
                ),
                host.get(
                    "hostname",
                    "-"
                ),
                host.get(
                    "mac",
                    "-"
                ),
                host.get(
                    "vendor",
                    "-"
                ),
                host.get(
                    "status",
                    "UNKNOWN"
                ),
                host.get(
                    "latency",
                    "-"
                ),
            ]

            for column, value in enumerate(
                values
            ):

                item = QTableWidgetItem(
                    str(value)
                )

                item.setTextAlignment(
                    Qt.AlignCenter
                )

                self.host_table.setItem(
                    row,
                    column,
                    item
                )

        self.host_count_label.setText(
            f"Hosts: {len(self.all_hosts)}"
        )

        self.device_metric.value_label.setText(
            str(len(self.all_hosts))
        )

    # ==========================================================
    # LOAD PORTS
    # ==========================================================

    def set_ports(
        self,
        ports
    ):

        self.all_ports = list(
            ports
        )

        self.port_table.setRowCount(
            0
        )

        for row, port_data in enumerate(
            self.all_ports
        ):

            self.port_table.insertRow(
                row
            )

            values = [
                port_data.get(
                    "host",
                    "-"
                ),
                port_data.get(
                    "port",
                    "-"
                ),
                port_data.get(
                    "service",
                    "-"
                ),
                port_data.get(
                    "version",
                    "-"
                ),
                port_data.get(
                    "risk",
                    "LOW"
                ),
            ]

            for column, value in enumerate(
                values
            ):

                item = QTableWidgetItem(
                    str(value)
                )

                item.setTextAlignment(
                    Qt.AlignCenter
                )

                if column == 4:

                    risk = str(
                        value
                    ).upper()

                    if risk == "HIGH":

                        item.setForeground(
                            Qt.GlobalColor.red
                        )

                    elif risk == "MEDIUM":

                        item.setForeground(
                            Qt.GlobalColor.yellow
                        )

                    else:

                        item.setForeground(
                            Qt.GlobalColor.green
                        )

                self.port_table.setItem(
                    row,
                    column,
                    item
                )

        self.port_count_label.setText(
            f"Open Ports: {len(self.all_ports)}"
        )

        self.open_port_metric.value_label.setText(
            str(len(self.all_ports))
        )

    # ==========================================================
    # LOAD VULNERABILITIES
    # ==========================================================

    def set_vulnerabilities(
        self,
        vulnerabilities
    ):

        self.all_vulnerabilities = list(
            vulnerabilities
        )

        self.vulnerability_table.setRowCount(
            0
        )

        critical = 0
        high = 0
        medium = 0
        low = 0

        for row, vuln in enumerate(
            self.all_vulnerabilities
        ):

            self.vulnerability_table.insertRow(
                row
            )

            severity = str(
                vuln.get(
                    "severity",
                    "LOW"
                )
            ).upper()

            if severity == "CRITICAL":
                critical += 1

            elif severity == "HIGH":
                high += 1

            elif severity == "MEDIUM":
                medium += 1

            else:
                low += 1

            values = [
                vuln.get(
                    "host",
                    "-"
                ),
                vuln.get(
                    "port",
                    "-"
                ),
                vuln.get(
                    "service",
                    "-"
                ),
                vuln.get(
                    "finding",
                    "-"
                ),
                severity,
                vuln.get(
                    "confidence",
                    "Medium"
                ),
            ]

            for column, value in enumerate(
                values
            ):

                item = QTableWidgetItem(
                    str(value)
                )

                if column != 3:

                    item.setTextAlignment(
                        Qt.AlignCenter
                    )

                if column == 4:

                    if severity == "CRITICAL":

                        item.setForeground(
                            Qt.GlobalColor.red
                        )

                    elif severity == "HIGH":

                        item.setForeground(
                            Qt.GlobalColor.red
                        )

                    elif severity == "MEDIUM":

                        item.setForeground(
                            Qt.GlobalColor.yellow
                        )

                    else:

                        item.setForeground(
                            Qt.GlobalColor.green
                        )

                self.vulnerability_table.setItem(
                    row,
                    column,
                    item
                )

        # ------------------------------------------------------
        # Update counters
        # ------------------------------------------------------

        self.critical_count.setText(
            f"CRITICAL {critical}"
        )

        self.high_count.setText(
            f"HIGH {high}"
        )

        self.medium_count.setText(
            f"MEDIUM {medium}"
        )

        self.low_count.setText(
            f"LOW {low}"
        )

        self.finding_count_label.setText(
            f"Findings: {len(self.all_vulnerabilities)}"
        )

        self.finding_count_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 11px;
                padding-left: 14px;
            }}
            """
        )

        # ------------------------------------------------------
        # Dashboard metrics
        # ------------------------------------------------------

        self.high_metric.value_label.setText(
            str(
                critical + high
            )
        )

        self.medium_metric.value_label.setText(
            str(medium)
        )

        # ------------------------------------------------------
        # Risk calculation
        # ------------------------------------------------------

        self.calculate_risk_score(
            critical,
            high,
            medium,
            low
        )

    # ==========================================================
    # RISK SCORE
    # ==========================================================

    def calculate_risk_score(
        self,
        critical,
        high,
        medium,
        low
    ):

        penalty = (
            critical * 30
            + high * 15
            + medium * 7
            + low * 2
        )

        score = max(
            0,
            100 - penalty
        )

        self.score_metric.value_label.setText(
            str(score)
        )

        self.large_score.setText(
            f"{score} / 100"
        )

        # ------------------------------------------------------
        # Risk classification
        # ------------------------------------------------------

        if score < 20:

            risk = "CRITICAL"
            color = COLOR_RED

        elif score < 40:

            risk = "HIGH"
            color = COLOR_RED

        elif score < 60:

            risk = "MEDIUM"
            color = COLOR_YELLOW

        elif score < 80:

            risk = "LOW"
            color = COLOR_GREEN

        else:

            risk = "SAFE"
            color = COLOR_GREEN

        self.risk_label.setText(
            f"Risk: {risk}"
        )

        self.risk_label.setStyleSheet(
            f"""
            QLabel {{
                color: {color};
                font-size: 11px;
                font-weight: 700;
                padding-left: 14px;
            }}
            """
        )

        self.large_score.setStyleSheet(
            f"""
            QLabel {{
                color: {color};
                font-size: 26px;
                font-weight: 700;
            }}
            """
        )

        self.large_score_status.setText(
            f" {risk}"
        )

        self.large_score_status.setStyleSheet(
            f"""
            QLabel {{
                color: {color};
                font-size: 12px;
                font-weight: 700;
            }}
            """
        )

        self.score_metric.value_label.setStyleSheet(
            f"""
            QLabel {{
                color: {color};
                font-size: 22px;
                font-weight: 700;
            }}
            """
        )

    # ==========================================================
    # HOST SELECTION
    # ==========================================================

    def on_host_selected(self):

        selected = (
            self.host_table.selectedItems()
        )

        if not selected:

            return

        row = selected[0].row()

        if row < len(
            self.all_hosts
        ):

            self.host_selected.emit(
                self.all_hosts[row]
            )

    # ==========================================================
    # VULNERABILITY SELECTION
    # ==========================================================

    def on_vulnerability_selected(self):

        selected = (
            self.vulnerability_table.selectedItems()
        )

        if not selected:

            return

        row = selected[0].row()

        if row < len(
            self.all_vulnerabilities
        ):

            self.vulnerability_selected.emit(
                self.all_vulnerabilities[row]
            )

    # ==========================================================
    # LOAD DEMO DATA
    # ==========================================================

    def load_demo_data(self):

        # ------------------------------------------------------
        # Hosts
        # ------------------------------------------------------

        hosts = [

            {
                "ip": "192.168.1.1",
                "hostname": "router",
                "mac": "AA:BB:CC:11:22:33",
                "vendor": "TP-Link",
                "status": "ONLINE",
                "latency": "1.8 ms",
            },

            {
                "ip": "192.168.1.10",
                "hostname": "desktop",
                "mac": "AA:BB:CC:22:33:44",
                "vendor": "Dell",
                "status": "ONLINE",
                "latency": "2.4 ms",
            },

            {
                "ip": "192.168.1.12",
                "hostname": "laptop",
                "mac": "AA:BB:CC:33:44:55",
                "vendor": "Lenovo",
                "status": "ONLINE",
                "latency": "2.1 ms",
            },

            {
                "ip": "192.168.1.20",
                "hostname": "printer",
                "mac": "AA:BB:CC:44:55:66",
                "vendor": "HP",
                "status": "ONLINE",
                "latency": "5.2 ms",
            },
        ]

        self.set_hosts(
            hosts
        )

        # ------------------------------------------------------
        # Ports
        # ------------------------------------------------------

        ports = [

            {
                "host": "192.168.1.1",
                "port": 80,
                "service": "HTTP",
                "version": "Unknown",
                "risk": "LOW",
            },

            {
                "host": "192.168.1.1",
                "port": 443,
                "service": "HTTPS",
                "version": "Unknown",
                "risk": "LOW",
            },

            {
                "host": "192.168.1.12",
                "port": 445,
                "service": "SMB",
                "version": "Microsoft",
                "risk": "HIGH",
            },

            {
                "host": "192.168.1.12",
                "port": 3389,
                "service": "RDP",
                "version": "Microsoft",
                "risk": "HIGH",
            },

            {
                "host": "192.168.1.20",
                "port": 80,
                "service": "HTTP",
                "version": "Printer Web",
                "risk": "MEDIUM",
            },
        ]

        self.set_ports(
            ports
        )

        # ------------------------------------------------------
        # Vulnerabilities
        # ------------------------------------------------------

        vulnerabilities = [

            {
                "host": "192.168.1.12",
                "port": 445,
                "service": "SMB",
                "finding": (
                    "SMB service is exposed on the network"
                ),
                "severity": "HIGH",
                "confidence": "Medium",
            },

            {
                "host": "192.168.1.12",
                "port": 3389,
                "service": "RDP",
                "finding": (
                    "Remote Desktop service is exposed"
                ),
                "severity": "HIGH",
                "confidence": "Medium",
            },

            {
                "host": "192.168.1.20",
                "port": 80,
                "service": "HTTP",
                "finding": (
                    "Web management interface is using HTTP"
                ),
                "severity": "MEDIUM",
                "confidence": "High",
            },

            {
                "host": "192.168.1.20",
                "port": 21,
                "service": "FTP",
                "finding": (
                    "Insecure FTP service detected"
                ),
                "severity": "MEDIUM",
                "confidence": "High",
            },
        ]

        self.set_vulnerabilities(
            vulnerabilities
        )

        # ------------------------------------------------------
        # Summary
        # ------------------------------------------------------

        self.summary_label.setText(
            "4 potential security findings detected. "
            "Two high-risk exposed services require attention. "
            "Findings are assessment indicators and require "
            "service/version verification before treating them "
            "as confirmed vulnerabilities."
        )

        # ------------------------------------------------------
        # Report
        # ------------------------------------------------------

        self.update_report()

    # ==========================================================
    # UPDATE REPORT
    # ==========================================================

    def update_report(self):

        score = (
            self.score_metric.value_label.text()
        )

        self.report_text.setText(
            f"""
NDM SECURITY ASSESSMENT

Target Network:
{self.network_input.text()}

Hosts Discovered:
{len(self.all_hosts)}

Open Ports:
{len(self.all_ports)}

Security Findings:
{len(self.all_vulnerabilities)}

Critical:
{self.critical_count.text().split()[-1]}

High:
{self.high_count.text().split()[-1]}

Medium:
{self.medium_count.text().split()[-1]}

Low:
{self.low_count.text().split()[-1]}

Security Score:
{score} / 100

Risk:
{self.risk_label.text().replace("Risk: ", "")}

Status:
Assessment ready.
            """
        )


# ==============================================================
# END OF NDM_SCANNER.PY
# ==============================================================