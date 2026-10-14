# ============================================================
# NDM SCANNER
# Network Defense Monitor
# UI ONLY
# ============================================================

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QPushButton,
    QLineEdit,
    QComboBox,
    QProgressBar,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QFrame,
    QTextEdit,
    QSpinBox,
    QScrollArea,
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
COLOR_ORANGE = "#F97316"
COLOR_RED = "#DC2626"
COLOR_PURPLE = "#A78BFA"

COLOR_TEXT = "#E5E7EB"
COLOR_SECONDARY = "#94A3B8"
COLOR_MUTED = "#64748B"


# ============================================================
# NDM SCANNER PAGE
# ============================================================

class NDMScannerPage(QWidget):

    start_scan_requested = Signal(dict)
    stop_scan_requested = Signal()

    host_selected = Signal(dict)
    vulnerability_selected = Signal(dict)

    # ========================================================
    # INITIALIZE
    # ========================================================

    def __init__(self, parent=None):

        super().__init__(parent)

        self.hosts = []
        self.ports = []
        self.services = []
        self.vulnerabilities = []
        self.threat_intelligence = []

        self.setup_ui()

        self.load_demo_data()

    # ========================================================
    # MAIN UI
    # ========================================================

    def setup_ui(self):

        self.setObjectName(
            "NDMScannerPage"
        )
        self.setAutoFillBackground(True)
        page_palette = self.palette()
        page_palette.setColor(page_palette.ColorRole.Window, QColor(COLOR_BG))
        page_palette.setColor(page_palette.ColorRole.Base, QColor(COLOR_BG))
        page_palette.setColor(page_palette.ColorRole.Text, QColor(COLOR_TEXT))
        self.setPalette(page_palette)

        # UI-only page theme: style native widgets that otherwise use
        # Windows' bright default palette (text areas, inputs, tables).
        self.setStyleSheet("""
            QWidget#NDMScannerPage {
                background-color: #0B1120;
                color: #E5E7EB;
                font-family: "Segoe UI";
                font-size: 10px;
            }
            QWidget#NDMScannerPage QWidget {
                color: #E5E7EB;
            }
            QWidget#NDMScannerPage,
            QWidget#NDMScannerPage QWidget,
            QWidget#NDMScannerPage QTabWidget,
            QWidget#NDMScannerPage QTabWidget::widget,
            QWidget#NDMScannerPage QStackedWidget,
            QWidget#NDMScannerPage QScrollArea,
            QWidget#NDMScannerPage QScrollArea > QWidget,
            QWidget#NDMScannerPage QScrollArea > QWidget > QWidget {
                background-color: #0B1120;
            }
            QWidget#NDMScannerPage QFrame {
                color: #E5E7EB;
            }
            QWidget#NDMScannerPage QLabel {
                background-color: transparent;
            }
            QWidget#NDMScannerPage QToolTip {
                background-color: #172033;
                color: #E5E7EB;
                border: 1px solid #334155;
                padding: 5px;
            }
            QWidget#NDMScannerPage QScrollArea,
            QWidget#NDMScannerPage QScrollArea > QWidget > QWidget {
                background-color: #0B1120;
                border: none;
            }
            QWidget#NDMScannerPage QTextEdit {
                background-color: #0F172A;
                color: #E5E7EB;
            }
            QWidget#NDMScannerPage QLineEdit,
            QWidget#NDMScannerPage QComboBox,
            QWidget#NDMScannerPage QSpinBox,
            QWidget#NDMScannerPage QTextEdit,
            QWidget#NDMScannerPage QPlainTextEdit {
                background-color: #0F172A;
                color: #E5E7EB;
                border: 1px solid #263449;
                border-radius: 5px;
                padding: 5px;
                selection-background-color: #2563EB;
                selection-color: #FFFFFF;
            }
            QWidget#NDMScannerPage QComboBox QAbstractItemView {
                background-color: #111827;
                color: #E5E7EB;
                border: 1px solid #334155;
                selection-background-color: #2563EB;
                selection-color: #FFFFFF;
            }
            QWidget#NDMScannerPage QTableWidget {
                background-color: #0F172A;
                alternate-background-color: #111827;
                color: #E5E7EB;
                gridline-color: #263449;
                border: 1px solid #263449;
                selection-background-color: #1D4ED8;
                selection-color: #FFFFFF;
                outline: 0;
            }
            QWidget#NDMScannerPage QTableWidget::item {
                padding: 5px;
                border-bottom: 1px solid #1F2937;
            }
            QWidget#NDMScannerPage QHeaderView::section {
                background-color: #172033;
                color: #93C5FD;
                border: 1px solid #263449;
                padding: 7px 5px;
                font-weight: 700;
            }
            QWidget#NDMScannerPage QTabWidget::pane {
                background-color: #0B1120;
                border: 1px solid #1F2937;
                border-radius: 6px;
                top: -1px;
            }
            QWidget#NDMScannerPage QTabBar::tab {
                background-color: #111827;
                color: #94A3B8;
                border: 1px solid #263449;
                padding: 9px 13px;
                margin-right: 2px;
            }
            QWidget#NDMScannerPage QTabBar::tab:selected {
                background-color: #2563EB;
                color: #FFFFFF;
                border-color: #3B82F6;
            }
            QWidget#NDMScannerPage QProgressBar {
                background-color: #0F172A;
                color: #E5E7EB;
                border: 1px solid #1F2937;
                border-radius: 4px;
                text-align: center;
            }
            QWidget#NDMScannerPage QProgressBar::chunk {
                background-color: #2563EB;
                border-radius: 3px;
            }
            QWidget#NDMScannerPage QScrollBar:vertical,
            QWidget#NDMScannerPage QScrollBar:horizontal {
                background-color: #0B1120;
                border: none;
                width: 10px;
                height: 10px;
            }
            QWidget#NDMScannerPage QScrollBar::handle:vertical,
            QWidget#NDMScannerPage QScrollBar::handle:horizontal {
                background-color: #334155;
                border-radius: 4px;
                min-height: 20px;
                min-width: 20px;
            }
        """)

        main_layout = QVBoxLayout(
            self
        )

        main_layout.setContentsMargins(
            16,
            14,
            16,
            14
        )

        main_layout.setSpacing(
            10
        )

        # ----------------------------------------------------
        # HEADER
        # ----------------------------------------------------

        header = QHBoxLayout()

        title_layout = QVBoxLayout()

        title = QLabel(
            "NDM SCANNER"
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
            "Network discovery, service detection and security assessment"
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

        self.scan_status = QLabel(
            "● READY"
        )

        self.set_status_style(
            COLOR_GREEN,
            "#10251A",
            "#1B5E36"
        )

        header.addWidget(
            self.scan_status
        )

        main_layout.addLayout(
            header
        )

        # ----------------------------------------------------
        # SCAN CONTROL
        # ----------------------------------------------------

        control_panel = QFrame()

        control_panel.setObjectName(
            "ScannerControlPanel"
        )

        control_panel.setStyleSheet(
            f"""
            QFrame#ScannerControlPanel {{
                background: {COLOR_PANEL};
                border: 1px solid {COLOR_BORDER};
                border-radius: 8px;
            }}
            """
        )

        control_layout = QGridLayout(
            control_panel
        )

        control_layout.setContentsMargins(
            14,
            12,
            14,
            12
        )

        control_layout.setHorizontalSpacing(
            10
        )

        control_layout.setVerticalSpacing(
            5
        )

        # Target

        target_label = self.create_control_label(
            "TARGET NETWORK"
        )

        self.target_input = QLineEdit()

        self.target_input.setText(
            "192.168.1.0/24"
        )

        self.target_input.setPlaceholderText(
            "192.168.1.0/24"
        )

        auto_button = QPushButton(
            "AUTO"
        )

        auto_button.setFixedWidth(
            70
        )

        auto_button.clicked.connect(
            self.auto_detect_network
        )

        control_layout.addWidget(
            target_label,
            0,
            0
        )

        control_layout.addWidget(
            self.target_input,
            1,
            0
        )

        control_layout.addWidget(
            auto_button,
            1,
            1
        )

        # Profile

        profile_label = self.create_control_label(
            "SCAN PROFILE"
        )

        self.profile_combo = QComboBox()

        self.profile_combo.addItems(
            [
                "Quick Discovery",
                "Standard Scan",
                "Full Network Scan",
                "Vulnerability Scan",
                "Custom Scan",
            ]
        )

        control_layout.addWidget(
            profile_label,
            0,
            2
        )

        control_layout.addWidget(
            self.profile_combo,
            1,
            2
        )

        # Timeout

        timeout_label = self.create_control_label(
            "TIMEOUT"
        )

        self.timeout_spin = QSpinBox()

        self.timeout_spin.setRange(
            1,
            30
        )

        self.timeout_spin.setValue(
            3
        )

        self.timeout_spin.setSuffix(
            " sec"
        )

        control_layout.addWidget(
            timeout_label,
            0,
            3
        )

        control_layout.addWidget(
            self.timeout_spin,
            1,
            3
        )

        # Start

        self.start_button = QPushButton(
            "START SCAN"
        )

        self.start_button.setObjectName(
            "PrimaryButton"
        )

        self.start_button.setFixedHeight(
            34
        )

        self.start_button.setStyleSheet(
            f"""
            QPushButton {{
                background: {COLOR_BLUE};
                color: white;
                border: none;
                border-radius: 5px;
                padding: 0 16px;
                font-size: 10px;
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
            self.start_scan
        )

        control_layout.addWidget(
            self.start_button,
            1,
            4
        )

        # Stop

        self.stop_button = QPushButton(
            "STOP"
        )

        self.stop_button.setFixedHeight(
            34
        )

        self.stop_button.setStyleSheet(
            f"""
            QPushButton {{
                background: #2A1111;
                color: {COLOR_RED};
                border: 1px solid #6B1B1B;
                border-radius: 5px;
                padding: 0 16px;
                font-size: 10px;
                font-weight: 700;
            }}

            QPushButton:hover {{
                background: #3A1515;
            }}
            """
        )

        self.stop_button.clicked.connect(
            self.stop_scan
        )

        control_layout.addWidget(
            self.stop_button,
            1,
            5
        )

        main_layout.addWidget(
            control_panel
        )

        # ----------------------------------------------------
        # STATUS CARDS
        # ----------------------------------------------------

        status_layout = QHBoxLayout()

        self.host_count_label = self.create_status_badge(
            "Hosts: 0"
        )

        self.open_ports_label = self.create_status_badge(
            "Open Ports: 0"
        )

        self.findings_label = self.create_status_badge(
            "Findings: 0"
        )

        self.risk_label = self.create_status_badge(
            "Risk: LOW"
        )

        status_layout.addWidget(
            self.host_count_label
        )

        status_layout.addWidget(
            self.open_ports_label
        )

        status_layout.addWidget(
            self.findings_label
        )

        status_layout.addWidget(
            self.risk_label
        )

        status_layout.addStretch()

        main_layout.addLayout(
            status_layout
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
            5
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

        main_layout.addWidget(
            self.progress_bar
        )

        # ----------------------------------------------------
        # TABS
        # ----------------------------------------------------

        self.tabs = QTabWidget()

        self.tabs.setDocumentMode(
            True
        )
        self.tabs.setAutoFillBackground(True)
        tabs_palette = self.tabs.palette()
        tabs_palette.setColor(tabs_palette.ColorRole.Window, QColor(COLOR_BG))
        tabs_palette.setColor(tabs_palette.ColorRole.Base, QColor(COLOR_BG))
        self.tabs.setPalette(tabs_palette)

        self.tabs.setStyleSheet(
            f"""
            QTabWidget::pane {{
                border: 1px solid {COLOR_BORDER};
                background: {COLOR_BG};
                border-radius: 5px;
            }}

            QTabBar::tab {{
                background: {COLOR_PANEL};
                color: {COLOR_SECONDARY};
                padding: 9px 14px;
                margin-right: 2px;
                border: 1px solid {COLOR_BORDER};
                border-bottom: none;
                font-size: 9px;
                font-weight: 600;
            }}

            QTabBar::tab:hover {{
                color: {COLOR_TEXT};
                background: #172033;
            }}

            QTabBar::tab:selected {{
                color: white;
                background: {COLOR_BLUE};
                border-color: {COLOR_BLUE};
            }}
            """
        )

        main_layout.addWidget(
            self.tabs
        )

        self.create_tabs()
        self._apply_tab_page_backgrounds()

    def _apply_tab_page_backgrounds(self):
        """Force each tab page's empty area to use the dark application theme."""
        for index in range(self.tabs.count()):
            page = self.tabs.widget(index)
            if page is None:
                continue

            page.setObjectName(f"NDMTabPage{index}")
            page.setAutoFillBackground(True)

            palette = page.palette()
            palette.setColor(palette.ColorRole.Window, QColor(COLOR_BG))
            palette.setColor(palette.ColorRole.Base, QColor(COLOR_BG))
            palette.setColor(palette.ColorRole.Text, QColor(COLOR_TEXT))
            page.setPalette(palette)

            # Target only the tab-page root. Nested cards/tables keep their own styles.
            page.setStyleSheet(
                f"QWidget#NDMTabPage{index} {{"
                f"background-color: {COLOR_BG}; color: {COLOR_TEXT};"
                "}"
            )


    # ========================================================
    # CREATE TABS
    # ========================================================

    def create_tabs(self):

        self.tabs.addTab(
            self.create_dashboard_tab(),
            "Dashboard"
        )

        self.tabs.addTab(
            self.create_hosts_tab(),
            "Hosts"
        )

        self.tabs.addTab(
            self.create_ports_tab(),
            "Ports"
        )

        self.tabs.addTab(
            self.create_services_tab(),
            "Services"
        )

        self.tabs.addTab(
            self.create_vulnerabilities_tab(),
            "Vulnerabilities"
        )

        self.tabs.addTab(
            self.create_threat_intelligence_tab(),
            "Threat Intelligence"
        )

        self.tabs.addTab(
            self.create_topology_tab(),
            "Topology"
        )

        self.tabs.addTab(
            self.create_reports_tab(),
            "Reports"
        )

    # ========================================================
    # DASHBOARD TAB
    # ========================================================

    def create_dashboard_tab(self):

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

        layout.setSpacing(
            12
        )

        metrics = QGridLayout()

        self.metric_devices = self.create_metric_card(
            "DEVICES",
            "0",
            COLOR_BLUE
        )

        self.metric_ports = self.create_metric_card(
            "OPEN PORTS",
            "0",
            COLOR_CYAN
        )

        self.metric_high = self.create_metric_card(
            "HIGH RISK",
            "0",
            COLOR_RED
        )

        self.metric_medium = self.create_metric_card(
            "MEDIUM RISK",
            "0",
            COLOR_YELLOW
        )

        self.metric_score = self.create_metric_card(
            "SECURITY SCORE",
            "100",
            COLOR_GREEN
        )

        metrics.addWidget(
            self.metric_devices,
            0,
            0
        )

        metrics.addWidget(
            self.metric_ports,
            0,
            1
        )

        metrics.addWidget(
            self.metric_high,
            0,
            2
        )

        metrics.addWidget(
            self.metric_medium,
            0,
            3
        )

        metrics.addWidget(
            self.metric_score,
            0,
            4
        )

        layout.addLayout(
            metrics
        )

        # Summary

        summary_frame = self.create_panel()

        summary_layout = QVBoxLayout(
            summary_frame
        )
        summary_layout.setContentsMargins(10, 10, 10, 10)
        summary_layout.setSpacing(8)

        summary_title = self.create_section_title(
            "SCAN SUMMARY"
        )

        summary_layout.addWidget(
            summary_title
        )

        self.summary_text = QTextEdit()

        self.summary_text.setReadOnly(
            True
        )
        self.summary_text.setMinimumHeight(120)
        self.summary_text.setMaximumHeight(190)
        self.summary_text.setLineWrapMode(QTextEdit.WidgetWidth)
        self.summary_text.setStyleSheet(
            "QTextEdit { background:#0B1424; color:#D7E3F4; "
            "border:1px solid #263449; border-radius:6px; "
            "padding:10px; font-family:Consolas; font-size:10px; }"
        )

        summary_layout.addWidget(
            self.summary_text
        )

        layout.addWidget(
            summary_frame
        )

        # Findings

        findings_frame = self.create_panel()

        findings_layout = QVBoxLayout(
            findings_frame
        )
        findings_layout.setContentsMargins(10, 10, 10, 10)
        findings_layout.setSpacing(8)

        findings_title = self.create_section_title(
            "SECURITY FINDINGS"
        )

        findings_layout.addWidget(
            findings_title
        )

        self.dashboard_findings = QTableWidget()

        self.dashboard_findings.setColumnCount(
            4
        )

        self.dashboard_findings.setHorizontalHeaderLabels(
            [
                "Severity",
                "Host",
                "Finding",
                "Status",
            ]
        )

        self.configure_table(
            self.dashboard_findings
        )

        findings_layout.addWidget(
            self.dashboard_findings
        )

        layout.addWidget(
            findings_frame
        )

        return widget

    # ========================================================
    # HOSTS TAB
    # ========================================================

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

        layout.addWidget(
            self.create_section_title(
                "NETWORK HOSTS"
            )
        )

        self.host_table = QTableWidget()

        self.host_table.setColumnCount(
            8
        )

        self.host_table.setHorizontalHeaderLabels(
            [
                "IP Address",
                "MAC Address",
                "Hostname",
                "Vendor",
                "Status",
                "Latency",
                "Open Ports",
                "Risk",
            ]
        )

        self.configure_table(
            self.host_table
        )

        self.host_table.itemSelectionChanged.connect(
            self.on_host_selected
        )

        layout.addWidget(
            self.host_table
        )

        return widget

    # ========================================================
    # PORTS TAB
    # ========================================================

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

        layout.addWidget(
            self.create_section_title(
                "OPEN PORTS"
            )
        )

        self.port_table = QTableWidget()

        self.port_table.setColumnCount(
            7
        )

        self.port_table.setHorizontalHeaderLabels(
            [
                "Host",
                "Port",
                "Protocol",
                "Service",
                "State",
                "Risk",
                "Banner",
            ]
        )

        self.configure_table(
            self.port_table
        )

        layout.addWidget(
            self.port_table
        )

        return widget

    # ========================================================
    # SERVICES TAB
    # ========================================================

    def create_services_tab(self):

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

        header = QHBoxLayout()

        header.addWidget(
            self.create_section_title(
                "SERVICE DETECTION"
            )
        )

        header.addStretch()

        self.service_summary = QLabel(
            "Services: 0"
        )

        self.service_summary.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 10px;
                font-weight: 600;
            }}
            """
        )

        header.addWidget(
            self.service_summary
        )

        layout.addLayout(
            header
        )

        self.service_table = QTableWidget()

        self.service_table.setColumnCount(
            7
        )

        self.service_table.setHorizontalHeaderLabels(
            [
                "Host",
                "Port",
                "Protocol",
                "Service",
                "Version",
                "State",
                "Risk",
            ]
        )

        self.configure_table(
            self.service_table
        )

        layout.addWidget(
            self.service_table
        )

        return widget

    # ========================================================
    # VULNERABILITY TAB
    # ========================================================

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

        counters = QHBoxLayout()

        self.critical_count = self.create_small_counter(
            "CRITICAL",
            "0",
            COLOR_RED
        )

        self.high_count = self.create_small_counter(
            "HIGH",
            "0",
            COLOR_ORANGE
        )

        self.medium_count = self.create_small_counter(
            "MEDIUM",
            "0",
            COLOR_YELLOW
        )

        self.low_count = self.create_small_counter(
            "LOW",
            "0",
            COLOR_GREEN
        )

        counters.addWidget(
            self.critical_count
        )

        counters.addWidget(
            self.high_count
        )

        counters.addWidget(
            self.medium_count
        )

        counters.addWidget(
            self.low_count
        )

        counters.addStretch()

        layout.addLayout(
            counters
        )

        layout.addWidget(
            self.create_section_title(
                "VULNERABILITY FINDINGS"
            )
        )

        self.vulnerability_table = QTableWidget()

        self.vulnerability_table.setColumnCount(
            8
        )

        self.vulnerability_table.setHorizontalHeaderLabels(
            [
                "Severity",
                "Host",
                "Port",
                "Service",
                "Finding",
                "Evidence",
                "Risk Score",
                "Status",
            ]
        )

        self.configure_table(
            self.vulnerability_table
        )

        self.vulnerability_table.itemSelectionChanged.connect(
            self.on_vulnerability_selected
        )

        layout.addWidget(
            self.vulnerability_table
        )

        return widget

    # ========================================================
    # THREAT INTELLIGENCE TAB
    # ========================================================

    def create_threat_intelligence_tab(self):

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

        header = QHBoxLayout()

        header.addWidget(
            self.create_section_title(
                "THREAT INTELLIGENCE"
            )
        )

        header.addStretch()

        self.threat_summary = QLabel(
            "Indicators: 0"
        )

        self.threat_summary.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 10px;
                font-weight: 600;
            }}
            """
        )

        header.addWidget(
            self.threat_summary
        )

        layout.addLayout(
            header
        )

        # Reputation

        reputation_frame = self.create_panel()

        reputation_layout = QGridLayout(
            reputation_frame
        )

        reputation_title = self.create_section_title(
            "REPUTATION OVERVIEW"
        )

        reputation_layout.addWidget(
            reputation_title,
            0,
            0,
            1,
            4
        )

        self.safe_indicator = self.create_reputation_card(
            "SAFE",
            "0",
            COLOR_GREEN
        )

        self.suspicious_indicator = self.create_reputation_card(
            "SUSPICIOUS",
            "0",
            COLOR_YELLOW
        )

        self.malicious_indicator = self.create_reputation_card(
            "MALICIOUS",
            "0",
            COLOR_RED
        )

        self.unknown_indicator = self.create_reputation_card(
            "UNKNOWN",
            "0",
            COLOR_SECONDARY
        )

        reputation_layout.addWidget(
            self.safe_indicator,
            1,
            0
        )

        reputation_layout.addWidget(
            self.suspicious_indicator,
            1,
            1
        )

        reputation_layout.addWidget(
            self.malicious_indicator,
            1,
            2
        )

        reputation_layout.addWidget(
            self.unknown_indicator,
            1,
            3
        )

        layout.addWidget(
            reputation_frame
        )

        # Table

        self.threat_table = QTableWidget()

        self.threat_table.setColumnCount(
            8
        )

        self.threat_table.setHorizontalHeaderLabels(
            [
                "Indicator",
                "Type",
                "Country",
                "Reputation",
                "Confidence",
                "Source",
                "First Seen",
                "Status",
            ]
        )

        self.configure_table(
            self.threat_table
        )

        layout.addWidget(
            self.threat_table
        )

        disclaimer = QLabel(
            "Threat intelligence is an assessment indicator and does not by itself prove malicious activity."
        )

        disclaimer.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_MUTED};
                font-size: 9px;
            }}
            """
        )

        layout.addWidget(
            disclaimer
        )

        return widget

    # ========================================================
    # TOPOLOGY TAB
    # ========================================================

    def create_topology_tab(self):

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

        layout.setSpacing(
            10
        )

        # ----------------------------------------------------
        # Header
        # ----------------------------------------------------

        header = QHBoxLayout()

        header.addWidget(
            self.create_section_title(
                "NETWORK TOPOLOGY"
            )
        )

        header.addStretch()

        topology_info = QLabel(
            "3 Hosts  •  15 Open Ports  •  2 Findings"
        )

        topology_info.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 9px;
                font-weight: 600;
            }}
            """
        )

        header.addWidget(
            topology_info
        )

        layout.addLayout(
            header
        )

        # ----------------------------------------------------
        # Scroll Area
        # ----------------------------------------------------

        scroll = QScrollArea()

        scroll.setWidgetResizable(
            True
        )

        scroll.setFrameShape(
            QFrame.NoFrame
        )

        scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarAsNeeded
        )

        scroll.setVerticalScrollBarPolicy(
            Qt.ScrollBarAsNeeded
        )

        # ----------------------------------------------------
        # Canvas
        # ----------------------------------------------------

        canvas = QFrame()

        canvas.setMinimumSize(
            900,
            650
        )

        canvas.setStyleSheet(
            f"""
            QFrame {{
                background: {COLOR_BG};
                border: 1px solid {COLOR_BORDER};
                border-radius: 8px;
            }}
            """
        )

        canvas_layout = QVBoxLayout(
            canvas
        )

        canvas_layout.setContentsMargins(
            30,
            25,
            30,
            25
        )

        canvas_layout.setSpacing(
            0
        )

        # ----------------------------------------------------
        # Internet
        # ----------------------------------------------------

        internet_row = QHBoxLayout()

        internet_row.setAlignment(
            Qt.AlignCenter
        )

        internet = self.create_network_node(
            "INTERNET",
            "WAN",
            "PUBLIC NETWORK",
            COLOR_PURPLE,
            "ONLINE"
        )

        internet_row.addWidget(
            internet
        )

        canvas_layout.addLayout(
            internet_row
        )

        canvas_layout.addWidget(
            self.create_topology_connector()
        )

        # ----------------------------------------------------
        # Router
        # ----------------------------------------------------

        router_row = QHBoxLayout()

        router_row.setAlignment(
            Qt.AlignCenter
        )

        router = self.create_network_node(
            "ROUTER",
            "192.168.1.1",
            "Default Gateway",
            COLOR_BLUE,
            "ONLINE"
        )

        router_row.addWidget(
            router
        )

        canvas_layout.addLayout(
            router_row
        )

        canvas_layout.addWidget(
            self.create_topology_connector()
        )

        # ----------------------------------------------------
        # Local Network
        # ----------------------------------------------------

        network_row = QHBoxLayout()

        network_row.setAlignment(
            Qt.AlignCenter
        )

        network = self.create_network_node(
            "LOCAL NETWORK",
            "192.168.1.0/24",
            "LAN / Wi-Fi",
            COLOR_CYAN,
            "ACTIVE"
        )

        network_row.addWidget(
            network
        )

        canvas_layout.addLayout(
            network_row
        )

        canvas_layout.addWidget(
            self.create_topology_connector()
        )

        # ----------------------------------------------------
        # Devices title
        # ----------------------------------------------------

        devices_title = QLabel(
            "DISCOVERED DEVICES"
        )

        devices_title.setAlignment(
            Qt.AlignCenter
        )

        devices_title.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 9px;
                font-weight: 700;
                padding: 8px;
            }}
            """
        )

        canvas_layout.addWidget(
            devices_title
        )

        # ----------------------------------------------------
        # Hosts
        # ----------------------------------------------------

        hosts_row = QHBoxLayout()

        hosts_row.setSpacing(
            18
        )

        hosts_row.setAlignment(
            Qt.AlignCenter
        )

        server = self.create_network_node(
            "SERVER",
            "192.168.1.12",
            "server.local",
            COLOR_YELLOW,
            "ONLINE",
            [
                "6 Open Ports",
                "SSH :22",
                "SMB :445",
                "RISK: MEDIUM",
            ]
        )

        windows_pc = self.create_network_node(
            "WINDOWS PC",
            "192.168.1.20",
            "windows-pc",
            COLOR_GREEN,
            "ONLINE",
            [
                "3 Open Ports",
                "RDP :3389",
                "HTTP :80",
                "RISK: LOW",
            ]
        )

        device = self.create_network_node(
            "DEVICE",
            "192.168.1.25",
            "network-device",
            COLOR_GREEN,
            "ONLINE",
            [
                "2 Open Ports",
                "HTTPS :443",
                "DNS :53",
                "RISK: LOW",
            ]
        )

        hosts_row.addWidget(
            server
        )

        hosts_row.addWidget(
            windows_pc
        )

        hosts_row.addWidget(
            device
        )

        canvas_layout.addLayout(
            hosts_row
        )

        # ----------------------------------------------------
        # Findings
        # ----------------------------------------------------

        canvas_layout.addSpacing(
            25
        )

        findings_title = QLabel(
            "SECURITY FINDINGS"
        )

        findings_title.setAlignment(
            Qt.AlignCenter
        )

        findings_title.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_RED};
                font-size: 9px;
                font-weight: 700;
            }}
            """
        )

        canvas_layout.addWidget(
            findings_title
        )

        findings_row = QHBoxLayout()

        findings_row.setAlignment(
            Qt.AlignCenter
        )

        finding1 = self.create_finding_node(
            "HIGH",
            "SMB EXPOSED",
            "192.168.1.12:445",
            COLOR_RED
        )

        finding2 = self.create_finding_node(
            "MEDIUM",
            "RDP EXPOSED",
            "192.168.1.20:3389",
            COLOR_YELLOW
        )

        findings_row.addWidget(
            finding1
        )

        findings_row.addWidget(
            finding2
        )

        canvas_layout.addLayout(
            findings_row
        )

        canvas_layout.addStretch()

        # ----------------------------------------------------
        # Legend
        # ----------------------------------------------------

        legend = QHBoxLayout()

        legend.setAlignment(
            Qt.AlignCenter
        )

        legend.addWidget(
            self.create_legend(
                COLOR_GREEN,
                "Safe"
            )
        )

        legend.addWidget(
            self.create_legend(
                COLOR_YELLOW,
                "Medium Risk"
            )
        )

        legend.addWidget(
            self.create_legend(
                COLOR_RED,
                "High Risk"
            )
        )

        legend.addWidget(
            self.create_legend(
                COLOR_PURPLE,
                "External"
            )
        )

        canvas_layout.addLayout(
            legend
        )

        scroll.setWidget(
            canvas
        )

        layout.addWidget(
            scroll
        )

        return widget

    # ========================================================
    # REPORTS TAB
    # ========================================================

    def create_reports_tab(self):

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

        layout.addWidget(
            self.create_section_title(
                "SECURITY REPORT"
            )
        )

        report_frame = self.create_panel()

        report_layout = QVBoxLayout(
            report_frame
        )

        self.report_text = QTextEdit()

        self.report_text.setReadOnly(
            True
        )
        self.report_text.setStyleSheet(
            "QTextEdit { background:#0B1424; color:#D7E3F4; "
            "border:1px solid #263449; border-radius:6px; "
            "padding:12px; font-family:Consolas; font-size:10px; }"
        )

        report_layout.addWidget(
            self.report_text
        )

        layout.addWidget(
            report_frame
        )

        export_layout = QHBoxLayout()

        json_button = QPushButton(
            "EXPORT JSON"
        )

        csv_button = QPushButton(
            "EXPORT CSV"
        )

        pdf_button = QPushButton(
            "EXPORT PDF"
        )

        for button in [
            json_button,
            csv_button,
            pdf_button,
        ]:

            button.setFixedHeight(
                32
            )

            export_layout.addWidget(
                button
            )

        export_layout.addStretch()

        layout.addLayout(
            export_layout
        )

        return widget

    # ========================================================
    # COMMON UI HELPERS
    # ========================================================

    def create_panel(self):

        frame = QFrame()

        frame.setStyleSheet(
            f"""
            QFrame {{
                background: {COLOR_PANEL};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 7px;
            }}
            """
        )

        return frame

    # ========================================================

    def create_section_title(
        self,
        text
    ):

        label = QLabel(
            text
        )

        label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_CYAN};
                font-size: 10px;
                font-weight: 700;
            }}
            """
        )

        return label

    # ========================================================

    def create_control_label(
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
                font-size: 8px;
                font-weight: 700;
            }}
            """
        )

        return label

    # ========================================================

    def create_status_badge(
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
                background: {COLOR_PANEL};
                border: 1px solid {COLOR_BORDER};
                border-radius: 5px;
                padding: 6px 12px;
                font-size: 9px;
                font-weight: 600;
            }}
            """
        )

        return label

    # ========================================================

    def configure_table(
        self,
        table
    ):

        table.setAlternatingRowColors(
            True
        )

        table.setSelectionBehavior(
            QTableWidget.SelectRows
        )

        table.setSelectionMode(
            QTableWidget.SingleSelection
        )

        table.setEditTriggers(
            QTableWidget.NoEditTriggers
        )

        table.verticalHeader().setVisible(
            False
        )
        table.verticalHeader().setDefaultSectionSize(30)
        table.setShowGrid(False)
        table.setWordWrap(False)
        table.verticalHeader().setDefaultSectionSize(30)
        table.horizontalHeader().setMinimumHeight(34)

        table.horizontalHeader().setStretchLastSection(
            True
        )

        table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Interactive
        )

        table.setSortingEnabled(
            True
        )

        table.setStyleSheet(
            f"""
            QTableWidget {{
                background: {COLOR_PANEL};
                alternate-background-color: {COLOR_PANEL_2};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
                gridline-color: {COLOR_BORDER};
                font-size: 9px;
            }}

            QTableWidget::item {{
                padding: 5px;
            }}

            QTableWidget::item:selected {{
                background: {COLOR_BLUE};
                color: white;
            }}

            QHeaderView::section {{
                background: #172033;
                color: {COLOR_SECONDARY};
                border: none;
                border-right: 1px solid {COLOR_BORDER};
                border-bottom: 1px solid {COLOR_BORDER};
                padding: 7px;
                font-size: 8px;
                font-weight: 700;
            }}
            """
        )

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
            9,
            12,
            9
        )

        title_label = QLabel(
            title
        )

        title_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 8px;
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
    # SMALL COUNTER
    # ========================================================

    def create_small_counter(
        self,
        title,
        value,
        color
    ):

        frame = QFrame()

        frame.setMinimumWidth(
            120
        )

        frame.setStyleSheet(
            f"""
            QFrame {{
                background: {COLOR_PANEL};
                border: 1px solid {COLOR_BORDER};
                border-radius: 5px;
            }}
            """
        )

        layout = QHBoxLayout(
            frame
        )

        layout.setContentsMargins(
            8,
            5,
            8,
            5
        )

        title_label = QLabel(
            title
        )

        title_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 8px;
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
                font-size: 15px;
                font-weight: 700;
            }}
            """
        )

        layout.addWidget(
            title_label
        )

        layout.addStretch()

        layout.addWidget(
            value_label
        )

        frame.value_label = value_label

        return frame

    # ========================================================
    # REPUTATION CARD
    # ========================================================

    def create_reputation_card(
        self,
        title,
        value,
        color
    ):

        frame = QFrame()

        frame.setMinimumHeight(
            65
        )

        frame.setStyleSheet(
            f"""
            QFrame {{
                background: {COLOR_PANEL_2};
                border: 1px solid {COLOR_BORDER};
                border-radius: 5px;
            }}
            """
        )

        layout = QVBoxLayout(
            frame
        )

        title_label = QLabel(
            title
        )

        title_label.setAlignment(
            Qt.AlignCenter
        )

        title_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 8px;
                font-weight: 700;
            }}
            """
        )

        value_label = QLabel(
            value
        )

        value_label.setAlignment(
            Qt.AlignCenter
        )

        value_label.setStyleSheet(
            f"""
            QLabel {{
                color: {color};
                font-size: 19px;
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
    # NETWORK TOPOLOGY NODE
    # ========================================================

    def create_network_node(
        self,
        title,
        address,
        description,
        border_color,
        status,
        details=None
    ):

        frame = QFrame()

        frame.setFixedWidth(
            215
        )

        if details:
            frame.setMinimumHeight(
                155
            )
        else:
            frame.setMinimumHeight(
                105
            )

        frame.setStyleSheet(
            f"""
            QFrame {{
                background: {COLOR_PANEL};
                border: 1px solid {border_color};
                border-radius: 8px;
            }}
            """
        )

        layout = QVBoxLayout(
            frame
        )

        layout.setContentsMargins(
            12,
            9,
            12,
            9
        )

        layout.setSpacing(
            3
        )

        title_label = QLabel(
            title
        )

        title_label.setAlignment(
            Qt.AlignCenter
        )

        title_label.setStyleSheet(
            f"""
            QLabel {{
                color: {border_color};
                font-size: 11px;
                font-weight: 700;
            }}
            """
        )

        layout.addWidget(
            title_label
        )

        address_label = QLabel(
            address
        )

        address_label.setAlignment(
            Qt.AlignCenter
        )

        address_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT};
                font-size: 10px;
                font-weight: 600;
            }}
            """
        )

        layout.addWidget(
            address_label
        )

        description_label = QLabel(
            description
        )

        description_label.setAlignment(
            Qt.AlignCenter
        )

        description_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 8px;
            }}
            """
        )

        layout.addWidget(
            description_label
        )

        status_label = QLabel(
            f"● {status}"
        )

        status_label.setAlignment(
            Qt.AlignCenter
        )

        status_label.setStyleSheet(
            f"""
            QLabel {{
                color: {border_color};
                font-size: 8px;
                font-weight: 700;
            }}
            """
        )

        layout.addWidget(
            status_label
        )

        if details:

            for detail in details:

                detail_label = QLabel(
                    detail
                )

                detail_label.setAlignment(
                    Qt.AlignCenter
                )

                detail_label.setStyleSheet(
                    f"""
                    QLabel {{
                        color: {COLOR_SECONDARY};
                        font-size: 8px;
                    }}
                    """
                )

                layout.addWidget(
                    detail_label
                )

        return frame

    # ========================================================
    # TOPOLOGY CONNECTOR
    # ========================================================

    def create_topology_connector(self):

        wrapper = QWidget()

        wrapper.setFixedHeight(
            28
        )

        layout = QHBoxLayout(
            wrapper
        )

        layout.setContentsMargins(
            0,
            0,
            0,
            0
        )

        layout.setAlignment(
            Qt.AlignCenter
        )

        line = QFrame()

        line.setFixedWidth(
            3
        )

        line.setFixedHeight(
            28
        )

        line.setStyleSheet(
            f"""
            QFrame {{
                background: {COLOR_BLUE};
                border: none;
            }}
            """
        )

        layout.addWidget(
            line
        )

        return wrapper

    # ========================================================
    # FINDING NODE
    # ========================================================

    def create_finding_node(
        self,
        severity,
        title,
        address,
        color
    ):

        frame = QFrame()

        frame.setFixedSize(
            220,
            82
        )

        frame.setStyleSheet(
            f"""
            QFrame {{
                background: {COLOR_PANEL};
                border: 1px solid {color};
                border-radius: 7px;
            }}
            """
        )

        layout = QVBoxLayout(
            frame
        )

        severity_label = QLabel(
            severity
        )

        severity_label.setAlignment(
            Qt.AlignCenter
        )

        severity_label.setStyleSheet(
            f"""
            QLabel {{
                color: {color};
                font-size: 9px;
                font-weight: 700;
            }}
            """
        )

        layout.addWidget(
            severity_label
        )

        title_label = QLabel(
            title
        )

        title_label.setAlignment(
            Qt.AlignCenter
        )

        title_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT};
                font-size: 10px;
                font-weight: 700;
            }}
            """
        )

        layout.addWidget(
            title_label
        )

        address_label = QLabel(
            address
        )

        address_label.setAlignment(
            Qt.AlignCenter
        )

        address_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 8px;
            }}
            """
        )

        layout.addWidget(
            address_label
        )

        return frame

    # ========================================================
    # LEGEND
    # ========================================================

    def create_legend(
        self,
        color,
        text
    ):

        widget = QWidget()

        layout = QHBoxLayout(
            widget
        )

        layout.setContentsMargins(
            8,
            4,
            8,
            4
        )

        dot = QLabel(
            "●"
        )

        dot.setStyleSheet(
            f"""
            QLabel {{
                color: {color};
                font-size: 12px;
            }}
            """
        )

        label = QLabel(
            text
        )

        label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 8px;
            }}
            """
        )

        layout.addWidget(
            dot
        )

        layout.addWidget(
            label
        )

        return widget

    # ========================================================
    # STATUS STYLE
    # ========================================================

    def set_status_style(
        self,
        text_color,
        background,
        border
    ):

        self.scan_status.setStyleSheet(
            f"""
            QLabel {{
                color: {text_color};
                background: {background};
                border: 1px solid {border};
                border-radius: 5px;
                padding: 7px 12px;
                font-size: 10px;
                font-weight: 700;
            }}
            """
        )

    # ========================================================
    # AUTO DETECT
    # ========================================================

    def auto_detect_network(self):

        self.target_input.setText(
            "192.168.1.0/24"
        )

    # ========================================================
    # START SCAN
    # ========================================================

    def start_scan(self):

        target = self.target_input.text().strip()

        if not target:
            return

        config = {
            "target": target,
            "profile": self.profile_combo.currentText(),
            "timeout": self.timeout_spin.value(),
        }

        self.start_button.setEnabled(
            False
        )

        self.scan_status.setText(
            "● SCANNING"
        )

        self.set_status_style(
            COLOR_YELLOW,
            "#2A230D",
            "#6B5A13"
        )

        self.progress_bar.setValue(
            10
        )

        self.start_scan_requested.emit(
            config
        )

    # ========================================================
    # STOP SCAN
    # ========================================================

    def stop_scan(self):

        self.start_button.setEnabled(
            True
        )

        self.progress_bar.setValue(
            0
        )

        self.scan_status.setText(
            "● STOPPED"
        )

        self.set_status_style(
            COLOR_RED,
            "#2A1111",
            "#6B1B1B"
        )

        self.stop_scan_requested.emit()

    # ========================================================
    # HOST SELECTION
    # ========================================================

    def on_host_selected(self):

        row = self.host_table.currentRow()

        if row < 0:
            return

        keys = [
            "ip",
            "mac",
            "hostname",
            "vendor",
            "status",
            "latency",
            "open_ports",
            "risk",
        ]

        host = {}

        for column, key in enumerate(keys):

            item = self.host_table.item(
                row,
                column
            )

            host[key] = (
                item.text()
                if item
                else ""
            )

        self.host_selected.emit(
            host
        )

    # ========================================================
    # VULNERABILITY SELECTION
    # ========================================================

    def on_vulnerability_selected(self):

        row = self.vulnerability_table.currentRow()

        if row < 0:
            return

        keys = [
            "severity",
            "host",
            "port",
            "service",
            "finding",
            "evidence",
            "score",
            "status",
        ]

        vulnerability = {}

        for column, key in enumerate(keys):

            item = self.vulnerability_table.item(
                row,
                column
            )

            vulnerability[key] = (
                item.text()
                if item
                else ""
            )

        self.vulnerability_selected.emit(
            vulnerability
        )

    # ========================================================
    # SET HOSTS
    # ========================================================

    def set_hosts(
        self,
        hosts
    ):

        self.hosts = hosts or []

        self.host_table.setRowCount(
            0
        )

        for host in self.hosts:

            row = self.host_table.rowCount()

            self.host_table.insertRow(
                row
            )

            values = [
                host.get("ip", ""),
                host.get("mac", ""),
                host.get("hostname", ""),
                host.get("vendor", ""),
                host.get("status", ""),
                host.get("latency", ""),
                host.get("open_ports", ""),
                host.get("risk", ""),
            ]

            for column, value in enumerate(values):

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
            f"Hosts: {len(self.hosts)}"
        )

        self.update_dashboard_metrics()

    # ========================================================
    # SET PORTS
    # ========================================================

    def set_ports(
        self,
        ports
    ):

        self.ports = ports or []

        self.port_table.setRowCount(
            0
        )

        for port in self.ports:

            row = self.port_table.rowCount()

            self.port_table.insertRow(
                row
            )

            values = [
                port.get("host", ""),
                port.get("port", ""),
                port.get("protocol", ""),
                port.get("service", ""),
                port.get("state", ""),
                port.get("risk", ""),
                port.get("banner", ""),
            ]

            for column, value in enumerate(values):

                item = QTableWidgetItem(
                    str(value)
                )

                item.setTextAlignment(
                    Qt.AlignCenter
                )

                self.port_table.setItem(
                    row,
                    column,
                    item
                )

        self.open_ports_label.setText(
            f"Open Ports: {len(self.ports)}"
        )

        self.update_dashboard_metrics()

    # ========================================================
    # SET SERVICES
    # ========================================================

    def set_services(
        self,
        services
    ):

        self.services = services or []

        self.service_table.setRowCount(
            0
        )

        for service in self.services:

            row = self.service_table.rowCount()

            self.service_table.insertRow(
                row
            )

            values = [
                service.get("host", ""),
                service.get("port", ""),
                service.get("protocol", ""),
                service.get("service", ""),
                service.get("version", ""),
                service.get("state", ""),
                service.get("risk", ""),
            ]

            for column, value in enumerate(values):

                item = QTableWidgetItem(
                    str(value)
                )

                item.setTextAlignment(
                    Qt.AlignCenter
                )

                self.service_table.setItem(
                    row,
                    column,
                    item
                )

        self.service_summary.setText(
            f"Services: {len(self.services)}"
        )

    # ========================================================
    # SET VULNERABILITIES
    # ========================================================

    def set_vulnerabilities(
        self,
        vulnerabilities
    ):

        self.vulnerabilities = (
            vulnerabilities or []
        )

        self.vulnerability_table.setRowCount(
            0
        )

        critical = 0
        high = 0
        medium = 0
        low = 0

        for vulnerability in self.vulnerabilities:

            severity = str(
                vulnerability.get(
                    "severity",
                    ""
                )
            ).upper()

            if severity == "CRITICAL":
                critical += 1

            elif severity == "HIGH":
                high += 1

            elif severity == "MEDIUM":
                medium += 1

            elif severity == "LOW":
                low += 1

            row = self.vulnerability_table.rowCount()

            self.vulnerability_table.insertRow(
                row
            )

            values = [
                vulnerability.get("severity", ""),
                vulnerability.get("host", ""),
                vulnerability.get("port", ""),
                vulnerability.get("service", ""),
                vulnerability.get("finding", ""),
                vulnerability.get("evidence", ""),
                vulnerability.get("score", ""),
                vulnerability.get("status", ""),
            ]

            for column, value in enumerate(values):

                item = QTableWidgetItem(
                    str(value)
                )

                item.setTextAlignment(
                    Qt.AlignCenter
                )

                self.vulnerability_table.setItem(
                    row,
                    column,
                    item
                )

        self.critical_count.value_label.setText(
            str(critical)
        )

        self.high_count.value_label.setText(
            str(high)
        )

        self.medium_count.value_label.setText(
            str(medium)
        )

        self.low_count.value_label.setText(
            str(low)
        )

        self.findings_label.setText(
            f"Findings: {len(self.vulnerabilities)}"
        )

        self.update_dashboard_metrics()

    # ========================================================
    # SET THREAT INTELLIGENCE
    # ========================================================

    def set_threat_intelligence(
        self,
        indicators
    ):

        self.threat_intelligence = (
            indicators or []
        )

        self.threat_table.setRowCount(
            0
        )

        safe = 0
        suspicious = 0
        malicious = 0
        unknown = 0

        for indicator in self.threat_intelligence:

            reputation = str(
                indicator.get(
                    "reputation",
                    "UNKNOWN"
                )
            )

            reputation_upper = reputation.upper()

            if reputation_upper == "SAFE":
                safe += 1

            elif reputation_upper == "SUSPICIOUS":
                suspicious += 1

            elif reputation_upper == "MALICIOUS":
                malicious += 1

            else:
                unknown += 1

            row = self.threat_table.rowCount()

            self.threat_table.insertRow(
                row
            )

            values = [
                indicator.get("indicator", ""),
                indicator.get("type", ""),
                indicator.get("country", ""),
                indicator.get("reputation", ""),
                indicator.get("confidence", ""),
                indicator.get("source", ""),
                indicator.get("first_seen", ""),
                indicator.get("status", ""),
            ]

            for column, value in enumerate(values):

                item = QTableWidgetItem(
                    str(value)
                )

                item.setTextAlignment(
                    Qt.AlignCenter
                )

                self.threat_table.setItem(
                    row,
                    column,
                    item
                )

        self.safe_indicator.value_label.setText(
            str(safe)
        )

        self.suspicious_indicator.value_label.setText(
            str(suspicious)
        )

        self.malicious_indicator.value_label.setText(
            str(malicious)
        )

        self.unknown_indicator.value_label.setText(
            str(unknown)
        )

        self.threat_summary.setText(
            f"Indicators: {len(self.threat_intelligence)}"
        )

    # ========================================================
    # UPDATE METRICS
    # ========================================================

    def update_dashboard_metrics(self):

        self.set_metric_value(
            self.metric_devices,
            len(self.hosts)
        )

        self.set_metric_value(
            self.metric_ports,
            len(self.ports)
        )

        high = 0
        medium = 0

        for vulnerability in self.vulnerabilities:

            severity = str(
                vulnerability.get(
                    "severity",
                    ""
                )
            ).upper()

            if severity in [
                "CRITICAL",
                "HIGH",
            ]:
                high += 1

            elif severity == "MEDIUM":
                medium += 1

        self.set_metric_value(
            self.metric_high,
            high
        )

        self.set_metric_value(
            self.metric_medium,
            medium
        )

        score = self.calculate_risk_score()

        self.set_metric_value(
            self.metric_score,
            score
        )

        self.risk_label.setText(
            f"Risk: {self.get_risk_level(score)}"
        )

    # ========================================================
    # METRIC VALUE
    # ========================================================

    def set_metric_value(
        self,
        frame,
        value
    ):

        if hasattr(
            frame,
            "value_label"
        ):
            frame.value_label.setText(
                str(value)
            )

    # ========================================================
    # RISK SCORE
    # ========================================================

    def calculate_risk_score(self):

        score = 100

        for vulnerability in self.vulnerabilities:

            severity = str(
                vulnerability.get(
                    "severity",
                    ""
                )
            ).upper()

            if severity == "CRITICAL":
                score -= 25

            elif severity == "HIGH":
                score -= 15

            elif severity == "MEDIUM":
                score -= 8

            elif severity == "LOW":
                score -= 3

        return max(
            0,
            min(
                100,
                score
            )
        )

    # ========================================================
    # RISK LEVEL
    # ========================================================

    def get_risk_level(
        self,
        score
    ):

        if score >= 80:
            return "LOW"

        if score >= 60:
            return "MEDIUM"

        if score >= 40:
            return "HIGH"

        return "CRITICAL"

    # ========================================================
    # DEMO DATA
    # ========================================================

    def load_demo_data(self):

        # ----------------------------------------------------
        # HOSTS
        # ----------------------------------------------------

        hosts = [
            {
                "ip": "192.168.1.1",
                "mac": "AA:BB:CC:11:22:33",
                "hostname": "router.local",
                "vendor": "TP-Link",
                "status": "ONLINE",
                "latency": "2 ms",
                "open_ports": "4",
                "risk": "LOW",
            },
            {
                "ip": "192.168.1.12",
                "mac": "AA:BB:CC:44:55:66",
                "hostname": "server.local",
                "vendor": "Dell",
                "status": "ONLINE",
                "latency": "5 ms",
                "open_ports": "6",
                "risk": "MEDIUM",
            },
            {
                "ip": "192.168.1.20",
                "mac": "AA:BB:CC:77:88:99",
                "hostname": "windows-pc",
                "vendor": "Microsoft",
                "status": "ONLINE",
                "latency": "8 ms",
                "open_ports": "3",
                "risk": "LOW",
            },
        ]

        # ----------------------------------------------------
        # PORTS
        # ----------------------------------------------------

        ports = [
            {
                "host": "192.168.1.1",
                "port": "80",
                "protocol": "TCP",
                "service": "HTTP",
                "state": "OPEN",
                "risk": "LOW",
                "banner": "HTTP Server",
            },
            {
                "host": "192.168.1.1",
                "port": "443",
                "protocol": "TCP",
                "service": "HTTPS",
                "state": "OPEN",
                "risk": "LOW",
                "banner": "HTTPS Server",
            },
            {
                "host": "192.168.1.12",
                "port": "22",
                "protocol": "TCP",
                "service": "SSH",
                "state": "OPEN",
                "risk": "LOW",
                "banner": "OpenSSH",
            },
            {
                "host": "192.168.1.12",
                "port": "445",
                "protocol": "TCP",
                "service": "SMB",
                "state": "OPEN",
                "risk": "HIGH",
                "banner": "Microsoft SMB",
            },
            {
                "host": "192.168.1.20",
                "port": "3389",
                "protocol": "TCP",
                "service": "RDP",
                "state": "OPEN",
                "risk": "MEDIUM",
                "banner": "Microsoft RDP",
            },
        ]

        # ----------------------------------------------------
        # SERVICES
        # ----------------------------------------------------

        services = [
            {
                "host": "192.168.1.1",
                "port": "80",
                "protocol": "TCP",
                "service": "HTTP",
                "version": "nginx",
                "state": "OPEN",
                "risk": "LOW",
            },
            {
                "host": "192.168.1.1",
                "port": "443",
                "protocol": "TCP",
                "service": "HTTPS",
                "version": "nginx",
                "state": "OPEN",
                "risk": "LOW",
            },
            {
                "host": "192.168.1.12",
                "port": "22",
                "protocol": "TCP",
                "service": "SSH",
                "version": "OpenSSH",
                "state": "OPEN",
                "risk": "LOW",
            },
            {
                "host": "192.168.1.12",
                "port": "445",
                "protocol": "TCP",
                "service": "SMB",
                "version": "Microsoft SMB",
                "state": "OPEN",
                "risk": "HIGH",
            },
            {
                "host": "192.168.1.20",
                "port": "3389",
                "protocol": "TCP",
                "service": "RDP",
                "version": "Microsoft RDP",
                "state": "OPEN",
                "risk": "MEDIUM",
            },
        ]

        # ----------------------------------------------------
        # VULNERABILITIES
        # ----------------------------------------------------

        vulnerabilities = [
            {
                "severity": "HIGH",
                "host": "192.168.1.12",
                "port": "445",
                "service": "SMB",
                "finding": "SMB service exposed",
                "evidence": "TCP/445 reachable on LAN",
                "score": "8.2",
                "status": "OPEN",
            },
            {
                "severity": "MEDIUM",
                "host": "192.168.1.20",
                "port": "3389",
                "service": "RDP",
                "finding": "RDP exposed",
                "evidence": "Remote Desktop detected",
                "score": "6.5",
                "status": "REVIEW",
            },
            {
                "severity": "LOW",
                "host": "192.168.1.1",
                "port": "80",
                "service": "HTTP",
                "finding": "Unencrypted HTTP service",
                "evidence": "TCP/80 detected",
                "score": "3.1",
                "status": "INFO",
            },
        ]

        # ----------------------------------------------------
        # THREAT INTELLIGENCE
        # ----------------------------------------------------

        threats = [
            {
                "indicator": "192.168.1.12",
                "type": "IP",
                "country": "LOCAL",
                "reputation": "UNKNOWN",
                "confidence": "N/A",
                "source": "Local Analysis",
                "first_seen": "Current",
                "status": "REVIEW",
            },
            {
                "indicator": "example.local",
                "type": "DOMAIN",
                "country": "LOCAL",
                "reputation": "SAFE",
                "confidence": "LOW",
                "source": "Local Analysis",
                "first_seen": "Current",
                "status": "CLEAR",
            },
        ]

        self.set_hosts(
            hosts
        )

        self.set_ports(
            ports
        )

        self.set_services(
            services
        )

        self.set_vulnerabilities(
            vulnerabilities
        )

        self.set_threat_intelligence(
            threats
        )

        # ----------------------------------------------------
        # Dashboard findings
        # ----------------------------------------------------

        self.dashboard_findings.setRowCount(
            0
        )

        for finding in vulnerabilities:

            row = self.dashboard_findings.rowCount()

            self.dashboard_findings.insertRow(
                row
            )

            values = [
                finding["severity"],
                finding["host"],
                finding["finding"],
                finding["status"],
            ]

            for column, value in enumerate(values):

                item = QTableWidgetItem(
                    value
                )

                item.setTextAlignment(
                    Qt.AlignCenter
                )

                self.dashboard_findings.setItem(
                    row,
                    column,
                    item
                )

        # ----------------------------------------------------
        # Summary
        # ----------------------------------------------------

        score = self.calculate_risk_score()

        self.summary_text.setPlainText(
            "NETWORK SECURITY SCAN\n"
            "=====================\n\n"
            "Target: 192.168.1.0/24\n"
            "Profile: Quick Discovery\n\n"
            f"Hosts discovered : {len(hosts)}\n"
            f"Open ports       : {len(ports)}\n"
            f"Services         : {len(services)}\n"
            f"Findings         : {len(vulnerabilities)}\n"
            f"Security score   : {score}/100\n"
            f"Risk level       : {self.get_risk_level(score)}\n\n"
            "This screen currently uses demonstration data.\n"
            "Real network scanning will be connected through "
            "the backend scanner services."
        )

        # ----------------------------------------------------
        # Report
        # ----------------------------------------------------

        self.report_text.setPlainText(
            "NETWORK DEFENSE MONITOR\n"
            "=======================\n\n"
            "SECURITY ASSESSMENT REPORT\n\n"
            "Target Network : 192.168.1.0/24\n"
            "Scan Profile   : Quick Discovery\n\n"
            "DISCOVERY\n"
            "---------\n"
            f"Hosts discovered : {len(hosts)}\n"
            f"Open ports       : {len(ports)}\n"
            f"Services         : {len(services)}\n\n"
            "SECURITY FINDINGS\n"
            "-----------------\n"
            f"Critical : 0\n"
            f"High     : 1\n"
            f"Medium   : 1\n"
            f"Low      : 1\n\n"
            f"Security Score : {score}/100\n"
            f"Risk Level     : {self.get_risk_level(score)}\n\n"
            "IMPORTANT\n"
            "---------\n"
            "Findings shown in this UI are demonstration data.\n"
            "A finding does not automatically prove compromise "
            "or malicious activity."
        )