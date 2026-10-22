# ============================================================
# MAIN WINDOW
# Network Traffic Analyzer
# ============================================================

from PySide6.QtCore import Qt

try:
    import psutil
except ImportError:
    psutil = None
from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QFrame,
    QStackedWidget,
    QListWidget,
    QListWidgetItem,
)

from frontend.dashboard import DashboardPage
from frontend.overview import OverviewPage
from frontend.inspection import InspectionPage
from frontend.speed_test import SpeedTestPage
from frontend.ndm_scanner import NDMScannerPage


class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle(
            "NETWORK TRAFFIC ANALYZER"
        )

        self.setMinimumSize(
            1250,
            760
        )

        self.setup_ui()

    # ========================================================
    # SETUP UI
    # ========================================================

    def setup_ui(self):

        central = QWidget()

        self.setCentralWidget(
            central
        )

        main_layout = QVBoxLayout(
            central
        )

        main_layout.setContentsMargins(
            0,
            0,
            0,
            0
        )

        main_layout.setSpacing(
            0
        )

        # ----------------------------------------------------
        # HEADER
        # ----------------------------------------------------

        header = self.create_header()

        main_layout.addWidget(
            header
        )

        # ----------------------------------------------------
        # BODY
        # ----------------------------------------------------

        body = QHBoxLayout()

        body.setContentsMargins(
            0,
            0,
            0,
            0
        )

        body.setSpacing(
            0
        )

        # Sidebar

        sidebar = self.create_sidebar()

        body.addWidget(
            sidebar
        )

        # Content

        self.stack = QStackedWidget()

        self.dashboard_page = DashboardPage()

        self.overview_page = OverviewPage()

        self.inspection_page = InspectionPage()

        self.speed_test_page = SpeedTestPage()

        self.ndm_scanner_page = NDMScannerPage()

        self.stack.addWidget(
            self.dashboard_page
        )

        self.stack.addWidget(
            self.overview_page
        )

        self.stack.addWidget(
            self.inspection_page
        )

        self.stack.addWidget(
            self.speed_test_page
        )

        self.stack.addWidget(
            self.ndm_scanner_page
        )

        body.addWidget(
            self.stack
        )

        main_layout.addLayout(
            body
        )

        # ----------------------------------------------------
        # FOOTER
        # ----------------------------------------------------

        footer = self.create_footer()

        main_layout.addWidget(
            footer
        )

        # Default page

        self.stack.setCurrentIndex(
            0
        )

        self.sidebar_list.setCurrentRow(
            0
        )

    # ========================================================
    # HEADER
    # ========================================================

    def create_header(self):

        header = QFrame()

        header.setFixedHeight(
            58
        )

        header.setObjectName(
            "MainHeader"
        )

        layout = QHBoxLayout(
            header
        )

        layout.setContentsMargins(
            20,
            0,
            20,
            0
        )

        title = QLabel(
            "NETWORK TRAFFIC ANALYZER"
        )

        title.setObjectName(
            "AppTitle"
        )

        layout.addWidget(
            title
        )

        layout.addStretch()

        status = QLabel(
            "● SYSTEM READY"
        )

        status.setObjectName(
            "SystemStatus"
        )

        layout.addWidget(
            status
        )

        header.setStyleSheet(
            """
            QFrame#MainHeader {
                background: #0B1120;
                border-bottom: 1px solid #1F2937;
            }

            QLabel#AppTitle {
                color: #E5E7EB;
                font-size: 15px;
                font-weight: 700;
            }

            QLabel#SystemStatus {
                color: #22C55E;
                font-size: 10px;
                font-weight: 700;
            }
            """
        )

        return header

    # ========================================================
    # SIDEBAR
    # ========================================================

    def create_sidebar(self):

        sidebar = QFrame()

        sidebar.setFixedWidth(
            235
        )

        sidebar.setObjectName(
            "Sidebar"
        )

        layout = QVBoxLayout(
            sidebar
        )

        layout.setContentsMargins(
            12,
            15,
            12,
            15
        )

        layout.setSpacing(
            6
        )

        # ----------------------------------------------------
        # Navigation title
        # ----------------------------------------------------

        navigation_title = QLabel(
            "NAVIGATION"
        )

        navigation_title.setObjectName(
            "NavigationTitle"
        )

        layout.addWidget(
            navigation_title
        )

        # ----------------------------------------------------
        # Sidebar list
        # ----------------------------------------------------

        self.sidebar_list = QListWidget()

        self.sidebar_list.setObjectName(
            "SidebarList"
        )

        self.sidebar_list.setSpacing(
            3
        )

        pages = [
            "Dashboard",
            "Overview",
            "Inspection",
            "Speed Test",
            "NDM Scanner",
        ]

        for page in pages:

            item = QListWidgetItem(
                page
            )

            item.setSizeHint(
                item.sizeHint()
            )

            self.sidebar_list.addItem(
                item
            )

        self.sidebar_list.currentRowChanged.connect(
            self.change_page
        )

        layout.addWidget(
            self.sidebar_list
        )

        # ----------------------------------------------------
        # Network adapters
        # ----------------------------------------------------

        adapter_title = QLabel(
            "NETWORK ADAPTERS"
        )

        adapter_title.setObjectName(
            "NavigationTitle"
        )

        layout.addWidget(
            adapter_title
        )

        # Show adapters detected on THIS computer, not a hardcoded list.
        # Hide virtual/tunnel/loopback interfaces from the sidebar so it
        # focuses on physical/local network adapters such as Wi-Fi/Ethernet.
        self.adapter_labels = []
        virtual_markers = (
            "vmware", "virtualbox", "vmnet", "veth", "hyper-v",
            "wsl", "npcap", "loopback", "tap-windows", "teredo",
            "isatap", "6to4", "pseudo-interface", "bluetooth device",
        )

        adapter_names = []
        if psutil is not None:
            try:
                addresses = psutil.net_if_addrs()
                stats = psutil.net_if_stats()
                for adapter_name in addresses:
                    lowered = adapter_name.lower()
                    if any(marker in lowered for marker in virtual_markers):
                        continue
                    # Only show an interface that has an IPv4/IPv6 or MAC address.
                    has_network_address = any(
                        getattr(addr, "address", "")
                        for addr in addresses[adapter_name]
                    )
                    if has_network_address:
                        adapter_names.append((adapter_name, bool(stats.get(adapter_name) and stats[adapter_name].isup)))
            except Exception:
                adapter_names = []

        if not adapter_names:
            empty_label = QLabel("No physical adapters detected")
            empty_label.setObjectName("AdapterItem")
            layout.addWidget(empty_label)
        else:
            for adapter_name, is_up in adapter_names:
                indicator = "●" if is_up else "○"
                label = QLabel(f"{indicator} {adapter_name}")
                label.setObjectName("AdapterItem")
                label.setToolTip("Interface is up" if is_up else "Interface is down")
                layout.addWidget(label)
                self.adapter_labels.append(label)

        layout.addStretch()

        sidebar.setStyleSheet(
            """
            QFrame#Sidebar {
                background: #0F172A;
                border-right: 1px solid #1F2937;
            }

            QLabel#NavigationTitle {
                color: #64748B;
                font-size: 9px;
                font-weight: 700;
                padding: 6px 8px;
            }

            QLabel#AdapterItem {
                color: #94A3B8;
                font-size: 10px;
                padding: 5px 8px;
            }

            QListWidget#SidebarList {
                background: transparent;
                border: none;
                outline: none;
            }

            QListWidget#SidebarList::item {
                color: #94A3B8;
                padding: 11px 12px;
                border-radius: 5px;
                font-size: 11px;
                font-weight: 600;
            }

            QListWidget#SidebarList::item:hover {
                background: #172033;
                color: #E5E7EB;
            }

            QListWidget#SidebarList::item:selected {
                background: #2563EB;
                color: white;
            }
            """
        )

        return sidebar

    # ========================================================
    # PAGE CHANGE
    # ========================================================

    def change_page(
        self,
        index
    ):

        if index < 0:
            return

        self.stack.setCurrentIndex(
            index
        )

    # ========================================================
    # FOOTER
    # ========================================================

    def create_footer(self):

        footer = QFrame()

        footer.setFixedHeight(
            32
        )

        footer.setObjectName(
            "Footer"
        )

        layout = QHBoxLayout(
            footer
        )

        layout.setContentsMargins(
            15,
            0,
            15,
            0
        )

        left = QLabel(
            "Network Traffic Analyzer"
        )

        right = QLabel(
            "Python / PySide6 / Scapy"
        )

        layout.addWidget(
            left
        )

        layout.addStretch()

        layout.addWidget(
            right
        )

        footer.setStyleSheet(
            """
            QFrame#Footer {
                background: #0B1120;
                border-top: 1px solid #1F2937;
            }

            QFrame#Footer QLabel {
                color: #64748B;
                font-size: 9px;
            }
            """
        )

        return footer