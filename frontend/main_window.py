from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from frontend.dashboard import DashboardPage


class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle(
            "Network Traffic Analyzer"
        )

        self.setMinimumSize(
            1400,
            850
        )

        self.load_theme()
        self.setup_ui()

    # ==================================================
    # LOAD THEME
    # ==================================================

    def load_theme(self):

        theme_path = (
            Path(__file__).parent
            / "styles"
            / "theme.qss"
        )

        if not theme_path.exists():
            print(
                "Theme file not found:",
                theme_path
            )
            return

        try:

            with open(
                theme_path,
                "r",
                encoding="utf-8"
            ) as file:

                self.setStyleSheet(
                    file.read()
                )

        except OSError as error:

            print(
                f"Unable to load theme: {error}"
            )

    # ==================================================
    # SETUP UI
    # ==================================================

    def setup_ui(self):

        central_widget = QWidget()

        self.setCentralWidget(
            central_widget
        )

        main_layout = QHBoxLayout(
            central_widget
        )

        main_layout.setContentsMargins(
            0,
            0,
            0,
            0
        )

        main_layout.setSpacing(0)

        # Sidebar
        sidebar = self.create_sidebar()

        # Main content
        content = self.create_content_area()

        main_layout.addWidget(
            sidebar
        )

        main_layout.addWidget(
            content
        )

        # Navigation
        self.navigation.currentRowChanged.connect(
            self.change_page
        )

        self.navigation.setCurrentRow(
            0
        )

    # ==================================================
    # SIDEBAR
    # ==================================================

    def create_sidebar(self):

        sidebar = QFrame()

        sidebar.setObjectName(
            "sidebar"
        )

        sidebar.setFixedWidth(
            250
        )

        sidebar_layout = QVBoxLayout(
            sidebar
        )

        sidebar_layout.setContentsMargins(
            15,
            20,
            15,
            20
        )

        sidebar_layout.setSpacing(
            8
        )

        # Application title
        app_title = QLabel(
            "NETWORK\nTRAFFIC ANALYZER"
        )

        app_title.setObjectName(
            "appTitle"
        )

        app_title.setAlignment(
            Qt.AlignCenter
        )

        sidebar_layout.addWidget(
            app_title
        )

        # Navigation
        navigation_title = QLabel(
            "NAVIGATION"
        )

        navigation_title.setObjectName(
            "sectionTitle"
        )

        sidebar_layout.addWidget(
            navigation_title
        )

        self.navigation = QListWidget()

        self.navigation.setObjectName(
            "navigation"
        )

        navigation_items = [
            "Dashboard",
            "Overview",
            "Inspection",
        ]

        for name in navigation_items:

            self.navigation.addItem(
                QListWidgetItem(name)
            )

        sidebar_layout.addWidget(
            self.navigation
        )

        # Network adapters
        adapter_title = QLabel(
            "NETWORK ADAPTERS"
        )

        adapter_title.setObjectName(
            "sectionTitle"
        )

        sidebar_layout.addWidget(
            adapter_title
        )

        self.adapter_list = QListWidget()

        self.adapter_list.setObjectName(
            "adapterList"
        )

        # Temporary data.
        # Later this will come from AdapterService.

        adapters = [
            "●  Wi-Fi",
            "○  Ethernet",
            "○  Bluetooth",
            "○  VMware Network",
            "○  VirtualBox Host-Only",
            "○  vEthernet (WSL)",
            "○  vEthernet (Default Switch)",
            "○  Npcap Loopback",
        ]

        for adapter in adapters:

            self.adapter_list.addItem(
                QListWidgetItem(adapter)
            )

        sidebar_layout.addWidget(
            self.adapter_list
        )

        sidebar_layout.addStretch()

        # Footer
        version = QLabel(
            "NETWORK TRAFFIC ANALYZER\n"
            "v0.3 • LOCAL MONITOR"
        )

        version.setObjectName(
            "footer"
        )

        version.setAlignment(
            Qt.AlignCenter
        )

        sidebar_layout.addWidget(
            version
        )

        return sidebar

    # ==================================================
    # CONTENT AREA
    # ==================================================

    def create_content_area(self):

        content = QFrame()

        content.setObjectName(
            "content"
        )

        content_layout = QVBoxLayout(
            content
        )

        content_layout.setContentsMargins(
            20,
            15,
            20,
            15
        )

        content_layout.setSpacing(
            12
        )

        # Header
        header = self.create_header()

        content_layout.addWidget(
            header
        )

        # Pages
        self.page_stack = QStackedWidget()

        self.page_stack.setObjectName(
            "pageStack"
        )

        # ==========================================
        # REAL DASHBOARD
        # ==========================================

        self.dashboard_page = DashboardPage()

        self.page_stack.addWidget(
            self.dashboard_page
        )

        # ==========================================
        # TEMPORARY OVERVIEW
        # ==========================================

        overview_page = self.create_placeholder_page(
            "Overview",
            "Network and adapter overview"
        )

        self.page_stack.addWidget(
            overview_page
        )

        # ==========================================
        # TEMPORARY INSPECTION
        # ==========================================

        inspection_page = self.create_placeholder_page(
            "Inspection",
            "Packet inspection and analysis"
        )

        self.page_stack.addWidget(
            inspection_page
        )

        content_layout.addWidget(
            self.page_stack
        )

        # Footer
        footer = QLabel(
            "Network Traffic Analyzer"
            "  •  Python"
            "  •  PySide6"
            "  •  Scapy"
            "  •  Local Network Monitoring"
        )

        footer.setObjectName(
            "footer"
        )

        footer.setAlignment(
            Qt.AlignCenter
        )

        content_layout.addWidget(
            footer
        )

        return content

    # ==================================================
    # HEADER
    # ==================================================

    def create_header(self):

        header = QFrame()

        header.setObjectName(
            "header"
        )

        header_layout = QHBoxLayout(
            header
        )

        header_layout.setContentsMargins(
            15,
            10,
            15,
            10
        )

        # Page title
        self.page_title = QLabel(
            "Dashboard"
        )

        self.page_title.setObjectName(
            "pageTitle"
        )

        header_layout.addWidget(
            self.page_title
        )

        header_layout.addStretch()

        # Capture status
        self.system_status = QLabel(
            "● SYSTEM READY"
        )

        self.system_status.setObjectName(
            "systemStatus"
        )

        header_layout.addWidget(
            self.system_status
        )

        return header

    # ==================================================
    # PLACEHOLDER
    # ==================================================

    def create_placeholder_page(
        self,
        title,
        description
    ):

        page = QWidget()

        layout = QVBoxLayout(
            page
        )

        title_label = QLabel(
            title
        )

        title_label.setObjectName(
            "placeholder"
        )

        title_label.setAlignment(
            Qt.AlignCenter
        )

        description_label = QLabel(
            description
        )

        description_label.setProperty(
            "secondary",
            True
        )

        description_label.setAlignment(
            Qt.AlignCenter
        )

        layout.addStretch()

        layout.addWidget(
            title_label
        )

        layout.addWidget(
            description_label
        )

        layout.addStretch()

        return page

    # ==================================================
    # PAGE CHANGE
    # ==================================================

    def change_page(
        self,
        index
    ):

        if index < 0:
            return

        if index >= self.page_stack.count():
            return

        self.page_stack.setCurrentIndex(
            index
        )

        page_names = [
            "Dashboard",
            "Overview",
            "Inspection",
        ]

        if index < len(page_names):

            self.page_title.setText(
                page_names[index]
            )

    # ==================================================
    # SYSTEM STATUS
    # ==================================================

    def set_system_status(
        self,
        status,
        status_type="normal"
    ):

        self.system_status.setText(
            f"● {status}"
        )

        self.system_status.setProperty(
            "status",
            status_type
        )

        self.system_status.style().unpolish(
            self.system_status
        )

        self.system_status.style().polish(
            self.system_status
        )