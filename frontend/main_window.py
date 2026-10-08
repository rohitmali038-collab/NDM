# ==============================================================
# NETWORK TRAFFIC ANALYZER
# MAIN WINDOW
# ==============================================================
#
# This file controls the COMMON application UI.
#
# Responsibilities:
#
#   1. Main application window
#   2. Common sidebar
#   3. Dashboard / Overview / Inspection navigation
#   4. Common header
#   5. Common footer
#   6. Network adapter list
#   7. Page switching
#
# FRONTEND ONLY
#
# Backend services will be connected later.
#
# ==============================================================


import os

from PySide6.QtCore import Qt, QSize
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from frontend.dashboard import DashboardPage
from frontend.overview import OverviewPage
from frontend.inspection import InspectionPage


# ==============================================================
# SIZE CONFIGURATION
# ==============================================================
#
# You can easily change the UI size from here.
#
# ==============================================================


# --------------------------------------------------------------
# MAIN WINDOW
# --------------------------------------------------------------

WINDOW_WIDTH = 1280
WINDOW_HEIGHT = 800

MIN_WINDOW_WIDTH = 1050
MIN_WINDOW_HEIGHT = 650


# --------------------------------------------------------------
# SIDEBAR
# --------------------------------------------------------------

SIDEBAR_WIDTH = 275


# --------------------------------------------------------------
# HEADER / FOOTER
# --------------------------------------------------------------

HEADER_HEIGHT = 52
FOOTER_HEIGHT = 28


# --------------------------------------------------------------
# SIDEBAR TITLE
# --------------------------------------------------------------

SIDEBAR_TITLE_HEIGHT = 115


# --------------------------------------------------------------
# NAVIGATION BUTTONS
# --------------------------------------------------------------

NAV_BUTTON_HEIGHT = 42


# --------------------------------------------------------------
# NETWORK ADAPTER ITEMS
# --------------------------------------------------------------

# Height of each adapter item.
#
# Example:
#
# ○ Wi-Fi
#   Intel(R) Wi-Fi 6 AX201 160MHz
#
# Each adapter gets 52 px.
#
ADAPTER_ITEM_HEIGHT = 52


# Maximum description width.
ADAPTER_DESCRIPTION_WIDTH = 205


# Refresh button size.
ADAPTER_REFRESH_SIZE = 22


# ==============================================================
# COLOR CONFIGURATION
# ==============================================================


COLOR_BACKGROUND = "#050B14"

COLOR_SIDEBAR = "#07111F"

COLOR_PANEL = "#0B1728"

COLOR_BORDER = "#17324D"

COLOR_BLUE = "#1683FF"

COLOR_CYAN = "#00E5FF"

COLOR_GREEN = "#00E676"

COLOR_RED = "#FF3B4E"

COLOR_TEXT = "#F1F5F9"

COLOR_SECONDARY = "#94A3B8"

COLOR_MUTED = "#64748B"


# ==============================================================
# MAIN WINDOW
# ==============================================================


class MainWindow(QWidget):

    def __init__(self):

        super().__init__()

        # ------------------------------------------------------
        # WINDOW TITLE
        # ------------------------------------------------------

        self.setWindowTitle(
            "Network Traffic Analyzer"
        )

        # ------------------------------------------------------
        # WINDOW SIZE
        # ------------------------------------------------------

        self.resize(
            WINDOW_WIDTH,
            WINDOW_HEIGHT
        )

        # ------------------------------------------------------
        # MINIMUM SIZE
        # ------------------------------------------------------

        self.setMinimumSize(
            MIN_WINDOW_WIDTH,
            MIN_WINDOW_HEIGHT
        )

        # ------------------------------------------------------
        # OBJECT NAME
        # ------------------------------------------------------

        self.setObjectName(
            "mainWindow"
        )

        # ------------------------------------------------------
        # CURRENT ADAPTER
        # ------------------------------------------------------

        self.selected_adapter = None

        # ------------------------------------------------------
        # BUILD UI
        # ------------------------------------------------------

        self.setup_ui()

        # ------------------------------------------------------
        # LOAD COMMON THEME
        # ------------------------------------------------------

        self.load_theme()

        # ------------------------------------------------------
        # OPEN DASHBOARD
        # ------------------------------------------------------

        self.show_dashboard()

    # ==========================================================
    # SETUP UI
    # ==========================================================

    def setup_ui(self):

        # ------------------------------------------------------
        # MAIN HORIZONTAL LAYOUT
        # ------------------------------------------------------

        main_layout = QHBoxLayout(
            self
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

        # ------------------------------------------------------
        # SIDEBAR
        # ------------------------------------------------------

        self.sidebar = (
            self.create_sidebar()
        )

        main_layout.addWidget(
            self.sidebar
        )

        # ------------------------------------------------------
        # RIGHT CONTENT CONTAINER
        # ------------------------------------------------------

        right_container = QFrame()

        right_container.setObjectName(
            "rightContainer"
        )

        right_container.setStyleSheet(
            f"""
            QFrame#rightContainer {{
                background-color: {COLOR_BACKGROUND};
                border: none;
            }}
            """
        )

        right_layout = QVBoxLayout(
            right_container
        )

        right_layout.setContentsMargins(
            0,
            0,
            0,
            0
        )

        right_layout.setSpacing(
            0
        )

        # ------------------------------------------------------
        # HEADER
        # ------------------------------------------------------

        self.header = (
            self.create_header()
        )

        right_layout.addWidget(
            self.header
        )

        # ------------------------------------------------------
        # PAGE STACK
        # ------------------------------------------------------

        self.stack = QStackedWidget()

        self.stack.setObjectName(
            "pageStack"
        )

        self.stack.setStyleSheet(
            f"""
            QStackedWidget#pageStack {{
                background-color: {COLOR_BACKGROUND};
                border: none;
            }}
            """
        )

        # ------------------------------------------------------
        # DASHBOARD PAGE
        # ------------------------------------------------------

        self.dashboard_page = (
            DashboardPage()
        )

        # ------------------------------------------------------
        # OVERVIEW PAGE
        # ------------------------------------------------------

        self.overview_page = (
            OverviewPage()
        )

        # ------------------------------------------------------
        # INSPECTION PAGE
        # ------------------------------------------------------

        self.inspection_page = (
            InspectionPage()
        )

        # ------------------------------------------------------
        # ADD PAGES
        # ------------------------------------------------------

        self.stack.addWidget(
            self.dashboard_page
        )

        self.stack.addWidget(
            self.overview_page
        )

        self.stack.addWidget(
            self.inspection_page
        )

        # ------------------------------------------------------
        # ADD STACK TO RIGHT AREA
        # ------------------------------------------------------

        right_layout.addWidget(
            self.stack,
            1
        )

        # ------------------------------------------------------
        # FOOTER
        # ------------------------------------------------------

        self.footer = (
            self.create_footer()
        )

        right_layout.addWidget(
            self.footer
        )

        # ------------------------------------------------------
        # ADD RIGHT AREA
        # ------------------------------------------------------

        main_layout.addWidget(
            right_container,
            1
        )

    # ==========================================================
    # CREATE SIDEBAR
    # ==========================================================

    def create_sidebar(self):

        sidebar = QFrame()

        sidebar.setObjectName(
            "sidebar"
        )

        # ------------------------------------------------------
        # SIDEBAR WIDTH
        # ------------------------------------------------------

        sidebar.setFixedWidth(
            SIDEBAR_WIDTH
        )

        # ------------------------------------------------------
        # SIDEBAR BACKGROUND
        # ------------------------------------------------------

        sidebar.setStyleSheet(
            f"""
            QFrame#sidebar {{
                background-color: {COLOR_SIDEBAR};
                border-right: 1px solid {COLOR_BORDER};
            }}
            """
        )

        # ------------------------------------------------------
        # SIDEBAR LAYOUT
        # ------------------------------------------------------

        layout = QVBoxLayout(
            sidebar
        )

        layout.setContentsMargins(
            16,
            18,
            16,
            12
        )

        layout.setSpacing(
            4
        )

        # ======================================================
        # APPLICATION TITLE
        # ======================================================

        title_container = QFrame()

        title_container.setFixedHeight(
            SIDEBAR_TITLE_HEIGHT
        )

        title_layout = QVBoxLayout(
            title_container
        )

        title_layout.setContentsMargins(
            0,
            0,
            0,
            0
        )

        title_layout.setAlignment(
            Qt.AlignCenter
        )

        # ------------------------------------------------------
        # TITLE 1
        # ------------------------------------------------------

        title_1 = QLabel(
            "NETWORK"
        )

        title_1.setObjectName(
            "appTitle"
        )

        title_1.setAlignment(
            Qt.AlignCenter
        )

        # ------------------------------------------------------
        # TITLE 2
        # ------------------------------------------------------

        title_2 = QLabel(
            "TRAFFIC ANALYZER"
        )

        title_2.setObjectName(
            "appTitle"
        )

        title_2.setAlignment(
            Qt.AlignCenter
        )

        title_layout.addWidget(
            title_1
        )

        title_layout.addWidget(
            title_2
        )

        layout.addWidget(
            title_container
        )

        # ======================================================
        # NAVIGATION TITLE
        # ======================================================

        navigation_title = QLabel(
            "NAVIGATION"
        )

        navigation_title.setObjectName(
            "sectionTitle"
        )

        layout.addWidget(
            navigation_title
        )

        layout.addSpacing(
            6
        )

        # ======================================================
        # DASHBOARD BUTTON
        # ======================================================

        self.dashboard_button = (
            self.create_navigation_button(
                "Dashboard"
            )
        )

        self.dashboard_button.clicked.connect(
            self.show_dashboard
        )

        layout.addWidget(
            self.dashboard_button
        )

        # ======================================================
        # OVERVIEW BUTTON
        # ======================================================

        self.overview_button = (
            self.create_navigation_button(
                "Overview"
            )
        )

        self.overview_button.clicked.connect(
            self.show_overview
        )

        layout.addWidget(
            self.overview_button
        )

        # ======================================================
        # INSPECTION BUTTON
        # ======================================================

        self.inspection_button = (
            self.create_navigation_button(
                "Inspection"
            )
        )

        self.inspection_button.clicked.connect(
            self.show_inspection
        )

        layout.addWidget(
            self.inspection_button
        )

        # ======================================================
        # SPACE BEFORE ADAPTERS
        # ======================================================

        layout.addSpacing(
            75
        )

        # ======================================================
        # NETWORK ADAPTER HEADER
        # ======================================================

        adapter_header = QHBoxLayout()

        adapter_title = QLabel(
            "NETWORK ADAPTERS"
        )

        adapter_title.setObjectName(
            "sectionTitle"
        )

        adapter_header.addWidget(
            adapter_title
        )

        adapter_header.addStretch()

        # ------------------------------------------------------
        # REFRESH BUTTON
        # ------------------------------------------------------

        refresh_button = QPushButton(
            "⟳"
        )

        refresh_button.setObjectName(
            "adapterRefreshButton"
        )

        refresh_button.setFixedSize(
            ADAPTER_REFRESH_SIZE,
            ADAPTER_REFRESH_SIZE
        )

        refresh_button.setCursor(
            Qt.PointingHandCursor
        )

        refresh_button.clicked.connect(
            self.refresh_adapters
        )

        adapter_header.addWidget(
            refresh_button
        )

        layout.addLayout(
            adapter_header
        )

        # ======================================================
        # ADAPTER LIST
        # ======================================================

        self.adapter_list = QListWidget()

        self.adapter_list.setObjectName(
            "adapterList"
        )

        # ------------------------------------------------------
        # IMPORTANT:
        #
        # Prevent horizontal scrollbar.
        #
        # This fixes the horizontal bar visible at the
        # bottom of the sidebar.
        #
        # ------------------------------------------------------

        self.adapter_list.setHorizontalScrollBarPolicy(
            Qt.ScrollBarAlwaysOff
        )

        # ------------------------------------------------------
        # Vertical scrollbar
        # ------------------------------------------------------

        self.adapter_list.setVerticalScrollBarPolicy(
            Qt.ScrollBarAsNeeded
        )

        # ------------------------------------------------------
        # Remove extra frame.
        # ------------------------------------------------------

        self.adapter_list.setFrameShape(
            QFrame.NoFrame
        )

        # ------------------------------------------------------
        # LIST STYLE
        # ------------------------------------------------------

        self.adapter_list.setStyleSheet(
            f"""
            QListWidget#adapterList {{
                background-color: transparent;
                border: none;
                outline: none;
                padding: 0px;
            }}

            QListWidget#adapterList::item {{
                border: none;
                padding: 0px;
                margin: 0px;
            }}

            QListWidget#adapterList::item:selected {{
                background-color: transparent;
            }}

            QScrollBar:vertical {{
                background: transparent;
                width: 7px;
                margin: 0px;
            }}

            QScrollBar::handle:vertical {{
                background: #214968;
                border-radius: 3px;
                min-height: 35px;
            }}

            QScrollBar::handle:vertical:hover {{
                background: #2B648A;
            }}

            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {{
                height: 0px;
            }}
            """
        )

        # ======================================================
        # ADAPTER DATA
        # ======================================================

        adapters = [

            (
                "Wi-Fi",
                "Intel(R) Wi-Fi 6 AX201 160MHz"
            ),

            (
                "Ethernet",
                "Realtek PCIe GbE Family"
            ),

            (
                "Bluetooth",
                "Bluetooth Device"
            ),

            (
                "VMware Network",
                "VMware Virtual Ethernet"
            ),

            (
                "VirtualBox Host-Only",
                "VirtualBox Host-Only"
            ),

            (
                "vEthernet (WSL)",
                "Hyper-V Virtual Ethernet"
            ),

            (
                "vEthernet (Default Switch)",
                "Hyper-V Virtual Ethernet"
            ),

            (
                "Npcap Loopback",
                "Npcap Loopback Adapter"
            ),

            (
                "TAP-Windows Adapter",
                "TAP-Windows Adapter V9"
            ),
        ]

        # ======================================================
        # ADD ADAPTER ITEMS
        # ======================================================

        for name, description in adapters:

            # --------------------------------------------------
            # LIST ITEM
            # --------------------------------------------------

            item = QListWidgetItem()

            # --------------------------------------------------
            # FIXED SIZE
            # --------------------------------------------------

            item.setSizeHint(
                self.adapter_item_size()
            )

            self.adapter_list.addItem(
                item
            )

            # --------------------------------------------------
            # CUSTOM WIDGET
            # --------------------------------------------------

            widget = (
                self.create_adapter_item(
                    name,
                    description
                )
            )

            self.adapter_list.setItemWidget(
                item,
                widget
            )

        # ======================================================
        # ADAPTER CLICK
        # ======================================================

        self.adapter_list.itemClicked.connect(
            self.on_adapter_selected
        )

        # ------------------------------------------------------
        # Add adapter list.
        #
        # stretch = 1 means it uses available space but does
        # not push the footer outside the window.
        #
        # ------------------------------------------------------

        layout.addWidget(
            self.adapter_list,
            1
        )

        # ======================================================
        # SIDEBAR FOOTER
        # ======================================================

        sidebar_footer = QLabel(
            "NETWORK TRAFFIC ANALYZER\n"
            "v0.3 · LOCAL MONITOR"
        )

        sidebar_footer.setObjectName(
            "sidebarFooter"
        )

        sidebar_footer.setAlignment(
            Qt.AlignCenter
        )

        sidebar_footer.setFixedHeight(
            38
        )

        layout.addWidget(
            sidebar_footer
        )

        return sidebar

    # ==========================================================
    # ADAPTER ITEM SIZE
    # ==========================================================

    def adapter_item_size(self):

        return QSize(
            SIDEBAR_WIDTH - 45,
            ADAPTER_ITEM_HEIGHT
        )

    # ==========================================================
    # CREATE ADAPTER ITEM
    # ==========================================================

    def create_adapter_item(
        self,
        name,
        description
    ):

        widget = QFrame()

        widget.setObjectName(
            "adapterItem"
        )

        # ------------------------------------------------------
        # FIXED HEIGHT
        # ------------------------------------------------------

        widget.setFixedHeight(
            ADAPTER_ITEM_HEIGHT
        )

        # ------------------------------------------------------
        # ITEM LAYOUT
        # ------------------------------------------------------

        layout = QHBoxLayout(
            widget
        )

        layout.setContentsMargins(
            2,
            4,
            2,
            4
        )

        layout.setSpacing(
            7
        )

        # ======================================================
        # ADAPTER STATUS ICON
        # ======================================================

        icon = QLabel(
            "○"
        )

        icon.setObjectName(
            "adapterIcon"
        )

        icon.setFixedWidth(
            18
        )

        icon.setAlignment(
            Qt.AlignTop |
            Qt.AlignHCenter
        )

        layout.addWidget(
            icon
        )

        # ======================================================
        # TEXT CONTAINER
        # ======================================================

        text_container = QFrame()

        text_layout = QVBoxLayout(
            text_container
        )

        text_layout.setContentsMargins(
            0,
            0,
            0,
            0
        )

        text_layout.setSpacing(
            0
        )

        # ------------------------------------------------------
        # ADAPTER NAME
        # ------------------------------------------------------

        adapter_name = QLabel(
            name
        )

        adapter_name.setObjectName(
            "adapterName"
        )

        adapter_name.setFixedHeight(
            20
        )

        # ------------------------------------------------------
        # DESCRIPTION
        # ------------------------------------------------------

        adapter_description = QLabel(
            description
        )

        adapter_description.setObjectName(
            "adapterDescription"
        )

        adapter_description.setFixedHeight(
            18
        )

        adapter_description.setMaximumWidth(
            ADAPTER_DESCRIPTION_WIDTH
        )

        # ------------------------------------------------------
        # IMPORTANT:
        #
        # Prevent description from wrapping to another line.
        #
        # ------------------------------------------------------

        adapter_description.setWordWrap(
            False
        )

        # ------------------------------------------------------
        # ADD TEXT
        # ------------------------------------------------------

        text_layout.addWidget(
            adapter_name
        )

        text_layout.addWidget(
            adapter_description
        )

        layout.addWidget(
            text_container,
            1
        )

        return widget

    # ==========================================================
    # NAVIGATION BUTTON
    # ==========================================================

    def create_navigation_button(
        self,
        text
    ):

        button = QPushButton(
            text
        )

        button.setObjectName(
            "navigationButton"
        )

        button.setFixedHeight(
            NAV_BUTTON_HEIGHT
        )

        button.setCursor(
            Qt.PointingHandCursor
        )

        return button

    # ==========================================================
    # HEADER
    # ==========================================================

    def create_header(self):

        header = QFrame()

        header.setObjectName(
            "mainHeader"
        )

        # ------------------------------------------------------
        # HEADER HEIGHT
        # ------------------------------------------------------

        header.setFixedHeight(
            HEADER_HEIGHT
        )

        # ------------------------------------------------------
        # HEADER STYLE
        # ------------------------------------------------------

        header.setStyleSheet(
            f"""
            QFrame#mainHeader {{
                background-color: {COLOR_PANEL};
                border-bottom: 1px solid {COLOR_BORDER};
            }}
            """
        )

        # ------------------------------------------------------
        # HEADER LAYOUT
        # ------------------------------------------------------

        layout = QHBoxLayout(
            header
        )

        layout.setContentsMargins(
            14,
            4,
            14,
            4
        )

        # ------------------------------------------------------
        # PAGE TITLE
        # ------------------------------------------------------

        self.page_title = QLabel(
            "Dashboard"
        )

        self.page_title.setObjectName(
            "pageHeaderTitle"
        )

        layout.addWidget(
            self.page_title
        )

        layout.addStretch()

        # ------------------------------------------------------
        # SYSTEM STATUS
        # ------------------------------------------------------

        self.system_status = QLabel(
            "● SYSTEM READY"
        )

        self.system_status.setObjectName(
            "systemStatus"
        )

        layout.addWidget(
            self.system_status
        )

        return header

    # ==========================================================
    # FOOTER
    # ==========================================================

    def create_footer(self):

        footer = QFrame()

        footer.setObjectName(
            "mainFooter"
        )

        # ------------------------------------------------------
        # FOOTER HEIGHT
        # ------------------------------------------------------

        footer.setFixedHeight(
            FOOTER_HEIGHT
        )

        # ------------------------------------------------------
        # FOOTER STYLE
        # ------------------------------------------------------

        footer.setStyleSheet(
            f"""
            QFrame#mainFooter {{
                background-color: {COLOR_PANEL};
                border-top: 1px solid {COLOR_BORDER};
            }}
            """
        )

        # ------------------------------------------------------
        # FOOTER LAYOUT
        # ------------------------------------------------------

        layout = QHBoxLayout(
            footer
        )

        layout.setContentsMargins(
            10,
            2,
            10,
            2
        )

        # ------------------------------------------------------
        # LEFT
        # ------------------------------------------------------

        left = QLabel(
            "Network Traffic Analyzer"
        )

        left.setObjectName(
            "footerText"
        )

        layout.addWidget(
            left
        )

        layout.addStretch()

        # ------------------------------------------------------
        # RIGHT
        # ------------------------------------------------------

        right = QLabel(
            "Python / PySide6 / Scapy"
        )

        right.setObjectName(
            "footerText"
        )

        layout.addWidget(
            right
        )

        return footer

    # ==========================================================
    # SHOW DASHBOARD
    # ==========================================================

    def show_dashboard(self):

        # ------------------------------------------------------
        # PAGE INDEX
        # ------------------------------------------------------

        self.stack.setCurrentIndex(
            0
        )

        # ------------------------------------------------------
        # HEADER TITLE
        # ------------------------------------------------------

        self.page_title.setText(
            "Dashboard"
        )

        # ------------------------------------------------------
        # ACTIVE BUTTON
        # ------------------------------------------------------

        self.set_active_navigation(
            self.dashboard_button
        )

    # ==========================================================
    # SHOW OVERVIEW
    # ==========================================================

    def show_overview(self):

        self.stack.setCurrentIndex(
            1
        )

        self.page_title.setText(
            "Overview"
        )

        self.set_active_navigation(
            self.overview_button
        )

    # ==========================================================
    # SHOW INSPECTION
    # ==========================================================

    def show_inspection(self):

        self.stack.setCurrentIndex(
            2
        )

        self.page_title.setText(
            "Inspection"
        )

        self.set_active_navigation(
            self.inspection_button
        )

    # ==========================================================
    # ACTIVE NAVIGATION
    # ==========================================================

    def set_active_navigation(
        self,
        active_button
    ):

        buttons = [

            self.dashboard_button,

            self.overview_button,

            self.inspection_button,
        ]

        for button in buttons:

            # --------------------------------------------------
            # Store active state.
            # theme.qss can use this property.
            # --------------------------------------------------

            button.setProperty(
                "active",
                button is active_button
            )

            # --------------------------------------------------
            # Refresh stylesheet state.
            # --------------------------------------------------

            button.style().unpolish(
                button
            )

            button.style().polish(
                button
            )

            button.update()

    # ==========================================================
    # ADAPTER SELECTION
    # ==========================================================

    def on_adapter_selected(
        self,
        item
    ):

        # ------------------------------------------------------
        # Get custom widget.
        # ------------------------------------------------------

        widget = (
            self.adapter_list.itemWidget(
                item
            )
        )

        if widget is None:
            return

        # ------------------------------------------------------
        # Find adapter name label.
        # ------------------------------------------------------

        name_label = widget.findChild(
            QLabel,
            "adapterName"
        )

        if name_label is None:
            return

        # ------------------------------------------------------
        # Get name.
        # ------------------------------------------------------

        adapter_name = (
            name_label.text()
        )

        # ------------------------------------------------------
        # Save selected adapter.
        # ------------------------------------------------------

        self.selected_adapter = (
            adapter_name
        )

        # ------------------------------------------------------
        # Send selection to Overview.
        # ------------------------------------------------------

        self.overview_page.set_adapter(

            adapter_name=adapter_name,

            description=(
                "Selected network adapter"
            ),

            status="Connected"
        )

        # ------------------------------------------------------
        # Send selection to Dashboard if supported.
        # ------------------------------------------------------

        if hasattr(
            self.dashboard_page,
            "set_selected_adapter"
        ):

            self.dashboard_page.set_selected_adapter(
                {
                    "name": adapter_name
                }
            )

    # ==========================================================
    # REFRESH ADAPTERS
    # ==========================================================

    def refresh_adapters(self):

        # ------------------------------------------------------
        # BACKEND CONNECTION WILL COME HERE.
        #
        # Future architecture:
        #
        # MainWindow
        #     ↓
        # AdapterService
        #     ↓
        # adapters.py
        #     ↓
        # psutil
        #
        # ------------------------------------------------------

        print(
            "Adapter refresh requested."
        )

    # ==========================================================
    # LOAD THEME
    # ==========================================================

    def load_theme(self):

        # ------------------------------------------------------
        # theme.qss location:
        #
        # frontend/
        #     styles/
        #         theme.qss
        #
        # ------------------------------------------------------

        theme_path = os.path.join(

            os.path.dirname(
                __file__
            ),

            "styles",

            "theme.qss"
        )

        # ------------------------------------------------------
        # CHECK THEME FILE
        # ------------------------------------------------------

        if not os.path.exists(
            theme_path
        ):

            print(
                "WARNING: theme.qss not found:"
            )

            print(
                theme_path
            )

            return

        # ------------------------------------------------------
        # READ THEME
        # ------------------------------------------------------

        try:

            with open(
                theme_path,
                "r",
                encoding="utf-8"
            ) as file:

                stylesheet = (
                    file.read()
                )

            # --------------------------------------------------
            # APPLY GLOBAL THEME
            # --------------------------------------------------

            self.setStyleSheet(
                stylesheet
            )

        except Exception as error:

            print(
                "Unable to load theme.qss:"
            )

            print(
                error
            )


# ==============================================================
# END OF MAIN_WINDOW.PY
# ==============================================================