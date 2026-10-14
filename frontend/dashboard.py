# ==============================================================
# NETWORK TRAFFIC ANALYZER
# DASHBOARD PAGE
# ==============================================================
#
# FRONTEND ONLY
#
# This file contains ONLY Dashboard UI.
#
# Backend will later provide:
#   - Network adapters
#   - Packet capture
#   - Process mapping
#   - GeoIP / Country information
#   - Traffic statistics
#
# CURRENT VERSION:
#   Dummy packet data is used only for UI development.
#
# ==============================================================


from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QHeaderView,
    QAbstractItemView,
)


# ==============================================================
# DASHBOARD SIZE CONFIGURATION
# ==============================================================
#
# Change these values if you want to resize the UI.
#
# ==============================================================


# --------------------------------------------------------------
# MAIN DASHBOARD
# --------------------------------------------------------------

# Outer margin of Dashboard.
# Current: 0 px
DASHBOARD_MARGIN = 0

# Space between major Dashboard sections.
# Current: 6 px
DASHBOARD_SECTION_SPACING = 6


# --------------------------------------------------------------
# CAPTURE CONTROL PANEL
# --------------------------------------------------------------

# ==============================================================
# IMPORTANT
# ==============================================================
#
# This controls the BIG BOX around:
#
#   Start Capture
#   Stop Capture
#   Rescan Adapters
#
# Current: 50 px
#
# Smaller:
#   44
#
# Recommended:
#   50
#
# Larger:
#   60
#
# ==============================================================

CAPTURE_PANEL_HEIGHT = 50


# --------------------------------------------------------------
# CAPTURE BUTTONS
# --------------------------------------------------------------

# Button height.
# Current: 26 px
CAPTURE_BUTTON_HEIGHT = 32

# Start Capture button width.
# Current: 125 px
START_BUTTON_WIDTH = 125

# Stop Capture button width.
# Current: 125 px
STOP_BUTTON_WIDTH = 125

# Rescan button width.
# Current: 145 px
RESCAN_BUTTON_WIDTH = 145


# --------------------------------------------------------------
# SELECTED NETWORK ADAPTER
# --------------------------------------------------------------

# Wi-Fi / Selected Adapter panel height.
# Current: 68 px
ADAPTER_PANEL_HEIGHT = 68


# --------------------------------------------------------------
# METRIC CARDS
# --------------------------------------------------------------

# Metric card height.
# Current: 70 px
METRIC_CARD_HEIGHT = 70

# Space between metric cards.
# Current: 6 px
METRIC_CARD_SPACING = 6

# Metric icon width.
# Current: 42 px
METRIC_ICON_WIDTH = 42

# Metric icon height.
# Current: 42 px
METRIC_ICON_HEIGHT = 42


# --------------------------------------------------------------
# PACKET ACTIVITY
# --------------------------------------------------------------

# Packet table height.
# Current: 300 px
PACKET_TABLE_HEIGHT = 300

# Packet row height.
# Current: 26 px
PACKET_ROW_HEIGHT = 26


# --------------------------------------------------------------
# BOTTOM STATISTICS
# --------------------------------------------------------------

# Bottom statistics panel height.
# Current: 120 px
BOTTOM_PANEL_HEIGHT = 120


# ==============================================================
# CYBERSECURITY COLORS
# ==============================================================
#
# Main theme is handled by:
#
# frontend/styles/theme.qss
#
# These colors are used by custom Dashboard widgets.
#
# ==============================================================


# Main application background
COLOR_BACKGROUND = "#050B14"

# Main panel
COLOR_PANEL = "#0B1728"

# Secondary panel
COLOR_SECONDARY_PANEL = "#0F1F33"

# Border
COLOR_BORDER = "#17324D"

# Primary blue
COLOR_BLUE = "#1683FF"

# Bright blue
COLOR_BRIGHT_BLUE = "#00A8FF"

# Cyber cyan
COLOR_CYAN = "#00E5FF"

# Success / Connected
COLOR_GREEN = "#00E676"

# Warning
COLOR_YELLOW = "#FFC107"

# Orange
COLOR_ORANGE = "#FF9800"

# Danger
COLOR_RED = "#FF3B4E"

# Purple
COLOR_PURPLE = "#8B5CF6"

# Main text
COLOR_TEXT = "#F1F5F9"

# Secondary text
COLOR_TEXT_SECONDARY = "#94A3B8"

# Muted text
COLOR_TEXT_MUTED = "#64748B"


# ==============================================================
# DASHBOARD PAGE
# ==============================================================


class DashboardPage(QWidget):

    def __init__(self):

        super().__init__()

        # Object name used by global QSS.
        self.setObjectName(
            "dashboardPage"
        )

        # Dashboard-local theme: keeps this page dark even when the
        # application-wide stylesheet does not reach its child widgets.
        self.setStyleSheet("""
            QWidget#dashboardPage {
                background-color: #0B1120;
                color: #E5E7EB;
                font-family: "Segoe UI";
                font-size: 10px;
            }
            QFrame[panel="true"], QFrame[metricCard="true"] {
                background-color: #111827;
                border: 1px solid #1F2937;
                border-radius: 7px;
            }
            QLabel[heading="true"] {
                color: #60A5FA;
                font-weight: 700;
            }
            QLabel[secondary="true"], QLabel[cardTitle="true"] {
                color: #94A3B8;
            }
            QPushButton {
                background-color: #172033;
                color: #E5E7EB;
                border: 1px solid #334155;
                border-radius: 5px;
                padding: 5px 10px;
            }
            QPushButton:hover {
                background-color: #24334B;
                border-color: #3B82F6;
            }
            QPushButton[success="true"] {
                background-color: #14532D;
                color: #DCFCE7;
                border: 1px solid #22C55E;
                font-weight: 600;
            }
            QPushButton[danger="true"] {
                background-color: #3A1720;
                color: #FCA5A5;
                border: 1px solid #DC2626;
                font-weight: 600;
            }
            QPushButton[secondary="true"] {
                background-color: #172033;
                color: #BFDBFE;
                border: 1px solid #334155;
            }
            QTableWidget {
                background-color: #0F172A;
                alternate-background-color: #111827;
                color: #E5E7EB;
                gridline-color: #263449;
                border: 1px solid #263449;
                selection-background-color: #1D4ED8;
                selection-color: #FFFFFF;
                outline: 0;
            }
            QTableWidget::item {
                padding: 4px;
                border-bottom: 1px solid #1F2937;
            }
            QHeaderView::section {
                background-color: #172033;
                color: #93C5FD;
                border: 1px solid #263449;
                padding: 7px 5px;
                font-weight: 700;
                font-size: 9px;
            }
            QScrollBar:vertical, QScrollBar:horizontal {
                background-color: #0B1120;
                border: none;
                width: 10px;
                height: 10px;
            }
            QScrollBar::handle:vertical, QScrollBar::handle:horizontal {
                background-color: #334155;
                border-radius: 4px;
                min-height: 20px;
                min-width: 20px;
            }
        """)

        # Build Dashboard UI.
        self.setup_ui()

    # ==========================================================
    # MAIN UI
    # ==========================================================

    def setup_ui(self):

        # ------------------------------------------------------
        # MAIN VERTICAL LAYOUT
        # ------------------------------------------------------

        main_layout = QVBoxLayout(
            self
        )

        # ------------------------------------------------------
        # DASHBOARD OUTER MARGIN
        # ------------------------------------------------------
        #
        # Current: 0 px
        #
        # This gives maximum available width.
        #
        # ------------------------------------------------------

        main_layout.setContentsMargins(
            DASHBOARD_MARGIN,
            DASHBOARD_MARGIN,
            DASHBOARD_MARGIN,
            DASHBOARD_MARGIN,
        )

        # ------------------------------------------------------
        # GAP BETWEEN SECTIONS
        # ------------------------------------------------------

        main_layout.setSpacing(
            DASHBOARD_SECTION_SPACING
        )

        # ------------------------------------------------------
        # 1. CAPTURE CONTROL PANEL
        # ------------------------------------------------------

        main_layout.addWidget(
            self.create_capture_bar()
        )

        # ------------------------------------------------------
        # 2. SELECTED NETWORK ADAPTER
        # ------------------------------------------------------

        main_layout.addWidget(
            self.create_adapter_panel()
        )

        # ------------------------------------------------------
        # 3. METRIC CARDS
        # ------------------------------------------------------

        main_layout.addLayout(
            self.create_metric_cards()
        )

        # ------------------------------------------------------
        # 4. PACKET ACTIVITY
        # ------------------------------------------------------

        main_layout.addWidget(
            self.create_packet_activity()
        )

        # ------------------------------------------------------
        # 5. BOTTOM STATISTICS
        # ------------------------------------------------------

        main_layout.addLayout(
            self.create_bottom_statistics()
        )

    # ==========================================================
    # CAPTURE CONTROL PANEL
    # ==========================================================
    #
    # This is the box that appears ABOVE the Wi-Fi panel.
    #
    # It contains:
    #
    #   Start Capture
    #   Stop Capture
    #   Rescan Adapters
    #
    # Search / Filter / Clear / Export are NOT here.
    #
    # ==============================================================

    def create_capture_bar(self):

        panel = QFrame()

        panel.setProperty(
            "panel",
            True
        )

        # ------------------------------------------------------
        # OUTER BOX HEIGHT
        # ------------------------------------------------------
        #
        # Current: 50 px
        #
        # This is the BIG BOX height,
        # not the button height.
        #
        # ------------------------------------------------------

        panel.setFixedHeight(
            CAPTURE_PANEL_HEIGHT
        )

        # ------------------------------------------------------
        # HORIZONTAL LAYOUT
        # ------------------------------------------------------

        layout = QHBoxLayout(
            panel
        )

        # ------------------------------------------------------
        # PANEL PADDING
        # ------------------------------------------------------
        #
        # Left   = 6 px
        # Top    = 4 px
        # Right  = 6 px
        # Bottom = 4 px
        #
        # ------------------------------------------------------

        layout.setContentsMargins(
            6,
            4,
            6,
            4
        )

        # Space between buttons.
        # Current: 6 px
        layout.setSpacing(
            6
        )

        # ======================================================
        # START CAPTURE
        # ======================================================

        start_button = QPushButton(
            "▶  Start Capture"
        )

        start_button.setProperty(
            "success",
            True
        )

        # ------------------------------------------------------
        # START BUTTON SIZE
        # ------------------------------------------------------
        #
        # Width  = 125 px
        # Height = 26 px
        #
        # ------------------------------------------------------

        start_button.setFixedSize(
            START_BUTTON_WIDTH,
            CAPTURE_BUTTON_HEIGHT
        )

        # ======================================================
        # STOP CAPTURE
        # ======================================================

        stop_button = QPushButton(
            "■  Stop Capture"
        )

        stop_button.setProperty(
            "danger",
            True
        )

        # ------------------------------------------------------
        # STOP BUTTON SIZE
        # ------------------------------------------------------

        stop_button.setFixedSize(
            STOP_BUTTON_WIDTH,
            CAPTURE_BUTTON_HEIGHT
        )

        # ======================================================
        # RESCAN ADAPTERS
        # ======================================================

        rescan_button = QPushButton(
            "⟳  Rescan Adapters"
        )

        rescan_button.setProperty(
            "secondary",
            True
        )

        # ------------------------------------------------------
        # RESCAN BUTTON SIZE
        # ------------------------------------------------------

        rescan_button.setFixedSize(
            RESCAN_BUTTON_WIDTH,
            CAPTURE_BUTTON_HEIGHT
        )

        # ======================================================
        # ADD BUTTONS
        # ======================================================

        layout.addWidget(
            start_button
        )

        layout.addWidget(
            stop_button
        )

        layout.addWidget(
            rescan_button
        )

        # ------------------------------------------------------
        # REMAINING SPACE
        # ------------------------------------------------------

        layout.addStretch()

        return panel

    # ==========================================================
    # SELECTED NETWORK ADAPTER
    # ==========================================================

    def create_adapter_panel(self):

        panel = QFrame()

        panel.setProperty(
            "panel",
            True
        )

        # ------------------------------------------------------
        # ADAPTER PANEL HEIGHT
        # ------------------------------------------------------
        #
        # Current: 68 px
        #
        # ------------------------------------------------------

        panel.setFixedHeight(
            ADAPTER_PANEL_HEIGHT
        )

        # ------------------------------------------------------
        # MAIN LAYOUT
        # ------------------------------------------------------

        layout = QHBoxLayout(
            panel
        )

        # Panel padding.
        layout.setContentsMargins(
            8,
            5,
            8,
            5
        )

        layout.setSpacing(
            10
        )

        # ======================================================
        # LEFT SIDE
        # ======================================================

        left_layout = QHBoxLayout()

        left_layout.setSpacing(
            8
        )

        # ------------------------------------------------------
        # WIFI ICON
        # ------------------------------------------------------

        wifi_icon = QLabel(
            "◉"
        )

        wifi_icon.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_CYAN};
                font-size: 28px;
                font-weight: bold;
            }}
            """
        )

        left_layout.addWidget(
            wifi_icon
        )

        # ------------------------------------------------------
        # ADAPTER INFORMATION
        # ------------------------------------------------------

        adapter_info = QVBoxLayout()

        adapter_info.setSpacing(
            0
        )

        adapter_name = QLabel(
            "Wi-Fi"
        )

        adapter_name.setProperty(
            "heading",
            True
        )

        adapter_description = QLabel(
            "Intel(R) Wi-Fi 6 AX201 160MHz"
        )

        adapter_description.setProperty(
            "secondary",
            True
        )

        adapter_status = QLabel(
            "●  Connected"
        )

        adapter_status.setProperty(
            "success",
            True
        )

        adapter_info.addWidget(
            adapter_name
        )

        adapter_info.addWidget(
            adapter_description
        )

        adapter_info.addWidget(
            adapter_status
        )

        left_layout.addLayout(
            adapter_info
        )

        layout.addLayout(
            left_layout
        )

        # Push network details toward right.
        layout.addStretch()

        # ======================================================
        # NETWORK DETAILS
        # ======================================================

        details_layout = QGridLayout()

        # Horizontal spacing.
        # Current: 8 px
        details_layout.setHorizontalSpacing(
            8
        )

        # Vertical spacing.
        # Current: 0 px
        details_layout.setVerticalSpacing(
            0
        )

        details = [

            (
                "IPv4 Address",
                "192.168.1.100"
            ),

            (
                "IPv6 Address",
                "2405:201:abcd:1234::1"
            ),

            (
                "MAC Address",
                "3C-52-82-9A-4F-1D"
            ),

            (
                "Status",
                "●  Up"
            ),
        ]

        for row, (
            name,
            value
        ) in enumerate(
            details
        ):

            name_label = QLabel(
                name
            )

            name_label.setProperty(
                "secondary",
                True
            )

            separator = QLabel(
                ":"
            )

            separator.setProperty(
                "secondary",
                True
            )

            value_label = QLabel(
                value
            )

            if name == "Status":

                value_label.setProperty(
                    "success",
                    True
                )

            else:

                value_label.setProperty(
                    "secondary",
                    True
                )

            details_layout.addWidget(
                name_label,
                row,
                0
            )

            details_layout.addWidget(
                separator,
                row,
                1
            )

            details_layout.addWidget(
                value_label,
                row,
                2
            )

        layout.addLayout(
            details_layout
        )

        return panel

    # ==========================================================
    # METRIC CARDS
    # ==========================================================

    def create_metric_cards(self):

        layout = QGridLayout()

        # Gap between cards.
        # Current: 6 px
        layout.setSpacing(
            METRIC_CARD_SPACING
        )

        # ------------------------------------------------------
        # TOTAL PACKETS
        # ------------------------------------------------------

        self.total_packet_card = (
            self.create_metric_card(
                icon="◉",
                title="TOTAL PACKETS",
                value="125,430",
                icon_color=COLOR_BLUE
            )
        )

        # ------------------------------------------------------
        # INCOMING
        # ------------------------------------------------------

        self.incoming_packet_card = (
            self.create_metric_card(
                icon="↓",
                title="INCOMING PACKETS",
                value="72,210",
                icon_color=COLOR_GREEN
            )
        )

        # ------------------------------------------------------
        # OUTGOING
        # ------------------------------------------------------

        self.outgoing_packet_card = (
            self.create_metric_card(
                icon="↑",
                title="OUTGOING PACKETS",
                value="53,220",
                icon_color=COLOR_RED
            )
        )

        layout.addWidget(
            self.total_packet_card,
            0,
            0
        )

        layout.addWidget(
            self.incoming_packet_card,
            0,
            1
        )

        layout.addWidget(
            self.outgoing_packet_card,
            0,
            2
        )

        # Equal width.
        layout.setColumnStretch(
            0,
            1
        )

        layout.setColumnStretch(
            1,
            1
        )

        layout.setColumnStretch(
            2,
            1
        )

        return layout

    # ==========================================================
    # SINGLE METRIC CARD
    # ==========================================================

    def create_metric_card(
        self,
        icon,
        title,
        value,
        icon_color
    ):

        card = QFrame()

        card.setProperty(
            "metricCard",
            True
        )

        # Current card height = 70 px.
        card.setFixedHeight(
            METRIC_CARD_HEIGHT
        )

        layout = QHBoxLayout(
            card
        )

        # Card padding.
        layout.setContentsMargins(
            8,
            6,
            8,
            6
        )

        layout.setSpacing(
            8
        )

        # ======================================================
        # ICON BOX
        # ======================================================

        icon_box = QFrame()

        # Current: 42 x 42 px.
        icon_box.setFixedSize(
            METRIC_ICON_WIDTH,
            METRIC_ICON_HEIGHT
        )

        icon_box.setStyleSheet(
            f"""
            QFrame {{
                background-color: {COLOR_SECONDARY_PANEL};
                border: 1px solid {icon_color};
                border-radius: 7px;
            }}
            """
        )

        icon_layout = QVBoxLayout(
            icon_box
        )

        icon_layout.setContentsMargins(
            0,
            0,
            0,
            0
        )

        icon_label = QLabel(
            icon
        )

        icon_label.setAlignment(
            Qt.AlignCenter
        )

        icon_label.setStyleSheet(
            f"""
            QLabel {{
                color: {icon_color};
                font-size: 23px;
                font-weight: bold;
            }}
            """
        )

        icon_layout.addWidget(
            icon_label
        )

        layout.addWidget(
            icon_box
        )

        # ======================================================
        # METRIC TEXT
        # ======================================================

        text_layout = QVBoxLayout()

        text_layout.setSpacing(
            0
        )

        title_label = QLabel(
            title
        )

        title_label.setProperty(
            "cardTitle",
            True
        )

        value_label = QLabel(
            value
        )

        value_label.setStyleSheet(
            f"""
            QLabel {{
                color: {icon_color};
                font-size: 21px;
                font-weight: 700;
            }}
            """
        )

        text_layout.addWidget(
            title_label
        )

        text_layout.addWidget(
            value_label
        )

        layout.addLayout(
            text_layout
        )

        return card

    # ==========================================================
    # PACKET ACTIVITY
    # ==========================================================
    #
    # IMPORTANT:
    #
    # Search       = REMOVED
    # Filter       = REMOVED
    # Clear button = REMOVED
    # Export       = REMOVED
    #
    # Only Packet Activity title + table remain.
    #
    # ==============================================================

    def create_packet_activity(self):

        panel = QFrame()

        panel.setProperty(
            "panel",
            True
        )

        # ------------------------------------------------------
        # PACKET PANEL HEIGHT
        # ------------------------------------------------------
        #
        # Table height = 300 px
        # Header       ≈ 25 px
        # Padding      ≈ 10 px
        #
        # ------------------------------------------------------

        panel.setFixedHeight(
            PACKET_TABLE_HEIGHT + 40
        )

        layout = QVBoxLayout(
            panel
        )

        # Small panel padding.
        layout.setContentsMargins(
            5,
            4,
            5,
            4
        )

        # Gap between title and table.
        layout.setSpacing(
            3
        )

        # ======================================================
        # PACKET ACTIVITY HEADER
        # ======================================================

        header = QHBoxLayout()

        title = QLabel(
            "⌁  Packet Activity"
        )

        title.setProperty(
            "heading",
            True
        )

        header.addWidget(
            title
        )

        # Keep title left.
        header.addStretch()

        layout.addLayout(
            header
        )

        # ======================================================
        # PACKET TABLE
        # ======================================================

        self.packet_table = QTableWidget()

        # ------------------------------------------------------
        # FINAL TABLE COLUMNS
        # ------------------------------------------------------

        columns = [

            "PACKET ID",

            "TIMESTAMP",

            "PROTO",

            "DIRECTION",

            "SOURCE IP",

            "SOURCE PORT",

            "DESTINATION IP",

            "DEST PORT",

            "LENGTH",

            "COUNTRY",

            "PROCESS",
        ]

        self.packet_table.setColumnCount(
            len(columns)
        )

        self.packet_table.setHorizontalHeaderLabels(
            columns
        )

        # ------------------------------------------------------
        # TEMPORARY ROWS
        # ------------------------------------------------------

        self.packet_table.setRowCount(
            10
        )

        # ------------------------------------------------------
        # TABLE HEIGHT
        # ------------------------------------------------------

        self.packet_table.setMinimumHeight(
            PACKET_TABLE_HEIGHT
        )

        # ------------------------------------------------------
        # TABLE BEHAVIOUR
        # ------------------------------------------------------

        # Read-only.
        self.packet_table.setEditTriggers(
            QAbstractItemView.NoEditTriggers
        )

        # Select complete row.
        self.packet_table.setSelectionBehavior(
            QAbstractItemView.SelectRows
        )

        # Hide row numbers.
        self.packet_table.verticalHeader().setVisible(
            False
        )

        # ------------------------------------------------------
        # ROW HEIGHT
        # ------------------------------------------------------

        self.packet_table.verticalHeader().setDefaultSectionSize(
            PACKET_ROW_HEIGHT
        )

        # ------------------------------------------------------
        # TABLE WIDTH
        # ------------------------------------------------------

        table_header = (
            self.packet_table.horizontalHeader()
        )

        # Allow manual resizing.
        table_header.setSectionResizeMode(
            QHeaderView.Interactive
        )

        # Last column fills remaining width.
        table_header.setStretchLastSection(
            True
        )

        # Alternating rows.
        self.packet_table.setAlternatingRowColors(
            True
        )
        self.packet_table.setWordWrap(False)
        self.packet_table.setHorizontalScrollMode(
            QAbstractItemView.ScrollPerPixel
        )
        self.packet_table.setVerticalScrollMode(
            QAbstractItemView.ScrollPerPixel
        )

        # ======================================================
        # TEMPORARY PACKET DATA
        # ======================================================
        #
        # UI TEST DATA ONLY.
        #
        # ======================================================

        packets = [

            (
                "pkt-10183",
                "14:25:06.800",
                "DNS",
                "OUT",
                "157.240.22.35",
                "41047",
                "1.1.1.1",
                "53",
                "397 B",
                "Australia",
                "System"
            ),

            (
                "pkt-10182",
                "14:25:06.029",
                "TLS",
                "OUT",
                "157.240.22.35",
                "44674",
                "10.0.2.10",
                "443",
                "462 B",
                "Private",
                "chrome.exe"
            ),

            (
                "pkt-10181",
                "14:25:05.256",
                "SSH",
                "IN",
                "10.0.3.51",
                "3635",
                "10.0.2.199",
                "22",
                "935 B",
                "Private",
                "sshd.exe"
            ),

            (
                "pkt-10180",
                "14:25:04.444",
                "HTTP",
                "OUT",
                "10.0.3.50",
                "43508",
                "10.0.2.10",
                "80",
                "782 B",
                "Private",
                "python.exe"
            ),

            (
                "pkt-10179",
                "14:25:03.642",
                "DNS",
                "OUT",
                "203.0.113.88",
                "17504",
                "1.1.1.1",
                "53",
                "554 B",
                "Australia",
                "System"
            ),

            (
                "pkt-10178",
                "14:25:02.781",
                "TLS",
                "OUT",
                "194.26.29.44",
                "18068",
                "10.0.2.10",
                "443",
                "384 B",
                "Private",
                "chrome.exe"
            ),

            (
                "pkt-10177",
                "14:25:02.144",
                "ICMP",
                "OUT",
                "45.142.214.19",
                "-",
                "8.8.8.8",
                "-",
                "128 B",
                "United States",
                "System"
            ),

            (
                "pkt-10176",
                "14:25:01.653",
                "ARP",
                "LOCAL",
                "192.168.1.1",
                "-",
                "192.168.1.100",
                "-",
                "60 B",
                "Private",
                "System"
            ),

            (
                "pkt-10175",
                "14:25:00.981",
                "HTTP",
                "OUT",
                "172.217.12.14",
                "52314",
                "10.0.2.10",
                "80",
                "420 B",
                "Private",
                "chrome.exe"
            ),

            (
                "pkt-10174",
                "14:25:00.452",
                "DNS",
                "OUT",
                "192.168.1.100",
                "52314",
                "8.8.8.8",
                "53",
                "72 B",
                "United States",
                "System"
            ),
        ]

        # ======================================================
        # INSERT DUMMY PACKETS
        # ======================================================

        for row_index, packet in enumerate(
            packets
        ):

            for column_index, value in enumerate(
                packet
            ):

                item = QTableWidgetItem(
                    str(value)
                )

                # Center-align packet values for a consistent table.
                item.setTextAlignment(Qt.AlignCenter)

                self.packet_table.setItem(
                    row_index,
                    column_index,
                    item
                )

        # ======================================================
        # TABLE COLUMN WIDTHS
        # ======================================================
        #
        # You can manually change these values.
        #
        # ======================================================

        column_widths = {

            # PACKET ID
            0: 110,

            # TIMESTAMP
            1: 115,

            # PROTO
            2: 70,

            # DIRECTION
            3: 85,

            # SOURCE IP
            4: 145,

            # SOURCE PORT
            5: 95,

            # DESTINATION IP
            6: 155,

            # DEST PORT
            7: 95,

            # LENGTH
            8: 75,

            # COUNTRY
            9: 120,

            # PROCESS
            10: 140,
        }

        # Apply column widths.
        for column, width in (
            column_widths.items()
        ):

            self.packet_table.setColumnWidth(
                column,
                width
            )

        # Add table.
        layout.addWidget(
            self.packet_table
        )

        return panel

    # ==========================================================
    # BOTTOM STATISTICS
    # ==========================================================

    def create_bottom_statistics(self):

        layout = QHBoxLayout()

        # Gap between panels.
        # Current: 6 px
        layout.setSpacing(
            6
        )

        # Protocol statistics.
        protocol_panel = (
            self.create_protocol_panel()
        )

        # Connection statistics.
        connection_panel = (
            self.create_connection_panel()
        )

        # Equal width.
        layout.addWidget(
            protocol_panel,
            1
        )

        layout.addWidget(
            connection_panel,
            1
        )

        return layout

    # ==========================================================
    # PROTOCOL STATISTICS
    # ==========================================================

    def create_protocol_panel(self):

        panel = QFrame()

        panel.setProperty(
            "panel",
            True
        )

        # Current: 120 px.
        panel.setFixedHeight(
            BOTTOM_PANEL_HEIGHT
        )

        layout = QVBoxLayout(
            panel
        )

        layout.setContentsMargins(
            10,
            6,
            10,
            6
        )

        layout.setSpacing(
            2
        )

        title = QLabel(
            "PROTOCOL STATISTICS"
        )

        title.setProperty(
            "heading",
            True
        )

        layout.addWidget(
            title
        )

        # ------------------------------------------------------
        # DUMMY DATA
        # ------------------------------------------------------

        protocols = [

            (
                "TCP",
                "52%",
                COLOR_BLUE,
                190
            ),

            (
                "UDP",
                "29%",
                COLOR_GREEN,
                110
            ),

            (
                "TLS",
                "8%",
                COLOR_PURPLE,
                60
            ),

            (
                "DNS",
                "5%",
                COLOR_YELLOW,
                40
            ),

            (
                "ICMP",
                "3%",
                COLOR_RED,
                25
            ),
        ]

        for (
            protocol,
            percentage,
            color,
            bar_width
        ) in protocols:

            row = QHBoxLayout()

            row.setSpacing(
                6
            )

            # Protocol name.
            name = QLabel(
                protocol
            )

            name.setMinimumWidth(
                45
            )

            # --------------------------------------------------
            # PROTOCOL BAR
            # --------------------------------------------------
            #
            # Height = 5 px
            # Width  = bar_width
            #
            # --------------------------------------------------

            bar = QFrame()

            bar.setFixedSize(
                bar_width,
                5
            )

            bar.setStyleSheet(
                f"""
                QFrame {{
                    background-color: {color};
                    border-radius: 2px;
                }}
                """
            )

            # Percentage.
            value = QLabel(
                percentage
            )

            value.setProperty(
                "secondary",
                True
            )

            row.addWidget(
                name
            )

            row.addWidget(
                bar
            )

            row.addStretch()

            row.addWidget(
                value
            )

            layout.addLayout(
                row
            )

        return panel

    # ==========================================================
    # CONNECTION STATISTICS
    # ==========================================================

    def create_connection_panel(self):

        panel = QFrame()

        panel.setProperty(
            "panel",
            True
        )

        # Current: 120 px.
        panel.setFixedHeight(
            BOTTOM_PANEL_HEIGHT
        )

        layout = QGridLayout(
            panel
        )

        layout.setContentsMargins(
            10,
            6,
            10,
            6
        )

        # Horizontal spacing.
        # Current: 18 px
        layout.setHorizontalSpacing(
            18
        )

        # Vertical spacing.
        # Current: 2 px
        layout.setVerticalSpacing(
            2
        )

        title = QLabel(
            "CONNECTION STATISTICS"
        )

        title.setProperty(
            "heading",
            True
        )

        layout.addWidget(
            title,
            0,
            0,
            1,
            4
        )

        # ------------------------------------------------------
        # DUMMY CONNECTION DATA
        # ------------------------------------------------------

        statistics = [

            (
                "ESTABLISHED",
                "314"
            ),

            (
                "LISTENING",
                "28"
            ),

            (
                "TIME_WAIT",
                "96"
            ),

            (
                "TCP",
                "218"
            ),

            (
                "UDP",
                "96"
            ),

            (
                "CLOSE_WAIT",
                "12"
            ),
        ]

        for index, (
            name,
            value
        ) in enumerate(
            statistics
        ):

            # Two items per row.
            row = (
                index // 2
            ) + 1

            # Left / right position.
            column = (
                index % 2
            ) * 2

            name_label = QLabel(
                name
            )

            name_label.setProperty(
                "secondary",
                True
            )

            value_label = QLabel(
                value
            )

            value_label.setProperty(
                "heading",
                True
            )

            layout.addWidget(
                name_label,
                row,
                column
            )

            layout.addWidget(
                value_label,
                row,
                column + 1
            )

        return panel

    # ==========================================================
    # UPDATE METRICS
    # ==========================================================
    #
    # Backend will use this method later.
    #
    # ==============================================================

    def update_metrics(
        self,
        total_packets,
        incoming_packets,
        outgoing_packets
    ):

        self.total_packets = (
            total_packets
        )

        self.incoming_packets = (
            incoming_packets
        )

        self.outgoing_packets = (
            outgoing_packets
        )

    # ==========================================================
    # ADD LIVE PACKET
    # ==========================================================
    #
    # Backend will send packet information here.
    #
    # ==============================================================

    def add_packet(
        self,
        packet
    ):

        # Current number of rows.
        row = (
            self.packet_table.rowCount()
        )

        # Add new row.
        self.packet_table.insertRow(
            row
        )

        # ------------------------------------------------------
        # PACKET DATA
        # ------------------------------------------------------

        values = [

            packet.get(
                "packet_id",
                "-"
            ),

            packet.get(
                "time",
                "-"
            ),

            packet.get(
                "protocol",
                "-"
            ),

            packet.get(
                "direction",
                "-"
            ),

            packet.get(
                "source",
                "-"
            ),

            packet.get(
                "source_port",
                "-"
            ),

            packet.get(
                "destination",
                "-"
            ),

            packet.get(
                "destination_port",
                "-"
            ),

            packet.get(
                "size",
                "-"
            ),

            packet.get(
                "country",
                "Unknown"
            ),

            packet.get(
                "process",
                "Unknown"
            ),
        ]

        # ------------------------------------------------------
        # INSERT DATA
        # ------------------------------------------------------

        for column, value in enumerate(
            values
        ):

            item = QTableWidgetItem(
                str(value)
            )

            item.setTextAlignment(
                Qt.AlignCenter
            )

            self.packet_table.setItem(
                row,
                column,
                item
            )

        # Scroll to newest packet.
        self.packet_table.scrollToBottom()

    # ==========================================================
    # CLEAR PACKETS
    # ==========================================================
    #
    # No Clear button exists anymore.
    #
    # This method remains available for future controller use.
    #
    # ==============================================================

    def clear_packets(self):

        self.packet_table.setRowCount(
            0
        )