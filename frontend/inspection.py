# ==============================================================
# NETWORK TRAFFIC ANALYZER
# INSPECTION PAGE
# ==============================================================
#
# FRONTEND ONLY
#
# This page displays captured network traffic.
#
# FINAL TABLE ORDER:
#
#   1. Program
#   2. Address (source)
#   3. Port (source)
#   4. Address (destination)
#   5. Country (destination)
#   6. Port (destination)
#   7. Protocol
#   8. Service
#   9. Bytes
#
# ==============================================================


from PySide6.QtCore import Qt, Signal

from PySide6.QtWidgets import (
    QWidget,
    QFrame,
    QLabel,
    QVBoxLayout,
    QHBoxLayout,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QAbstractItemView,
    QHeaderView,
)


# ==============================================================
# SIZE CONFIGURATION
# ==============================================================
#
# Change these values when you want to resize the UI.
#
# ==============================================================


# --------------------------------------------------------------
# Main page
# --------------------------------------------------------------

PAGE_SPACING = 6


# --------------------------------------------------------------
# Filter toolbar
# --------------------------------------------------------------

TOOLBAR_HEIGHT = 58


# --------------------------------------------------------------
# Filter boxes
# --------------------------------------------------------------

FILTER_HEIGHT = 30


# --------------------------------------------------------------
# Packet table
# --------------------------------------------------------------

TABLE_MIN_HEIGHT = 500

TABLE_ROW_HEIGHT = 28


# --------------------------------------------------------------
# Traffic summary
# --------------------------------------------------------------

TRAFFIC_SUMMARY_HEIGHT = 38

TRAFFIC_BAR_HEIGHT = 8


# ==============================================================
# TABLE COLUMN WIDTHS
# ==============================================================
#
# Change only these values to resize individual columns.
#
# ==============================================================


# Program column
PROGRAM_COLUMN_WIDTH = 100


# Source IP column
# Reduced width as requested.
SOURCE_IP_COLUMN_WIDTH = 175


# Source port
SOURCE_PORT_COLUMN_WIDTH = 100


# Destination IP column
# Reduced width as requested.
DESTINATION_IP_COLUMN_WIDTH = 175


# Destination country
DESTINATION_COUNTRY_COLUMN_WIDTH = 150


# Destination port
DESTINATION_PORT_COLUMN_WIDTH = 110


# Protocol
PROTOCOL_COLUMN_WIDTH = 90


# Service
SERVICE_COLUMN_WIDTH = 110


# Bytes
BYTES_COLUMN_WIDTH = 90


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

COLOR_RED = "#FF3B4E"

COLOR_TEXT = "#F1F5F9"

COLOR_SECONDARY = "#94A3B8"

COLOR_MUTED = "#64748B"


# ==============================================================
# INSPECTION PAGE
# ==============================================================


class InspectionPage(QWidget):

    # ----------------------------------------------------------
    # Signal emitted when a packet is selected.
    # ----------------------------------------------------------

    packet_selected = Signal(dict)

    # ==========================================================
    # CONSTRUCTOR
    # ==========================================================

    def __init__(self):

        super().__init__()

        # ------------------------------------------------------
        # Object name
        # ------------------------------------------------------

        self.setObjectName(
            "inspectionPage"
        )

        # ------------------------------------------------------
        # Page background
        # ------------------------------------------------------

        self.setStyleSheet(
            f"""
            QWidget#inspectionPage {{
                background-color: {COLOR_BACKGROUND};
            }}
            """
        )

        # ------------------------------------------------------
        # Store all packets.
        # Backend will populate this later.
        # ------------------------------------------------------

        self.all_packets = []

        # ------------------------------------------------------
        # Build UI
        # ------------------------------------------------------

        self.setup_ui()

        # ------------------------------------------------------
        # Temporary demo data.
        # Remove/replace when backend is connected.
        # ------------------------------------------------------

        self.load_demo_packets()

    # ==========================================================
    # MAIN UI
    # ==========================================================

    def setup_ui(self):

        # ------------------------------------------------------
        # Main vertical layout
        # ------------------------------------------------------

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
        # Filter toolbar
        # ------------------------------------------------------

        toolbar = (
            self.create_toolbar()
        )

        main_layout.addWidget(
            toolbar
        )

        # ------------------------------------------------------
        # Packet table
        # ------------------------------------------------------

        table_panel = (
            self.create_packet_table_panel()
        )

        main_layout.addWidget(
            table_panel,
            1
        )

        # ------------------------------------------------------
        # Traffic summary
        # ------------------------------------------------------

        traffic_summary = (
            self.create_traffic_summary()
        )

        main_layout.addWidget(
            traffic_summary
        )

    # ==========================================================
    # FILTER TOOLBAR
    # ==========================================================

    def create_toolbar(self):

        toolbar = QFrame()

        toolbar.setObjectName(
            "inspectionToolbar"
        )

        # ------------------------------------------------------
        # Toolbar height
        # ------------------------------------------------------

        toolbar.setFixedHeight(
            TOOLBAR_HEIGHT
        )

        # ------------------------------------------------------
        # Toolbar style
        # ------------------------------------------------------

        toolbar.setStyleSheet(
            f"""
            QFrame#inspectionToolbar {{
                background-color: {COLOR_PANEL};
                border: 1px solid {COLOR_BORDER};
                border-radius: 7px;
            }}
            """
        )

        # ------------------------------------------------------
        # Toolbar layout
        # ------------------------------------------------------

        layout = QHBoxLayout(
            toolbar
        )

        layout.setContentsMargins(
            10,
            6,
            10,
            6
        )

        layout.setSpacing(
            10
        )

        # ======================================================
        # CAPTURE STATUS
        # ======================================================

        status = QLabel(
            "●"
        )

        status.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_GREEN};
                font-size: 14px;
            }}
            """
        )

        layout.addWidget(
            status
        )

        # ======================================================
        # BLOCK ICON
        # ======================================================

        block_icon = QLabel(
            "⊘"
        )

        block_icon.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT};
                font-size: 19px;
            }}
            """
        )

        layout.addWidget(
            block_icon
        )

        # ======================================================
        # STAR
        # ======================================================

        star = QLabel(
            "☆"
        )

        star.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT};
                font-size: 25px;
            }}
            """
        )

        layout.addWidget(
            star
        )

        # ======================================================
        # COUNTRY FILTER
        # ======================================================

        country_label = QLabel(
            "Country:"
        )

        country_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT};
                font-size: 13px;
            }}
            """
        )

        layout.addWidget(
            country_label
        )

        self.country_filter = (
            self.create_filter(
                "Country"
            )
        )

        layout.addWidget(
            self.country_filter
        )

        # ======================================================
        # DOMAIN FILTER
        # ======================================================

        domain_label = QLabel(
            "Domain:"
        )

        domain_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT};
                font-size: 13px;
            }}
            """
        )

        layout.addWidget(
            domain_label
        )

        self.domain_filter = (
            self.create_filter(
                "Domain"
            )
        )

        layout.addWidget(
            self.domain_filter
        )

        # ======================================================
        # ASN FILTER
        # ======================================================

        asn_label = QLabel(
            "ASN:"
        )

        asn_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT};
                font-size: 13px;
            }}
            """
        )

        layout.addWidget(
            asn_label
        )

        self.asn_filter = (
            self.create_filter(
                "ASN"
            )
        )

        layout.addWidget(
            self.asn_filter
        )

        # ======================================================
        # PROGRAM FILTER
        # ======================================================

        program_label = QLabel(
            "Program:"
        )

        program_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT};
                font-size: 13px;
            }}
            """
        )

        layout.addWidget(
            program_label
        )

        self.program_filter = (
            self.create_filter(
                "Program"
            )
        )

        # Program filter uses remaining space.
        layout.addWidget(
            self.program_filter,
            1
        )

        # ======================================================
        # FILTER EVENTS
        # ======================================================

        self.country_filter.textChanged.connect(
            self.apply_filters
        )

        self.domain_filter.textChanged.connect(
            self.apply_filters
        )

        self.asn_filter.textChanged.connect(
            self.apply_filters
        )

        self.program_filter.textChanged.connect(
            self.apply_filters
        )

        return toolbar

    # ==========================================================
    # CREATE FILTER
    # ==========================================================

    def create_filter(
        self,
        placeholder
    ):

        field = QLineEdit()

        # ------------------------------------------------------
        # Placeholder
        # ------------------------------------------------------

        field.setPlaceholderText(
            placeholder
        )

        # ------------------------------------------------------
        # Filter height
        # ------------------------------------------------------

        field.setFixedHeight(
            FILTER_HEIGHT
        )

        # ------------------------------------------------------
        # Minimum width
        # ------------------------------------------------------

        field.setMinimumWidth(
            120
        )

        # ------------------------------------------------------
        # Filter style
        # ------------------------------------------------------

        field.setStyleSheet(
            f"""
            QLineEdit {{
                background-color: #0A1627;
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 5px;
                padding-left: 8px;
                padding-right: 8px;
                font-size: 11px;
            }}

            QLineEdit:focus {{
                border: 1px solid {COLOR_CYAN};
            }}
            """
        )

        return field

    # ==========================================================
    # PACKET TABLE PANEL
    # ==========================================================

    def create_packet_table_panel(self):

        panel = QFrame()

        panel.setObjectName(
            "packetTablePanel"
        )

        # ------------------------------------------------------
        # Panel style
        # ------------------------------------------------------

        panel.setStyleSheet(
            f"""
            QFrame#packetTablePanel {{
                background-color: {COLOR_PANEL};
                border: 1px solid {COLOR_BORDER};
                border-radius: 8px;
            }}
            """
        )

        # ------------------------------------------------------
        # Panel layout
        # ------------------------------------------------------

        layout = QVBoxLayout(
            panel
        )

        layout.setContentsMargins(
            8,
            7,
            8,
            7
        )

        layout.setSpacing(
            4
        )

        # ======================================================
        # TABLE
        # ======================================================

        self.packet_table = QTableWidget()

        self.packet_table.setObjectName(
            "inspectionTable"
        )

        # ------------------------------------------------------
        # FINAL COLUMN ORDER
        # ------------------------------------------------------

        columns = [

            # 0
            "Program",

            # 1
            "Address (source)",

            # 2
            "Port (source)",

            # 3
            "Address (destination)",

            # 4
            "Country (destination)",

            # 5
            "Port (destination)",

            # 6
            "Protocol",

            # 7
            "Service",

            # 8
            "Bytes",
        ]

        self.packet_table.setColumnCount(
            len(columns)
        )

        self.packet_table.setHorizontalHeaderLabels(
            columns
        )

        # ------------------------------------------------------
        # Table minimum height
        # ------------------------------------------------------

        self.packet_table.setMinimumHeight(
            TABLE_MIN_HEIGHT
        )

        # ------------------------------------------------------
        # Read-only table
        # ------------------------------------------------------

        self.packet_table.setEditTriggers(
            QAbstractItemView.NoEditTriggers
        )

        # ------------------------------------------------------
        # Select complete row
        # ------------------------------------------------------

        self.packet_table.setSelectionBehavior(
            QAbstractItemView.SelectRows
        )

        self.packet_table.setSelectionMode(
            QAbstractItemView.SingleSelection
        )

        # ------------------------------------------------------
        # Hide row numbers
        # ------------------------------------------------------

        self.packet_table.verticalHeader().setVisible(
            False
        )

        # ------------------------------------------------------
        # Row height
        # ------------------------------------------------------

        self.packet_table.verticalHeader().setDefaultSectionSize(
            TABLE_ROW_HEIGHT
        )

        # ======================================================
        # TABLE HEADER
        # ======================================================

        header = (
            self.packet_table.horizontalHeader()
        )

        header.setSectionResizeMode(
            QHeaderView.Interactive
        )

        # ======================================================
        # COLUMN WIDTHS
        # ======================================================
        #
        # All widths can be changed from the configuration
        # section at the top of this file.
        #
        # ======================================================

        # Program
        self.packet_table.setColumnWidth(
            0,
            PROGRAM_COLUMN_WIDTH
        )

        # Address (source)
        self.packet_table.setColumnWidth(
            1,
            SOURCE_IP_COLUMN_WIDTH
        )

        # Port (source)
        self.packet_table.setColumnWidth(
            2,
            SOURCE_PORT_COLUMN_WIDTH
        )

        # Address (destination)
        self.packet_table.setColumnWidth(
            3,
            DESTINATION_IP_COLUMN_WIDTH
        )

        # Country (destination)
        self.packet_table.setColumnWidth(
            4,
            DESTINATION_COUNTRY_COLUMN_WIDTH
        )

        # Port (destination)
        self.packet_table.setColumnWidth(
            5,
            DESTINATION_PORT_COLUMN_WIDTH
        )

        # Protocol
        self.packet_table.setColumnWidth(
            6,
            PROTOCOL_COLUMN_WIDTH
        )

        # Service
        self.packet_table.setColumnWidth(
            7,
            SERVICE_COLUMN_WIDTH
        )

        # Bytes
        self.packet_table.setColumnWidth(
            8,
            BYTES_COLUMN_WIDTH
        )

        # ------------------------------------------------------
        # Vertical scroll
        # ------------------------------------------------------

        self.packet_table.setVerticalScrollBarPolicy(
            Qt.ScrollBarAsNeeded
        )

        # ------------------------------------------------------
        # Horizontal scroll
        # ------------------------------------------------------

        self.packet_table.setHorizontalScrollBarPolicy(
            Qt.ScrollBarAsNeeded
        )

        # ======================================================
        # TABLE STYLE
        # ======================================================

        self.packet_table.setStyleSheet(
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
                font-size: 11px;
                font-weight: 600;
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

            QScrollBar::handle:vertical:hover {{
                background: #2B648A;
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

            QScrollBar::handle:horizontal:hover {{
                background: #2B648A;
            }}

            QScrollBar::add-line,
            QScrollBar::sub-line {{
                width: 0px;
                height: 0px;
            }}
            """
        )

        # ------------------------------------------------------
        # Packet selection event
        # ------------------------------------------------------

        self.packet_table.itemSelectionChanged.connect(
            self.on_packet_selected
        )

        # ------------------------------------------------------
        # Add table to panel
        # ------------------------------------------------------

        layout.addWidget(
            self.packet_table
        )

        return panel

    # ==========================================================
    # TRAFFIC SUMMARY
    # ==========================================================

    def create_traffic_summary(self):

        panel = QFrame()

        panel.setObjectName(
            "trafficSummary"
        )

        panel.setFixedHeight(
            TRAFFIC_SUMMARY_HEIGHT
        )

        # ------------------------------------------------------
        # Panel style
        # ------------------------------------------------------

        panel.setStyleSheet(
            f"""
            QFrame#trafficSummary {{
                background-color: {COLOR_PANEL};
                border: 1px solid {COLOR_BORDER};
                border-radius: 6px;
            }}
            """
        )

        # ------------------------------------------------------
        # Layout
        # ------------------------------------------------------

        layout = QHBoxLayout(
            panel
        )

        layout.setContentsMargins(
            8,
            5,
            8,
            5
        )

        layout.setSpacing(
            8
        )

        # ======================================================
        # TRAFFIC BAR
        # ======================================================

        bar_container = QFrame()

        bar_container.setFixedHeight(
            TRAFFIC_BAR_HEIGHT
        )

        bar_container.setStyleSheet(
            """
            QFrame {
                background-color: #17263B;
                border-radius: 4px;
            }
            """
        )

        bar_layout = QHBoxLayout(
            bar_container
        )

        bar_layout.setContentsMargins(
            0,
            0,
            0,
            0
        )

        bar_layout.setSpacing(
            0
        )

        # ------------------------------------------------------
        # Incoming traffic
        # ------------------------------------------------------

        incoming_bar = QFrame()

        incoming_bar.setStyleSheet(
            f"""
            QFrame {{
                background-color: {COLOR_YELLOW};
                border-radius: 4px;
            }}
            """
        )

        bar_layout.addWidget(
            incoming_bar,
            75
        )

        # ------------------------------------------------------
        # Outgoing traffic
        # ------------------------------------------------------

        outgoing_bar = QFrame()

        outgoing_bar.setStyleSheet(
            f"""
            QFrame {{
                background-color: {COLOR_CYAN};
                border-radius: 4px;
            }}
            """
        )

        bar_layout.addWidget(
            outgoing_bar,
            25
        )

        layout.addWidget(
            bar_container,
            1
        )

        # ======================================================
        # TOTAL BYTES
        # ======================================================

        self.total_bytes_label = QLabel(
            "476 MB"
        )

        self.total_bytes_label.setMinimumWidth(
            70
        )

        self.total_bytes_label.setAlignment(
            Qt.AlignRight |
            Qt.AlignVCenter
        )

        self.total_bytes_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 12px;
                font-weight: 600;
            }}
            """
        )

        layout.addWidget(
            self.total_bytes_label
        )

        return panel

    # ==========================================================
    # DEMO PACKETS
    # ==========================================================
    #
    # Temporary UI testing data.
    # Backend will replace this later.
    #
    # ==============================================================

    def load_demo_packets(self):

        packets = [

            {
                "program": "chrome.exe",
                "source": "2402:e280:3e55:589:24e1::",
                "source_port": "-",
                "destination": "fe80::1",
                "destination_country": "Local",
                "destination_port": "-",
                "protocol": "ICMP",
                "service": "-",
                "bytes": "16 KB",
                "domain": "",
                "asn": "",
            },

            {
                "program": "System",
                "source": "fe80::1",
                "source_port": "-",
                "destination": "2402:e280:3e55:589:24e1::",
                "destination_country": "Local",
                "destination_port": "-",
                "protocol": "ICMP",
                "service": "-",
                "bytes": "16 KB",
                "domain": "",
                "asn": "",
            },

            {
                "program": "chrome.exe",
                "source": "2404:6800:4000:101d::5f",
                "source_port": "443",
                "destination": "2402:e280:3e55:589:24e1::",
                "destination_country": "India",
                "destination_port": "55579",
                "protocol": "UDP",
                "service": "https",
                "bytes": "23 KB",
                "domain": "google.com",
                "asn": "AS15169",
            },

            {
                "program": "chrome.exe",
                "source": "2402:e280:3e55:589:24e1::",
                "source_port": "55579",
                "destination": "2404:6800:4000:101d::5f",
                "destination_country": "United States",
                "destination_port": "443",
                "protocol": "UDP",
                "service": "https",
                "bytes": "23 KB",
                "domain": "google.com",
                "asn": "AS15169",
            },

            {
                "program": "svchost.exe",
                "source": "192.168.1.12",
                "source_port": "18963",
                "destination": "44.228.229.106",
                "destination_country": "United States",
                "destination_port": "443",
                "protocol": "TCP",
                "service": "https",
                "bytes": "5.7 KB",
                "domain": "amazon.com",
                "asn": "AS16509",
            },

            {
                "program": "python.exe",
                "source": "4.145.11.36",
                "source_port": "443",
                "destination": "192.168.1.12",
                "destination_country": "Local",
                "destination_port": "19022",
                "protocol": "TCP",
                "service": "https",
                "bytes": "17 KB",
                "domain": "azure.com",
                "asn": "AS8075",
            },

            {
                "program": "python.exe",
                "source": "192.168.1.12",
                "source_port": "19022",
                "destination": "4.145.11.36",
                "destination_country": "United States",
                "destination_port": "443",
                "protocol": "TCP",
                "service": "https",
                "bytes": "12 KB",
                "domain": "azure.com",
                "asn": "AS8075",
            },

            {
                "program": "brave.exe",
                "source": "148.113.9.222",
                "source_port": "443",
                "destination": "192.168.1.12",
                "destination_country": "Local",
                "destination_port": "60572",
                "protocol": "TCP",
                "service": "https",
                "bytes": "49 KB",
                "domain": "example.com",
                "asn": "AS16276",
            },

            {
                "program": "brave.exe",
                "source": "192.168.1.12",
                "source_port": "60572",
                "destination": "148.113.9.222",
                "destination_country": "France",
                "destination_port": "443",
                "protocol": "TCP",
                "service": "https",
                "bytes": "46 KB",
                "domain": "example.com",
                "asn": "AS16276",
            },

            {
                "program": "svchost.exe",
                "source": "192.168.1.12",
                "source_port": "19029",
                "destination": "52.140.63.241",
                "destination_country": "United States",
                "destination_port": "443",
                "protocol": "TCP",
                "service": "https",
                "bytes": "3.8 KB",
                "domain": "microsoft.com",
                "asn": "AS8075",
            },

            {
                "program": "svchost.exe",
                "source": "52.140.63.241",
                "source_port": "443",
                "destination": "192.168.1.12",
                "destination_country": "Local",
                "destination_port": "19029",
                "protocol": "TCP",
                "service": "https",
                "bytes": "8.8 KB",
                "domain": "microsoft.com",
                "asn": "AS8075",
            },

            {
                "program": "svchost.exe",
                "source": "20.42.73.28",
                "source_port": "443",
                "destination": "192.168.1.12",
                "destination_country": "Local",
                "destination_port": "18804",
                "protocol": "TCP",
                "service": "https",
                "bytes": "25 KB",
                "domain": "microsoft.com",
                "asn": "AS8075",
            },

            {
                "program": "svchost.exe",
                "source": "192.168.1.12",
                "source_port": "18804",
                "destination": "20.42.73.28",
                "destination_country": "United States",
                "destination_port": "443",
                "protocol": "TCP",
                "service": "https",
                "bytes": "422 KB",
                "domain": "microsoft.com",
                "asn": "AS8075",
            },

            {
                "program": "brave.exe",
                "source": "2606:4700:4403::ac40:94eb",
                "source_port": "443",
                "destination": "2402:e280:3e55:589:24e1::",
                "destination_country": "Local",
                "destination_port": "18156",
                "protocol": "TCP",
                "service": "https",
                "bytes": "42 KB",
                "domain": "cloudflare.com",
                "asn": "AS13335",
            },

            {
                "program": "brave.exe",
                "source": "2402:e280:3e55:589:24e1::",
                "source_port": "18156",
                "destination": "2606:4700:4403::ac40:94eb",
                "destination_country": "United States",
                "destination_port": "443",
                "protocol": "TCP",
                "service": "https",
                "bytes": "40 KB",
                "domain": "cloudflare.com",
                "asn": "AS13335",
            },
        ]

        self.set_packets(
            packets
        )

    # ==========================================================
    # SET PACKETS
    # ==========================================================

    def set_packets(
        self,
        packets
    ):

        # ------------------------------------------------------
        # Save complete packet list.
        # ------------------------------------------------------

        self.all_packets = list(
            packets
        )

        # ------------------------------------------------------
        # Display packets.
        # ------------------------------------------------------

        self.populate_table(
            self.all_packets
        )

    # ==========================================================
    # POPULATE TABLE
    # ==========================================================

    def populate_table(
        self,
        packets
    ):

        # ------------------------------------------------------
        # Remove old rows.
        # ------------------------------------------------------

        self.packet_table.setRowCount(
            0
        )

        # ------------------------------------------------------
        # Add packets.
        # ------------------------------------------------------

        for row, packet in enumerate(
            packets
        ):

            self.packet_table.insertRow(
                row
            )

            # --------------------------------------------------
            # FINAL TABLE ORDER
            # --------------------------------------------------

            values = [

                # 0 - Program
                packet.get(
                    "program",
                    "-"
                ),

                # 1 - Address (source)
                packet.get(
                    "source",
                    "-"
                ),

                # 2 - Port (source)
                packet.get(
                    "source_port",
                    "-"
                ),

                # 3 - Address (destination)
                packet.get(
                    "destination",
                    "-"
                ),

                # 4 - Country (destination)
                packet.get(
                    "destination_country",
                    "Unknown"
                ),

                # 5 - Port (destination)
                packet.get(
                    "destination_port",
                    "-"
                ),

                # 6 - Protocol
                packet.get(
                    "protocol",
                    "-"
                ),

                # 7 - Service
                packet.get(
                    "service",
                    "-"
                ),

                # 8 - Bytes
                packet.get(
                    "bytes",
                    "-"
                ),
            ]

            # --------------------------------------------------
            # INSERT CELLS
            # --------------------------------------------------

            for column, value in enumerate(
                values
            ):

                item = QTableWidgetItem(
                    str(value)
                )

                # ==================================================
                # CENTER ALIGNMENT
                # ==================================================
                #
                # Program stays LEFT aligned.
                #
                # Source address -> CENTER
                # Source port    -> CENTER
                # Destination IP -> CENTER
                # Country        -> CENTER
                # Destination port -> CENTER
                # Protocol       -> CENTER
                # Service        -> CENTER
                # Bytes          -> CENTER
                #
                # ==================================================

                if column in [

                    1,  # Address (source)

                    2,  # Port (source)

                    3,  # Address (destination)

                    4,  # Country (destination)

                    5,  # Port (destination)

                    6,  # Protocol

                    7,  # Service

                    8,  # Bytes
                ]:

                    item.setTextAlignment(
                        Qt.AlignCenter
                    )

                # ==================================================
                # PROGRAM COLOR
                # ==================================================

                if column == 0:

                    item.setForeground(
                        Qt.GlobalColor.white
                    )

                # ==================================================
                # COUNTRY COLOR
                # ==================================================

                if column == 4:

                    item.setForeground(
                        Qt.GlobalColor.cyan
                    )

                # ==================================================
                # PROTOCOL COLOR
                # ==================================================

                if column == 6:

                    protocol = str(
                        value
                    ).upper()

                    if protocol == "TCP":

                        item.setForeground(
                            Qt.GlobalColor.cyan
                        )

                    elif protocol == "UDP":

                        item.setForeground(
                            Qt.GlobalColor.yellow
                        )

                    elif protocol == "ICMP":

                        item.setForeground(
                            Qt.GlobalColor.cyan
                        )

                # ==================================================
                # BYTES COLOR
                # ==================================================

                if column == 8:

                    item.setForeground(
                        Qt.GlobalColor.cyan
                    )

                # ==================================================
                # STORE COMPLETE PACKET
                # ==================================================

                if column == 0:

                    item.setData(
                        Qt.UserRole,
                        packet
                    )

                # --------------------------------------------------
                # ADD ITEM TO TABLE
                # --------------------------------------------------

                self.packet_table.setItem(
                    row,
                    column,
                    item
                )

        # ------------------------------------------------------
        # Update total bytes.
        # ------------------------------------------------------

        self.update_total_bytes(
            packets
        )

    # ==========================================================
    # FILTER PACKETS
    # ==========================================================

    def apply_filters(self):

        # ------------------------------------------------------
        # Read filters.
        # ------------------------------------------------------

        country = (
            self.country_filter.text()
            .strip()
            .lower()
        )

        domain = (
            self.domain_filter.text()
            .strip()
            .lower()
        )

        asn = (
            self.asn_filter.text()
            .strip()
            .lower()
        )

        program = (
            self.program_filter.text()
            .strip()
            .lower()
        )

        # ------------------------------------------------------
        # Filtered result.
        # ------------------------------------------------------

        filtered_packets = []

        # ------------------------------------------------------
        # Process every packet.
        # ------------------------------------------------------

        for packet in self.all_packets:

            # ==================================================
            # COUNTRY FILTER
            # ==================================================

            if country:

                packet_country = str(
                    packet.get(
                        "destination_country",
                        ""
                    )
                ).lower()

                if country not in packet_country:

                    continue

            # ==================================================
            # DOMAIN FILTER
            # ==================================================

            if domain:

                packet_domain = str(
                    packet.get(
                        "domain",
                        ""
                    )
                ).lower()

                if domain not in packet_domain:

                    continue

            # ==================================================
            # ASN FILTER
            # ==================================================

            if asn:

                packet_asn = str(
                    packet.get(
                        "asn",
                        ""
                    )
                ).lower()

                if asn not in packet_asn:

                    continue

            # ==================================================
            # PROGRAM FILTER
            # ==================================================

            if program:

                packet_program = str(
                    packet.get(
                        "program",
                        ""
                    )
                ).lower()

                if program not in packet_program:

                    continue

            # --------------------------------------------------
            # Packet passed all filters.
            # --------------------------------------------------

            filtered_packets.append(
                packet
            )

        # ------------------------------------------------------
        # Display filtered result.
        # ------------------------------------------------------

        self.populate_table(
            filtered_packets
        )

    # ==========================================================
    # PACKET SELECTED
    # ==========================================================

    def on_packet_selected(self):

        selected_items = (
            self.packet_table.selectedItems()
        )

        if not selected_items:

            return

        # ------------------------------------------------------
        # Get selected row.
        # ------------------------------------------------------

        row = selected_items[0].row()

        # ------------------------------------------------------
        # Get first cell.
        # ------------------------------------------------------

        item = self.packet_table.item(
            row,
            0
        )

        if item is None:

            return

        # ------------------------------------------------------
        # Get complete packet object.
        # ------------------------------------------------------

        packet = item.data(
            Qt.UserRole
        )

        # ------------------------------------------------------
        # Emit packet.
        # ------------------------------------------------------

        if packet:

            self.packet_selected.emit(
                packet
            )

    # ==========================================================
    # ADD SINGLE PACKET
    # ==========================================================

    def add_packet(
        self,
        packet
    ):

        # ------------------------------------------------------
        # Add new packet at top.
        # ------------------------------------------------------

        self.all_packets.insert(
            0,
            packet
        )

        # ------------------------------------------------------
        # Refresh table.
        # ------------------------------------------------------

        self.apply_filters()

    # ==========================================================
    # UPDATE TOTAL BYTES
    # ==========================================================

    def update_total_bytes(
        self,
        packets
    ):

        # ------------------------------------------------------
        # Empty table.
        # ------------------------------------------------------

        if not packets:

            self.total_bytes_label.setText(
                "0 B"
            )

            return

        # ------------------------------------------------------
        # Temporary UI value.
        #
        # Backend will calculate actual bytes later.
        # ------------------------------------------------------

        self.total_bytes_label.setText(
            "476 MB"
        )

    # ==========================================================
    # CLEAR PACKETS
    # ==========================================================

    def clear_packets(self):

        # ------------------------------------------------------
        # Remove stored packets.
        # ------------------------------------------------------

        self.all_packets.clear()

        # ------------------------------------------------------
        # Clear table.
        # ------------------------------------------------------

        self.packet_table.setRowCount(
            0
        )

        # ------------------------------------------------------
        # Reset total.
        # ------------------------------------------------------

        self.total_bytes_label.setText(
            "0 B"
        )


# ==============================================================
# END OF INSPECTION.PY
# ==============================================================