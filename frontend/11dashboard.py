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

from backend.network.adapter_info import get_network_adapters
from PySide6.QtCore import Qt, QTimer, QThread, Signal
from datetime import datetime
import socket
import uuid
import time

try:
    import psutil
except ImportError:
    psutil = None

try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP
except ImportError:
    sniff = IP = IPv6 = TCP = UDP = ICMP = ARP = None

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
ADAPTER_PANEL_HEIGHT = 88


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


class PacketCaptureWorker(QThread):
    packets_received = Signal(list)
    capture_error = Signal(str)

    def __init__(self):
        super().__init__()
        self._stop_requested = False
        self._packet_batch = []
        self._last_batch_emit = time.monotonic()
        try:
            self._local_addresses = {
                address.address.split("%", 1)[0]
                for address_list in psutil.net_if_addrs().values()
                for address in address_list
                if address.family in (socket.AF_INET, socket.AF_INET6)
            } if psutil else set()
        except Exception:
            self._local_addresses = set()

    def stop(self):
        self._stop_requested = True

    def run(self):
        if sniff is None:
            self.capture_error.emit("Scapy is not installed. Install it with: python -m pip install scapy")
            return
        try:
            # Windows packet capture generally requires Npcap and elevated permissions.
            sniff(prn=self._handle_packet, store=False, stop_filter=lambda _pkt: self._stop_requested)
        except Exception as exc:
            self.capture_error.emit(str(exc))
        finally:
            self._emit_packet_batch()

    def _emit_packet_batch(self):
        if self._packet_batch:
            batch = self._packet_batch
            self._packet_batch = []
            self._last_batch_emit = time.monotonic()
            self.packets_received.emit(batch)

    def _handle_packet(self, pkt):
        if self._stop_requested:
            return
        try:
            proto = "OTHER"
            src_port = dst_port = "-"
            src = dst = "-"
            if IP in pkt:
                src, dst = pkt[IP].src, pkt[IP].dst
            elif IPv6 in pkt:
                src, dst = pkt[IPv6].src, pkt[IPv6].dst
            if TCP in pkt:
                src_port, dst_port = pkt[TCP].sport, pkt[TCP].dport
                # Classify well-known application traffic before transport protocol.
                if src_port == 53 or dst_port == 53:
                    proto = "DNS"
                elif src_port == 443 or dst_port == 443:
                    proto = "TLS"
                else:
                    proto = "TCP"
            elif UDP in pkt:
                src_port, dst_port = pkt[UDP].sport, pkt[UDP].dport
                if src_port == 53 or dst_port == 53:
                    proto = "DNS"
                else:
                    proto = "UDP"
            elif ICMP in pkt:
                proto = "ICMP"
            elif ARP in pkt:
                proto = "ARP"
                src, dst = pkt[ARP].psrc, pkt[ARP].pdst
            direction = "OUT" if src in self._local_addresses else ("IN" if dst in self._local_addresses else "TRANSIT")
            packet = {
                "packet_id": uuid.uuid4().hex[:8],
                "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "protocol": proto,
                "direction": direction,
                "source": src,
                "source_port": src_port,
                "destination": dst,
                "destination_port": dst_port,
                "size": f"{len(pkt)} B",
                "country": "Unknown",
                "process": "Unknown",
            }
            self._packet_batch.append(packet)
            # Batch UI updates to avoid a redraw for every captured packet.
            now = time.monotonic()
            if len(self._packet_batch) >= 30 or now - self._last_batch_emit >= 0.10:
                self._emit_packet_batch()
        except Exception:
            pass


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
        self.capture_worker = None
        self.total_packets = 0
        self.incoming_packets = 0
        self.outgoing_packets = 0
        self.protocol_counts = {"TCP": 0, "UDP": 0, "TLS": 0, "DNS": 0, "ICMP": 0}
        self._protocol_widgets = {}
        self._connection_labels = {}
        self._adapter_labels = {}
        self.setup_ui()
        self.refresh_adapter_info()
        self.refresh_timer = QTimer(self)
        self.refresh_timer.setInterval(5000)
        self.refresh_timer.timeout.connect(self.refresh_live_statistics)
        self.refresh_timer.start()
        self.refresh_live_statistics()

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
        self.start_button = start_button
        start_button.clicked.connect(self.start_capture)

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
        self.stop_button = stop_button
        stop_button.clicked.connect(self.stop_capture)
        stop_button.setEnabled(False)

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
        self.rescan_button = rescan_button
        rescan_button.clicked.connect(self.rescan_adapters)

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

        # Live capture indicator: appears beside Rescan only while capturing.
        self.capture_status_label = QLabel("●  Packet Capturing...")
        self.capture_status_label.setStyleSheet(
            "QLabel { color: #00E676; font-weight: 700; padding-left: 8px; }"
        )
        self.capture_status_label.hide()

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

        layout.addWidget(self.capture_status_label)

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
            "Detecting adapter..."
        )
        self._adapter_labels["name"] = adapter_name

        adapter_name.setProperty(
            "heading",
            True
        )

        adapter_description = QLabel(
            "Reading network interface details"
        )
        self._adapter_labels["description"] = adapter_description

        adapter_description.setProperty(
            "secondary",
            True
        )

        adapter_status = QLabel(
            "●  Checking status"
        )
        self._adapter_labels["status"] = adapter_status

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
                "Detecting..."
            ),

            (
                "IPv6 Address",
                "Detecting..."
            ),

            (
                "MAC Address",
                "Detecting..."
            ),

            (
                "Status",
                "Checking..."
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
            self._adapter_labels[name] = value_label

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
                value="0",
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
                value="0",
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
                value="0",
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
        card.metric_value_label = value_label

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
        # Live packet rows are inserted only after capture starts.
        self.packet_table.setRowCount(0)

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
        # No fabricated packets: the table stays empty until live capture.

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
        panel.setProperty("panel", True)
        panel.setFixedHeight(BOTTOM_PANEL_HEIGHT)

        layout = QVBoxLayout(panel)
        layout.setContentsMargins(10, 6, 10, 6)
        layout.setSpacing(2)

        title = QLabel("PROTOCOL STATISTICS")
        title.setProperty("heading", True)
        layout.addWidget(title)

        protocols = [
            ("TCP", COLOR_BLUE),
            ("UDP", COLOR_GREEN),
            ("TLS", COLOR_PURPLE),
            ("DNS", COLOR_YELLOW),
            ("ICMP", COLOR_RED),
        ]

        self._protocol_widgets = {}
        for protocol, color in protocols:
            row = QHBoxLayout()
            row.setSpacing(6)

            name = QLabel(protocol)
            name.setMinimumWidth(45)
            # Explicitly set the protocol name color so the global QSS
            # cannot render labels black on the dark dashboard panel.
            name.setStyleSheet("QLabel { color: #94A3B8; font-weight: 500; }")

            bar = QFrame()
            bar.setFixedSize(0, 5)
            bar.setStyleSheet(
                f"QFrame {{ background-color: {color}; border-radius: 2px; }}"
            )

            value = QLabel("0%")
            value.setMinimumWidth(35)
            value.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            value.setProperty("secondary", True)

            row.addWidget(name)
            row.addWidget(bar)
            row.addStretch()
            row.addWidget(value)
            layout.addLayout(row)

            self._protocol_widgets[protocol] = {
                "bar": bar,
                "value": value,
                "color": color,
            }

        return panel

    def update_protocol_statistics(self, protocol):
        """Compatibility helper for a single captured protocol."""
        self.update_protocol_statistics_batch([protocol])

    def update_protocol_statistics_batch(self, protocols):
        """Update protocol counts and redraw bars only once per packet batch."""
        for protocol in protocols:
            protocol = str(protocol).upper()
            if protocol in self.protocol_counts:
                self.protocol_counts[protocol] += 1

        total = sum(self.protocol_counts.values())
        if total <= 0:
            return

        max_bar_width = 180
        for name, widgets in self._protocol_widgets.items():
            percentage = (self.protocol_counts.get(name, 0) / total) * 100
            widgets["bar"].setFixedWidth(max(0, round(max_bar_width * percentage / 100)))
            widgets["value"].setText(f"{percentage:.0f}%")

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
                "0"
            )
            self._connection_labels[name] = value_label

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

        self.total_packets = int(total_packets)
        self.incoming_packets = int(incoming_packets)
        self.outgoing_packets = int(outgoing_packets)
        self.total_packet_card.metric_value_label.setText(f"{self.total_packets:,}")
        self.incoming_packet_card.metric_value_label.setText(f"{self.incoming_packets:,}")
        self.outgoing_packet_card.metric_value_label.setText(f"{self.outgoing_packets:,}")

    # ==========================================================
    # ADD LIVE PACKET
    # ==========================================================
    #
    # Backend will send packet information here.
    #
    # ==============================================================

    def add_packet(self, packet):
        """Add one packet through the same efficient batch path."""
        self.add_packets([packet])

    def add_packets(self, packets):
        """Insert a batch of packets with one table refresh/scroll operation."""
        if not packets:
            return

        table = self.packet_table
        table.setUpdatesEnabled(False)
        try:
            for packet in packets:
                row = table.rowCount()
                table.insertRow(row)
                values = [
                    packet.get("packet_id", "-"),
                    packet.get("time", "-"),
                    packet.get("protocol", "-"),
                    packet.get("direction", "-"),
                    packet.get("source", "-"),
                    packet.get("source_port", "-"),
                    packet.get("destination", "-"),
                    packet.get("destination_port", "-"),
                    packet.get("size", "-"),
                    packet.get("country", "Unknown"),
                    packet.get("process", "Unknown"),
                ]
                for column, value in enumerate(values):
                    item = QTableWidgetItem(str(value))
                    item.setTextAlignment(Qt.AlignCenter)
                    table.setItem(row, column, item)

            # Keep only the newest 500 rows; remove overflow in one operation.
            overflow = table.rowCount() - 500
            if overflow > 0:
                table.setUpdatesEnabled(True)
                for _ in range(overflow):
                    table.removeRow(0)
                table.setUpdatesEnabled(False)
        finally:
            table.setUpdatesEnabled(True)

        table.scrollToBottom()

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

    # ==========================================================
    # LIVE NETWORK INTEGRATION
    # ==========================================================

    def rescan_adapters(self):
        """Refresh adapter information and give visible feedback."""
        self.refresh_adapter_info()

        button = getattr(self, "rescan_button", None)
        if button is not None:
            button.setText("✓ Scan Complete")
            button.setEnabled(False)
            QTimer.singleShot(1200, self._restore_rescan_button)

    def _restore_rescan_button(self):
        button = getattr(self, "rescan_button", None)
        if button is not None:
            button.setText("⟳  Rescan Adapters")
            button.setEnabled(True)

    def refresh_adapter_info(self):
        """Read live interface details and prefer the active Wi-Fi adapter."""
        if psutil is None:
            self._set_adapter_text("name", "Network adapter")
            self._set_adapter_text("description", "psutil is not installed")
            self._set_adapter_text("status", "●  Dependency missing")
            for key in ("IPv4 Address", "IPv6 Address", "MAC Address", "Status"):
                self._set_adapter_text(key, "—")
            return

        try:
            stats = psutil.net_if_stats()
            addresses = psutil.net_if_addrs()
            candidates = []

            for name, addr_list in addresses.items():
                stat = stats.get(name)
                if not stat or not stat.isup:
                    continue

                ipv4 = next(
                    (
                        address.address
                        for address in addr_list
                        if address.family == socket.AF_INET
                        and not address.address.startswith("127.")
                        and not address.address.startswith("169.254.")
                    ),
                    "",
                )
                if ipv4:
                    candidates.append((name, addr_list, stat, ipv4))

            if not candidates:
                self._set_adapter_text("name", "No active adapter")
                self._set_adapter_text("description", "No active IPv4 interface detected")
                self._set_adapter_text("status", "●  Disconnected")
                for key in ("IPv4 Address", "IPv6 Address", "MAC Address", "Status"):
                    self._set_adapter_text(key, "—")
                return

            # Prefer Wi-Fi if it is active; otherwise use the first active
            # adapter with a usable IPv4 address (excluding APIPA/loopback).
            selected = next(
                (item for item in candidates if item[0].lower() == "wi-fi"),
                candidates[0],
            )
            name, addr_list, stat, ipv4 = selected

            # Prefer a global IPv6 address. If the adapter only has a
            # link-local address (common on Windows), display that instead.
            ipv6_addresses = [
                address.address.split("%", 1)[0]
                for address in addr_list
                if address.family == socket.AF_INET6
                and address.address != "::1"
                and not address.address.startswith("::ffff:127.")
            ]
            ipv6 = next(
                (address for address in ipv6_addresses if not address.lower().startswith("fe80:")),
                ipv6_addresses[0] if ipv6_addresses else "N/A",
            )
            mac = next(
                (
                    address.address
                    for address in addr_list
                    if getattr(psutil, "AF_LINK", object()) == address.family
                ),
                "—",
            )

            self._set_adapter_text("name", name)
            self._set_adapter_text(
                "description",
                f"Speed: {stat.speed} Mbps · Updated {datetime.now().strftime('%H:%M:%S')}"
                if stat.speed
                else f"Active network interface · Updated {datetime.now().strftime('%H:%M:%S')}",
            )
            # "Online" means this adapter can reach an external network.
            # Interface-up alone is not enough to prove Internet connectivity.
            is_online = self._can_reach_external_network()
            connection_status = "●  Online" if is_online else "●  Offline"

            self._set_adapter_text("status", connection_status)
            self._set_adapter_text("IPv4 Address", ipv4)
            self._set_adapter_text("IPv6 Address", ipv6)
            self._set_adapter_text("MAC Address", mac)
            self._set_adapter_text("Status", "Online" if is_online else "Offline")

            status_label = self._adapter_labels.get("Status")
            if status_label is not None:
                status_label.setStyleSheet(
                    "color: #00E676; font-weight: 700;" if is_online
                    else "color: #FF3B4E; font-weight: 700;"
                )
            header_status = self._adapter_labels.get("status")
            if header_status is not None:
                header_status.setStyleSheet(
                    "color: #00E676; font-weight: 700;" if is_online
                    else "color: #FF3B4E; font-weight: 700;"
                )

        except Exception as exc:
            self._set_adapter_text("description", f"Adapter read error: {exc}")
            self._set_adapter_text("status", "●  Scan failed")

    def _can_reach_external_network(self):
        """Return True if a TCP connection to a public endpoint succeeds.

        This checks external network reachability, not just whether the
        Windows network adapter is switched on. A restrictive firewall or
        proxy can cause a false Offline result even when another route works.
        """
        endpoints = (("1.1.1.1", 443), ("8.8.8.8", 443))
        for host, port in endpoints:
            try:
                with socket.create_connection((host, port), timeout=1.0):
                    return True
            except OSError:
                continue
        return False

    def _set_adapter_text(self, key, value):
        label = self._adapter_labels.get(key)
        if label is not None:
            label.setText(str(value))

    def refresh_live_statistics(self):
        """Refresh real OS connection counts; does not fabricate packet rows."""
        if psutil is None:
            for label in self._connection_labels.values():
                label.setText("N/A")
            return
        counts = {"ESTABLISHED": 0, "LISTENING": 0, "TIME_WAIT": 0, "TCP": 0, "UDP": 0, "CLOSE_WAIT": 0}
        try:
            for conn in psutil.net_connections(kind="inet"):
                kind = getattr(conn, "type", None)
                if kind == socket.SOCK_STREAM:
                    counts["TCP"] += 1
                elif kind == socket.SOCK_DGRAM:
                    counts["UDP"] += 1
                status = str(getattr(conn, "status", "")).upper()
                if status in counts:
                    counts[status] += 1
            for name, label in self._connection_labels.items():
                label.setText(str(counts.get(name, 0)))
        except (psutil.AccessDenied, PermissionError):
            for label in self._connection_labels.values():
                label.setText("Access denied")
        except Exception:
            for label in self._connection_labels.values():
                label.setText("N/A")

    def start_capture(self):
        if self.capture_worker is not None and self.capture_worker.isRunning():
            return
        if sniff is None:
            from PySide6.QtWidgets import QMessageBox
            QMessageBox.warning(self, "Packet capture unavailable", "Scapy is not installed. Run: python -m pip install scapy\n\nOn Windows, install Npcap and run the application with suitable permissions to capture packets.")
            return
        self.capture_worker = PacketCaptureWorker()
        self.capture_worker.packets_received.connect(self._on_live_packets)
        self.capture_worker.capture_error.connect(self._on_capture_error)
        self.capture_worker.finished.connect(self._on_capture_finished)
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.capture_status_label.setText("●  Packet Capturing...")
        self.capture_status_label.show()
        self.capture_worker.start()

    def stop_capture(self):
        if self.capture_worker is not None and self.capture_worker.isRunning():
            self.capture_worker.stop()
            self.capture_worker.requestInterruption()
        self.capture_status_label.hide()
        self.stop_button.setEnabled(False)
        self.start_button.setEnabled(True)

    def _on_live_packet(self, packet):
        """Compatibility slot for callers that provide one packet."""
        self._on_live_packets([packet])

    def _on_live_packets(self, packets):
        """Process captured packets in batches to keep the UI responsive."""
        if not packets:
            return

        self.add_packets(packets)
        self.update_protocol_statistics_batch(
            packet.get("protocol", "") for packet in packets
        )
        self.total_packets += len(packets)
        self.incoming_packets += sum(1 for packet in packets if packet.get("direction") == "IN")
        self.outgoing_packets += sum(1 for packet in packets if packet.get("direction") == "OUT")
        self.update_metrics(self.total_packets, self.incoming_packets, self.outgoing_packets)

    def _on_capture_error(self, message):
        from PySide6.QtWidgets import QMessageBox
        self.capture_status_label.hide()
        self.stop_button.setEnabled(False)
        self.start_button.setEnabled(True)
        QMessageBox.warning(self, "Capture error", f"Packet capture could not start or stopped unexpectedly:\n{message}\n\nCheck Npcap installation and run with suitable permissions.")

    def _on_capture_finished(self):
        self.capture_status_label.hide()
        self.stop_button.setEnabled(False)
        self.start_button.setEnabled(True)
