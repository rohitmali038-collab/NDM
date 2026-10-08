# ==============================================================
# NETWORK TRAFFIC ANALYZER
# OVERVIEW PAGE
# ==============================================================
#
# FRONTEND ONLY
#
# IMPORTANT:
# The common page header is NOT created here.
#
# main_window.py already provides:
#
#     Overview                         ● SYSTEM READY
#
# Therefore this page contains only the actual Overview content.
#
# ==============================================================


from PySide6.QtWidgets import (
    QWidget,
    QFrame,
    QLabel,
    QVBoxLayout,
    QHBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QAbstractItemView,
    QHeaderView,
)

from PySide6.QtCore import Qt
from PySide6.QtGui import QPen

import pyqtgraph as pg


# ==============================================================
# SIZE CONFIGURATION
# ==============================================================
#
# Change these values to easily adjust the UI.
#
# ==============================================================


# Main spacing between sections.
# Current: 6 px
OVERVIEW_SPACING = 6


# --------------------------------------------------------------
# TOP SECTION
# --------------------------------------------------------------

# Network Adapter panel width.
# Current: 230 px
ADAPTER_PANEL_WIDTH = 230

# Top section height.
# Current: 205 px
TOP_PANEL_HEIGHT = 205


# --------------------------------------------------------------
# TRAFFIC GRAPH
# --------------------------------------------------------------

# Graph height.
# Current: 185 px
GRAPH_HEIGHT = 185


# --------------------------------------------------------------
# LOWER PANELS
# --------------------------------------------------------------

# Lower panel height.
# Current: 235 px
LOWER_PANEL_HEIGHT = 235


# --------------------------------------------------------------
# TABLE ROW
# --------------------------------------------------------------

# Height of each table row.
# Current: 28 px
TABLE_ROW_HEIGHT = 28


# ==============================================================
# COLORS
# ==============================================================

COLOR_BACKGROUND = "#050B14"

COLOR_PANEL = "#0B1728"

COLOR_BORDER = "#17324D"

COLOR_BLUE = "#1683FF"

COLOR_CYAN = "#00E5FF"

COLOR_GREEN = "#00E676"

COLOR_YELLOW = "#FFC107"

COLOR_TEXT = "#F1F5F9"

COLOR_SECONDARY = "#94A3B8"


# ==============================================================
# OVERVIEW PAGE
# ==============================================================


class OverviewPage(QWidget):

    def __init__(self):

        super().__init__()

        # ------------------------------------------------------
        # OBJECT NAME
        # ------------------------------------------------------

        self.setObjectName(
            "overviewPage"
        )

        # ------------------------------------------------------
        # DARK BACKGROUND
        # ------------------------------------------------------

        self.setStyleSheet(
            f"""
            QWidget#overviewPage {{
                background-color: {COLOR_BACKGROUND};
            }}
            """
        )

        # ------------------------------------------------------
        # BUILD UI
        # ------------------------------------------------------

        self.setup_ui()

    # ==========================================================
    # MAIN UI
    # ==========================================================

    def setup_ui(self):

        # ------------------------------------------------------
        # MAIN LAYOUT
        # ------------------------------------------------------

        layout = QVBoxLayout(
            self
        )

        layout.setContentsMargins(
            0,
            0,
            0,
            0
        )

        layout.setSpacing(
            OVERVIEW_SPACING
        )

        # ------------------------------------------------------
        # TOP AREA
        # ------------------------------------------------------

        layout.addLayout(
            self.create_top_section()
        )

        # ------------------------------------------------------
        # LOWER AREA
        # ------------------------------------------------------

        layout.addLayout(
            self.create_lower_section()
        )

    # ==========================================================
    # TOP SECTION
    # ==========================================================

    def create_top_section(self):

        layout = QHBoxLayout()

        layout.setContentsMargins(
            0,
            0,
            0,
            0
        )

        layout.setSpacing(
            6
        )

        # ------------------------------------------------------
        # NETWORK ADAPTER
        # ------------------------------------------------------

        adapter_panel = (
            self.create_adapter_panel()
        )

        # ------------------------------------------------------
        # TRAFFIC GRAPH
        # ------------------------------------------------------

        graph_panel = (
            self.create_traffic_graph()
        )

        # ------------------------------------------------------
        # ADD PANELS
        # ------------------------------------------------------

        layout.addWidget(
            adapter_panel
        )

        layout.addWidget(
            graph_panel,
            1
        )

        return layout

    # ==========================================================
    # NETWORK ADAPTER PANEL
    # ==========================================================

    def create_adapter_panel(self):

        panel = QFrame()

        panel.setObjectName(
            "overviewPanel"
        )

        # ------------------------------------------------------
        # PANEL SIZE
        # ------------------------------------------------------

        panel.setFixedWidth(
            ADAPTER_PANEL_WIDTH
        )

        panel.setFixedHeight(
            TOP_PANEL_HEIGHT
        )

        # ------------------------------------------------------
        # PANEL LAYOUT
        # ------------------------------------------------------

        layout = QVBoxLayout(
            panel
        )

        layout.setContentsMargins(
            10,
            8,
            10,
            8
        )

        layout.setSpacing(
            4
        )

        # ------------------------------------------------------
        # TITLE
        # ------------------------------------------------------

        title = QLabel(
            "Network Adapter"
        )

        title.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_CYAN};
                font-size: 14px;
                font-weight: 700;
            }}
            """
        )

        layout.addWidget(
            title
        )

        # ------------------------------------------------------
        # ADAPTER NAME
        # ------------------------------------------------------

        adapter_name = QLabel(
            "Wi-Fi"
        )

        adapter_name.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT};
                font-size: 15px;
                font-weight: 600;
            }}
            """
        )

        layout.addWidget(
            adapter_name
        )

        # ------------------------------------------------------
        # DESCRIPTION
        # ------------------------------------------------------

        description = QLabel(
            "Intel(R) Wi-Fi 6 AX201 160MHz"
        )

        description.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 11px;
            }}
            """
        )

        layout.addWidget(
            description
        )

        # ------------------------------------------------------
        # CONNECTION STATUS
        # ------------------------------------------------------

        status = QLabel(
            "● Connected"
        )

        status.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_GREEN};
                font-size: 11px;
                font-weight: 600;
            }}
            """
        )

        layout.addWidget(
            status
        )

        # ------------------------------------------------------
        # SEPARATOR
        # ------------------------------------------------------

        separator = QFrame()

        separator.setFrameShape(
            QFrame.HLine
        )

        separator.setStyleSheet(
            f"""
            QFrame {{
                color: {COLOR_BORDER};
            }}
            """
        )

        layout.addWidget(
            separator
        )

        # ------------------------------------------------------
        # ACTIVE FILTER
        # ------------------------------------------------------

        filter_title = QLabel(
            "Active filters"
        )

        filter_title.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 10px;
            }}
            """
        )

        layout.addWidget(
            filter_title
        )

        filter_value = QLabel(
            "none"
        )

        filter_value.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT};
                font-size: 11px;
            }}
            """
        )

        layout.addWidget(
            filter_value
        )

        # ------------------------------------------------------
        # DATA REPRESENTATION
        # ------------------------------------------------------

        representation = QLabel(
            "Data representation"
        )

        representation.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 10px;
            }}
            """
        )

        layout.addWidget(
            representation
        )

        representation_value = QLabel(
            "bits     bytes     packets"
        )

        representation_value.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT};
                font-size: 10px;
            }}
            """
        )

        layout.addWidget(
            representation_value
        )

        # ------------------------------------------------------
        # TRAFFIC SUMMARY
        # ------------------------------------------------------

        summary = QLabel(
            "Traffic Summary"
        )

        summary.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_CYAN};
                font-size: 12px;
                font-weight: 600;
            }}
            """
        )

        layout.addWidget(
            summary
        )

        # Incoming
        incoming = QLabel(
            "● Incoming: 75 MB"
        )

        incoming.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_YELLOW};
                font-size: 10px;
            }}
            """
        )

        layout.addWidget(
            incoming
        )

        # Outgoing
        outgoing = QLabel(
            "● Outgoing: 88 MB"
        )

        outgoing.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_CYAN};
                font-size: 10px;
            }}
            """
        )

        layout.addWidget(
            outgoing
        )

        # Captured
        captured = QLabel(
            "● Captured: 163 MB"
        )

        captured.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SECONDARY};
                font-size: 10px;
            }}
            """
        )

        layout.addWidget(
            captured
        )

        layout.addStretch()

        # ------------------------------------------------------
        # PANEL STYLE
        # ------------------------------------------------------

        panel.setStyleSheet(
            f"""
            QFrame#overviewPanel {{
                background-color: {COLOR_PANEL};
                border: 1px solid {COLOR_BORDER};
                border-radius: 7px;
            }}
            """
        )

        return panel

    # ==========================================================
    # TRAFFIC GRAPH
    # ==========================================================

    def create_traffic_graph(self):

        panel = QFrame()

        panel.setObjectName(
            "trafficGraphPanel"
        )

        panel.setFixedHeight(
            GRAPH_HEIGHT
        )

        # ------------------------------------------------------
        # PANEL LAYOUT
        # ------------------------------------------------------

        layout = QVBoxLayout(
            panel
        )

        layout.setContentsMargins(
            6,
            5,
            6,
            5
        )

        layout.setSpacing(
            2
        )

        # ------------------------------------------------------
        # TITLE
        # ------------------------------------------------------

        title = QLabel(
            "Traffic Rate"
        )

        title.setAlignment(
            Qt.AlignCenter
        )

        title.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_CYAN};
                font-size: 14px;
                font-weight: 700;
            }}
            """
        )

        layout.addWidget(
            title
        )

        # ------------------------------------------------------
        # GRAPH
        # ------------------------------------------------------

        self.traffic_graph = pg.PlotWidget()

        self.traffic_graph.setBackground(
            COLOR_PANEL
        )

        # ------------------------------------------------------
        # GRAPH HEIGHT
        # ------------------------------------------------------

        self.traffic_graph.setFixedHeight(
            GRAPH_HEIGHT - 30
        )

        # ------------------------------------------------------
        # GRID
        # ------------------------------------------------------

        self.traffic_graph.showGrid(
            x=True,
            y=True,
            alpha=0.12
        )

        # ------------------------------------------------------
        # HIDE DEFAULT BUTTONS
        # ------------------------------------------------------

        self.traffic_graph.hideButtons()

        self.traffic_graph.setMenuEnabled(
            False
        )

        # ------------------------------------------------------
        # AXIS
        # ------------------------------------------------------

        left_axis = (
            self.traffic_graph.getAxis(
                "left"
            )
        )

        bottom_axis = (
            self.traffic_graph.getAxis(
                "bottom"
            )
        )

        left_axis.setTextPen(
            COLOR_SECONDARY
        )

        bottom_axis.setTextPen(
            COLOR_SECONDARY
        )

        # ------------------------------------------------------
        # LABELS
        # ------------------------------------------------------

        self.traffic_graph.setLabel(
            "left",
            "KB/s"
        )

        self.traffic_graph.setLabel(
            "bottom",
            "Time"
        )

        # ------------------------------------------------------
        # DUMMY DATA
        # ------------------------------------------------------

        x = list(
            range(20)
        )

        incoming = [
            5, 6, 5, 8, 75,
            90, 88, 12, 8, 7,
            9, 7, 10, 8, 9,
            12, 13, 35, 36, 18
        ]

        outgoing = [
            -3, -5, -4, -7, -12,
            -45, -46, -10, -4, -3,
            -8, -50, -52, -28, -28,
            -5, -4, -5, -12, -16
        ]

        # ------------------------------------------------------
        # INCOMING LINE
        # ------------------------------------------------------

        incoming_pen = QPen(
            COLOR_YELLOW
        )

        incoming_pen.setWidth(
            2
        )

        self.incoming_curve = (
            self.traffic_graph.plot(
                x,
                incoming,
                pen=incoming_pen
            )
        )

        # ------------------------------------------------------
        # OUTGOING LINE
        # ------------------------------------------------------

        outgoing_pen = QPen(
            COLOR_CYAN
        )

        outgoing_pen.setWidth(
            2
        )

        self.outgoing_curve = (
            self.traffic_graph.plot(
                x,
                outgoing,
                pen=outgoing_pen
            )
        )

        layout.addWidget(
            self.traffic_graph
        )

        # ------------------------------------------------------
        # PANEL STYLE
        # ------------------------------------------------------

        panel.setStyleSheet(
            f"""
            QFrame#trafficGraphPanel {{
                background-color: {COLOR_PANEL};
                border: 1px solid {COLOR_BORDER};
                border-radius: 7px;
            }}
            """
        )

        return panel

    # ==========================================================
    # LOWER SECTION
    # ==========================================================

    def create_lower_section(self):

        layout = QHBoxLayout()

        layout.setContentsMargins(
            0,
            0,
            0,
            0
        )

        layout.setSpacing(
            6
        )

        # ------------------------------------------------------
        # NETWORK HOSTS
        # ------------------------------------------------------

        hosts = (
            self.create_hosts_panel()
        )

        # ------------------------------------------------------
        # SERVICES
        # ------------------------------------------------------

        services = (
            self.create_services_panel()
        )

        # ------------------------------------------------------
        # PROGRAMS
        # ------------------------------------------------------

        programs = (
            self.create_programs_panel()
        )

        # ------------------------------------------------------
        # WIDTH RATIO
        # ------------------------------------------------------
        #
        # Hosts  = 2
        # Services = 1
        # Programs = 1
        #
        # ------------------------------------------------------

        layout.addWidget(
            hosts,
            2
        )

        layout.addWidget(
            services,
            1
        )

        layout.addWidget(
            programs,
            1
        )

        return layout

    # ==========================================================
    # NETWORK HOSTS
    # ==========================================================

    def create_hosts_panel(self):

        panel = self.create_table_panel(
            "Network Hosts",
            [
                "HOST",
                "TYPE",
                "TRAFFIC"
            ]
        )

        table = panel.property(
            "table"
        )

        self.hosts_table = table

        data = [

            (
                "192.168.1.6",
                "Local",
                "177 KB"
            ),

            (
                "2606:4700:48::ac49:b9d1",
                "Cloudflare",
                "39 MB"
            ),

            (
                "fe80::9be6:a778:491b:12871",
                "IPv6",
                "347 KB"
            ),

            (
                "192.168.1.8",
                "Local",
                "124 KB"
            ),

            (
                "fe80::cc76:d5ff:fe8c:2936",
                "IPv6",
                "185 KB"
            ),

            (
                "192.168.1.2",
                "Local",
                "169 KB"
            ),

            (
                "2603:1046:2300::",
                "Microsoft",
                "49 KB"
            ),
        ]

        self.fill_table(
            table,
            data
        )

        return panel

    # ==========================================================
    # SERVICES
    # ==========================================================

    def create_services_panel(self):

        panel = self.create_table_panel(
            "Services",
            [
                "SERVICE",
                "TRAFFIC"
            ]
        )

        table = panel.property(
            "table"
        )

        self.services_table = table

        data = [

            (
                "zeroconf",
                "1.9 MB"
            ),

            (
                "https",
                "148 MB"
            ),

            (
                "upnp",
                "465 KB"
            ),

            (
                "?",
                "633 KB"
            ),

            (
                "secure-mqtt",
                "38 KB"
            ),

            (
                "hvproon",
                "222 KB"
            ),

            (
                "netbios-ns",
                "167 KB"
            ),
        ]

        self.fill_table(
            table,
            data
        )

        return panel

    # ==========================================================
    # PROGRAMS
    # ==========================================================

    def create_programs_panel(self):

        panel = self.create_table_panel(
            "Programs",
            [
                "PROCESS",
                "TRAFFIC"
            ]
        )

        table = panel.property(
            "table"
        )

        self.programs_table = table

        data = [

            (
                "ChatGPT.exe",
                "7.8 MB"
            ),

            (
                "svchost.exe",
                "7.8 MB"
            ),

            (
                "claude.exe",
                "9.4 MB"
            ),

            (
                "svchost.exe",
                "1.2 MB"
            ),

            (
                "?",
                "5.4 MB"
            ),

            (
                "brave.exe",
                "53 MB"
            ),

            (
                "bservicesthost.exe",
                "684 KB"
            ),
        ]

        self.fill_table(
            table,
            data
        )

        return panel

    # ==========================================================
    # GENERIC TABLE PANEL
    # ==========================================================

    def create_table_panel(
        self,
        title_text,
        headers
    ):

        panel = QFrame()

        panel.setObjectName(
            "tablePanel"
        )

        panel.setMinimumHeight(
            LOWER_PANEL_HEIGHT
        )

        panel.setStyleSheet(
            f"""
            QFrame#tablePanel {{
                background-color: {COLOR_PANEL};
                border: 1px solid {COLOR_BORDER};
                border-radius: 7px;
            }}
            """
        )

        layout = QVBoxLayout(
            panel
        )

        layout.setContentsMargins(
            5,
            5,
            5,
            5
        )

        layout.setSpacing(
            4
        )

        # ------------------------------------------------------
        # TITLE
        # ------------------------------------------------------

        title = QLabel(
            title_text
        )

        title.setAlignment(
            Qt.AlignCenter
        )

        title.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_CYAN};
                font-size: 14px;
                font-weight: 700;
            }}
            """
        )

        layout.addWidget(
            title
        )

        # ------------------------------------------------------
        # TABLE
        # ------------------------------------------------------

        table = QTableWidget()

        table.setColumnCount(
            len(headers)
        )

        table.setHorizontalHeaderLabels(
            headers
        )

        # ------------------------------------------------------
        # TABLE HEIGHT
        # ------------------------------------------------------

        table.setMinimumHeight(
            LOWER_PANEL_HEIGHT - 45
        )

        # ------------------------------------------------------
        # READ ONLY
        # ------------------------------------------------------

        table.setEditTriggers(
            QAbstractItemView.NoEditTriggers
        )

        # ------------------------------------------------------
        # ROW SELECTION
        # ------------------------------------------------------

        table.setSelectionBehavior(
            QAbstractItemView.SelectRows
        )

        # ------------------------------------------------------
        # HIDE ROW NUMBERS
        # ------------------------------------------------------

        table.verticalHeader().setVisible(
            False
        )

        # ------------------------------------------------------
        # ROW HEIGHT
        # ------------------------------------------------------

        table.verticalHeader().setDefaultSectionSize(
            TABLE_ROW_HEIGHT
        )

        # ------------------------------------------------------
        # HEADER
        # ------------------------------------------------------

        header = (
            table.horizontalHeader()
        )

        header.setSectionResizeMode(
            QHeaderView.Stretch
        )

        # ------------------------------------------------------
        # STORE TABLE IN PANEL
        # ------------------------------------------------------

        panel.setProperty(
            "table",
            table
        )

        layout.addWidget(
            table
        )

        return panel

    # ==========================================================
    # FILL TABLE
    # ==========================================================

    def fill_table(
        self,
        table,
        data
    ):

        # ------------------------------------------------------
        # NUMBER OF ROWS
        # ------------------------------------------------------

        table.setRowCount(
            len(data)
        )

        # ------------------------------------------------------
        # INSERT DATA
        # ------------------------------------------------------

        for row, values in enumerate(
            data
        ):

            for column, value in enumerate(
                values
            ):

                item = QTableWidgetItem(
                    str(value)
                )

                # Center numeric/traffic values.
                if column > 0:

                    item.setTextAlignment(
                        Qt.AlignCenter
                    )

                table.setItem(
                    row,
                    column,
                    item
                )

    # ==========================================================
    # BACKEND INTEGRATION
    # ==========================================================

    def set_adapter(
        self,
        adapter_name,
        description,
        status,
        ipv4=None,
        ipv6=None,
        mac=None,
        speed=None
    ):

        # ------------------------------------------------------
        # Store backend information.
        # ------------------------------------------------------

        self.current_adapter = {

            "name": adapter_name,

            "description": description,

            "status": status,

            "ipv4": ipv4,

            "ipv6": ipv6,

            "mac": mac,

            "speed": speed,
        }

    # ==========================================================
    # UPDATE TRAFFIC GRAPH
    # ==========================================================

    def update_traffic_graph(
        self,
        incoming,
        outgoing
    ):

        # ------------------------------------------------------
        # Generate X axis.
        # ------------------------------------------------------

        x = list(
            range(
                len(incoming)
            )
        )

        # ------------------------------------------------------
        # Update incoming.
        # ------------------------------------------------------

        self.incoming_curve.setData(
            x,
            incoming
        )

        # ------------------------------------------------------
        # Update outgoing.
        # ------------------------------------------------------

        self.outgoing_curve.setData(
            x,
            outgoing
        )

    # ==========================================================
    # UPDATE HOSTS
    # ==========================================================

    def update_hosts(
        self,
        hosts
    ):

        data = []

        for host in hosts:

            data.append(
                (
                    host.get(
                        "host",
                        "-"
                    ),

                    host.get(
                        "type",
                        "-"
                    ),

                    host.get(
                        "traffic",
                        "-"
                    ),
                )
            )

        self.fill_table(
            self.hosts_table,
            data
        )

    # ==========================================================
    # UPDATE SERVICES
    # ==========================================================

    def update_services(
        self,
        services
    ):

        data = []

        for service in services:

            data.append(
                (
                    service.get(
                        "service",
                        "-"
                    ),

                    service.get(
                        "traffic",
                        "-"
                    ),
                )
            )

        self.fill_table(
            self.services_table,
            data
        )

    # ==========================================================
    # UPDATE PROGRAMS
    # ==========================================================

    def update_programs(
        self,
        programs
    ):

        data = []

        for program in programs:

            data.append(
                (
                    program.get(
                        "process",
                        "-"
                    ),

                    program.get(
                        "traffic",
                        "-"
                    ),
                )
            )

        self.fill_table(
            self.programs_table,
            data
        )

    # ==========================================================
    # RESET PAGE
    # ==========================================================

    def reset(self):

        # Clear graph.
        self.incoming_curve.setData(
            [],
            []
        )

        self.outgoing_curve.setData(
            [],
            []
        )

        # Clear tables.
        self.hosts_table.setRowCount(
            0
        )

        self.services_table.setRowCount(
            0
        )

        self.programs_table.setRowCount(
            0
        )


# ==============================================================
# END OF OVERVIEW.PY
# ==============================================================