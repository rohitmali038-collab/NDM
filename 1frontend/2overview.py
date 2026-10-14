from __future__ import annotations

import ipaddress
import math
import psutil
import queue
import socket
import threading
import time
import zlib
from collections import defaultdict
from typing import Dict, List

from PySide6.QtCore import Qt, QTimer, QRectF, QPointF, Signal
from PySide6.QtGui import (
    QColor,
    QFont,
    QFontMetrics,
    QPainter,
    QPainterPath,
    QPen,
    QBrush,
)
from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QFrame,
    QScrollArea,
    QSizePolicy,
    QComboBox,
)

from gui.app_state import app_state


# ============================================================
# SIZE SETTINGS
# ============================================================

# Screenshot-based Overview sizing
RATE_PANEL_HEIGHT = 210       # compact top graph panel
GRAPH_HEIGHT = 132            # graph area inside Traffic Rate
LIST_PANEL_HEIGHT = 520        # bottom Host/Services/Programs panels
LIST_ROW_HEIGHT = 42           # each traffic row
MAX_LIST_ROWS = 7
MAX_GRAPH_POINTS = 120


# ============================================================
# COLORS
# ============================================================

BG = "#06121F"
PANEL = "#0B1B35"
PANEL_DARK = "#09182C"
CARD = "#101F3A"
ROW_BG = "#142844"

BORDER = "#1B3154"
BORDER_LIGHT = "#263D62"

TEXT = "#E5EAF2"
TEXT_SECONDARY = "#AEB9C9"
MUTED = "#64738C"

YELLOW = "#FFC21A"

INCOMING = "#FFB000"
OUTGOING = "#00D4FF"
DROPPED = "#435675"

BLUE = "#168CFF"
BLUE_DARK = "#0C4F91"
ACTIVE = "#00E676"

GRAPH_BG = "#081525"
GRID = "#1D3552"
AXIS = "#607A96"

WHITE = "#FFFFFF"


# ============================================================
# HELPERS
# ============================================================

def format_bytes(value: float) -> str:

    value = max(0.0, float(value))

    units = [
        "B",
        "KB",
        "MB",
        "GB",
        "TB",
    ]

    index = 0

    while value >= 1024 and index < len(units) - 1:
        value /= 1024
        index += 1

    if index == 0:
        return f"{value:.0f} {units[index]}"

    if value >= 100:
        return f"{value:.0f} {units[index]}"

    if value >= 10:
        return f"{value:.1f} {units[index]}"

    return f"{value:.2f} {units[index]}"


def format_bits(value: float) -> str:

    value = max(0.0, float(value))

    units = [
        "b/s",
        "Kb/s",
        "Mb/s",
        "Gb/s",
        "Tb/s",
    ]

    index = 0

    while value >= 1000 and index < len(units) - 1:
        value /= 1000
        index += 1

    if index == 0:
        return f"{value:.0f} {units[index]}"

    if value >= 100:
        return f"{value:.0f} {units[index]}"

    if value >= 10:
        return f"{value:.1f} {units[index]}"

    return f"{value:.2f} {units[index]}"


def format_rate(
    value: float,
    representation: str,
) -> str:

    if representation == "Bits":
        return format_bits(value)

    if representation == "Bytes":
        return f"{format_bytes(value)}/s"

    if value >= 100:
        return f"{value:.0f} pkt/s"

    return f"{value:.1f} pkt/s"


def format_packet_count(value: int) -> str:

    value = int(value)

    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"

    if value >= 1_000:
        return f"{value / 1_000:.1f}K"

    return str(value)


def clean_address(address) -> str:

    if not address:
        return "-"

    address = str(address)

    if address.startswith("[") and "]" in address:
        address = address[1:address.find("]")]

    return address


def service_from_port(port, protocol=""):
    """Return a readable network service name."""
    try:
        port = int(port or 0)
    except Exception:
        port = 0

    proto = str(protocol or "").upper()

    services = {
        20: "FTP",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        143: "IMAP",
        161: "SNMP",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        587: "SMTP",
        636: "LDAPS",
        853: "DNS-over-TLS",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        27017: "MongoDB",
    }

    if port in services:
        return services[port]

    if proto == "TCP":
        return "TCP"
    if proto == "UDP":
        return "UDP"
    if proto:
        return proto

    return "Unknown"


def badge_color_for(name: str) -> str:

    palette = [
        "#E8590C",
        "#168CFF",
        "#2F9E44",
        "#9C36B5",
        "#C2255C",
        "#0C8599",
        "#F08C00",
        "#5C7CFA",
    ]

    return palette[
        zlib.crc32(
            name.encode("utf-8")
        ) % len(palette)
    ]


# ============================================================
# HOST RESOLVER
# ============================================================

class HostResolver:

    def __init__(
        self,
        workers: int = 3,
    ):

        self.cache: Dict[str, str] = {}
        self.pending = set()
        self.jobs = queue.Queue()

        for _ in range(workers):

            threading.Thread(
                target=self._worker,
                daemon=True,
            ).start()

    def get(
        self,
        ip: str,
    ) -> str:

        if ip in self.cache:
            return self.cache[ip]

        if ip not in self.pending:

            self.pending.add(ip)

            self.jobs.put(ip)

        return ""

    def _worker(self):

        while True:

            ip = self.jobs.get()

            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = ""

            self.cache[ip] = hostname


HOST_RESOLVER = HostResolver()


def describe_host(
    ip: str,
):

    try:
        address = ipaddress.ip_address(ip)

    except ValueError:

        return (
            ip,
            "◉",
            BLUE,
        )

    if address.is_loopback:

        return (
            f"{ip} - Loopback",
            "◌",
            "#5A6A85",
        )

    if address.is_multicast:

        return (
            f"{ip} - Multicast",
            "⌁",
            "#7B63C9",
        )

    if (
        address.is_private
        or address.is_link_local
    ):

        return (
            f"{ip} - Local network",
            "▣",
            "#4A6A94",
        )

    hostname = HOST_RESOLVER.get(ip)

    if hostname:

        return (
            f"{ip} - {hostname}",
            "◉",
            BLUE,
        )

    return (
        ip,
        "◉",
        BLUE,
    )


# ============================================================
# ADAPTER CARD
# ============================================================

class AdapterInfoCard(QFrame):

    def __init__(
        self,
        parent=None,
    ):

        super().__init__(
            parent
        )

        self.setStyleSheet(
            f"""
            QFrame {{
                background: {CARD};
                border: 1px solid {BORDER};
                border-radius: 12px;
            }}
            """
        )

        layout = QVBoxLayout(
            self
        )

        layout.setContentsMargins(
            16,
            14,
            16,
            14,
        )

        layout.setSpacing(
            5
        )

        header = QHBoxLayout()

        icon = QLabel(
            "◉"
        )

        icon.setFixedSize(
            58,
            58,
        )

        icon.setAlignment(
            Qt.AlignCenter
        )

        icon.setStyleSheet(
            f"""
            QLabel {{
                background: #082E55;
                border: 1px solid {OUTGOING};
                border-radius: 10px;
                color: {OUTGOING};
                font-size: 25px;
            }}
            """
        )

        header.addWidget(
            icon
        )

        title_layout = QVBoxLayout()

        self.name = QLabel(
            "Wi-Fi"
        )

        self.name.setStyleSheet(
            f"""
            color: {TEXT};
            font-size: 19px;
            font-weight: 700;
            """
        )

        self.description = QLabel(
            "Network adapter"
        )

        self.description.setStyleSheet(
            f"""
            color: {TEXT_SECONDARY};
            font-size: 12px;
            """
        )

        title_layout.addWidget(
            self.name
        )

        title_layout.addWidget(
            self.description
        )

        header.addLayout(
            title_layout,
            1,
        )

        self.status = QLabel(
            "● UP"
        )

        self.status.setAlignment(
            Qt.AlignCenter
        )

        self.status.setMinimumWidth(
            65
        )

        self.status.setStyleSheet(
            f"""
            QLabel {{
                background: #063E31;
                border: 1px solid {ACTIVE};
                border-radius: 12px;
                color: {ACTIVE};
                padding: 5px 8px;
                font-weight: 700;
                font-size: 11px;
            }}
            """
        )

        header.addWidget(
            self.status,
            0,
            Qt.AlignTop,
        )

        layout.addLayout(
            header
        )

        self.ipv4 = self._detail(
            "▣",
            "IPv4",
        )

        self.ipv6 = self._detail(
            "◎",
            "IPv6",
        )

        self.mac = self._detail(
            "⌁",
            "MAC",
        )

        self.speed = self._detail(
            "◌",
            "Speed",
        )

        self.mtu = self._detail(
            "⚙",
            "MTU",
        )

        layout.addWidget(
            self.ipv4
        )

        layout.addWidget(
            self.ipv6
        )

        layout.addWidget(
            self.mac
        )

        layout.addWidget(
            self.speed
        )

        layout.addWidget(
            self.mtu
        )

    def _detail(
        self,
        icon: str,
        name: str,
    ):

        widget = QWidget()

        layout = QHBoxLayout(
            widget
        )

        layout.setContentsMargins(
            0,
            2,
            0,
            2,
        )

        icon_label = QLabel(
            icon
        )

        icon_label.setFixedWidth(
            24
        )

        icon_label.setStyleSheet(
            f"color: {TEXT_SECONDARY};"
        )

        name_label = QLabel(
            name
        )

        name_label.setFixedWidth(
            55
        )

        name_label.setStyleSheet(
            f"color: {TEXT_SECONDARY};"
        )

        value = QLabel(
            "-"
        )

        value.setStyleSheet(
            f"color: {TEXT};"
        )

        value.setTextInteractionFlags(
            Qt.TextSelectableByMouse
        )

        layout.addWidget(
            icon_label
        )

        layout.addWidget(
            name_label
        )

        layout.addWidget(
            value,
            1,
        )

        widget.value_label = value

        return widget

    def update_adapter(
        self,
        adapter,
    ):

        if adapter is None:
            return

        self.name.setText(
            adapter.name or "Network"
        )

        self.description.setText(
            adapter.description
            or "Network adapter"
        )

        self.ipv4.value_label.setText(
            adapter.ipv4 or "-"
        )

        self.ipv6.value_label.setText(
            adapter.ipv6 or "-"
        )

        self.mac.value_label.setText(
            adapter.mac or "-"
        )

        if adapter.speed:
            self.speed.value_label.setText(
                f"{adapter.speed} Mbps"
            )
        else:
            self.speed.value_label.setText(
                "-"
            )

        self.mtu.value_label.setText(
            str(adapter.mtu)
            if adapter.mtu
            else "-"
        )

        status = (
            adapter.status
            or "UP"
        )

        self.status.setText(
            f"● {status.upper()}"
        )


# ============================================================
# DONUT
# ============================================================

class TrafficDonut(QWidget):

    def __init__(
        self,
        parent=None,
    ):

        super().__init__(
            parent
        )

        self.incoming = 0
        self.outgoing = 0
        self.dropped = 0

        self.setMinimumHeight(
            150
        )

        self.setMaximumHeight(
            170
        )

    def set_values(
        self,
        incoming,
        outgoing,
        dropped,
    ):

        self.incoming = max(
            0,
            incoming,
        )

        self.outgoing = max(
            0,
            outgoing,
        )

        self.dropped = max(
            0,
            dropped,
        )

        self.update()

    def paintEvent(
        self,
        event,
    ):

        painter = QPainter(
            self
        )

        painter.setRenderHint(
            QPainter.Antialiasing
        )

        rect = self.rect()

        center = QPointF(
            rect.center().x(),
            rect.center().y(),
        )

        radius = min(
            rect.width(),
            rect.height(),
        ) * 0.30

        ring = QRectF(
            center.x() - radius,
            center.y() - radius,
            radius * 2,
            radius * 2,
        )

        total = (
            self.incoming
            + self.outgoing
        )

        pen = QPen(
            QColor("#203A5E")
        )

        pen.setWidth(
            17
        )

        painter.setPen(
            pen
        )

        painter.drawArc(
            ring,
            0,
            360 * 16,
        )

        if total > 0:

            incoming_angle = (
                self.incoming
                / total
                * 360
            )

            pen = QPen(
                QColor(INCOMING)
            )

            pen.setWidth(
                17
            )

            pen.setCapStyle(
                Qt.RoundCap
            )

            painter.setPen(
                pen
            )

            painter.drawArc(
                ring,
                90 * 16,
                -int(
                    incoming_angle
                    * 16
                ),
            )

            pen = QPen(
                QColor(OUTGOING)
            )

            pen.setWidth(
                17
            )

            pen.setCapStyle(
                Qt.RoundCap
            )

            painter.setPen(
                pen
            )

            painter.drawArc(
                ring,
                int(
                    (
                        90
                        - incoming_angle
                    )
                    * 16
                ),
                -int(
                    (
                        360
                        - incoming_angle
                    )
                    * 16
                ),
            )

        total_text = format_bytes(
            self.incoming
            + self.outgoing
        )

        painter.setPen(
            QColor(TEXT)
        )

        font = QFont(
            "Segoe UI",
            15,
            QFont.Bold,
        )

        painter.setFont(
            font
        )

        painter.drawText(
            QRectF(
                center.x() - 100,
                center.y() - 16,
                200,
                28,
            ),
            Qt.AlignCenter,
            total_text,
        )

        painter.setFont(
            QFont(
                "Segoe UI",
                9,
            )
        )

        painter.setPen(
            QColor(TEXT_SECONDARY)
        )

        painter.drawText(
            QRectF(
                center.x() - 100,
                center.y() + 13,
                200,
                20,
            ),
            Qt.AlignCenter,
            "Total traffic",
        )


# ============================================================
# TRAFFIC GRAPH
# ============================================================

class TrafficGraph(QWidget):

    def __init__(
        self,
        parent=None,
    ):

        super().__init__(
            parent
        )

        self.incoming = []
        self.outgoing = []

        self.representation = "Bits"

        self.setMinimumHeight(
            GRAPH_HEIGHT
        )

        self.setMaximumHeight(
            GRAPH_HEIGHT
        )

    def set_data(
        self,
        incoming,
        outgoing,
        representation,
    ):

        self.incoming = list(
            incoming
        )

        self.outgoing = list(
            outgoing
        )

        self.representation = (
            representation
        )

        self.update()

    def _nice_max(
        self,
        value,
    ):

        if value <= 0:
            return 1

        exponent = math.floor(
            math.log10(value)
        )

        fraction = (
            value
            / (10 ** exponent)
        )

        if fraction <= 1:
            nice = 1
        elif fraction <= 2:
            nice = 2
        elif fraction <= 5:
            nice = 5
        else:
            nice = 10

        return nice * (
            10 ** exponent
        )

    def _axis_text(
        self,
        value,
    ):

        if self.representation == "Bits":
            return format_bits(value)

        if self.representation == "Bytes":
            return f"{format_bytes(value)}/s"

        return f"{value:.0f} pkt/s"

    def _path(
        self,
        values,
        rect,
        maximum,
        direction=1,
    ):

        path = QPainterPath()

        if not values:
            return path

        count = len(
            values
        )

        if count == 1:

            ratio = (
                values[0]
                / maximum
                if maximum
                else 0
            )

            baseline = rect.center().y()
            amplitude = rect.height() / 2
            y = baseline - direction * ratio * amplitude

            path.moveTo(
                rect.left(),
                y,
            )

            return path

        for index, value in enumerate(
            values
        ):

            ratio = (
                value
                / maximum
                if maximum
                else 0
            )

            ratio = max(
                0,
                min(
                    1,
                    ratio,
                ),
            )

            x = (
                rect.left()
                + index
                * rect.width()
                / (count - 1)
            )

            baseline = rect.center().y()
            amplitude = rect.height() / 2
            y = baseline - direction * ratio * amplitude

            if index == 0:
                path.moveTo(
                    x,
                    y,
                )
            else:
                path.lineTo(
                    x,
                    y,
                )

        return path

    def paintEvent(
        self,
        event,
    ):

        painter = QPainter(
            self
        )

        painter.setRenderHint(
            QPainter.Antialiasing
        )

        painter.fillRect(
            self.rect(),
            QColor(GRAPH_BG),
        )

        left = 70
        right = 12
        top = 10
        bottom = 28

        graph_rect = QRectF(
            left,
            top,
            max(
                20,
                self.width()
                - left
                - right,
            ),
            max(
                30,
                self.height()
                - top
                - bottom,
            ),
        )

        maximum = 0

        if self.incoming:
            maximum = max(
                maximum,
                max(self.incoming),
            )

        if self.outgoing:
            maximum = max(
                maximum,
                max(self.outgoing),
            )

        maximum = self._nice_max(
            maximum * 1.15
        )

        # Grid
        painter.setPen(
            QPen(
                QColor(GRID),
                1,
            )
        )

        for i in range(5):

            ratio = i / 4

            y = (
                graph_rect.top()
                + ratio
                * graph_rect.height()
            )

            painter.drawLine(
                QPointF(
                    graph_rect.left(),
                    y,
                ),
                QPointF(
                    graph_rect.right(),
                    y,
                ),
            )

        for i in range(11):

            ratio = i / 10

            x = (
                graph_rect.left()
                + ratio
                * graph_rect.width()
            )

            painter.drawLine(
                QPointF(
                    x,
                    graph_rect.top(),
                ),
                QPointF(
                    x,
                    graph_rect.bottom(),
                ),
            )

        # Zero baseline separates incoming and outgoing traffic.
        zero_y = graph_rect.center().y()
        painter.setPen(QPen(QColor(AXIS), 1.2))
        painter.drawLine(
            QPointF(graph_rect.left(), zero_y),
            QPointF(graph_rect.right(), zero_y),
        )

        # Y labels
        painter.setFont(
            QFont(
                "Segoe UI",
                8,
            )
        )

        painter.setPen(
            QColor(TEXT_SECONDARY)
        )

        for i in range(5):

            ratio = i / 4

            value = maximum * (1 - 2 * ratio)

            y = (
                graph_rect.top()
                + ratio
                * graph_rect.height()
            )

            painter.drawText(
                QRectF(
                    0,
                    y - 8,
                    65,
                    16,
                ),
                Qt.AlignRight
                | Qt.AlignVCenter,
                self._axis_text(
                    value
                ),
            )

        # Paths
        incoming_path = (
            self._path(
                self.incoming,
                graph_rect,
                maximum,
                1,
            )
        )

        outgoing_path = (
            self._path(
                self.outgoing,
                graph_rect,
                maximum,
                -1,
            )
        )

        # Incoming
        if not incoming_path.isEmpty():

            painter.setPen(
                QPen(
                    QColor(INCOMING, 45),
                    3,
                )
            )

            painter.drawPath(
                incoming_path
            )

            painter.setPen(
                QPen(
                    QColor(INCOMING),
                    2,
                )
            )

            painter.drawPath(
                incoming_path
            )

        # Outgoing
        if not outgoing_path.isEmpty():

            painter.setPen(
                QPen(
                    QColor(OUTGOING, 45),
                    3,
                )
            )

            painter.drawPath(
                outgoing_path
            )

            painter.setPen(
                QPen(
                    QColor(OUTGOING),
                    2,
                )
            )

            painter.drawPath(
                outgoing_path
            )

        # Current dots
        if self.incoming:

            value = self.incoming[-1]

            ratio = (
                value
                / maximum
                if maximum
                else 0
            )

            x = graph_rect.right()

            y = graph_rect.center().y() - ratio * graph_rect.height() / 2

            painter.setPen(
                Qt.NoPen
            )

            painter.setBrush(
                QColor(INCOMING)
            )

            painter.drawEllipse(
                QPointF(x, y),
                5,
                5,
            )

        if self.outgoing:

            value = self.outgoing[-1]

            ratio = (
                value
                / maximum
                if maximum
                else 0
            )

            x = graph_rect.right()

            y = graph_rect.center().y() + ratio * graph_rect.height() / 2

            painter.setPen(
                Qt.NoPen
            )

            painter.setBrush(
                QColor(OUTGOING)
            )

            painter.drawEllipse(
                QPointF(x, y),
                5,
                5,
            )


# ============================================================
# RATE CARD
# ============================================================

class RateBox(QFrame):

    def __init__(
        self,
        title,
        color,
        arrow,
        parent=None,
    ):

        super().__init__(
            parent
        )

        self.setFixedHeight(
            52
        )

        self.setMinimumWidth(
            165
        )

        self.setStyleSheet(
            f"""
            QFrame {{
                background: {CARD};
                border: 1px solid {BORDER};
                border-radius: 9px;
            }}
            """
        )

        layout = QHBoxLayout(
            self
        )

        layout.setContentsMargins(
            8,
            3,
            8,
            3,
        )

        icon = QLabel(
            arrow
        )

        icon.setStyleSheet(
            f"""
            color: {color};
            font-size: 25px;
            font-weight: bold;
            """
        )

        layout.addWidget(
            icon
        )

        text_layout = QVBoxLayout()

        text_layout.setSpacing(
            0
        )

        self.value = QLabel(
            "0 b/s"
        )

        self.value.setStyleSheet(
            f"""
            color: {color};
            font-size: 16px;
            font-weight: 700;
            """
        )

        label = QLabel(
            title
        )

        label.setStyleSheet(
            f"""
            color: {TEXT_SECONDARY};
            font-size: 10px;
            """
        )

        text_layout.addWidget(
            self.value
        )

        text_layout.addWidget(
            label
        )

        layout.addLayout(
            text_layout
        )

    def set_value(
        self,
        value,
        representation,
    ):

        self.value.setText(
            format_rate(
                value,
                representation,
            )
        )


# ============================================================
# TRAFFIC RATE PANEL
# ============================================================

class TrafficRatePanel(QFrame):

    def __init__(
        self,
        parent=None,
    ):

        super().__init__(
            parent
        )

        self.representation = "Bits"

        self.last_time = None

        self.last_incoming = None
        self.last_outgoing = None

        self.last_incoming_packets = None
        self.last_outgoing_packets = None

        self.incoming_bits = []
        self.outgoing_bits = []

        self.incoming_bytes = []
        self.outgoing_bytes = []

        self.incoming_packets = []
        self.outgoing_packets = []

        self.setFixedHeight(
            RATE_PANEL_HEIGHT
        )

        self.setStyleSheet(
            f"""
            QFrame {{
                background: {PANEL};
                border: 1px solid {BORDER};
                border-radius: 12px;
            }}
            """
        )

        layout = QVBoxLayout(
            self
        )

        layout.setContentsMargins(
            8,
            6,
            8,
            6,
        )

        layout.setSpacing(
            3
        )

        header = QHBoxLayout()

        title = QLabel(
            "Traffic Rate"
        )

        title.setStyleSheet(
            f"""
            color: {TEXT};
            font-size: 14px;
            font-weight: 700;
            """
        )

        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(
            f"color: {OUTGOING}; font-size: 14px; font-weight: 700;"
        )
        header.addStretch()
        header.addWidget(
            title,
            1,
        )

        live = QLabel(
            "● LIVE"
        )

        live.setStyleSheet(
            f"""
            color: {ACTIVE};
            font-size: 12px;
            font-weight: 600;
            """
        )

        header.addWidget(
            live
        )

        self.incoming_box = RateBox(
            "Incoming",
            INCOMING,
            "↓",
        )

        self.outgoing_box = RateBox(
            "Outgoing",
            OUTGOING,
            "↑",
        )

        header.addWidget(
            self.incoming_box
        )

        header.addWidget(
            self.outgoing_box
        )

        layout.addLayout(
            header
        )

        self.graph = TrafficGraph()

        layout.addWidget(
            self.graph
        )

        legend = QHBoxLayout()

        legend.addStretch()

        incoming = QLabel(
            "● Incoming"
        )

        incoming.setStyleSheet(
            f"color: {INCOMING};"
        )

        outgoing = QLabel(
            "● Outgoing"
        )

        outgoing.setStyleSheet(
            f"color: {OUTGOING};"
        )

        legend.addWidget(
            incoming
        )

        legend.addSpacing(
            20
        )

        legend.addWidget(
            outgoing
        )

        legend.addStretch()

        layout.addLayout(
            legend
        )

    def set_representation(
        self,
        representation,
    ):

        self.representation = (
            representation
        )

        self._update_graph()

    def _update_graph(self):

        if self.representation == "Bits":

            incoming = (
                self.incoming_bits
            )

            outgoing = (
                self.outgoing_bits
            )

        elif self.representation == "Bytes":

            incoming = (
                self.incoming_bytes
            )

            outgoing = (
                self.outgoing_bytes
            )

        else:

            incoming = (
                self.incoming_packets
            )

            outgoing = (
                self.outgoing_packets
            )

        self.graph.set_data(
            incoming,
            outgoing,
            self.representation,
        )

        if incoming:

            self.incoming_box.set_value(
                incoming[-1],
                self.representation,
            )

        if outgoing:

            self.outgoing_box.set_value(
                outgoing[-1],
                self.representation,
            )

    def update_live_data(self):

        now = time.monotonic()

        stats = app_state.traffic

        incoming = float(
            stats.incoming_bytes
        )

        outgoing = float(
            stats.outgoing_bytes
        )

        incoming_packets = float(
            stats.incoming_packets
        )

        outgoing_packets = float(
            stats.outgoing_packets
        )

        if self.last_time is None:

            self.last_time = now

            self.last_incoming = incoming
            self.last_outgoing = outgoing

            self.last_incoming_packets = (
                incoming_packets
            )

            self.last_outgoing_packets = (
                outgoing_packets
            )

            return

        elapsed = max(
            0.05,
            now - self.last_time,
        )

        incoming_delta = (
            incoming
            - self.last_incoming
        )

        outgoing_delta = (
            outgoing
            - self.last_outgoing
        )

        incoming_packet_delta = (
            incoming_packets
            - self.last_incoming_packets
        )

        outgoing_packet_delta = (
            outgoing_packets
            - self.last_outgoing_packets
        )

        if incoming_delta < 0:
            incoming_delta = incoming

        if outgoing_delta < 0:
            outgoing_delta = outgoing

        if incoming_packet_delta < 0:
            incoming_packet_delta = (
                incoming_packets
            )

        if outgoing_packet_delta < 0:
            outgoing_packet_delta = (
                outgoing_packets
            )

        incoming_bytes_rate = (
            incoming_delta
            / elapsed
        )

        outgoing_bytes_rate = (
            outgoing_delta
            / elapsed
        )

        incoming_bits_rate = (
            incoming_bytes_rate
            * 8
        )

        outgoing_bits_rate = (
            outgoing_bytes_rate
            * 8
        )

        incoming_packet_rate = (
            incoming_packet_delta
            / elapsed
        )

        outgoing_packet_rate = (
            outgoing_packet_delta
            / elapsed
        )

        self.incoming_bytes.append(
            incoming_bytes_rate
        )

        self.outgoing_bytes.append(
            outgoing_bytes_rate
        )

        self.incoming_bits.append(
            incoming_bits_rate
        )

        self.outgoing_bits.append(
            outgoing_bits_rate
        )

        self.incoming_packets.append(
            incoming_packet_rate
        )

        self.outgoing_packets.append(
            outgoing_packet_rate
        )

        for history in [
            self.incoming_bytes,
            self.outgoing_bytes,
            self.incoming_bits,
            self.outgoing_bits,
            self.incoming_packets,
            self.outgoing_packets,
        ]:

            if len(history) > MAX_GRAPH_POINTS:

                del history[
                    :-MAX_GRAPH_POINTS
                ]

        self.last_time = now

        self.last_incoming = incoming
        self.last_outgoing = outgoing

        self.last_incoming_packets = (
            incoming_packets
        )

        self.last_outgoing_packets = (
            outgoing_packets
        )

        self._update_graph()


# ============================================================
# TRAFFIC ROW
# ============================================================

class TrafficRow(QFrame):

    favorite_changed = Signal(
        str,
        bool,
    )

    def __init__(
        self,
        key,
        title,
        icon,
        color,
        incoming,
        outgoing,
        parent=None,
    ):

        super().__init__(
            parent
        )

        self.key = key

        self.setFixedHeight(
            LIST_ROW_HEIGHT
        )

        self.setStyleSheet(
            f"""
            QFrame {{
                background: transparent;
                border: none;
                border-radius: 7px;
            }}

            QFrame:hover {{
                background: {ROW_BG};
            }}
            """
        )

        layout = QHBoxLayout(
            self
        )

        layout.setContentsMargins(
            5,
            2,
            5,
            2,
        )

        layout.setSpacing(
            7
        )

        # Star
        self.star = QPushButton(
            "☆"
        )

        self.star.setCheckable(
            True
        )

        self.star.setFixedSize(
            27,
            32,
        )

        self.star.setStyleSheet(
            f"""
            QPushButton {{
                background: transparent;
                border: none;
                color: {MUTED};
                font-size: 20px;
            }}

            QPushButton:hover {{
                color: {YELLOW};
            }}

            QPushButton:checked {{
                color: {YELLOW};
            }}
            """
        )

        self.star.toggled.connect(
            lambda checked:
            self.favorite_changed.emit(
                self.key,
                checked,
            )
        )

        layout.addWidget(
            self.star
        )

        # Badge
        badge = QLabel(
            icon
            if icon
            else "•"
        )

        badge.setFixedSize(
            32,
            32,
        )

        badge.setAlignment(
            Qt.AlignCenter
        )

        badge.setStyleSheet(
            f"""
            QLabel {{
                background: {color};
                color: white;
                border-radius: 8px;
                font-size: 14px;
                font-weight: 700;
            }}
            """
        )

        layout.addWidget(
            badge
        )

        # Name
        self.name = QLabel(
            title
        )

        self.name.setToolTip(
            title
        )

        self.name.setSizePolicy(
            QSizePolicy.Ignored,
            QSizePolicy.Preferred,
        )

        self.name.setStyleSheet(
            f"""
            color: {TEXT};
            font-size: 13px;
            font-weight: 600;
            """
        )

        layout.addWidget(
            self.name,
            1,
        )

        # Traffic bar
        self.bar = QWidget()

        self.bar.setMinimumWidth(
            80
        )

        self.bar.setMaximumWidth(
            120
        )

        self.bar.setFixedHeight(
            8
        )

        self.bar.setStyleSheet(
            f"""
            QWidget {{
                background: #19324E;
                border-radius: 4px;
            }}
            """
        )

        self.bar_layout = QHBoxLayout(
            self.bar
        )

        self.bar_layout.setContentsMargins(
            0,
            0,
            0,
            0,
        )

        self.in_bar = QFrame()

        self.in_bar.setStyleSheet(
            f"""
            QFrame {{
                background: {INCOMING};
                border-radius: 4px;
            }}
            """
        )

        self.out_bar = QFrame()

        self.out_bar.setStyleSheet(
            f"""
            QFrame {{
                background: {OUTGOING};
                border-radius: 4px;
            }}
            """
        )

        self.bar_layout.addWidget(
            self.in_bar,
            1
        )

        self.bar_layout.addWidget(
            self.out_bar,
            1
        )

        layout.addWidget(
            self.bar
        )

        # Value
        self.value = QLabel(
            ""
        )

        self.value.setFixedWidth(
            76
        )

        self.value.setAlignment(
            Qt.AlignRight
            | Qt.AlignVCenter
        )

        self.value.setStyleSheet(
            f"""
            color: {TEXT_SECONDARY};
            font-size: 11px;
            """
        )

        layout.addWidget(
            self.value
        )

        self.set_traffic(
            incoming,
            outgoing,
        )

    def set_traffic(
        self,
        incoming,
        outgoing,
    ):

        incoming = max(
            0,
            float(incoming),
        )

        outgoing = max(
            0,
            float(outgoing),
        )

        total = (
            incoming
            + outgoing
        )

        if total <= 0:

            self.in_bar.setMinimumWidth(
                0
            )

            self.out_bar.setMinimumWidth(
                0
            )

            self.value.setText(
                "0 B"
            )

            return

        incoming_ratio = (
            incoming
            / total
        )

        outgoing_ratio = (
            outgoing
            / total
        )

        self.in_bar.setMinimumWidth(
            3
        )

        self.out_bar.setMinimumWidth(
            3
        )

        self.bar_layout.setStretch(
            0,
            max(1, int(incoming_ratio * 1000))
        )

        self.bar_layout.setStretch(
            1,
            max(1, int(outgoing_ratio * 1000))
        )

        self.value.setText(
            format_bytes(
                total
            )
        )


# ============================================================
# TRAFFIC LIST PANEL
# ============================================================

class TrafficListPanel(QFrame):

    def __init__(
        self,
        title,
        icon,
        parent=None,
    ):

        super().__init__(
            parent
        )

        self.title = title
        self.icon = icon

        self.favorites = set()

        self.setMinimumHeight(
            LIST_PANEL_HEIGHT
        )

        self.setStyleSheet(
            f"""
            QFrame {{
                background: {PANEL};
                border: 1px solid {BORDER};
                border-radius: 12px;
            }}
            """
        )

        layout = QVBoxLayout(
            self
        )

        layout.setContentsMargins(
            12,
            10,
            12,
            10,
        )

        layout.setSpacing(
            5
        )

        # Header
        header = QHBoxLayout()

        title_label = QLabel(
            f"{icon}  {title}"
        )

        title_label.setStyleSheet(
            f"""
            color: {YELLOW};
            font-size: 14px;
            font-weight: 700;
            """
        )

        header.addWidget(
            title_label
        )

        header.addStretch()

        top = QLabel(
            "Live"
        )

        top.setStyleSheet(
            f"""
            color: {MUTED};
            font-size: 11px;
            """
        )

        header.addWidget(
            top
        )

        layout.addLayout(
            header
        )

        line = QFrame()

        line.setFrameShape(
            QFrame.HLine
        )

        line.setStyleSheet(
            f"""
            color: {BORDER};
            """
        )

        layout.addWidget(
            line
        )

        # Rows
        self.rows_layout = QVBoxLayout()

        self.rows_layout.setSpacing(
            2
        )

        layout.addLayout(
            self.rows_layout
        )

        layout.addStretch()

    def set_entries(
        self,
        entries,
    ):

        while self.rows_layout.count():

            item = self.rows_layout.takeAt(
                0
            )

            widget = item.widget()

            if widget:
                widget.deleteLater()

        if not entries:

            empty = QLabel(
                "Waiting for network traffic..."
            )

            empty.setAlignment(
                Qt.AlignCenter
            )

            empty.setStyleSheet(
                f"""
                color: {MUTED};
                font-size: 12px;
                padding: 30px;
                """
            )

            self.rows_layout.addWidget(
                empty
            )

            return

        entries = sorted(
            entries,
            key=lambda entry:
            (
                entry["incoming"]
                + entry["outgoing"]
            ),
            reverse=True,
        )

        entries = entries[
            :MAX_LIST_ROWS
        ]

        maximum = max(
            (
                entry["incoming"]
                + entry["outgoing"]
            )
            for entry in entries
        )

        if maximum <= 0:
            maximum = 1

        for entry in entries:

            row = TrafficRow(
                entry["key"],
                entry["title"],
                entry.get(
                    "icon",
                    "•",
                ),
                entry.get(
                    "color",
                    BLUE,
                ),
                entry["incoming"],
                entry["outgoing"],
            )

            row.favorite_changed.connect(
                self._favorite_changed
            )

            row.star.setChecked(
                entry["key"]
                in self.favorites
            )

            self.rows_layout.addWidget(
                row
            )

    def _favorite_changed(
        self,
        key,
        checked,
    ):

        if checked:
            self.favorites.add(
                key
            )
        else:
            self.favorites.discard(
                key
            )


# ============================================================
# OVERVIEW PAGE
# ============================================================

class OverviewPage(QWidget):

    def __init__(
        self,
        parent=None,
    ):

        super().__init__(
            parent
        )

        self.representation = "Bits"

        self.setObjectName(
            "overviewPage"
        )

        self.setStyleSheet(
            f"""
            QWidget#overviewPage {{
                background: {BG};
                color: {TEXT};
            }}
            QScrollArea, QScrollArea > QWidget > QWidget {{
                background: {BG};
                border: none;
            }}
            QLabel {{
                background: transparent;
                color: {TEXT};
            }}
            QComboBox, QPushButton {{
                background: {CARD};
                color: {TEXT};
                border: 1px solid {BORDER};
                border-radius: 5px;
                padding: 4px 7px;
            }}
            QComboBox QAbstractItemView {{
                background: {PANEL};
                color: {TEXT};
                selection-background-color: {BLUE_DARK};
            }}
            """
        )

        self._build_ui()

        self.timer = QTimer(
            self
        )

        self.timer.setInterval(
            500
        )

        self.timer.timeout.connect(
            self.refresh
        )

        self.timer.start()

        QTimer.singleShot(
            100,
            self.refresh,
        )

    # ========================================================
    # UI
    # ========================================================

    def _build_ui(self):

        outer = QVBoxLayout(
            self
        )

        outer.setContentsMargins(
            0,
            0,
            0,
            0,
        )

        outer.setSpacing(
            0
        )

        scroll = QScrollArea()

        scroll.setWidgetResizable(
            True
        )

        scroll.setFrameShape(
            QFrame.NoFrame
        )

        scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarAlwaysOff
        )

        content = QWidget()

        content.setStyleSheet(
            f"""
            QWidget {{
                background: {BG};
            }}
            """
        )

        scroll.setWidget(
            content
        )

        outer.addWidget(
            scroll
        )

        main = QHBoxLayout(
            content
        )

        main.setContentsMargins(
            12,
            12,
            12,
            12,
        )

        main.setSpacing(
            12
        )

        # ====================================================
        # LEFT COLUMN
        # Screenshot target:
        # Network adapter panel spans the full left side.
        # ====================================================

        self.info_panel = (
            OverviewInfoPanel()
        )

        self.info_panel.setMinimumWidth(220)
        self.info_panel.setMaximumWidth(260)
        self.info_panel.setFixedWidth(248)

        # Keep the adapter/summary card compact at the top. The right
        # column uses the remaining width for the graph and traffic lists.
        self.info_panel.setFixedHeight(
            RATE_PANEL_HEIGHT
        )

        main.addWidget(
            self.info_panel,
            0,
            Qt.AlignTop,
        )

        # ====================================================
        # RIGHT COLUMN
        # Traffic Rate on top
        # Host / Services / Programs below
        # ====================================================

        right = QVBoxLayout()

        right.setSpacing(
            12
        )

        self.rate_panel = (
            TrafficRatePanel()
        )

        self.rate_panel.setFixedHeight(
            RATE_PANEL_HEIGHT
        )

        right.addWidget(
            self.rate_panel,
            0
        )

        bottom = QHBoxLayout()

        bottom.setSpacing(
            12
        )

        self.host_panel = (
            TrafficListPanel(
                "Network Host",
                "◎",
            )
        )

        self.service_panel = (
            TrafficListPanel(
                "Services",
                "▤",
            )
        )

        self.program_panel = (
            TrafficListPanel(
                "Programs",
                "▣",
            )
        )

        self.host_panel.setMinimumHeight(
            LIST_PANEL_HEIGHT
        )

        self.service_panel.setMinimumHeight(
            LIST_PANEL_HEIGHT
        )

        self.program_panel.setMinimumHeight(
            LIST_PANEL_HEIGHT
        )

        # 50% / 25% / 25%
        bottom.addWidget(
            self.host_panel,
            2
        )

        bottom.addWidget(
            self.service_panel,
            1
        )

        bottom.addWidget(
            self.program_panel,
            1
        )

        right.addLayout(
            bottom,
            0
        )

        main.addLayout(
            right,
            1
        )

        # Representation callback
        self.info_panel.set_representation_callback(
            self._representation_changed
        )

    # ========================================================
    # REPRESENTATION
    # ========================================================

    def _representation_changed(
        self,
        representation,
    ):

        self.representation = (
            representation
        )

        self.rate_panel.set_representation(
            representation
        )

        self.refresh()

    # ========================================================
    # LOCAL ADDRESSES
    # ========================================================

    @staticmethod
    def _local_addresses(
        adapter,
    ):

        addresses = set()

        if adapter is None:
            return addresses

        for address in [
            getattr(
                adapter,
                "ipv4",
                "",
            ),
            getattr(
                adapter,
                "ipv6",
                "",
            ),
        ]:

            if address:

                addresses.add(
                    str(
                        address
                    ).split("%")[0]
                )

        return addresses

    # ========================================================
    # PACKET DIRECTION
    # ========================================================

    @staticmethod
    def _packet_direction(
        packet,
        source,
        destination,
        local,
    ):

        direction = str(
            getattr(
                packet,
                "direction",
                "",
            )
        ).lower()

        if direction.startswith(
            "in"
        ):
            return "in"

        if direction.startswith(
            "out"
        ):
            return "out"

        if source in local:
            return "out"

        if destination in local:
            return "in"

        return "in"

    # ========================================================
    # CONNECTION / PROCESS CORRELATION
    # ========================================================

    @staticmethod
    def _connection_key(address):
        """Normalize a psutil address into (ip, port)."""
        try:
            ip = str(address.ip)
            port = int(address.port)
            return ip.split("%")[0], port
        except Exception:
            return "", 0

    def _build_process_map(self):
        """
        Build local-port -> executable mapping using Windows
        network connections.

        This keeps the UI unchanged but allows the Programs
        panel to show real process names when Windows exposes
        the PID for a connection.
        """
        mapping = {}

        try:
            connections = psutil.net_connections(
                kind="inet"
            )
        except Exception:
            return mapping

        for conn in connections:
            try:
                if not conn.pid or not conn.laddr:
                    continue

                local_ip, local_port = (
                    self._connection_key(conn.laddr)
                )

                if not local_port:
                    continue

                try:
                    process = psutil.Process(conn.pid)
                    name = process.name()
                except Exception:
                    name = f"PID {conn.pid}"

                if not name:
                    name = f"PID {conn.pid}"

                mapping[local_port] = name
                mapping[(local_ip, local_port)] = name

            except Exception:
                continue

        return mapping

    @staticmethod
    def _packet_service(packet):
        service = (
            getattr(packet, "service", None)
            or getattr(packet, "destination_service", None)
            or getattr(packet, "source_service", None)
        )

        if service:
            return str(service)

        protocol = str(
            getattr(packet, "protocol", "")
            or ""
        ).upper()

        destination_port = getattr(
            packet,
            "destination_port",
            0,
        )

        source_port = getattr(
            packet,
            "source_port",
            0,
        )

        # Prefer the remote/destination port because it normally
        # identifies the service being contacted.
        try:
            port = int(destination_port or 0)
        except Exception:
            port = 0

        if not port:
            try:
                port = int(source_port or 0)
            except Exception:
                port = 0

        return service_from_port(
            port,
            protocol,
        )

    # ========================================================
    # NETWORK HOST

    def _get_hosts(self):

        packets = (
            app_state.get_packets()
        )

        adapter = (
            app_state.get_selected_adapter()
        )

        local = (
            self._local_addresses(
                adapter
            )
        )

        hosts = defaultdict(
            lambda: [0, 0]
        )

        for packet in packets:

            try:
                size = int(
                    getattr(
                        packet,
                        "bytes",
                        0,
                    )
                )
            except Exception:
                size = 0

            source = clean_address(
                getattr(
                    packet,
                    "source",
                    "",
                )
            )

            destination = clean_address(
                getattr(
                    packet,
                    "destination",
                    "",
                )
            )

            direction = (
                self._packet_direction(
                    packet,
                    source,
                    destination,
                    local,
                )
            )

            if direction == "in":

                remote = source
                slot = 0

            else:

                remote = destination
                slot = 1

            if (
                remote
                and remote != "-"
            ):

                hosts[
                    remote
                ][slot] += size

        entries = []

        for ip, values in hosts.items():

            title, glyph, color = (
                describe_host(
                    ip
                )
            )

            entries.append(
                {
                    "key": ip,
                    "title": title,
                    "icon": glyph,
                    "color": color,
                    "incoming": values[0],
                    "outgoing": values[1],
                }
            )

        return entries

    # ========================================================
    # SERVICES
    # ========================================================

    def _get_services(self):

        packets = app_state.get_packets()

        services = defaultdict(
            lambda: [0, 0]
        )

        adapter = app_state.get_selected_adapter()
        local = self._local_addresses(adapter)

        for packet in packets:

            try:
                size = int(
                    getattr(
                        packet,
                        "bytes",
                        0,
                    )
                )
            except Exception:
                size = 0

            source = clean_address(
                getattr(
                    packet,
                    "source",
                    "",
                )
            )

            destination = clean_address(
                getattr(
                    packet,
                    "destination",
                    "",
                )
            )

            direction = self._packet_direction(
                packet,
                source,
                destination,
                local,
            )

            service = self._packet_service(
                packet
            )

            slot = (
                0
                if direction == "in"
                else 1
            )

            services[service][slot] += size

        entries = []

        for name, values in services.items():

            entries.append(
                {
                    "key": name,
                    "title": name,
                    "icon": name[:1].upper()
                    if name else "?",
                    "color": badge_color_for(
                        name
                    ),
                    "incoming": values[0],
                    "outgoing": values[1],
                }
            )

        return entries

    # ========================================================
    # PROGRAMS
    # ========================================================
    # PROGRAMS
    # ========================================================

    def _get_programs(self):

        packets = app_state.get_packets()

        programs = defaultdict(
            lambda: [0, 0]
        )

        adapter = app_state.get_selected_adapter()
        local = self._local_addresses(adapter)

        process_map = self._build_process_map()

        for packet in packets:

            try:
                size = int(
                    getattr(
                        packet,
                        "bytes",
                        0,
                    )
                )
            except Exception:
                size = 0

            source = clean_address(
                getattr(
                    packet,
                    "source",
                    "",
                )
            )

            destination = clean_address(
                getattr(
                    packet,
                    "destination",
                    "",
                )
            )

            direction = self._packet_direction(
                packet,
                source,
                destination,
                local,
            )

            program = (
                getattr(
                    packet,
                    "process_name",
                    None,
                )
                or getattr(
                    packet,
                    "program",
                    None,
                )
                or getattr(
                    packet,
                    "process",
                    None,
                )
            )

            # If PacketRecord does not yet carry process metadata,
            # correlate the packet's local port with Windows
            # connections.
            if not program:

                source_port = getattr(
                    packet,
                    "source_port",
                    0,
                )

                destination_port = getattr(
                    packet,
                    "destination_port",
                    0,
                )

                try:
                    source_port = int(
                        source_port or 0
                    )
                except Exception:
                    source_port = 0

                try:
                    destination_port = int(
                        destination_port or 0
                    )
                except Exception:
                    destination_port = 0

                if direction == "out":
                    program = (
                        process_map.get(
                            (source, source_port)
                        )
                        or process_map.get(
                            source_port
                        )
                    )
                else:
                    program = (
                        process_map.get(
                            (destination, destination_port)
                        )
                        or process_map.get(
                            destination_port
                        )
                    )

            if not program:
                program = "System / Unknown"

            slot = (
                0
                if direction == "in"
                else 1
            )

            programs[str(program)][slot] += size

        entries = []

        for name, values in programs.items():

            entries.append(
                {
                    "key": name,
                    "title": name,
                    "icon": (
                        name[:1].upper()
                        if name
                        else "?"
                    ),
                    "color": badge_color_for(
                        name
                    ),
                    "incoming": values[0],
                    "outgoing": values[1],
                }
            )

        return entries

    # ========================================================
    # UPDATE BOTTOM PANELS
    # ========================================================
    # UPDATE BOTTOM PANELS
    # ========================================================

    def _update_bottom_panels(self):

        self.host_panel.set_entries(
            self._get_hosts()
        )

        self.service_panel.set_entries(
            self._get_services()
        )

        self.program_panel.set_entries(
            self._get_programs()
        )

    # ========================================================
    # REFRESH
    # ========================================================

    def refresh(self):

        adapter = (
            app_state.get_selected_adapter()
        )

        self.info_panel.update_adapter(
            adapter
        )

        stats = (
            app_state.traffic
        )

        self.info_panel.update_stats(
            stats.incoming_bytes,
            stats.outgoing_bytes,
            stats.dropped_packets,
        )

        self.rate_panel.update_live_data()

        self._update_bottom_panels()


# ============================================================
# INFO PANEL
# ============================================================

class OverviewInfoPanel(QFrame):

    def __init__(
        self,
        parent=None,
    ):

        super().__init__(
            parent
        )

        self.setStyleSheet(
            f"""
            QFrame {{
                background: {PANEL};
                border: 1px solid {BORDER};
                border-radius: 12px;
            }}
            """
        )

        layout = QVBoxLayout(
            self
        )

        layout.setContentsMargins(
            14,
            12,
            14,
            12,
        )

        layout.setSpacing(
            7
        )

        title = QLabel(
            "Network adapter"
        )

        title.setStyleSheet(
            f"""
            color: {TEXT};
            font-size: 18px;
            font-weight: 700;
            """
        )

        layout.addWidget(
            title
        )

        self.adapter_card = (
            AdapterInfoCard()
        )

        layout.addWidget(
            self.adapter_card
        )

        filter_title = QLabel(
            "Active filters"
        )

        filter_title.setStyleSheet(
            f"""
            color: {TEXT};
            font-size: 16px;
            font-weight: 700;
            """
        )

        layout.addWidget(
            filter_title
        )

        filter_layout = QHBoxLayout()

        icon = QLabel(
            "▼"
        )

        icon.setFixedSize(
            48,
            38,
        )

        icon.setAlignment(
            Qt.AlignCenter
        )

        icon.setStyleSheet(
            f"""
            background: {CARD};
            border: 1px solid {BORDER};
            border-radius: 8px;
            color: {OUTGOING};
            """
        )

        self.filter_combo = QComboBox()

        self.filter_combo.addItems(
            [
                "All traffic",
                "Incoming",
                "Outgoing",
                "TCP",
                "UDP",
            ]
        )

        self.filter_combo.setFixedHeight(
            38
        )

        self.filter_combo.setStyleSheet(
            f"""
            QComboBox {{
                background: {CARD};
                border: 1px solid {BORDER};
                border-radius: 8px;
                color: {TEXT};
                padding-left: 10px;
            }}
            """
        )

        filter_layout.addWidget(
            icon
        )

        filter_layout.addWidget(
            self.filter_combo,
            1,
        )

        layout.addLayout(
            filter_layout
        )

        representation_title = QLabel(
            "Data representation"
        )

        representation_title.setStyleSheet(
            f"""
            color: {TEXT};
            font-size: 16px;
            font-weight: 700;
            """
        )

        layout.addWidget(
            representation_title
        )

        representation_layout = QHBoxLayout()

        self.bits = QPushButton(
            "Bits"
        )

        self.bytes = QPushButton(
            "Bytes"
        )

        self.packets = QPushButton(
            "Packets"
        )

        self.buttons = [
            self.bits,
            self.bytes,
            self.packets,
        ]

        for button in self.buttons:

            button.setCheckable(
                True
            )

            button.setFixedHeight(
                36
            )

            button.setStyleSheet(
                f"""
                QPushButton {{
                    background: {CARD};
                    border: 1px solid {BORDER};
                    border-radius: 7px;
                    color: {TEXT_SECONDARY};
                }}

                QPushButton:checked {{
                    background: {BLUE_DARK};
                    border: 1px solid {OUTGOING};
                    color: {WHITE};
                }}
                """
            )

            representation_layout.addWidget(
                button
            )

        self.bits.setChecked(
            True
        )

        self.bits.clicked.connect(
            lambda:
            self._representation(
                "Bits"
            )
        )

        self.bytes.clicked.connect(
            lambda:
            self._representation(
                "Bytes"
            )
        )

        self.packets.clicked.connect(
            lambda:
            self._representation(
                "Packets"
            )
        )

        layout.addLayout(
            representation_layout
        )

        self.donut = TrafficDonut()

        layout.addWidget(
            self.donut
        )

        self.incoming = self._legend(
            INCOMING,
            "Incoming",
        )

        self.outgoing = self._legend(
            OUTGOING,
            "Outgoing",
        )

        self.dropped = self._legend(
            DROPPED,
            "Dropped",
        )

        layout.addWidget(
            self.incoming
        )

        layout.addWidget(
            self.outgoing
        )

        layout.addWidget(
            self.dropped
        )

        self.callback = None

    def _legend(
        self,
        color,
        title,
    ):

        widget = QWidget()

        layout = QHBoxLayout(
            widget
        )

        layout.setContentsMargins(
            2,
            0,
            2,
            0,
        )

        dot = QLabel(
            "●"
        )

        dot.setStyleSheet(
            f"color: {color};"
        )

        name = QLabel(
            title
        )

        name.setStyleSheet(
            f"color: {TEXT_SECONDARY};"
        )

        value = QLabel(
            "0"
        )

        value.setStyleSheet(
            f"color: {TEXT};"
        )

        value.setAlignment(
            Qt.AlignRight
        )

        layout.addWidget(
            dot
        )

        layout.addWidget(
            name
        )

        layout.addStretch()

        layout.addWidget(
            value
        )

        widget.value_label = value

        return widget

    def set_representation_callback(
        self,
        callback,
    ):

        self.callback = callback

    def _representation(
        self,
        representation,
    ):

        for button in self.buttons:

            button.setChecked(
                button.text()
                == representation
            )

        if self.callback:

            self.callback(
                representation
            )

    def update_adapter(
        self,
        adapter,
    ):

        self.adapter_card.update_adapter(
            adapter
        )

    def update_stats(
        self,
        incoming,
        outgoing,
        dropped,
    ):

        self.donut.set_values(
            incoming,
            outgoing,
            dropped,
        )

        self.incoming.value_label.setText(
            format_bytes(
                incoming
            )
        )

        self.outgoing.value_label.setText(
            format_bytes(
                outgoing
            )
        )

        self.dropped.value_label.setText(
            format_packet_count(
                dropped
            )
        )


# ============================================================
# DEMO
# ============================================================

def create_demo_data():

    from gui.app_state import (
        NetworkAdapter,
    )

    adapter = NetworkAdapter(
        name="Wi-Fi",
        ipv4="192.168.1.5",
        ipv6="fe80::d4f2:9c8a:5b2e:7c11",
        mac="CC-6B-1E-59-15-A3",
        status="UP",
        speed=866,
        mtu=1500,
        description=(
            "Realtek 8821CE Wireless LAN"
        ),
        npcap_name="",
    )

    app_state.set_adapters(
        [adapter]
    )

    app_state.select_adapter(
        adapter
    )


class DemoTraffic:

    def __init__(self):

        self.timer = QTimer()

        self.timer.timeout.connect(
            self.tick
        )

        self.timer.start(
            500
        )

    def tick(self):

        import random

        hosts = [
            "142.250.72.14",
            "142.250.191.78",
            "8.8.8.8",
            "1.1.1.1",
            "20.205.243.166",
            "13.107.42.14",
        ]

        host = random.choice(
            hosts
        )

        incoming = random.randint(
            5000,
            400000,
        )

        outgoing = random.randint(
            3000,
            250000,
        )

        app_state.add_packet(
            host,
            443,
            "192.168.1.5",
            random.randint(
                40000,
                60000,
            ),
            "TCP",
            "https",
            "incoming",
            incoming,
        )

        app_state.add_packet(
            "192.168.1.5",
            random.randint(
                40000,
                60000,
            ),
            host,
            443,
            "TCP",
            "https",
            "outgoing",
            outgoing,
        )


# ============================================================
# MAIN TEST
# ============================================================

def main():

    app = QApplication([])

    create_demo_data()

    window = QWidget()

    window.setWindowTitle(
        "Network Traffic Analyzer - Overview"
    )

    window.resize(
        1900,
        900,
    )

    window.setStyleSheet(
        f"""
        QWidget {{
            background: {BG};
        }}
        """
    )

    layout = QVBoxLayout(
        window
    )

    layout.setContentsMargins(
        0,
        0,
        0,
        0,
    )

    overview = OverviewPage()

    layout.addWidget(
        overview
    )

    demo = DemoTraffic()

    window.demo = demo

    window.show()

    app.exec()


if __name__ == "__main__":
    main()