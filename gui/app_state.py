

from dataclasses import dataclass
from collections import deque


@dataclass
class NetworkAdapter:
    name: str = "Unknown"
    ipv4: str = ""
    ipv6: str = ""
    mac: str = ""
    status: str = "Unknown"
    speed: int = 0
    mtu: int = 1500
    description: str = ""
    npcap_name: str = ""


@dataclass
class Packet:
    source: str = ""
    source_port: int = 0
    destination: str = ""
    destination_port: int = 0
    protocol: str = "Unknown"
    service: str = ""
    direction: str = ""
    bytes: int = 0
    status: str = "Captured"
    process_name: str = ""
    program: str = ""
    process: str = ""


class TrafficStats:
    def __init__(self):
        self.incoming_bytes = 0
        self.outgoing_bytes = 0
        self.incoming_packets = 0
        self.outgoing_packets = 0
        self.dropped_packets = 0


class AppState:
    def __init__(self):
        self.traffic = TrafficStats()
        self.adapters = []
        self.selected_adapter = None
        self.packets = deque(maxlen=5000)

    def get_packets(self):
        return list(self.packets)

    def get_selected_adapter(self):
        return self.selected_adapter

    def set_adapters(self, adapters):
        self.adapters = list(adapters or [])
        if self.selected_adapter not in self.adapters:
            self.selected_adapter = (
                self.adapters[0] if self.adapters else None
            )

    def select_adapter(self, adapter):
        self.selected_adapter = adapter

    def add_packet(
        self,
        source,
        source_port,
        destination,
        destination_port,
        protocol,
        service,
        direction,
        size,
    ):
        size = int(size or 0)
        direction = str(direction or "").lower()

        packet = Packet(
            source=str(source or ""),
            source_port=int(source_port or 0),
            destination=str(destination or ""),
            destination_port=int(destination_port or 0),
            protocol=str(protocol or "Unknown"),
            service=str(service or ""),
            direction=direction,
            bytes=size,
            status="Captured",
        )

        self.packets.appendleft(packet)

        if direction == "incoming":
            self.traffic.incoming_bytes += size
            self.traffic.incoming_packets += 1
        elif direction == "outgoing":
            self.traffic.outgoing_bytes += size
            self.traffic.outgoing_packets += 1


app_state = AppState()
