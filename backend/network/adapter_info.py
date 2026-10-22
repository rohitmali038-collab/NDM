
import psutil
import socket


def get_network_adapters():
    """Return available network adapters and their IP information."""

    adapters = psutil.net_if_addrs()
    adapter_stats = psutil.net_if_stats()

    results = []

    for adapter_name, addresses in adapters.items():
        stats = adapter_stats.get(adapter_name)

        ipv4 = "N/A"
        ipv6 = "N/A"
        mac = "N/A"

        for address in addresses:
            if address.family == socket.AF_INET:
                ipv4 = address.address

            elif address.family == socket.AF_INET6:
                ipv6 = address.address.split("%")[0]

            elif getattr(psutil, "AF_LINK", None) == address.family:
                mac = address.address

        results.append({
            "name": adapter_name,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "mac": mac,
            "is_up": stats.isup if stats else False,
            "speed": stats.speed if stats else 0,
        })

    return results
