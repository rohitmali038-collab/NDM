
from backend.network.adapter_info import get_network_adapters

for adapter in get_network_adapters():
    print(adapter)
