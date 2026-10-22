
from backend.network.adapter_info import get_network_adapters

if __name__ == "__main__":
    for adapter in get_network_adapters():
        print(adapter)
