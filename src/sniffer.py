from scapy.all import IP, sniff
import datetime


class NIDSSniffer:
    def __init__(
        self,
        interface=None,
        callback_function=None,
        bpf_filter="ip",
        packet_count=0,
    ):
        self.interface = interface
        self.packet_handler = callback_function
        self.bpf_filter = bpf_filter
        self.packet_count = packet_count

    def _process_packet(self, packet):
        if packet.haslayer(IP):
            if self.packet_handler:
                self.packet_handler(packet)
            else:
                self._default_print(packet)

    def _default_print(self, packet):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip_layer = packet.getlayer(IP)
        print(f"[{timestamp}] {ip_layer.src} -> {ip_layer.dst} | Protocol: {ip_layer.proto}")

    def start(self):
        print(f"[*] Starting sniffer on {self.interface if self.interface else 'all interfaces'}...")
        print(f"[*] BPF filter: {self.bpf_filter or 'none'}")
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._process_packet,
                store=0,
                count=self.packet_count,
            )
        except KeyboardInterrupt:
            print("\n[*] Sniffer stopped.")
        except PermissionError:
            print("[!] Error: Sniffing requires Root/Admin privileges.")
        except Exception as e:
            print(f"[!] Sniffer Error: {e}")


if __name__ == "__main__":
    sniffer = NIDSSniffer()
    sniffer.start()
