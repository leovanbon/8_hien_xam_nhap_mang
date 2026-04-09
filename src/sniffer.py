from scapy.all import sniff, IP, TCP, UDP, ICMP
import datetime

class NIDSSniffer:
    def __init__(self, interface=None, callback_function=None):
        self.interface = interface
        self.packet_handler = callback_function

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
        try:
            sniff(iface=self.interface, prn=self._process_packet, store=0)
        except PermissionError:
            print("[!] Error: Sniffing requires Root/Admin privileges.")
        except Exception as e:
            print(f"[!] Sniffer Error: {e}")


if __name__ == "__main__":
    sniffer = NIDSSniffer()
    sniffer.start()