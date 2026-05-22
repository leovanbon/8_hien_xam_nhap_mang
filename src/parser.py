from scapy.all import ICMP, IP, Raw, TCP, UDP


class PacketParser:
    def __init__(self):
        pass

    def parse(self, packet):
        if not packet.haslayer(IP):
            return None

        parsed_data = {
            "timestamp": float(packet.time),
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "protocol": self._get_protocol_name(packet[IP].proto),
            "length": len(packet),
            "payload": "",
            "src_port": None,
            "dst_port": None,
            "tcp_flags": None
        }

        if packet.haslayer(TCP):
            parsed_data["src_port"] = packet[TCP].sport
            parsed_data["dst_port"] = packet[TCP].dport
            parsed_data["tcp_flags"] = self._parse_tcp_flags(packet[TCP].flags)

        elif packet.haslayer(UDP):
            parsed_data["src_port"] = packet[UDP].sport
            parsed_data["dst_port"] = packet[UDP].dport

        elif packet.haslayer(ICMP):
            parsed_data["protocol"] = "ICMP"

        if packet.haslayer(Raw):
            raw_payload = packet[Raw].load
            parsed_data["payload"] = raw_payload.decode("utf-8", errors="ignore")

        return parsed_data

    def _get_protocol_name(self, proto_num):
        mapping = {6: "TCP", 17: "UDP", 1: "ICMP"}
        return mapping.get(proto_num, str(proto_num))

    def _parse_tcp_flags(self, flags):
        flag_names = {
            'F': 'FIN',
            'S': 'SYN',
            'R': 'RST',
            'P': 'PSH',
            'A': 'ACK',
            'U': 'URG',
            'E': 'ECE',
            'C': 'CWR'
        }
        return "-".join([flag_names.get(f, f) for f in str(flags)])
