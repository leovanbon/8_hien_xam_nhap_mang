from src.sniffer import NIDSSniffer

def our_detector_logic(packet):
    src_ip = packet['IP'].src
    print(f"Analyzing packet from: {src_ip}")

if __name__ == "__main__":
    nids = NIDSSniffer(interface=None, callback_function=our_detector_logic)
    nids.start()