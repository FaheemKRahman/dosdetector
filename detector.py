from scapy.all import sniff, IP

def packet_handler(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dest_ip = packet[IP].dst
        protocol = packet[IP].proto

        print(f"Packet: {src_ip} -> {dest_ip} | Protocol: {protocol}")

print("[*] Starting packet capture...press CTRL+C to abort.")

sniff(prn=packet_handler, store = False)