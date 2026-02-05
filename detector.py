from scapy.all import sniff, IP
from collections import defaultdict
import time

#Dictionary to store packet counts per IP address
packet_counts = defaultdict(int)

#Prints information every 5 seconds
REPEAT_INTERVAL = 5
last_report_time = time.time()



def packet_handler(packet):
    global last_report_time
    
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        packet_counts[src_ip] += 1

    current_time = time.time()


    #prints stats every (REPEAT_INTERVAL) SECONDS
    if current_time - last_report_time >= REPEAT_INTERVAL:
        print("\n--- Traffic stats (last {} seconds) ---",format(REPEAT_INTERVAL))

        for ip, count in packet_counts.items():
            print(f"{ip}: {count} packets")

        print("------------------------------------")

        #Clear for the next interval
        packet_counts.clear()
        last_report_time = current_time

print("Starting traffic monitoring, press CTRL + C to abort")
sniff(prn=packet_handler, store=False)