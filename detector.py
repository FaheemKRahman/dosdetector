from scapy.all import sniff, IP
from collections import defaultdict
import time

#Dictionary to store packet counts per IP address
packet_counts = defaultdict(int)

#For detection

WINDOW = 1 # second
THRESHOLD = 50# packets per window

window_start = time.time()

#Prints information every 5 seconds
#REPEAT_INTERVAL = 5
#last_report_time = time.time()



def packet_handler(packet):
    global window_start
    
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        packet_counts[src_ip] += 1

    current_time = time.time()


    #prints stats every (REPEAT_INTERVAL) SECONDS
    if current_time - window_start >= WINDOW:
        for ip, count in packet_counts.items():
            if count > THRESHOLD:
                print(f"[ALERT] Possible DOS detected from {ip} ({count} packets/sec)")

        #Reset counting 
        packet_counts.clear()
        window_start = current_time

print("Starting traffic monitoring, press CTRL + C to abort")
sniff(prn=packet_handler, store=False)