from scapy.all import *

packet = rdpcap("packets.pcap")
all_raw_data = bytearray()
for pkt in packet:
    if Raw in pkt and TCP in pkt and pkt[TCP].dport == 9000 :
        all_raw_data.extend(pkt[Raw].load)
h = bytearray()
for b in all_raw_data:
    h.append((b-42) % 256)
f = open("flag","wb")
f.write(h)
