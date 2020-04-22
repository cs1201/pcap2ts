from scapy.all import *
import sys
print("Opening .pcap file")
packet_data = rdpcap("capture2.pcap", count=10000)

print(f"Packets found: {len(packet_data)}")

ts_file = open("test.ts", "wb+")
print(packet_data[0].summary())

# ts_packets = []
for packet in packet_data:
    ts_packet = bytes(packet[UDP].payload)
    ts_file.write(ts_packet)