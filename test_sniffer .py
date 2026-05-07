from scapy.all import sniff, IP, wrpcap
import os

# Create captures folder
os.makedirs("captures", exist_ok=True)

packets = []
def capture(pkt):
    packets.append(pkt)
    print(f"Captured {len(packets)} packets...")

print("Capturing 10 packets...")
sniff(prn=capture, count=10)

# Save to file
filename = "captures/test_capture.pcap"
wrpcap(filename, packets)
print(f"\n✅ Saved {len(packets)} packets to: {os.path.abspath(filename)}")
print(f"📂 Full path: {os.path.abspath(filename)}")