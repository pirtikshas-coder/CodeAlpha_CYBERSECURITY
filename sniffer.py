from scapy.all import sniff, IP, TCP, UDP, Raw

def process_packet(packet):
    print("\n--- Packet Captured ---")

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")

    if packet.haslayer(TCP):
        print("Protocol: TCP")
    elif packet.haslayer(UDP):
        print("Protocol: UDP")

    # Show payload (NEW)
    if packet.haslayer(Raw):
        print("Payload:", packet[Raw].load)

    print(packet.summary())

print("Starting packet sniffing...")
sniff(prn=process_packet, count=20)
