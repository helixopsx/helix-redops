from scapy.all import sniff

print("DDoS Detection Tool started...")
print("Listening for network packets...")

def packet_handler(packet):
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        print(f"Packet: {src_ip} -> {dst_ip}")

sniff(prn=packet_handler, store=False)


