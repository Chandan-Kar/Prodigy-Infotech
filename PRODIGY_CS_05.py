import scapy.all as scapy

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dest_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        print(f"\n[+] IP Packet: {src_ip} -> {dest_ip}, Protocol: {protocol}")

        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dest_port = packet[scapy.TCP].dport
            print(f"    [+] TCP Segment: {src_port} -> {dest_port}")

        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dest_port = packet[scapy.UDP].dport
            print(f"    [+] UDP Datagram: {src_port} -> {dest_port}")

        elif packet.haslayer(scapy.ICMP):
            icmp_type = packet[scapy.ICMP].type
            icmp_code = packet[scapy.ICMP].code
            print(f"    [+] ICMP Packet: Type {icmp_type}, Code {icmp_code}")

        print(f"    [+] Payload: {packet[scapy.Raw].load.decode('utf-8', 'ignore')}")


