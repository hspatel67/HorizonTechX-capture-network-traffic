import sys
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def format_payload(payload_bytes: bytes, max_len: int = 64) -> str:
    """Converts raw bytes to printable ASCII characters for easy reading."""
    preview = payload_bytes[:max_len]
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in preview)

def process_packet(packet):
    """Parses and displays network packet details."""
    # Ensure it's an IP packet
    if not packet.haslayer(IP):
        return

    timestamp = datetime.now().strftime("%H:%M:%S")
    ip = packet[IP]
    src_ip = ip.src
    dst_ip = ip.dst
    proto_num = ip.proto
    ttl = ip.ttl

    proto_name = "OTHER"
    src_port = "-"
    dst_port = "-"
    flags_info = "-"

    # Layer 4 (Transport Layer) Parsing
    if packet.haslayer(TCP):
        proto_name = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags_info = f"Flags: {packet[TCP].flags}"
    elif packet.haslayer(UDP):
        proto_name = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif packet.haslayer(ICMP):
        proto_name = "ICMP"
        flags_info = f"Type: {packet[ICMP].type}, Code: {packet[ICMP].code}"

    # Print Packet Summary
    print("-" * 70)
    print(f"[{timestamp}] {proto_name} (Proto ID: {proto_num}) | TTL: {ttl}")
    print(f"  Source:      {src_ip}:{src_port}")
    print(f"  Destination: {dst_ip}:{dst_port}")
    
    if flags_info != "-":
        print(f"  Details:     {flags_info}")

    # Layer 7 (Application / Payload)
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load
        payload = format_payload(raw_data)
        print(f"  Payload ({len(raw_data)} bytes): {payload}")

def main():
    print("=" * 70)
    print("[*] Starting Packet Sniffer on Windows...")
    print("[*] Capturing IPv4 packets. Press Ctrl + C to stop.")
    print("=" * 70)

    try:
        # sniff() on Windows automatically binds to the active Npcap interface
        sniff(filter="ip", prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n[!] Sniffer stopped by user.")
    except PermissionError:
        print("\n[!] ERROR: Please run Command Prompt or PowerShell as Administrator.")
    except Exception as e:
        print(f"\n[!] Unexpected Error: {e}")

if __name__ == "__main__":
    main()