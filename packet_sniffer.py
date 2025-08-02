from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

# === CONFIGURATION ===
LOG_FILE = "packets.log"
FILTER_PROTOCOLS = ['TCP', 'UDP', 'ICMP']  # Options: TCP, UDP, ICMP
FILTER_IP = None  # Example: '192.168.1.1' or None to disable filter

# === Logging Function ===
def log_packet(info):
    with open(LOG_FILE, "a") as f:
        f.write(info + "\n")

# === Packet Processing ===
def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = ""
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Filter by IP if specified
        if FILTER_IP and (FILTER_IP not in [src_ip, dst_ip]):
            return

        output = f"\n{'-'*60}\n"
        output += f"📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        output += f"📤 Source IP: {src_ip}\n"
        output += f"📥 Destination IP: {dst_ip}\n"

        if TCP in packet and 'TCP' in FILTER_PROTOCOLS:
            protocol = "TCP"
            output += f"🧱 Protocol: TCP\n"
            output += f"🔼 Src Port: {packet[TCP].sport}, 🔽 Dst Port: {packet[TCP].dport}\n"
            
        elif UDP in packet and 'UDP' in FILTER_PROTOCOLS:
            protocol = "UDP"
            output += f"🧱 Protocol: UDP\n"
            output += f"🔼 Src Port: {packet[UDP].sport}, 🔽 Dst Port: {packet[UDP].dport}\n"
            
        elif ICMP in packet and 'ICMP' in FILTER_PROTOCOLS:
            protocol = "ICMP"
            output += f"🧱 Protocol: ICMP\n"
            
        else:
            return  # Skip non-matching protocols

        if Raw in packet:
            try:
                payload = bytes(packet[Raw].load).decode(errors='ignore')
                output += f"📦 Payload:\n{payload}\n"
            except:
                output += "📦 Payload: <binary/unreadable>\n"

        print(output)
        log_packet(output)  # Save to log file

# === Start Sniffing ===
print("📡 Starting packet sniffer... Press CTRL+C to stop.")
print(f"📁 Logging to: {LOG_FILE}")
print(f"🔍 Filtering Protocols: {', '.join(FILTER_PROTOCOLS)}")
if FILTER_IP:
    print(f"📌 Filtering IP: {FILTER_IP}")

sniff(prn=packet_callback, store=False)
