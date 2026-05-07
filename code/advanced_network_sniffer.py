# advanced_network_sniffer.py

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Ether, ARP, DNS, DNSQR
from scapy.all import wrpcap, rdpcap
from datetime import datetime
from collections import defaultdict
import threading
import time
import os
import json
from colorama import init, Fore, Style

# Initialize colorama for colored output
init(autoreset=True)

# ============ CONFIGURATION ============
CONFIG = {
    "save_packets": True,
    "pcap_file": "captured_traffic.pcap",
    "log_file": "packet_log.json",
    "max_payload_display": 100,
    "show_hex": False,
    "show_ascii": True,
    "show_mac": True,
    "statistics_interval": 10  # seconds
}

# ============ STATISTICS TRACKING ============
class NetworkStats:
    def __init__(self):
        self.packet_count = 0
        self.protocol_counts = defaultdict(int)
        self.ip_traffic = defaultdict(lambda: {"sent": 0, "received": 0})
        self.port_traffic = defaultdict(int)
        self.start_time = datetime.now()
        self.lock = threading.Lock()
    
    def update(self, packet):
        with self.lock:
            self.packet_count += 1
            
            if IP in packet:
                proto = packet[IP].proto
                proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"Other({proto})")
                self.protocol_counts[proto_name] += 1
                
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                self.ip_traffic[src_ip]["sent"] += len(packet)
                self.ip_traffic[dst_ip]["received"] += len(packet)
                
                if TCP in packet:
                    self.port_traffic[packet[TCP].sport] += 1
                    self.port_traffic[packet[TCP].dport] += 1
                elif UDP in packet:
                    self.port_traffic[packet[UDP].sport] += 1
                    self.port_traffic[packet[UDP].dport] += 1
    
    def display(self):
        with self.lock:
            elapsed = (datetime.now() - self.start_time).seconds
            print(f"\n{Fore.CYAN}{'='*70}")
            print(f"{Fore.YELLOW}📊 LIVE STATISTICS (Running: {elapsed}s)")
            print(f"{Fore.CYAN}{'='*70}")
            print(f"{Fore.WHITE}Total Packets: {Fore.GREEN}{self.packet_count}")
            print(f"\n{Fore.YELLOW}Protocol Breakdown:")
            for proto, count in sorted(self.protocol_counts.items(), key=lambda x: x[1], reverse=True):
                bar = "█" * int(count / max(max(self.protocol_counts.values()), 1) * 30)
                print(f"  {Fore.WHITE}{proto:<10}: {Fore.CYAN}{count:>6} {bar}")
            
            print(f"\n{Fore.YELLOW}Top IP Addresses (by bytes):")
            top_ips = sorted(self.ip_traffic.items(), key=lambda x: x[1]["sent"] + x[1]["received"], reverse=True)[:5]
            for ip, data in top_ips:
                total = data["sent"] + data["received"]
                print(f"  {Fore.WHITE}{ip:<16}: {Fore.GREEN}{total:>10,} bytes")
            
            print(f"{Fore.CYAN}{'='*70}\n")

stats = NetworkStats()

# ============ PACKET LOGGING ============
packet_log = []
all_packets = []

def save_packets_to_file():
    """Save captured packets to PCAP and JSON files"""
    if CONFIG["save_packets"] and all_packets:
        try:
            # Save as PCAP (readable by Wireshark)
            wrpcap(CONFIG["pcap_file"], all_packets)
            print(f"{Fore.GREEN}✓ Packets saved to {CONFIG['pcap_file']}")
            
            # Save as JSON (readable by Python)
            with open(CONFIG["log_file"], "w") as f:
                json.dump(packet_log, f, indent=2)
            print(f"{Fore.GREEN}✓ Log saved to {CONFIG['log_file']}")
        except Exception as e:
            print(f"{Fore.RED}Error saving packets: {e}")

# ============ PAYLOAD ANALYSIS ============
def analyze_payload(payload):
    """Extract and analyze packet payload"""
    if not payload:
        return None
    
    result = {
        "hex": payload.hex()[:CONFIG["max_payload_display"] * 2],
        "length": len(payload)
    }
    
    if CONFIG["show_ascii"]:
        # Try to decode as readable text
        ascii_text = payload.decode('utf-8', errors='ignore')
        result["ascii"] = ascii_text[:CONFIG["max_payload_display"]]
        result["is_printable"] = all(c < 128 and (c == 32 or 32 < c < 127) for c in payload[:100])
    
    return result

def reconstruct_http(payload):
    """Try to reconstruct HTTP requests/responses"""
    if not payload:
        return None
    
    try:
        data = payload.decode('utf-8', errors='ignore')
        http_lines = []
        
        # Check for HTTP request
        if data.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD')):
            lines = data.split('\r\n')
            http_lines.append(f"{Fore.YELLOW}📡 HTTP Request:")
            http_lines.append(f"  {lines[0]}")  # Request line
            
            # Extract Host header
            for line in lines:
                if line.lower().startswith('host:'):
                    http_lines.append(f"  {Fore.CYAN}{line}")
            
            return "\n".join(http_lines)
        
        # Check for HTTP response
        elif data.startswith(('HTTP/1.', 'HTTP/2.')):
            lines = data.split('\r\n')
            http_lines.append(f"{Fore.GREEN}📡 HTTP Response:")
            http_lines.append(f"  {lines[0]}")  # Status line
            return "\n".join(http_lines)
    
    except:
        pass
    return None

def extract_dns_query(packet):
    """Extract DNS query information"""
    if DNS in packet and packet[DNS].qr == 0:  # Query
        if packet[DNS].qd:
            query = packet[DNS].qd
            return f"DNS Query: {query.qname.decode('utf-8')} (Type: {query.qtype})"
    return None

# ============ PACKET ANALYSIS ============
def analyze_packet(packet):
    """Analyze and display packet information"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    # Store for statistics
    stats.update(packet)
    
    # Store for saving
    all_packets.append(packet)
    
    # Build display output
    output_lines = []
    output_lines.append(f"\n{Fore.CYAN}{'='*80}")
    output_lines.append(f"{Fore.WHITE}[{timestamp}] Packet #{len(all_packets)}")
    output_lines.append(f"{Fore.CYAN}{'-'*80}")
    
    # Ethernet/MAC Layer
    if CONFIG["show_mac"] and Ether in packet:
        eth = packet[Ether]
        output_lines.append(f"{Fore.MAGENTA}📡 Ethernet:")
        output_lines.append(f"  MAC Source: {eth.src}")
        output_lines.append(f"  MAC Dest  : {eth.dst}")
        output_lines.append(f"  Type      : 0x{eth.type:04x}")
    
    # IP Layer
    if IP in packet:
        ip = packet[IP]
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(ip.proto, f"Proto-{ip.proto}")
        
        output_lines.append(f"{Fore.BLUE}🌐 IP Layer:")
        output_lines.append(f"  Source     : {ip.src}")
        output_lines.append(f"  Destination: {ip.dst}")
        output_lines.append(f"  Protocol   : {proto_name}")
        output_lines.append(f"  TTL        : {ip.ttl}")
        output_lines.append(f"  Length     : {ip.len} bytes")
        
        # Log to JSON
        log_entry = {
            "timestamp": timestamp,
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "protocol": proto_name,
            "length": ip.len
        }
        
        # TCP Layer
        if TCP in packet:
            tcp = packet[TCP]
            flags = []
            if tcp.flags.S: flags.append("SYN")
            if tcp.flags.A: flags.append("ACK")
            if tcp.flags.F: flags.append("FIN")
            if tcp.flags.R: flags.append("RST")
            if tcp.flags.P: flags.append("PSH")
            
            output_lines.append(f"{Fore.GREEN}🔌 TCP Segment:")
            output_lines.append(f"  Source Port : {tcp.sport}")
            output_lines.append(f"  Dest Port   : {tcp.dport}")
            output_lines.append(f"  Flags       : {'-'.join(flags) if flags else 'None'}")
            output_lines.append(f"  Sequence    : {tcp.seq}")
            output_lines.append(f"  Acknowledgment: {tcp.ack}")
            
            log_entry["src_port"] = tcp.sport
            log_entry["dst_port"] = tcp.dport
            
            # Payload
            if Raw in packet:
                payload = packet[Raw].load
                payload_info = analyze_payload(payload)
                if payload_info:
                    output_lines.append(f"{Fore.YELLOW}📦 Payload:")
                    output_lines.append(f"  Length: {payload_info['length']} bytes")
                    
                    if CONFIG["show_hex"]:
                        output_lines.append(f"  HEX   : {payload_info['hex']}...")
                    
                    if CONFIG["show_ascii"] and payload_info.get("ascii"):
                        output_lines.append(f"  ASCII : {payload_info['ascii']}...")
                    
                    log_entry["payload"] = payload_info["hex"]
                    
                    # HTTP reconstruction
                    http_info = reconstruct_http(payload)
                    if http_info:
                        output_lines.append(f"  {http_info}")
        
        # UDP Layer
        elif UDP in packet:
            udp = packet[UDP]
            output_lines.append(f"{Fore.MAGENTA}📦 UDP Datagram:")
            output_lines.append(f"  Source Port : {udp.sport}")
            output_lines.append(f"  Dest Port   : {udp.dport}")
            output_lines.append(f"  Length      : {udp.len} bytes")
            
            log_entry["src_port"] = udp.sport
            log_entry["dst_port"] = udp.dport
            
            # DNS Query
            dns_query = extract_dns_query(packet)
            if dns_query:
                output_lines.append(f"{Fore.CYAN}🔍 {dns_query}")
            
            # Payload
            if Raw in packet:
                payload = packet[Raw].load
                payload_info = analyze_payload(payload)
                if payload_info:
                    output_lines.append(f"  Payload: {payload_info['ascii'][:50]}...")
                    log_entry["payload"] = payload_info["hex"]
        
        # ICMP Layer
        elif ICMP in packet:
            icmp = packet[ICMP]
            icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Destination Unreachable", 11: "Time Exceeded"}
            icmp_type_name = icmp_types.get(icmp.type, f"Type-{icmp.type}")
            
            output_lines.append(f"{Fore.YELLOW}⚠️ ICMP Packet:")
            output_lines.append(f"  Type: {icmp_type_name} ({icmp.type})")
            output_lines.append(f"  Code: {icmp.code}")
        
        packet_log.append(log_entry)
    
    # ARP Layer
    elif ARP in packet:
        arp = packet[ARP]
        output_lines.append(f"{Fore.RED}🔗 ARP Packet:")
        output_lines.append(f"  Operation: {'Request' if arp.op == 1 else 'Reply'}")
        output_lines.append(f"  Sender IP : {arp.psrc} ({arp.hwsrc})")
        output_lines.append(f"  Target IP : {arp.pdst}")
        
        packet_log.append({
            "timestamp": timestamp,
            "type": "ARP",
            "operation": "Request" if arp.op == 1 else "Reply",
            "src_ip": arp.psrc,
            "dst_ip": arp.pdst
        })
    
    # Print output
    for line in output_lines:
        print(line)
    
    print(f"{Fore.CYAN}{'='*80}")

# ============ STATISTICS DISPLAY THREAD ============
def display_stats_periodically():
    """Display statistics at regular intervals"""
    while True:
        time.sleep(CONFIG["statistics_interval"])
        if stats.packet_count > 0:
            stats.display()

# ============ PACKET FILTERING ============
def create_filter(filter_string=None):
    """
    Create BPF filter string
    Examples:
      - "tcp" - Only TCP packets
      - "udp" - Only UDP packets  
      - "icmp" - Only ICMP packets
      - "port 80" - HTTP traffic
      - "host 192.168.1.1" - Traffic to/from specific IP
      - "tcp port 443" - HTTPS traffic
    """
    if filter_string:
        return filter_string
    return None

# ============ HTTP/PAYLOAD EXTRACTION FUNCTIONS ============
def extract_http_host(payload):
    """Extract HTTP Host header from payload"""
    try:
        data = payload.decode('utf-8', errors='ignore')
        for line in data.split('\r\n'):
            if line.lower().startswith('host:'):
                return line.split(':', 1)[1].strip()
    except:
        pass
    return None

def extract_http_user_agent(payload):
    """Extract HTTP User-Agent from payload"""
    try:
        data = payload.decode('utf-8', errors='ignore')
        for line in data.split('\r\n'):
            if line.lower().startswith('user-agent:'):
                return line.split(':', 1)[1].strip()
    except:
        pass
    return None

def extract_http_method_and_path(payload):
    """Extract HTTP method and path from payload"""
    try:
        data = payload.decode('utf-8', errors='ignore')
        if data.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS')):
            parts = data.split(' ', 2)
            if len(parts) >= 2:
                return parts[0], parts[1]
    except:
        pass
    return None, None

# ============ MAIN SNIFFING FUNCTION ============
def start_sniffing(interface=None, packet_count=0, bpf_filter=None, save_on_exit=True):
    """
    Start advanced packet capture
    
    Parameters:
    - interface: Network interface (None = default)
    - packet_count: Number of packets (0 = infinite)
    - bpf_filter: BPF filter string (e.g., "tcp", "port 80")
    - save_on_exit: Save packets to file when stopping
    """
    print(f"{Fore.GREEN}{'='*80}")
    print(f"{Fore.YELLOW}🚀 ADVANCED NETWORK SNIFFER")
    print(f"{Fore.GREEN}{'='*80}")
    print(f"{Fore.WHITE}Interface    : {interface or 'Default'}")
    print(f"Filter       : {bpf_filter or 'None (all packets)'}")
    print(f"Packet Count : {packet_count if packet_count > 0 else 'Infinite'}")
    print(f"Save PCAP    : {CONFIG['save_packets']}")
    print(f"Show MAC     : {CONFIG['show_mac']}")
    print(f"Show HEX     : {CONFIG['show_hex']}")
    print(f"{Fore.GREEN}{'='*80}")
    print(f"{Fore.RED}Press Ctrl+C to stop capturing{Style.RESET_ALL}\n")
    
    # Start statistics thread
    stats_thread = threading.Thread(target=display_stats_periodically, daemon=True)
    stats_thread.start()
    
    try:
        # Start capturing
        sniff(
            iface=interface,
            filter=bpf_filter,
            prn=analyze_packet,
            count=packet_count if packet_count > 0 else 0,
            store=False
        )
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}\n⚠️ Capture stopped by user")
    except PermissionError:
        print(f"{Fore.RED}\n❌ Permission denied! Run with administrator/root privileges.")
        return
    except Exception as e:
        print(f"{Fore.RED}\n❌ Error: {e}")
        return
    
    # Save packets
    if save_on_exit and CONFIG["save_packets"] and all_packets:
        save_packets_to_file()
    
    # Final statistics
    print(f"\n{Fore.CYAN}FINAL STATISTICS:")
    stats.display()

# ============ MENU SYSTEM ============
def show_menu():
    """Display interactive menu"""
    print(f"{Fore.CYAN}{'='*80}")
    print(f"{Fore.YELLOW}📡 ADVANCED NETWORK SNIFFER - MENU")
    print(f"{Fore.CYAN}{'='*80}")
    print(f"{Fore.WHITE}1. {Fore.GREEN}Basic Capture (All Packets)")
    print(f"{Fore.WHITE}2. {Fore.GREEN}Capture HTTP Traffic (Port 80)")
    print(f"{Fore.WHITE}3. {Fore.GREEN}Capture HTTPS Traffic (Port 443)")
    print(f"{Fore.WHITE}4. {Fore.GREEN}Capture DNS Traffic (Port 53)")
    print(f"{Fore.WHITE}5. {Fore.GREEN}Capture Specific IP")
    print(f"{Fore.WHITE}6. {Fore.GREEN}Capture Specific Protocol")
    print(f"{Fore.WHITE}7. {Fore.GREEN}Load & Analyze PCAP File")
    print(f"{Fore.WHITE}8. {Fore.GREEN}Configure Settings")
    print(f"{Fore.WHITE}9. {Fore.RED}Exit")
    print(f"{Fore.CYAN}{'='*80}")
    
    choice = input(f"{Fore.YELLOW}Enter your choice (1-9): {Fore.WHITE}").strip()
    return choice

def configure_settings():
    """Interactive configuration menu"""
    print(f"\n{Fore.CYAN}CONFIGURATION MENU")
    print(f"1. Save packets to file: {Fore.GREEN if CONFIG['save_packets'] else Fore.RED}{CONFIG['save_packets']}")
    print(f"2. Show MAC addresses: {Fore.GREEN if CONFIG['show_mac'] else Fore.RED}{CONFIG['show_mac']}")
    print(f"3. Show HEX dump: {Fore.GREEN if CONFIG['show_hex'] else Fore.RED}{CONFIG['show_hex']}")
    print(f"4. Show ASCII text: {Fore.GREEN if CONFIG['show_ascii'] else Fore.RED}{CONFIG['show_ascii']}")
    print(f"5. Max payload display: {CONFIG['max_payload_display']} bytes")
    print(f"6. Back to main menu")
    
    subchoice = input(f"{Fore.YELLOW}Enter setting to toggle (1-6): {Fore.WHITE}").strip()
    
    if subchoice == '1':
        CONFIG['save_packets'] = not CONFIG['save_packets']
    elif subchoice == '2':
        CONFIG['show_mac'] = not CONFIG['show_mac']
    elif subchoice == '3':
        CONFIG['show_hex'] = not CONFIG['show_hex']
    elif subchoice == '4':
        CONFIG['show_ascii'] = not CONFIG['show_ascii']
    elif subchoice == '5':
        try:
            new_val = int(input("New max payload bytes: "))
            CONFIG['max_payload_display'] = new_val
        except:
            pass
    
    print(f"{Fore.GREEN}Configuration updated!")

def load_and_analyze_pcap():
    """Load existing PCAP file for analysis"""
    filename = input("Enter PCAP filename: ").strip()
    try:
        packets = rdpcap(filename)
        print(f"{Fore.GREEN}Loaded {len(packets)} packets from {filename}")
        
        # Analyze statistics
        temp_stats = defaultdict(int)
        for pkt in packets:
            if IP in pkt:
                proto = pkt[IP].proto
                proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"Other({proto})")
                temp_stats[proto_name] += 1
        
        print(f"{Fore.YELLOW}Protocol breakdown:")
        for proto, count in temp_stats.items():
            print(f"  {proto}: {count}")
    except Exception as e:
        print(f"{Fore.RED}Error loading file: {e}")

# ============ MAIN EXECUTION ============
if __name__ == "__main__":
    try:
        from colorama import init, Fore, Style
    except ImportError:
        print("Installing colorama for colored output...")
        os.system("pip install colorama")
        from colorama import init, Fore, Style
        init(autoreset=True)
    
    # Interactive menu
    while True:
        choice = show_menu()
        
        if choice == '1':
            start_sniffing(packet_count=50)  # Capture 50 packets
            break
        elif choice == '2':
            start_sniffing(bpf_filter="tcp port 80", packet_count=30)
            break
        elif choice == '3':
            start_sniffing(bpf_filter="tcp port 443", packet_count=30)
            break
        elif choice == '4':
            start_sniffing(bpf_filter="udp port 53", packet_count=20)
            break
        elif choice == '5':
            ip = input("Enter IP address to monitor: ")
            start_sniffing(bpf_filter=f"host {ip}", packet_count=30)
            break
        elif choice == '6':
            print("\nProtocol options: tcp, udp, icmp, arp")
            proto = input("Enter protocol: ").lower()
            start_sniffing(bpf_filter=proto, packet_count=30)
            break
        elif choice == '7':
            load_and_analyze_pcap()
            input("\nPress Enter to continue...")
        elif choice == '8':
            configure_settings()
            input("\nPress Enter to continue...")
        elif choice == '9':
            print(f"{Fore.RED}Exiting...")
            break
        else:
            print(f"{Fore.RED}Invalid choice!")