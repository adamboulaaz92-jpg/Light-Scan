import argparse
import time
import platform
from scapy.all import sniff, wrpcap, Ether, IP, TCP, UDP, ICMP, ARP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers.l2 import Dot1Q

try:
    from scapy.all import get_if_list

    HAVE_IF_LIST = True
except:
    HAVE_IF_LIST = False

Version = "1.0.0"

if platform.system() == "Windows":
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        GREEN = '\033[92m'
        RED = '\033[91m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        PURPLE = '\033[95m'
        CYAN = '\033[96m'
        WHITE = '\033[97m'
        RESET = '\033[0m'
        BOLD = '\033[1m'
        DIM = '\033[2m'
    except:
        GREEN = RED = YELLOW = BLUE = PURPLE = CYAN = WHITE = RESET = BOLD = DIM = ''
else:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'


def get_interfaces():
    interfaces = []

    if platform.system() == "Windows":
        try:
            import subprocess
            import re

            result = subprocess.run('netsh interface show interface', shell=True, capture_output=True, text=True)
            lines = result.stdout.split('\n')

            guid_result = subprocess.run('wmic nic where "NetEnabled=True" get Name,Index', shell=True,
                                         capture_output=True, text=True)

            for line in lines:
                if 'Connected' in line or 'Disconnected' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        name = ' '.join(parts[3:]).strip()
                        if name and name not in ['Loopback', 'Npcap']:
                            interfaces.append(name)

            if not interfaces:
                from scapy.all import get_if_list, get_if_name
                raw_ifaces = get_if_list()
                for iface in raw_ifaces:
                    if 'NPF_Loopback' not in iface and 'Loopback' not in iface:
                        try:
                            friendly = get_if_name(iface)
                            interfaces.append(friendly)
                        except:
                            interfaces.append(iface)

        except Exception as e:
            pass

    elif platform.system() == "Linux":
        try:
            import subprocess
            result = subprocess.run('ip -br link show', shell=True, capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if ': ' in line and 'LOOPBACK' not in line.upper():
                    parts = line.split()
                    if parts:
                        iface = parts[0]
                        if not iface.startswith('docker') and not iface.startswith('veth'):
                            interfaces.append(iface)
        except:
            from scapy.all import get_if_list
            interfaces = [i for i in get_if_list() if 'lo' not in i]

    if not interfaces:
        interfaces = ['eth0', 'wlan0', 'Wi-Fi']

    return interfaces


def get_eth_type_name(eth_type):
    types = {
        0x0800: "IPv4",
        0x0806: "ARP",
        0x86DD: "IPv6",
        0x8100: "VLAN",
        0x88CC: "LLDP",
        0x0842: "WoL",
        0x9000: "Loopback",
    }
    return types.get(eth_type, f"0x{eth_type:04x}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="LightSniff - Light-Scan Packet Capture Tool",
        epilog="Examples:\n  LightSniff -i eth0 |  LightSniff -i eth0 -f 'tcp port 80' -w http.pcap |  LightSniff -i Wi-Fi -c 100 -v"
    )
    parser.add_argument("-i", "--interface", help="Network interface (e.g., eth0, Wi-Fi, wlan0)")
    parser.add_argument("-f", "--filter", help="BPF filter (e.g., 'tcp port 80', 'icmp', 'arp')")
    parser.add_argument("-c", "--count", type=int, default=100, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("-w", "--write", help="Save to PCAP file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed packet info")
    parser.add_argument("--no-promisc", action="store_true", help="Disable promiscuous mode")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (no banner)")
    parser.add_argument("--eth", action="store_true", help="Show Ethernet frame info (MAC addresses, frame type)")
    parser.add_argument("--vlan", action="store_true", help="Show VLAN tags (802.1Q)")
    parser.add_argument("--arp", action="store_true", help="Show only ARP packets")
    parser.add_argument("--mac", help="Filter by source or destination MAC address (e.g., aa:bb:cc:dd:ee:ff)")

    return parser.parse_args()


def extract_port(packet, direction):
    if TCP in packet:
        if direction == "src":
            return packet[TCP].sport
        return packet[TCP].dport
    elif UDP in packet:
        if direction == "src":
            return packet[UDP].sport
        return packet[UDP].dport
    return ""


def packet_callback(packet, verbose, packet_count, args):
    timestamp = time.strftime('%H:%M:%S')

    eth = packet[Ether] if Ether in packet else None
    src_mac = eth.src if eth else "N/A"
    dst_mac = eth.dst if eth else "N/A"
    eth_type = eth.type if eth else 0
    eth_type_name = get_eth_type_name(eth_type)

    vlan_id = None
    if Dot1Q in packet and args.vlan:
        vlan = packet[Dot1Q]
        vlan_id = vlan.vlan

    src_ip = "N/A"
    dst_ip = "N/A"
    proto = "OTHER"
    proto_color = RED
    details = ""
    size = len(packet)

    if IP in packet:
        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        proto = "IPv4"
        proto_color = GREEN
        size = len(ip)

    elif IPv6 in packet:
        ipv6 = packet[IPv6]
        src_ip = ipv6.src
        dst_ip = ipv6.dst
        proto = "IPv6"
        proto_color = CYAN
        size = len(ipv6)

        if ICMPv6EchoRequest in packet:
            proto = "ICMPv6"
            details = "Echo Request (ping)"
        elif ICMPv6EchoReply in packet:
            proto = "ICMPv6"
            details = "Echo Reply (pong)"

    if TCP in packet:
        tcp = packet[TCP]
        proto = "TCP"
        proto_color = GREEN
        flags = tcp.sprintf("%flags%")
        details = f"S:{tcp.sport} → D:{tcp.dport} Flags:[{flags}]"
        size = len(tcp.payload)

        if tcp.dport == 53 or tcp.sport == 53:
            proto = "DNS"
            proto_color = PURPLE
            try:
                from scapy.layers.dns import DNS, DNSQR
                if len(tcp.payload) > 2:
                    dns_payload = bytes(tcp.payload)[2:]
                    dns = DNS(dns_payload)
                    if dns and dns.qr == 0:
                        if dns.qd:
                            query_name = dns.qd.qname.decode('utf-8', errors='ignore')
                            query_type = dns.qd.qtype
                            type_names = {1: 'A', 28: 'AAAA', 15: 'MX', 2: 'NS', 5: 'CNAME', 12: 'PTR', 16: 'TXT',
                                          6: 'SOA', 33: 'SRV'}
                            type_str = type_names.get(query_type, str(query_type))
                            details = f"Query: {query_name} ({type_str})"
                    elif dns and dns.qr == 1:
                        if dns.an:
                            answer = dns.an
                            if hasattr(answer, 'rdata'):
                                details = f"Response: {answer.rdata}"
                        else:
                            details = f"Response: No answer"
            except Exception as e:
                pass

        if tcp.dport == 80 or tcp.sport == 80:
            proto = "HTTP"
            proto_color = YELLOW
            if tcp.payload:
                try:
                    payload = bytes(tcp.payload).decode('utf-8', errors='ignore')[:50]
                    if 'GET' in payload or 'POST' in payload or 'HTTP' in payload:
                        details = f"{payload.replace(chr(13), '').replace(chr(10), ' ')[:40]}..."
                except:
                    pass

    elif UDP in packet:
        udp = packet[UDP]
        proto = "UDP"
        proto_color = CYAN
        details = f"S:{udp.sport} → D:{udp.dport}"
        size = len(udp.payload)

        if udp.dport == 53 or udp.sport == 53:
            proto = "DNS"
            proto_color = PURPLE

            try:
                from scapy.layers.dns import DNS, DNSQR
                if DNS in packet:
                    dns = packet[DNS]
                    if dns.qr == 0:
                        if dns.qd:
                            query_name = dns.qd.qname.decode('utf-8', errors='ignore')
                            query_type = dns.qd.qtype
                            type_names = {1: 'A', 28: 'AAAA', 15: 'MX', 2: 'NS', 5: 'CNAME', 12: 'PTR', 16: 'TXT',
                                          6: 'SOA', 33: 'SRV'}
                            type_str = type_names.get(query_type, str(query_type))
                            details = f"Query: {query_name} ({type_str})"
                    elif dns.qr == 1:
                        if dns.an:
                            answer = dns.an
                            if hasattr(answer, 'rdata'):
                                details = f"Response: {answer.rdata}"
                        else:
                            details = f"Response: No answer"
            except Exception as e:
                pass

    elif ICMP in packet and proto != "ICMPv6":
        icmp = packet[ICMP]
        proto = "ICMP"
        proto_color = YELLOW
        details = f"Type:{icmp.type} Code:{icmp.code}"
        size = 0

    elif ARP in packet:
        arp = packet[ARP]
        proto = "ARP"
        proto_color = PURPLE
        src_ip = arp.psrc
        dst_ip = arp.pdst
        details = f"{arp.psrc} → {arp.pdst}"
        size = 0

    if vlan_id is not None:
        details += f" [VLAN:{vlan_id}]"

    if verbose:
        print(f"{BOLD}[{timestamp}]{RESET} {proto_color}{proto:6}{RESET} "
              f"{str(src_ip):16} → {str(dst_ip):16} | "
              f"{src_mac:17} → {dst_mac:17} | "
              f"{eth_type_name:8} | "
              f"{details:35} | "
              f"Size: {size:4} bytes")
    else:
        src_port = extract_port(packet, 'src')
        dst_port = extract_port(packet, 'dst')

        if args.eth:
            src_display = f"{src_mac}"
            dst_display = f"{dst_mac}"
            if src_port:
                src_display += f":{src_port}"
            if dst_port:
                dst_display += f":{dst_port}"
        else:
            src_display = f"{src_ip}:{src_port}" if src_port else str(src_ip)
            dst_display = f"{dst_ip}:{dst_port}" if dst_port else str(dst_ip)

        if args.eth:
            print(f"{BOLD}[{timestamp}]{RESET} {proto_color}{proto:4}{RESET} "
                  f"{src_display:27} {GREEN}→{RESET} "
                  f"{dst_display:27} "
                  f"{DIM}{eth_type_name:8} {details[:35]}{RESET}")
        else:
            print(f"{BOLD}[{timestamp}]{RESET} {proto_color}{proto:4}{RESET} "
                  f"{src_display:22} {GREEN}→{RESET} "
                  f"{dst_display:22} "
                  f"{DIM}{details[:40]}{RESET}")


def check_admin():
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        return os.geteuid() == 0


def main():
    args = parse_args()

    if args.arp:
        args.filter = "arp"

    if not args.quiet:
        print(f"""
    {GREEN}╔══════════════════════════════════════╗
    ║           LightSniff v{Version}          ║
    ║      Light-Scan Packet Sniffer       ║
    ╚══════════════════════════════════════╝{RESET}
        """)

    if not check_admin():
        print(f"{YELLOW}[!] Warning: Running without admin/root privileges{RESET}")
        print(f"{YELLOW}[!] Some interfaces may not be accessible{RESET}\n")

    if not args.interface:
        print(f"{YELLOW}[!] No interface specified{RESET}")
        print(f"{GREEN}[+] Available interfaces:{RESET}")
        for iface in get_interfaces():
            print(f"    - {iface}")
        print(f"\n{GREEN}[+] Usage: LightSniff -i eth0 -f 'tcp port 80' -w capture.pcap{RESET}")
        return

    if args.mac:
        mac_filter = args.mac.lower()
        print(f"{CYAN}[+] Filtering by MAC: {mac_filter}{RESET}")

    print(f"{GREEN}[+] Sniffing on {args.interface}{RESET}")
    if args.filter:
        print(f"{CYAN}[+] Filter: {args.filter}{RESET}")
    if args.eth:
        print(f"{CYAN}[+] Ethernet mode enabled (showing MAC addresses){RESET}")
    if args.vlan:
        print(f"{CYAN}[+] VLAN tag detection enabled{RESET}")
    if args.count > 0:
        print(f"{YELLOW}[+] Capturing {args.count} packets...{RESET}")
    else:
        print(f"{YELLOW}[+] Press Ctrl+C to stop{RESET}")
    print()

    if args.verbose:
        print(f"{BOLD}{'Time':10} {'Proto':6} {'Source IP':16} → {'Dest IP':16} | "
              f"{'Source MAC':17} → {'Dest MAC':17} | {'Type':8} | {'Details':35} | {'Size':6}{RESET}")
        print("-" * 145)
    elif args.eth:
        print(f"{BOLD}{'Time':10} {'Proto':4} {'Source MAC':27} → {'Dest MAC':27} {'Type':8} {'Details':35}{RESET}")
        print("-" * 105)
    else:
        print(f"{BOLD}{'Time':10} {'Proto':4} {'Source':22} {'→':2} {'Destination':22} {'Details':40}{RESET}")
        print("-" * 95)

    packets = []

    def callback(packet):
        if args.mac:
            eth = packet[Ether] if Ether in packet else None
            if eth:
                if args.mac.lower() not in (eth.src.lower(), eth.dst.lower()):
                    return
        packets.append(packet)
        packet_callback(packet, args.verbose, len(packets), args)

    try:
        if args.count > 0:
            sniff(
                iface=args.interface,
                filter=args.filter,
                count=args.count,
                prn=callback,
                store=True,
                promisc=not args.no_promisc
            )
        else:
            print(f"{YELLOW}[+] Sniffing indefinitely. Press Ctrl+C to stop...{RESET}\n")
            sniff(
                iface=args.interface,
                filter=args.filter,
                prn=callback,
                store=True,
                promisc=not args.no_promisc,
                timeout=None
            )

        if args.write and packets:
            wrpcap(args.write, packets)
            print(f"\n{GREEN}[+] Saved {len(packets)} packets to {args.write}{RESET}")

    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Stopped by user{RESET}")
        if args.write and packets:
            wrpcap(args.write, packets)
            print(f"{GREEN}[+] Saved {len(packets)} packets to {args.write}{RESET}")
    except PermissionError:
        print(f"{RED}[-] Permission denied! Run as administrator/root.{RESET}")
    except Exception as e:
        print(f"{RED}[-] Error: {e}{RESET}")
        print(f"{YELLOW}[!] Make sure Npcap/WinPcap is installed on Windows{RESET}")


if __name__ == "__main__":
    import os
    main()