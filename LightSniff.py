import argparse
import time
import platform
import os
import struct
import pickle
from datetime import datetime
from scapy.all import sniff, wrpcap, rdpcap, Ether, IP, TCP, UDP, ICMP, ARP, DNS
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers.l2 import Dot1Q
import zlib

try:
    from scapy.all import get_if_list

    HAVE_IF_LIST = True
except:
    HAVE_IF_LIST = False

Version = "1.0.1"

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

LIGHTBIN_MAGIC = b'LBN\x00'
LIGHTBIN_VERSION = 1
FLAG_COMPRESSED = 0x01
FLAG_METADATA_ONLY = 0x02

def detect_file_type(filename):
    try:
        with open(filename, 'rb') as f:
            magic = f.read(4)
            if magic == LIGHTBIN_MAGIC:
                return 'lightbin'
            elif magic[:4] == b'\xd4\xc3\xb2\xa1' or magic[:4] == b'\xa1\xb2\xc3\xd4':
                return 'pcap'
            elif magic[:4] == b'\x0a\x0d\x0d\x0a':
                return 'pcapng'
            else:
                return 'unknown'
    except:
        return 'unknown'

def lbn_chksum(version, created, count, flags):
    header_data = struct.pack('<IIII', version, created, count, flags)
    return zlib.crc32(header_data) & 0xFFFFFFFF

def save_binary(filename, packets, compress, args=None, stats=None):
    try:
        creation_time = int(time.time())
        packet_count = 0
        packet_types = []
        if compress:
            FLAG = FLAG_COMPRESSED
        else:
            FLAG = FLAG_METADATA_ONLY

        with open(filename, 'wb') as f:
            header = struct.pack(
                '<4sIIIII',
                LIGHTBIN_MAGIC,
                LIGHTBIN_VERSION,
                creation_time,
                0,
                FLAG,
                0
            )
            f.write(header)
            header_pos = f.tell() - 24

            for pkt in packets:
                timestamp = time.time()
                if compress:
                    raw_bytes = zlib.compress(bytes(pkt), 6)
                else:
                    raw_bytes = bytes(pkt)

                if pkt.haslayer(Ether):
                    if pkt[Ether].type == 0x8100:
                        packet_types.append('ether-vlan')
                    packet_types.append('ether')
                elif pkt.haslayer(IP):
                    packet_types.append('ip')
                elif pkt.haslayer(IPv6):
                    packet_types.append('ipv6')
                else:
                    packet_types.append('raw')

                f.write(struct.pack('<dI', timestamp, len(raw_bytes)))
                f.write(raw_bytes)

                packet_count += 1

            metadata = {
                'version': LIGHTBIN_VERSION,
                'created': creation_time,
                'packet_count': packet_count,
                'args': vars(args) if args else None,
                'stats': stats,
                'tool': f'LightSniff v{Version}',
                'packet_types': packet_types
            }

            metadata_bytes = pickle.dumps(metadata)
            if compress:
                metadata_bytes = zlib.compress(metadata_bytes, 6)
            f.write(struct.pack('<I', len(metadata_bytes)))
            f.write(metadata_bytes)

            f.seek(header_pos + 12)
            f.write(struct.pack('<I', packet_count))
            CHKSUM = lbn_chksum(LIGHTBIN_VERSION, creation_time, packet_count, FLAG)
            f.seek(header_pos + 20)
            f.write(struct.pack('<I', CHKSUM))


        print(f"{GREEN}[+] Saved {packet_count} packets to {filename} (LightBin format){RESET}")
        return True

    except Exception as e:
        print(f"{RED}[-] Error saving LightBin: {e}{RESET}")
        return False


def load_binary(filename):
    try:
        with open(filename, 'rb') as f:
            header_data = f.read(24)
            if len(header_data) != 24:
                raise ValueError("Invalid LightBin file (header too short)")

            magic, version, created, count, flags, ck = struct.unpack('<4sIIIII', header_data)

            if magic != LIGHTBIN_MAGIC:
                raise ValueError(f"Invalid LightBin file (magic: {magic})")

            is_compressed = bool(flags & FLAG_COMPRESSED)
            CHKSUM = lbn_chksum(version, created, count, flags)

            print(f"{GREEN}[+] Loading LightBin file...{RESET}")
            print(f"{CYAN}    Version: {version}{RESET}")
            print(f"{CYAN}    Created: {datetime.fromtimestamp(created).strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
            print(f"{CYAN}    Packets: {count}{RESET}")
            if is_compressed:
                print(f"{CYAN}    Compression: Enabled{RESET}")
            else:
                print(f"{CYAN}    Metadata-Only: Enabled{RESET}")

            if CHKSUM != ck:
                print(f"{RED}    Chksum: Invalid{RESET}")

            packets = []
            packet_timestamps = []

            for i in range(count):
                pkt_header = f.read(12)
                if len(pkt_header) != 12:
                    break

                timestamp, size = struct.unpack('<dI', pkt_header)

                pkt_data = f.read(size)
                if len(pkt_data) != size:
                    break
                if is_compressed:
                    pkt_data = zlib.decompress(pkt_data)

                if len(pkt_data) > 0:
                    first_byte = pkt_data[0]
                    if first_byte in [0x45, 0x46]:
                        try:
                            from scapy.layers.inet import IP as IPLayer
                            packet = IPLayer(pkt_data)
                        except:
                            packet = Ether(pkt_data)
                    elif first_byte == 0x60:
                        try:
                            from scapy.layers.inet6 import IPv6 as IPv6Layer
                            packet = IPv6Layer(pkt_data)
                        except:
                            packet = Ether(pkt_data)
                    else:
                        try:
                            packet = Ether(pkt_data)
                            if packet.haslayer(IP) and packet.haslayer(IPv6):
                                try:
                                    from scapy.layers.inet import IP as IPLayer
                                    packet = IPLayer(pkt_data)
                                except:
                                    packet = Ether(pkt_data)
                            elif packet.haslayer(ARP):
                                packet = Ether(pkt_data)
                        except:
                            packet = Ether(pkt_data)
                else:
                    packet = Ether(pkt_data)

                packets.append(packet)
                packet_timestamps.append(timestamp)

            metadata_size_bytes = f.read(4)
            if metadata_size_bytes:
                metadata_size = struct.unpack('<I', metadata_size_bytes)[0]
                metadata_bytes = f.read(metadata_size)
                if is_compressed:
                    try:
                        metadata_bytes = zlib.decompress(metadata_bytes)
                    except zlib.error as e:
                        print(f"{YELLOW}[!] Warning: Could not decompress metadata: {e}{RESET}")
                metadata = pickle.loads(metadata_bytes)
            else:
                metadata = {}

            print(f"{GREEN}[+] Loaded {len(packets)} packets from {filename}{RESET}")

            metadata['packet_timestamps'] = packet_timestamps

            return packets, metadata

    except FileNotFoundError:
        print(f"{RED}[-] File not found: {filename}{RESET}")
        return None, None
    except Exception as e:
        print(f"{RED}[-] Error loading LightBin: {e}{RESET}")
        return None, None

def get_interfaces():
    interfaces = []

    if platform.system() == "Windows":
        try:
            import subprocess
            result = subprocess.run('netsh interface show interface', shell=True, capture_output=True, text=True)
            lines = result.stdout.split('\n')

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
        epilog="Examples:\n"
               "  LightSniff -i eth0\n"
               "  LightSniff -i eth0 -f 'tcp port 80' -w http.pcap\n"
               "  LightSniff -i Wi-Fi -c 100 -v\n"
               "  LightSniff -r capture.pcap\n"
               "  LightSniff --bin-load capture.lbn"
    )
    parser.add_argument("-i", "--interface", help="Network interface (e.g., eth0, Wi-Fi, wlan0)")
    parser.add_argument("-f", "--filter", help="BPF filter (e.g., 'tcp port 80', 'icmp', 'arp')")
    parser.add_argument("-c", "--count", type=int, default=100, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("-w", "--write", help="Save to PCAP/PCAPNG file")
    parser.add_argument("-r", "--read", help="Read packets from PCAP/PCAPNG file (offline mode)")
    parser.add_argument("--bin-save", help="Save to LightBin binary format (.lbn)")
    parser.add_argument("--bin-load", help="Load from LightBin binary format (.lbn)")
    parser.add_argument("-C", "--compress",action="store_true", help="To compress saved output (only for .lbn)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed packet info")
    parser.add_argument("--no-promisc", action="store_true", help="Disable promiscuous mode")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (no banner)")
    parser.add_argument("--eth", action="store_true", help="Show Ethernet frame info (MAC addresses, frame type)")
    parser.add_argument("--vlan", action="store_true", help="Show VLAN tags (802.1Q)")
    parser.add_argument("--arp", action="store_true", help="Show only ARP packets")
    parser.add_argument("--tcp", action="store_true", help="Show only TCP packets")
    parser.add_argument("--udp", action="store_true", help="Show only UDP packets")
    parser.add_argument("--icmp", action="store_true", help="Show only ICMP packets")
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

        tls_ports = [443, 465, 587, 993, 995, 8443, 8080]
        is_tls_port = tcp.sport in tls_ports or tcp.dport in tls_ports
        if tcp.payload and len(tcp.payload) > 5:
            payload = bytes(tcp.payload)

            if is_tls_port or (len(payload) >= 6 and payload[0] == 0x16 and payload[1] in [0x03, 0x02, 0x01]):

                tls_version = None
                version_bytes = payload[1:3] if len(payload) >= 3 else b''

                if version_bytes == b'\x03\x00':
                    tls_version = "SSLv3 (WEAK - Deprecated)"
                elif version_bytes == b'\x03\x01':
                    tls_version = "TLS 1.0 (WEAK - Deprecated)"
                elif version_bytes == b'\x03\x02':
                    tls_version = "TLS 1.1 (WEAK - Deprecated)"
                elif version_bytes == b'\x03\x03':
                    tls_version = "TLS 1.2"
                elif version_bytes == b'\x03\x04':
                    tls_version = "TLS 1.3"

                if len(payload) >= 6 and payload[5] == 0x01:
                    proto = "TLS"
                    proto_color = BLUE
                    details = f"Client Hello [{tls_version if tls_version else 'Unknown'}]"

                    try:
                        offset = 6

                        if len(payload) > offset + 4:
                            offset += 4

                            offset += 2

                            offset += 32

                            if len(payload) > offset:
                                session_id_len = payload[offset]
                                offset += 1 + session_id_len

                            if len(payload) > offset + 2:
                                cipher_suites_len = int.from_bytes(payload[offset:offset + 2], 'big')
                                offset += 2 + cipher_suites_len

                            if len(payload) > offset:
                                compression_len = payload[offset]
                                offset += 1 + compression_len

                            if len(payload) > offset + 2:
                                extensions_len = int.from_bytes(payload[offset:offset + 2], 'big')
                                offset += 2
                                end_offset = offset + extensions_len

                                while offset + 4 <= len(payload) and offset < end_offset:
                                    ext_type = int.from_bytes(payload[offset:offset + 2], 'big')
                                    ext_len = int.from_bytes(payload[offset + 2:offset + 4], 'big')
                                    offset += 4

                                    if ext_type == 0x0000 and ext_len > 2:
                                        if len(payload) > offset + 2:
                                            sni_len = int.from_bytes(payload[offset:offset + 2], 'big')
                                            if sni_len > 0 and len(payload) > offset + 2 + sni_len:
                                                sni = payload[offset + 2:offset + 2 + sni_len].decode('utf-8',
                                                                                                      errors='ignore')
                                                details += f" SNI: {sni}"

                                    offset += ext_len
                    except Exception as e:
                        pass

                elif len(payload) >= 6 and payload[5] == 0x02:
                    proto = "TLS"
                    proto_color = CYAN
                    details = f"Server Hello [{tls_version if tls_version else 'Unknown'}]"

                elif len(payload) >= 6 and payload[5] == 0x0B:
                    proto = "TLS"
                    proto_color = GREEN
                    details = f"Certificate [{tls_version if tls_version else 'Unknown'}]"

                    if args.verbose:
                        try:
                            cert_start = payload.find(b'\x30\x82')
                            if cert_start > 0:
                                cert_info = f" (Certificate chain length: {len(payload) - cert_start} bytes)"
                                details += cert_info
                        except:
                            pass

                elif len(payload) >= 1 and payload[0] == 0x17:
                    proto = "TLS"
                    proto_color = BLUE
                    details = f"Application Data [{tls_version if tls_version else 'Unknown'}]"
                    size = len(payload)

                elif len(payload) >= 1 and payload[0] == 0x15:
                    proto = "TLS"
                    proto_color = YELLOW
                    alert_level = "Unknown"
                    alert_desc = "Unknown"
                    if len(payload) >= 2:
                        alert_level = "Warning" if payload[1] == 0x01 else "Fatal"
                    if len(payload) >= 3:
                        desc_map = {
                            0x00: "close_notify", 0x0A: "unexpected_message",
                            0x14: "bad_record_mac", 0x15: "decryption_failed",
                            0x16: "record_overflow", 0x1E: "decompression_failure",
                            0x28: "handshake_failure", 0x29: "no_certificate",
                            0x2A: "bad_certificate", 0x2B: "unsupported_certificate",
                            0x2C: "certificate_revoked", 0x2D: "certificate_expired",
                            0x2E: "certificate_unknown", 0x2F: "illegal_parameter",
                            0x30: "unknown_ca", 0x31: "access_denied",
                            0x32: "decode_error", 0x33: "decrypt_error",
                            0x3C: "export_restriction", 0x46: "protocol_version",
                            0x47: "insufficient_security", 0x50: "internal_error",
                            0x5A: "user_canceled", 0x64: "no_renegotiation"
                        }
                        alert_desc = desc_map.get(payload[2], f"0x{payload[2]:02x}")
                    details = f"Alert [{alert_level}: {alert_desc}]"

        if tcp.dport == 853 or tcp.sport == 853:
            proto = "DoT"
            proto_color = PURPLE
            details = f"DNS over TLS {details}"

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

        http_ports = [80, 8080, 8000, 8888]
        if tcp.dport in http_ports or tcp.sport in http_ports:
            if tcp.payload and len(tcp.payload) > 0:
                try:
                    payload = bytes(tcp.payload)
                    payload_str = payload.decode('utf-8', errors='ignore')[:200]

                    http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT']
                    is_http = False

                    for method in http_methods:
                        if payload_str.startswith(method + ' '):
                            is_http = True
                            proto = "HTTP"
                            proto_color = YELLOW

                            lines = payload_str.split('\r\n')
                            if lines:
                                parts = lines[0].split(' ')
                                if len(parts) >= 3:
                                    path = parts[1][:30]
                                    if len(parts[1]) > 30:
                                        path += '...'
                                    details = f"{method} {path}"
                                else:
                                    details = payload_str[:40].replace('\r', '').replace('\n', ' ')
                            break

                    if not is_http and payload_str.startswith('HTTP/'):
                        is_http = True
                        proto = "HTTP"
                        proto_color = CYAN
                        lines = payload_str.split('\r\n')
                        if lines:
                            parts = lines[0].split(' ')
                            if len(parts) >= 3:
                                details = f"{parts[0]} {parts[1]} {parts[2][:20]}"
                            else:
                                details = payload_str[:40].replace('\r', '').replace('\n', ' ')

                    if not is_http:
                        http_keywords = [b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ', b'HTTP/', b'<html',
                                         b'<!DOCTYPE']
                        for keyword in http_keywords:
                            if keyword in payload[:100]:
                                is_http = True
                                proto = "HTTP"
                                proto_color = YELLOW
                                details = payload_str[:40].replace('\r', '').replace('\n', ' ') + '...'
                                break

                except Exception as e:
                    try:
                        payload = bytes(tcp.payload)
                        http_keywords = [b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ', b'HTTP/', b'<html',
                                         b'<!DOCTYPE']
                        for keyword in http_keywords:
                            if keyword in payload[:100]:
                                proto = "HTTP"
                                proto_color = YELLOW
                                details = "HTTP traffic detected"
                                break
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
              f"{details[:40]:40} | "
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


def process_packets(packets, args):
    if not packets:
        print(f"{YELLOW}[!] No packets to process{RESET}")
        return

    print(f"{GREEN}[+] Analyzing {len(packets)} packets...{RESET}\n")

    if args.verbose:
        print(f"{BOLD}{'Time':10} {'Proto':6} {'Source IP':16} → {'Dest IP':16} | "
              f"{'Source MAC':17} → {'Dest MAC':17} | {'Type':8} | {'Details':40} | {'Size':6}{RESET}")
        print("-" * 145)
    elif args.eth:
        print(f"{BOLD}{'Time':10} {'Proto':4} {'Source MAC':27} → {'Dest MAC':27} {'Type':8} {'Details':35}{RESET}")
        print("-" * 105)
    else:
        print(f"{BOLD}{'Time':10} {'Proto':4} {'Source':22} {'→':2} {'Destination':22} {'Details':40}{RESET}")
        print("-" * 95)

    packet_count = 0
    for idx, packet in enumerate(packets, 1):
        if args.mac:
            eth = packet[Ether] if Ether in packet else None
            if eth:
                if args.mac.lower() not in (eth.src.lower(), eth.dst.lower()):
                    continue

        packet_count += 1
        packet_callback(packet, args.verbose, packet_count, args)

    print(f"\n{GREEN}[+] Processed {packet_count} packets{RESET}")


def main():
    args = parse_args()

    if args.bin_load:
        packets, metadata = load_binary(args.bin_load)
        if packets is None:
            return
        process_packets(packets, args)

        if args.write and packets:
            wrpcap(args.write, packets)
            print(f"{GREEN}[+] Saved packets to {args.write}{RESET}")
        return

    if args.read:
        try:
            file_type = detect_file_type(args.read)
            if file_type == 'lightbin':
                packets, metadata = load_binary(args.read)
                if packets is None:
                    return
                process_packets(packets, args)
                if args.write and packets:
                    wrpcap(args.write, packets)
                    print(f"{GREEN}[+] Saved packets to {args.write}{RESET}")
                return
            elif file_type == 'unknown':
                print(f"{YELLOW}[!] Unknown file format: {args.read}{RESET}")
                print(f"{YELLOW}[!] Trying as PCAP...{RESET}")

            packets = rdpcap(args.read)
            print(f"{GREEN}[+] Loaded {len(packets)} packets from {args.read}{RESET}")

            if not packets:
                print(f"{YELLOW}[!] No packets in PCAP file{RESET}")
                return

            if args.filter:
                def packet_filter(packet):
                    if 'arp' in args.filter.lower() and ARP in packet:
                        return True
                    elif 'tcp' in args.filter.lower() and TCP in packet:
                        return True
                    elif 'udp' in args.filter.lower() and UDP in packet:
                        return True
                    elif 'icmp' in args.filter.lower() and ICMP in packet:
                        return True
                    elif 'port 80' in args.filter and TCP in packet and (
                            packet[TCP].dport == 80 or packet[TCP].sport == 80):
                        return True
                    elif 'port 443' in args.filter and TCP in packet and (
                            packet[TCP].dport == 443 or packet[TCP].sport == 443):
                        return True
                    elif 'port 53' in args.filter and (UDP in packet or TCP in packet) and (
                            packet[TCP].dport == 53 or packet[TCP].sport == 53 or packet[UDP].dport == 53 or packet[
                        UDP].sport == 53):
                        return True
                    return False

                filtered_packets = [p for p in packets if packet_filter(p)]
                print(f"{GREEN}[+] Filtered to {len(filtered_packets)} packets with filter: {args.filter}{RESET}")
                packets = filtered_packets

            if args.count > 0 and args.count < len(packets):
                packets = packets[:args.count]
                print(f"{GREEN}[+] Limited to {args.count} packets{RESET}")

            process_packets(packets, args)

            if args.write and packets:
                wrpcap(args.write, packets)
                print(f"{GREEN}[+] Saved packets to {args.write}{RESET}")

            if args.bin_save and packets:
                save_binary(args.bin_save, packets, args.compress, args)

            return

        except FileNotFoundError:
            print(f"{RED}[-] File not found: {args.read}{RESET}")
            return
        except Exception as e:
            print(f"{RED}[-] Error loading file: {e}{RESET}")
            return

    filter_parts = []

    if args.arp:
        filter_parts.append("arp")
    if args.tcp:
        filter_parts.append("tcp")
    if args.udp:
        filter_parts.append("udp")
    if args.icmp:
        filter_parts.append("icmp")

    if filter_parts:
        args.filter = " or ".join(filter_parts)
    elif args.filter:
        pass
    else:
        args.filter = None

    if not args.quiet:
        print(f"""
    {GREEN}             ╔══════════════════════════════════════╗
                 ║           LightSniff v{Version}          ║
                 ║      Light-Scan Packet Sniffer       ║
                 ╚══════════════════════════════════════╝{RESET}
        """)
        print(f"""{PURPLE}
                    .                              .
                 _.-'\\          |\\--"--/\\          /`-._
             _.-`     `.       /         \\       ,'     '-._
          _.'           `._   ;   \\   /   ;   _,'           `._
        .'                 `-.:           :.-'                 `.
      ,`                           , ,                           '.
    ,`                                                             '.
   /                                                                 \\
  :,-""-,                                                     ,-""-,:
 /'       `                                                   '       '\\
          :                                                   :
          : ,-""-,                                   ,-""-, :
          /'       `.       _.-'         '-._       .'       '\\
                     \\    .`    :       :    '.    /
                      . .`       :     :       '. .
                      :/          :   :          \\:
                      :            : :            :
                                    :
                                    
{GREEN}[+] By  Colin J. Randall (CJRandall) 
        {RESET}""")

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
              f"{'Source MAC':17} → {'Dest MAC':17} | {'Type':8} | {'Details':40} | {'Size':6}{RESET}")
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

        if args.bin_save and packets:
            save_binary(args.bin_save, packets, args.compress, args)

    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Stopped by user{RESET}")
        if args.write and packets:
            wrpcap(args.write, packets)
            print(f"{GREEN}[+] Saved {len(packets)} packets to {args.write}{RESET}")
        if args.bin_save and packets:
            save_binary(args.bin_save, packets, args.compress, args)

    except PermissionError:
        print(f"{RED}[-] Permission denied! Run as administrator/root.{RESET}")
    except Exception as e:
        print(f"{RED}[-] Error: {e}{RESET}")

    if packets and args.verbose:
        print(f"\n{GREEN}[+] Captured {len(packets)} packets{RESET}")


if __name__ == "__main__":
    main()