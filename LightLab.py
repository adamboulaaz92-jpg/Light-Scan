import ast
import cmd
import time

from scapy.all import *
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6Unknown
from scapy.layers.l2 import ARP, Dot1Q
from scapy.layers.http import HTTPRequest, HTTP
from scapy.layers.dns import DNS, DNSQR, DNSRR
import struct
import pickle
import zlib

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'
BOLD = '\033[1m'

version = "1.0.0"

LIGHTBIN_MAGIC = b'LBN\x00'
LIGHTBIN_VERSION = 1
FLAG_COMPRESSED = 0x01
FLAG_METADATA_ONLY = 0x02

def lbn_chksum(version, created, count, flags):
    header_data = struct.pack('<IIII', version, created, count, flags)
    return zlib.crc32(header_data) & 0xFFFFFFFF

def save_binary(filename, packets, layers=None, args=None, stats=None):
    try:
        packet_data = []
        for pkt in packets:
            timestamp = time.time()
            raw_bytes = zlib.compress(bytes(pkt), 6)
            packet_data.append({
                'timestamp': timestamp,
                'size': len(raw_bytes),
                'data': raw_bytes
            })
        Timeheader = int(time.time())

        metadata = {
            'version': LIGHTBIN_VERSION,
            'created': Timeheader,
            'packet_count': len(packets),
            'args': vars(args) if args else None,
            'stats': stats,
            'tool': 'LightLab'
        }
        CHKSUM = lbn_chksum(LIGHTBIN_VERSION, Timeheader, len(packets), FLAG_COMPRESSED)

        header = struct.pack(
            '<4sIIIII',
            LIGHTBIN_MAGIC,
            LIGHTBIN_VERSION,
            Timeheader,
            len(packet_data),
            FLAG_COMPRESSED,
            CHKSUM
        )

        with open(filename, 'wb') as f:
            f.write(header)
            for pkt in packet_data:
                f.write(struct.pack('<dI', pkt['timestamp'], pkt['size']))
                f.write(pkt['data'])

            metadata_bytes = pickle.dumps(metadata)
            metadata_bytes = zlib.compress(metadata_bytes, 6)
            f.write(struct.pack('<I', len(metadata_bytes)))
            f.write(metadata_bytes)

        print(f"{GREEN}[+] Saved {len(packets)} packets to {filename} (LightBin){RESET}")
        return True
    except Exception as e:
        print(f"{RED}[!] Save failed: {e}{RESET}")
        return False


def load_binary(filename):
    try:
        with open(filename, 'rb') as f:
            header_data = f.read(24)
            if len(header_data) != 24:
                raise ValueError("Invalid LightBin file")

            magic, version, created, count, flags, ck = struct.unpack('<4sIIIII', header_data)

            if magic != LIGHTBIN_MAGIC:
                raise ValueError(f"Invalid LightBin magic: {magic}")

            is_compressed = bool(flags & FLAG_COMPRESSED)
            chksum = lbn_chksum(version, created, count, flags)

            print(f"{GREEN}[+] Loading LightBin...{RESET}")
            print(f"{CYAN}     Version: {version}{RESET}")
            print(f"{CYAN}     Created: {time.ctime(created)}{RESET}")
            print(f"{CYAN}     Packets: {count}{RESET}")
            if is_compressed:
                print(f"{CYAN}     Compression: Enabled{RESET}")
            else:
                print(f"{CYAN}    Metadata-Only: Enabled{RESET}")

            if chksum != chksum:
                print(f"{RED}     Chksum: Invalid{RESET}")

            packets = []
            for i in range(1):
                pkt_header = f.read(12)
                if len(pkt_header) != 12:
                    break
                timestamp, size = struct.unpack('<dI', pkt_header)
                pkt_data = f.read(size)
                if len(pkt_data) != size:
                    break
                if is_compressed:
                    pkt_data = zlib.decompress(pkt_data)

                packet = Ether(pkt_data)
                packets.append(packet)

            metadata = {}
            if flags & FLAG_METADATA_ONLY:
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

            print(f"{GREEN}[+] Loaded {len(packets)} packets{RESET}")
            return packets, metadata

    except FileNotFoundError:
        print(f"{RED}[-] File not found: {filename}{RESET}")
        return None, None
    except Exception as e:
        print(f"{RED}[!] Load failed: {e}{RESET}")
        return None, None


class LightLab(cmd.Cmd):
    intro = f"""
{BOLD}{CYAN}LightLab v{version} - Lightscan Packet Crafting Laboratory{RESET}
{YELLOW}Type 'help' for commands{RESET}
"""
    prompt = f"{CYAN}LightLab>{RESET} "

    def __init__(self):
        super().__init__()
        self.packet_layers = []
        self.timeout = 10
        self.interval = 0.5
        self._history = []

        self.layer_params = {
            'ether': ['dst', 'src', 'type'],
            'vlan': ['prio', 'vlan', 'dei', 'type'],
            'arp': ['hwtype', 'ptype', 'hwlen', 'plen', 'op', 'hwsrc', 'psrc', 'hwdst', 'pdst'],
            'ip': ['dst', 'src', 'ttl', 'id', 'flags', 'proto', 'version', 'ihl', 'len', 'tos', 'frag', 'chksum'],
            'ipv6': ['dst', 'src', 'hlim', 'nh', 'version', 'tc', 'fl', 'plen'],
            'ndp_ns': ['tgt', 'type', 'code', 'cksum', 'res'],
            'ndp_na': ['tgt', 'R', 'S', 'O', 'type', 'code', 'cksum', 'res'],
            'ndp_rs': ['type', 'code', 'cksum', 'res'],
            'ndp_ra': ['chlim', 'M', 'O', 'H', 'P', 'prf', 'type', 'code', 'cksum', 'res', 'reachabletime',
                       'retranstimer', 'routerlifetime'],
            'tcp': ['dport', 'sport', 'flags', 'seq', 'ack','dataofs','chksum', 'window', 'urgptr', 'reserved', 'options'],
            'udp': ['dport', 'sport', 'len','chksum'],
            'dns': ['id', 'qr', 'opcode', 'aa', 'tc', 'rd', 'ra', 'z', 'rcode', 'qdcount', 'ancount', 'nscount',
                    'arcount', 'qd', 'an', 'ns', 'ar'],
            'icmp': ['type', 'code', 'id', 'seq','chksum','ts_ori','ts_rx','ts_tx','gw','ptr','reserved','addr_mask',
                     'nexthopmtu','unused','extpad','ext'],
            'icmpv6': ['type', 'code', 'cksum', 'msgbody'],
            'icmpv6_echo': ['type', 'code', 'cksum', 'id', 'seq', 'data'],
            'http': ['Method', 'Path', 'Http_Version', 'Host', 'Connection', 'Content_Type', 'Content_Length',
                     'User_Agent', 'Cookie', 'Referer', 'Accept', 'Accept_Language', 'Accept_Encoding',
                     'Upgrade_Insecure_Requests', 'Origin', 'Cache_Control', 'Pragma', 'Authorization',
                     'X_Forwarded_For',
                     'Proxy_Authorization', 'Proxy_Connection', 'Keep_Alive', 'X_Wap_Profile', 'X_Request_ID', 'DNT',
                     'TE',
                     'Date', 'Upgrade', 'X_ATT_DeviceId', 'X_Correlation_ID', 'X_Csrf_Token', 'X_Forwarded_Host',
                     'X_Forwarded_Proto',
                     'X_Http_Method_Override', 'X_Requested_With', 'X_UIDH', 'Unknown_Headers', 'Content_MD5'],
            'raw': ['load']
        }

    def onecmd(self, line):
        if line and line not in ['history', 'exit', 'quit']:
            self._history.append(line)
        return super().onecmd(line)

    def do_new(self, arg):
        if not arg:
            print(f"{RED}[!] Usage: new <layer>{RESET}")
            return

        layer_type = arg.lower()
        valid = ['ether', 'vlan', 'arp', 'ip', 'ipv6', 'tcp', 'udp', 'icmp', 'icmpv6', 'icmpv6_echo',
                 'http', 'raw', 'ndp_ns', 'ndp_na', 'ndp_rs', 'ndp_ra', 'dns']

        if layer_type not in valid:
            print(f"{RED}[!] Unknown: {layer_type}{RESET}")
            return

        self.packet_layers.append({'type': layer_type, 'params': {}})
        print(f"{GREEN}[+] Added {layer_type}{RESET}")
        self._show()

    def do_savebin(self, arg):
        if not arg:
            print(f"{RED}[!] Usage: savebin <filename.lbn>{RESET}")
            return

        packet = self._build()
        if not packet:
            print(f"{RED}[!] Nothing to save{RESET}")
            return

        save_binary(arg, [packet], self.packet_layers)

    def do_loadbin(self, arg):
        if not arg:
            print(f"{RED}[!] Usage: loadbin <filename.lbn>{RESET}")
            return

        packets, metadata = load_binary(arg)
        if not packets:
            return

        self.packet_layers = []

        if metadata and 'layers' in metadata:
            self.packet_layers = metadata['layers']
            print(f"{GREEN}[+] Loaded layers from metadata{RESET}")
        else:
            self._packet_to_layers(packets[0])

        print(f"{GREEN}[+] Loaded from {arg}{RESET}")
        self._show()

    def do_timeout(self, arg):
        try:
            self.timeout = int(arg)
            print(f"{GREEN}[+] Timeout set to {self.timeout} seconds{RESET}")
        except:
            print(f"{RED}[!] Invalid timeout{RESET}")

    def do_interval(self, arg):
        try:
            self.interval = int(arg)
            print(f"{GREEN}[+] Interval set to {self.interval} seconds{RESET}")
        except:
            print(f"{RED}[!] Invalid interval{RESET}")

    def do_params(self, arg):
        if not arg:
            print(f"{RED}[!] Usage: params <layer>{RESET}")
            return

        layer = arg.lower()
        if layer in self.layer_params:
            print(f"\n{BOLD}{layer.upper()} parameters:{RESET}")
            for p in self.layer_params[layer]:
                print(f"  {p}")
            print()
        else:
            print(f"{RED}[!] Unknown layer: {layer}{RESET}")

    def do_set(self, arg):
        if not arg:
            print(f"{RED}[!] Usage: set <layer>.<param>=<value>{RESET}")
            return

        try:
            if '=' not in arg or '.' not in arg:
                print(f"{RED}[!] Format: layer.param=value{RESET}")
                return

            left, value = arg.split('=', 1)
            value = value.strip().strip('"')
            layer_name, param = left.split('.', 1)
            layer_name = layer_name.lower()

            for layer in self.packet_layers:
                if layer['type'] == layer_name:
                    if param in ['dport', 'sport', 'ttl', 'id', 'hlim', 'seq', 'ack', 'window',
                                 'type', 'code', 'Status_Code', 'len', 'urgptr', 'reserved',
                                 'prio', 'dei', 'vlan', 'qdcount', 'ancount', 'nscount', 'arcount',
                                 'qr', 'opcode', 'aa', 'tc', 'rd', 'ra', 'z', 'rcode']:
                        try:
                            if isinstance(value, str) and value.lower().startswith('0x'):
                                value = int(value, 16)
                            else:
                                value = int(value)
                        except:
                            print(f"{RED}[!] {param} needs a number{RESET}")
                            return

                    layer['params'][param] = value
                    print(f"{GREEN}[+] {layer_name}.{param} = {value}{RESET}")
                    return

            print(f"{RED}[!] Layer '{layer_name}' not found{RESET}")
        except Exception as e:
            print(f"{RED}[!] Error: {e}{RESET}")

    def do_show(self, arg):
        self._show()

    def do_clear(self, arg):
        self.packet_layers = []
        print(f"{GREEN}[+] Cleared{RESET}")

    def do_send(self, arg):
        if not self.packet_layers:
            print(f"{RED}[!] No layers. Use 'new'{RESET}")
            return

        count = 1
        verbose = False
        if arg:
            parts = arg.split()
            if '-v' in parts:
                verbose = True
            for p in parts:
                if p.isdigit():
                    count = int(p)

        packet = self._build()
        if not packet:
            print(f"{RED}[!] Build failed{RESET}")
            return

        has_ether = any(l['type'] == 'ether' for l in self.packet_layers)
        has_http = any(l['type'] == 'http' for l in self.packet_layers)

        if verbose:
            print()
            packet.show2()
            print()

        print(f"{YELLOW}[*] Sending {count} packet(s)...{RESET}")

        for i in range(count):
            try:
                start = time.time()

                if has_http:
                    response = self._send_http(packet)
                    elapsed = (time.time() - start) * 1000
                    if response:
                        print(f"{GREEN}[+] Response ({elapsed:.2f}ms){RESET}")
                        print('=' * 50)
                        response.show2()
                        if response.haslayer(Raw):
                            raw = response[Raw].load
                            print(f"\n{CYAN}[RAW]{RESET}")
                            print(f"Hex: {raw.hex()}")
                            try:
                                text = raw.decode('utf-8', errors='ignore')
                                if text.strip():
                                    print(f"Text: {text[:500]}")
                            except:
                                pass
                        print('=' * 50)
                    else:
                        print(f"{YELLOW}[!] No response{RESET}")

                elif has_ether:
                    response, unanswered = srp(packet, timeout=self.timeout, verbose=0)
                    elapsed = (time.time() - start) * 1000
                    if response:
                        print(f"{GREEN}[+] Response ({elapsed:.2f}ms){RESET}")
                        print('=' * 50)
                        for sent, received in response:
                            received.show2()
                        print('=' * 50)
                    else:
                        print(f"{YELLOW}[!] No response{RESET}")

                else:
                    response = sr1(packet, timeout=self.timeout, verbose=0)
                    elapsed = (time.time() - start) * 1000
                    if response:
                        print(f"{GREEN}[+] Response ({elapsed:.2f}ms){RESET}")
                        print('=' * 50)
                        response.show2()
                        if response.haslayer(Raw):
                            raw = response[Raw].load
                            print(f"\n{CYAN}[RAW]{RESET}")
                            print(f"Hex: {raw.hex()[:200]}{'...' if len(raw) > 100 else ''}")
                            try:
                                text = raw.decode('utf-8', errors='ignore')
                                if text.strip():
                                    print(f"Text: {text[:500]}")
                            except:
                                pass
                        print('=' * 50)
                    else:
                        print(f"{YELLOW}[!] No response{RESET}")

                if count > 1 and i < count - 1:
                    time.sleep(self.interval)
            except Exception as e:
                print(f"{RED}[!] Error: {e}{RESET}")

    def do_save(self, arg):
        if not arg:
            print(f"{RED}[!] Usage: save <filename.pcap>{RESET}")
            return

        packet = self._build()
        if not packet:
            print(f"{RED}[!] Nothing to save{RESET}")
            return

        try:
            if Dot1Q in packet:
                if not packet.haslayer(Ether):
                    packet = Ether() / packet
                    print(f"{YELLOW}[!] Wrapped VLAN packet in Ethernet for PCAP compatibility{RESET}")

            wrpcap(arg, packet)
            print(f"{GREEN}[+] Saved to {arg}{RESET}")
        except Exception as e:
            print(f"{RED}[!] Save failed: {e}{RESET}")

    def do_load(self, arg):
        if not arg:
            print(f"{RED}[!] Usage: load <filename.pcap>{RESET}")
            return

        try:
            packets = rdpcap(arg)
            if not packets:
                print(f"{RED}[!] No packets in {arg}{RESET}")
                return

            self.packet_layers = []
            packet = packets[0]

            self._packet_to_layers(packet)

            print(f"{GREEN}[+] Loaded {len(packets)} packet(s) from {arg} (using first){RESET}")
            self._show()
        except Exception as e:
            print(f"{RED}[!] Load failed: {e}{RESET}")

    def _packet_to_layers(self, packet):
        layers = []
        current = packet

        if not packet.haslayer(Ether):
            pass

        while current:
            layer_name = current.name.lower()

            if layer_name == 'ethernet' and len(current.payload) == 0:
                current = current.payload if hasattr(current, 'payload') and current.payload else None
                continue

            if 'dot1q' in layer_name or 'vlan' in layer_name:
                layer_type = 'vlan'
                params = {}
                for field in current.fields_desc:
                    value = getattr(current, field.name)
                    if value is not None and value != field.default:
                        params[field.name] = value
                layers.append({'type': layer_type, 'params': params})
                current = current.payload if hasattr(current, 'payload') and current.payload else None
                continue

            elif 'dns' in layer_name:
                layer_type = 'dns'
                params = {}
                for field in current.fields_desc:
                    value = getattr(current, field.name)
                    if value is not None and value != field.default:
                        params[field.name] = value
                layers.append({'type': layer_type, 'params': params})
                current = current.payload if hasattr(current, 'payload') and current.payload else None
                continue

            elif layer_name == 'raw' and current.haslayer(Raw):
                raw_data = current[Raw].load
                try:
                    data_str = raw_data.decode('utf-8', errors='ignore')
                    if data_str.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ')):
                        lines = data_str.split('\r\n')
                        if lines:
                            request_line = lines[0].split(' ')
                            if len(request_line) >= 3:
                                http_params = {
                                    'Method': request_line[0],
                                    'Path': request_line[1],
                                    'Http_Version': request_line[2].split('/')[1] if '/' in request_line[2] else
                                    request_line[2]
                                }
                                for line in lines[1:]:
                                    if ': ' in line:
                                        key, val = line.split(': ', 1)
                                        key_clean = key.replace('-', '_')
                                        if key_clean in ['Host', 'User_Agent', 'Connection', 'Content_Type',
                                                         'Content_Length', 'Cookie', 'Referer', 'Accept']:
                                            http_params[key_clean] = val
                                layers.append({'type': 'http', 'params': http_params})
                                current = current.payload if hasattr(current, 'payload') and current.payload else None
                                continue
                except:
                    pass

                # If it's a raw layer with hex data, try to parse it as a packet
                if isinstance(raw_data, bytes) and len(raw_data) > 0:
                    try:
                        # Check if raw_data contains a valid IP packet
                        if raw_data[0] in [0x45, 0x46] and len(raw_data) > 20:
                            # It's an IP packet, parse it
                            from scapy.layers.inet import IP
                            ip = IP(raw_data)
                            self._packet_to_layers(ip)
                            return
                    except:
                        pass

            if 'neighbor solicitation' in layer_name:
                layer_type = 'ndp_ns'
            elif 'neighbor advertisement' in layer_name:
                layer_type = 'ndp_na'
            elif 'router solicitation' in layer_name:
                layer_type = 'ndp_rs'
            elif 'router advertisement' in layer_name:
                layer_type = 'ndp_ra'
            elif 'icmpv6 echo request' in layer_name:
                layer_type = 'icmpv6_echo'
            elif 'icmpv6 fallback class' in layer_name:
                layer_type = 'icmpv6'
            elif 'http request' in layer_name:
                layer_type = 'http'
            elif '802.1q' in layer_name:
                layer_type = 'vlan'
            elif 'ipv6' in layer_name:
                layer_type = 'ipv6'
            elif 'ip' in layer_name:
                layer_type = 'ip'
            elif 'tcp' in layer_name:
                layer_type = 'tcp'
            elif 'udp' in layer_name:
                layer_type = 'udp'
            elif 'icmp' in layer_name and 'v6' not in layer_name:
                layer_type = 'icmp'
            elif 'icmpv6' in layer_name:
                layer_type = 'icmpv6'
            elif 'arp' in layer_name:
                layer_type = 'arp'
            else:
                name_map = {
                    'ethernet': 'ether',
                    'ip': 'ip',
                    'ipv6': 'ipv6',
                    'tcp': 'tcp',
                    'udp': 'udp',
                    'icmp': 'icmp',
                    'icmpv6': 'icmpv6',
                    'raw': 'raw',
                    'arp': 'arp',
                    'ndp_rs': 'ndp_rs',
                    'ndp_ra': 'ndp_ra',
                    'ndp_ns': 'ndp_ns',
                    'ndp_na': 'ndp_na',
                }
                layer_type = name_map.get(layer_name, layer_name)

            if layer_type == 'raw' and layers and layers[-1].get('type') == 'http':
                current = current.payload if hasattr(current, 'payload') and current.payload else None
                continue

            params = {}
            for field in current.fields_desc:
                value = getattr(current, field.name)
                if value is not None and value != field.default:
                    if layer_type == 'tcp' and field.name == 'flags':
                        flag_map = {0x01: 'F', 0x02: 'S', 0x04: 'R', 0x08: 'P', 0x10: 'A', 0x20: 'U', 0x40: 'E',
                                    0x80: 'C'}
                        flag_str = ''
                        for fnum, fchar in flag_map.items():
                            if value & fnum:
                                flag_str += fchar
                        params[field.name] = flag_str if flag_str else 'None'
                    elif layer_type == 'ip' and field.name == 'flags':
                        params[field.name] = str(value)
                    elif field.name == 'load' and isinstance(value, bytes):
                        if not (layers and layers[-1].get('type') == 'http'):
                            try:
                                params[field.name] = value.decode('utf-8', errors='ignore')
                            except:
                                params[field.name] = value.hex()
                    elif field.name == 'dst' and isinstance(value, bytes):
                        continue
                    elif field.name == 'src' and isinstance(value, bytes):
                        continue
                    else:
                        params[field.name] = value

            if params:
                layers.append({'type': layer_type, 'params': params})

            current = current.payload if hasattr(current, 'payload') and current.payload else None

        self.packet_layers = layers

    def do_templates(self, arg):
        print(f"""
{BOLD}{CYAN}===== LightLab Templates ====={RESET}

{BOLD}1. TCP SYN Scan:{RESET}
  new ip
  set ip.dst=192.168.1.1
  new tcp
  set tcp.dport=80
  set tcp.flags=S
  send -v

{BOLD}2. HTTP GET Request:{RESET}
  new ip
  set ip.dst=example.com
  new tcp
  set tcp.dport=80
  new http
  set http.Method=GET
  set http.Path=/
  set http.Host=example.com
  send -v

{BOLD}3. HTTP POST Request:{RESET}
  new ip
  set ip.dst=example.com
  new tcp
  set tcp.dport=80
  new http
  set http.Method=POST
  set http.Path=/login
  set http.Host=example.com
  set http.Content_Type=application/x-www-form-urlencoded
  new raw
  set raw.load=username=admin&password=test
  send -v

{BOLD}4. UDP DNS Query:{RESET}
  new ip
  set ip.dst=8.8.8.8
  new udp
  set udp.dport=53
  new dns
  set dns.id=1234
  set dns.rd=1
  set dns.qd=DNSQR(qname="google.com", qtype=1)
  send -v

{BOLD}5. ICMP Ping:{RESET}
  new ip
  set ip.dst=192.168.1.1
  new icmp
  set icmp.type=8
  set icmp.id=1234
  set icmp.seq=1
  send -v

{BOLD}6. ARP Request:{RESET}
  new ether
  set ether.dst=ff:ff:ff:ff:ff:ff
  new arp
  set arp.pdst=192.168.1.1
  send -v

{BOLD}7. VLAN Tagged Packet:{RESET}
  new vlan
  set vlan.vlan=100
  set vlan.prio=5
  new ip
  set ip.dst=192.168.1.1
  new icmp
  send -v

{BOLD}8. Custom TCP with Options:{RESET}
  new ip
  set ip.dst=192.168.1.1
  new tcp
  set tcp.dport=443
  set tcp.flags=S
  set tcp.window=65535
  set tcp.options=[('MSS', 1460), ('SAckOK', ''), ('WScale', 7)]
  send -v

{BOLD}9. IPv6 ICMPv6 Echo:{RESET}
  new ipv6
  set ipv6.dst=::1
  new icmpv6_echo
  send -v

{BOLD}10. IPv6 Neighbor Solicitation:{RESET}
  new ipv6
  set ipv6.dst=ff02::1:ff00:1234
  new ndp_ns
  set ndp_ns.tgt=fe80::1234
  send -v

{BOLD}11. DNS ANY Query (Amplification Test):{RESET}
  new ip
  set ip.src=192.168.1.100
  set ip.dst=8.8.8.8
  new udp
  set udp.dport=53
  new dns
  set dns.id=5678
  set dns.rd=1
  set dns.qd=DNSQR(qname="isc.org", qtype=255,unicastresponse=0,qclass=1)
  send -v

{BOLD}12. VLAN (Dot1Q):{RESET}
  new vlan
  set vlan.vlan=1
  new vlan
  set vlan.vlan=100
  new ip
  set ip.dst=192.168.100.1
  new icmp
  send -v
""")

    def do_exit(self, arg):
        print(f"{CYAN}[+] Bye from Heretic{RESET}")
        return True

    def do_delete(self, arg):
        for i, layer in enumerate(self.packet_layers):
            if layer['type'] == arg.lower():
                self.packet_layers.pop(i)
                print(f"{GREEN}[+] Removed {arg}{RESET}")
                self._show()
                return
        print(f"{RED}[!] Layer not found{RESET}")

    def do_quit(self, arg):
        return self.do_exit(arg)

    def do_history(self, arg):
        """Show command history"""
        if not self._history:
            print(f"{YELLOW}[!] No history{RESET}")
            return

        for i, cmd in enumerate(self._history, 1):
            print(f"{i:4}  {cmd}")

    def do_help(self, arg):
        print(f"""
{BOLD}{CYAN}LightLab v{version} Commands{RESET}

{BOLD}Layer Management:{RESET}
  {GREEN}new <layer>{RESET}        - Add layer (ether,vlan,arp,ip,ipv6,tcp,udp,icmp,ndp_rs,ndp_ra,ndp_na,ndp_ns,icmpv6,icmpv6_echo,http,dns,raw)
  {GREEN}delete <layer>{RESET}        - Delete layer
  {GREEN}params <layer>{RESET}        - Show available parameters for a layer
  {GREEN}set <layer>.<param>=<value>{RESET} - Set parameter value
  {GREEN}show{RESET}                 - Show current packet structure
  {GREEN}clear{RESET}               - Clear all layers

{BOLD}Packet Operations:{RESET}
  {GREEN}send [count] [-v]{RESET}    - Send packet (count=number, -v=verbose)
  {GREEN}timeout <seconds>{RESET}    - Set response timeout
  {GREEN}interval <seconds>{RESET}    - Set interval time between packets

{BOLD}Help:{RESET}
  {GREEN}templates{RESET}            - Show example configurations
  {GREEN}history{RESET}             - Show command history
  {GREEN}help{RESET}                - Show this message
  {GREEN}exit{RESET}                - Quit LightLab

{BOLD}File Operations:{RESET}
  {GREEN}save <filename.pcap/.pcapng>{RESET}     - Save current packet to PCAP/PCAPNG
  {GREEN}load <filename.pcap/.pcapng>{RESET}     - Load packet from PCAP/PCAPNG
  {GREEN}savebin <filename.lbn>{RESET}  - Save current packet to LightBin
  {GREEN}loadbin <filename.lbn>{RESET}  - Load packet from LightBin

{BOLD}Example Workflow:{RESET}
  LightLab> {CYAN}new ip{RESET}
  LightLab> {CYAN}params tcp{RESET}
  LightLab> {CYAN}set ip.dst=192.168.1.1{RESET}
  LightLab> {CYAN}new tcp{RESET}
  LightLab> {CYAN}set tcp.dport=80{RESET}
  LightLab> {CYAN}set tcp.flags=S{RESET}
  LightLab> {CYAN}send -v{RESET}

{BOLD}DNS Example:{RESET}
  LightLab> {CYAN}new ip{RESET}
  LightLab> {CYAN}set ip.dst=8.8.8.8{RESET}
  LightLab> {CYAN}new udp{RESET}
  LightLab> {CYAN}set udp.dport=53{RESET}
  LightLab> {CYAN}new dns{RESET}
  LightLab> {CYAN}set dns.id=1234{RESET}
  LightLab> {CYAN}set dns.rd=1{RESET}
  LightLab> {CYAN}set dns.qd=DNSQR(qname="google.com", qtype=1,unicastresponse=0,qclass=1){RESET}
  LightLab> {CYAN}send -v{RESET}

{BOLD}VLAN Example:{RESET}
  LightLab> {CYAN}new vlan{RESET}
  LightLab> {CYAN}set vlan.vlan=100{RESET}
  LightLab> {CYAN}new ip{RESET}
  LightLab> {CYAN}set ip.dst=192.168.1.1{RESET}
  LightLab> {CYAN}new icmp{RESET}
  LightLab> {CYAN}send -v{RESET}
""")

    def _show(self):
        if not self.packet_layers:
            print(f"{YELLOW}[!] No layers{RESET}")
            return

        print(f"\n{BOLD}{CYAN}Current Packet (layers from bottom to top):{RESET}")
        for i, layer in enumerate(self.packet_layers):
            print(f"  {i + 1}. {BOLD}{layer['type'].upper()}{RESET}")
            if layer['params']:
                for p, v in layer['params'].items():
                    if p in ['qd', 'an', 'ns', 'ar'] and hasattr(v, 'summary'):
                        print(f"       {p}: {v.summary()}")
                    else:
                        print(f"       {p}: {v}")
        print()

    def _send_http(self, packet):
        if not packet.haslayer(IP):
            print(f"{RED}[!] HTTP requires an IP layer{RESET}")
            return None

        ip_layer = packet[IP]
        tcp_layer = packet[TCP] if packet.haslayer(TCP) else None

        if tcp_layer and tcp_layer.dport == 80:
            dst = ip_layer.dst
            dport = tcp_layer.dport
        elif tcp_layer and tcp_layer.sport == 80:
            dst = ip_layer.src
            dport = tcp_layer.sport
        else:
            dst = ip_layer.dst
            dport = 80

        sport = random.randint(1024, 65535)

        http_layer = None
        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            print(f"{YELLOW}[*] Found HTTPRequest layer{RESET}")
        elif packet.haslayer(Raw):
            raw_data = packet[Raw].load
            try:
                http_str = raw_data.decode('utf-8', errors='ignore')
                if http_str.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ')):
                    lines = http_str.split('\r\n')
                    if lines:
                        request_line = lines[0].split(' ')
                        if len(request_line) >= 3:
                            method = request_line[0]
                            path = request_line[1]
                            http_ver = request_line[2].split('/')[1] if '/' in request_line[2] else request_line[2]

                            host = 'localhost'
                            user_agent = f'LightLab/{version}'
                            connection = 'close'
                            content_type = None
                            content_length = 0

                            for line in lines[1:]:
                                if ': ' in line:
                                    key, val = line.split(': ', 1)
                                    key_lower = key.lower()
                                    if key_lower == 'host':
                                        host = val
                                    elif key_lower == 'user-agent':
                                        user_agent = val
                                    elif key_lower == 'connection':
                                        connection = val
                                    elif key_lower == 'content-type':
                                        content_type = val
                                    elif key_lower == 'content-length':
                                        content_length = int(val)

                            http_layer = HTTPRequest(
                                Method=method,
                                Path=path,
                                Http_Version=http_ver,
                                Host=host,
                                User_Agent=user_agent,
                                Connection=connection
                            )
                            if content_type:
                                http_layer.Content_Type = content_type
                            if content_length:
                                http_layer.Content_Length = str(content_length)

                            print(f"{YELLOW}[*] Parsed HTTP request from Raw layer{RESET}")
            except Exception as e:
                print(f"{YELLOW}[!] Could not parse Raw as HTTP: {e}{RESET}")

        if not http_layer:
            print(f"{RED}[!] No HTTPRequest layer found in packet{RESET}")
            return None

        print(f"{YELLOW}[*] TCP handshake to {dst}:{dport}...{RESET}")
        syn = IP(dst=dst) / TCP(sport=sport, dport=dport, flags='S', seq=1000)
        syn_ack = sr1(syn, timeout=self.timeout, verbose=0)

        if not syn_ack or not syn_ack.haslayer(TCP):
            print(f"{RED}[!] No SYN-ACK — host may be down or port closed{RESET}")
            return None

        server_seq = syn_ack[TCP].seq
        server_ack = syn_ack[TCP].ack

        ack = IP(dst=dst) / TCP(
            sport=sport, dport=dport, flags='A',
            seq=server_ack, ack=server_seq + 1
        )
        send(ack, verbose=0)

        http_pkt = IP(dst=dst) / TCP(
            sport=sport, dport=dport, flags='PA',
            seq=server_ack, ack=server_seq + 1
        ) / http_layer

        print(f"{YELLOW}[*] Sending HTTP request...{RESET}")
        print(f"{CYAN}[DEBUG] Request: {http_layer.Method} {http_layer.Path} HTTP/{http_layer.Http_Version}{RESET}")

        response = sr1(http_pkt, timeout=self.timeout, verbose=0)

        if response and response.haslayer(Raw):
            raw_response = response[Raw].load
            try:
                resp_str = raw_response.decode('utf-8', errors='ignore')
                if resp_str.startswith('HTTP/'):
                    print(f"{GREEN}[+] HTTP Response received:{RESET}")
                    lines = resp_str.split('\r\n')
                    if lines:
                        print(f"    {lines[0]}")
            except:
                pass

        return response

    def _build(self):
        packet = None
        for info in self.packet_layers:
            t = info['type'].lower()
            p = info['params'].copy()

            if t in ['http', 'http request', 'http_request']:
                http_params = {}
                for k, v in p.items():
                    if isinstance(v, bytes):
                        v = v.decode('utf-8', errors='ignore')
                    if k == 'Http_Version':
                        k = 'Http_Version'
                    elif k == 'User_Agent':
                        k = 'User_Agent'
                    elif k == 'Content_Type':
                        k = 'Content_Type'
                    elif k == 'Content_Length':
                        k = 'Content_Length'
                    http_params[k] = v
                layer = HTTP() / HTTPRequest(**http_params)
            elif t == 'ether':
                layer = Ether(**p)
            elif t == 'vlan':
                vlan_params = {}
                if 'prio' in p:
                    vlan_params['prio'] = p['prio']
                if 'vlan' in p:
                    vlan_params['vlan'] = p['vlan']
                if 'dei' in p:
                    vlan_params['dei'] = p['dei']
                if 'type' in p:
                    vlan_params['type'] = p['type']
                layer = Dot1Q(**vlan_params)
            elif t == 'arp':
                layer = ARP(**p)
            elif t == 'ip':
                if 'dst' in p and isinstance(p['dst'], bytes):
                    p['dst'] = p['dst'].decode('utf-8', errors='ignore')
                if 'src' in p and isinstance(p['src'], bytes):
                    p['src'] = p['src'].decode('utf-8', errors='ignore')
                layer = IP(**p)

            elif t == 'ipv6':
                layer = IPv6(**p)
            elif t == 'ndp_ns':
                from scapy.layers.inet6 import ICMPv6ND_NS
                layer = ICMPv6ND_NS(**p)
            elif t == 'ndp_na':
                from scapy.layers.inet6 import ICMPv6ND_NA
                layer = ICMPv6ND_NA(**p)
            elif t == 'ndp_rs':
                from scapy.layers.inet6 import ICMPv6ND_RS
                layer = ICMPv6ND_RS(**p)
            elif t == 'ndp_ra':
                from scapy.layers.inet6 import ICMPv6ND_RA
                layer = ICMPv6ND_RA(**p)
            elif t == 'tcp':
                if 'options' in p and isinstance(p['options'], str):
                    try:
                        p['options'] = ast.literal_eval(p['options'])
                    except:
                        pass
                if 'sport' in p and isinstance(p['sport'], bytes):
                    p['sport'] = int(p['sport'].decode('utf-8', errors='ignore'))
                if 'dport' in p and isinstance(p['dport'], bytes):
                    p['dport'] = int(p['dport'].decode('utf-8', errors='ignore'))
                layer = TCP(**p)
            elif t == 'udp':
                layer = UDP(**p)
            elif t == 'dns':
                dns_params = {}
                for k, v in p.items():
                    if k in ['qd', 'an', 'ns', 'ar']:
                        if isinstance(v, str):
                            if 'DNSQR' in v:
                                import re
                                match = re.search(r"qname=['\"]([^'\"]+)['\"]", v)
                                qname = match.group(1) if match else "."
                                match = re.search(r"qtype[=:]\s*(\d+)", v)
                                qtype = int(match.group(1)) if match else 1
                                match = re.search(r"qclass[=:]\s*(\d+)", v)
                                qclass = int(match.group(1)) if match else 1

                                dns_params[k] = DNSQR(qname=qname, qtype=qtype, qclass=qclass)
                            elif 'DNSRR' in v:
                                import re
                                match = re.search(r"rrname=['\"]([^'\"]+)['\"]", v)
                                rrname = match.group(1) if match else "."
                                match = re.search(r"type[=:]\s*(\d+)", v)
                                rtype = int(match.group(1)) if match else 1
                                match = re.search(r"rdata=['\"]([^'\"]+)['\"]", v)
                                rdata = match.group(1) if match else ""
                                dns_params[k] = DNSRR(rrname=rrname, type=rtype, rdata=rdata)
                            else:
                                dns_params[k] = v
                        else:
                            dns_params[k] = v
                    else:
                        dns_params[k] = v
                layer = DNS(**dns_params)
            elif t == 'icmp':
                layer = ICMP(**p)
            elif t == 'icmpv6':
                layer = ICMPv6Unknown(**p)
            elif t == 'icmpv6_echo':
                layer = ICMPv6EchoRequest(**p)
            elif t == 'raw':
                if 'load' in p:
                    load = p['load']
                    if isinstance(load, str):
                        test = load.replace(' ', '').replace('\\x', '')
                        if all(c in '0123456789abcdefABCDEF' for c in test) and '\\x' in load:
                            try:
                                load = bytes.fromhex(test)
                            except:
                                pass
                        elif '\\x' in load:
                            try:
                                load = load.encode('utf-8').decode('unicode_escape').encode('latin-1')
                            except:
                                pass
                    p['load'] = load
                layer = Raw(**p)
            else:
                print(f"{RED}[!] Unknown layer type: {t}{RESET}")
                return None

            packet = layer if packet is None else packet / layer
        return packet


if __name__ == "__main__":
    try:
        LightLab().cmdloop()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Exiting{RESET}")
        sys.exit(0)