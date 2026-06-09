from scapy.layers.inet import IP, TCP, sr1
from scapy.layers.inet6 import IPv6, TCP as TCP6
import random
import ipaddress

red = "\033[31m"
reset = "\033[0m"
yellow = "\033[33m"
green = "\033[32m"
cyan = "\033[36m"


class OS_DB:
    def __init__(self):
        self.os_signatures = {
            'Linux': {
                'common_orders': [
                    ['MSS', 'SAckOK', 'Timestamp', 'WScale'],
                    ['MSS', 'SAckOK', 'Timestamp', 'NOP', 'WScale'],
                    ['MSS', 'WScale', 'SAckOK', 'Timestamp'],
                    ['MSS', 'NOP', 'WScale', 'NOP', 'NOP', 'SAckOK', 'Timestamp'],
                    ['MSS', 'Timestamp', 'SAckOK', 'WScale'],
                    ['MSS', 'SAckOK', 'Timestamp', 'NOP', 'NOP', 'WScale']
                ],
                'windows': [5720, 29200, 65535, 64240, 32120, 65160],
                'ttl_range': (64, 255),
                'hlim_range': (64, 255),  # IPv6 Hop Limit
                'timestamp_high': True
            },
            'BSD': {
                'common_orders': [
                    ['MSS', 'NOP', 'WScale', 'SAckOK', 'Timestamp'],
                    ['MSS', 'SAckOK', 'Timestamp', 'WScale'],
                    ['MSS', 'NOP', 'WScale', 'NOP', 'NOP', 'SAckOK', 'Timestamp'],
                    ['MSS', 'WScale', 'SAckOK', 'Timestamp'],
                    ['MSS', 'NOP', 'WScale', 'Timestamp', 'SAckOK']
                ],
                'windows': [65535, 57344, 29200, 16384, 8760, 17520],
                'ttl_range': (64, 64),
                'hlim_range': (64, 64),
                'timestamp_high': True,
                'ip_id_sequential': True
            },
            'Windows': {
                'common_orders': [
                    ['MSS', 'NOP', 'WScale', 'NOP', 'NOP', 'SAckOK', 'NOP', 'NOP'],
                    ['MSS', 'NOP', 'WScale', 'NOP', 'NOP', 'SAckOK'],
                    ['WScale', 'MSS', 'SAckOK', 'Timestamp'],
                    ['MSS', 'NOP', 'WScale', 'SAckOK', 'NOP', 'NOP', 'Timestamp'],
                    ['MSS', 'SAckOK', 'Timestamp', 'WScale'],
                    ['MSS', 'NOP', 'WScale', 'NOP', 'NOP', 'SAckOK']
                ],
                'windows': [64240, 65535, 8192, 16384, 32768, 25600, 51200, 5840],
                'ttl_range': (65, 128),
                'hlim_range': (65, 128),
                'timestamp_high': False
            },
            'Cisco': {
                'common_orders': [
                    ['MSS', 'SAckOK'],
                    ['MSS', 'SAckOK', 'Timestamp']
                ],
                'windows': [4128, 9112, 16384, 32768],
                'ttl_range': (255, 255),
                'hlim_range': (255, 255),
                'timestamp_high': False
            },
            'Android': {
                'common_orders': [
                    ['MSS', 'SAckOK', 'Timestamp', 'NOP', 'WScale'],
                    ['MSS', 'SAckOK', 'Timestamp', 'WScale'],
                    ['MSS', 'NOP', 'WScale', 'NOP', 'SAckOK', 'Timestamp']
                ],
                'windows': [65535, 29200, 64240, 14600, 32120, 8760],
                'ttl_range': (64, 64),
                'hlim_range': (64, 64),
                'timestamp_high': True
            },
            'MacOS': {
                'common_orders': [
                    ['MSS', 'NOP', 'NOP', 'SAckOK', 'Timestamp', 'NOP', 'WScale'],
                    ['MSS', 'SAckOK', 'Timestamp', 'WScale']
                ],
                'windows': [65535, 32768],
                'ttl_range': (64, 64),
                'hlim_range': (64, 64),
                'timestamp_high': True
            }
        }

        self.ipv6_signatures = {
            'Linux': {
                'common_orders': self.os_signatures['Linux']['common_orders'],
                'windows': self.os_signatures['Linux']['windows'],
                'hlim_range': (64, 255),
                'timestamp_high': True
            },
            'Windows': {
                'common_orders': self.os_signatures['Windows']['common_orders'],
                'windows': self.os_signatures['Windows']['windows'],
                'hlim_range': (65, 128),
                'timestamp_high': False
            },
            'BSD': {
                'common_orders': self.os_signatures['BSD']['common_orders'],
                'windows': self.os_signatures['BSD']['windows'],
                'hlim_range': (64, 64),
                'timestamp_high': True
            },
            'Android': {
                'common_orders': self.os_signatures['Android']['common_orders'],
                'windows': self.os_signatures['Android']['windows'],
                'hlim_range': (64, 64),
                'timestamp_high': True
            },
            'MacOS': {
                'common_orders': self.os_signatures['MacOS']['common_orders'],
                'windows': self.os_signatures['MacOS']['windows'],
                'hlim_range': (64, 64),
                'timestamp_high': True
            }
        }

    def is_ipv6(self, target):
        try:
            ipaddress.IPv6Address(target)
            return True
        except:
            return False

    def craft_probe(self, target, port, version=4):
        if version == 6:
            probe = IPv6(
                dst=target,
                hlim=128,
                nh=6
            ) / TCP6(
                dport=port,
                sport=random.randint(60000, 65535),
                seq=random.randint(1000000000, 4294967295),
                window=65535,
                options=[
                    ('MSS', 1460),
                    ('SAckOK', b''),
                    ('Timestamp', (random.randint(1, 1000000000), 0)),
                    ('NOP', None),
                    ('WScale', 8)
                ],
                flags="S"
            )
        else:
            probe = IP(
                dst=target,
                id=random.randint(1, 65535),
                ttl=128
            ) / TCP(
                dport=port,
                sport=random.randint(60000, 65535),
                seq=random.randint(1000000000, 4294967295),
                window=65535,
                options=[
                    ('MSS', 1460),
                    ('SAckOK', b''),
                    ('Timestamp', (random.randint(1, 1000000000), 0)),
                    ('NOP', None),
                    ('WScale', 8)
                ],
                flags="S"
            )
        return probe

    def send_probe(self, probe, timeout=2, version=4):
        if version == 6:
            return sr1(probe, timeout=timeout, verbose=False)
        else:
            return sr1(probe, timeout=timeout, verbose=False)

    def OS_fingerprint(self, target, open_ports, banner, Services, window_scan_os, verbose=False, print_output=True,
                       version=4):
        os_that_have_versions_detection = ['BSD', 'Android']
        os_list = {
            'Linux': 0,
            'Windows': 0,
            'Cisco': 0,
            'BSD': 0,
            'Android': 0,
            'MacOS': 0,
            'IOS': 0,
            'Unknown': 0
        }

        if not open_ports:
            if print_output:
                print(f"\n{yellow}[!] Lightscan need at least 1 open port for OS detection{reset}")
            return

        for port in open_ports[:5]:
            try:
                probe = self.craft_probe(target, port, version)
                resp = self.send_probe(probe, timeout=2, version=version)

                if resp and resp.haslayer(TCP if version == 4 else TCP6) and resp.haslayer(
                        IPv6 if version == 6 else IP):
                    tcp_layer = resp.getlayer(TCP if version == 4 else TCP6)
                    ip_layer = resp.getlayer(IPv6 if version == 6 else IP)

                    if tcp_layer.flags & 0x12:
                        if version == 6:
                            hlim = ip_layer.hlim
                            ttl = hlim
                        else:
                            ttl = ip_layer.ttl
                            hlim = ttl

                        window = tcp_layer.window
                        options = tcp_layer.options

                        if verbose:
                            if print_output:
                                print(f"\n[+] Response from port {port} (IPv{version}):")
                                print(f"    Window: {window}")
                                print(f"    {'Hop Limit' if version == 6 else 'TTL'}: {hlim if version == 6 else ttl}")
                                if version == 4:
                                    print(f"    IP ID: {ip_layer.id}")
                                print(f"    TCP Seq: {tcp_layer.seq}")
                                print(f"    Options: {options}")

                        analysis = self.analyze_options(options, getattr(ip_layer, 'id', 0), version)
                        port_scores = self.match_os_signature(analysis, window, hlim if version == 6 else ttl, banner,
                                                              Services, version)

                        for os_type, score in port_scores.items():
                            os_list[os_type] += score

            except Exception as e:
                if verbose:
                    if print_output:
                        print(f"{red}[!] OS fingerprint error on port {port} (IPv{version}): {e}{reset}")
                continue

        Top_1 = max(os_list.values()) if os_list.values() else 0
        total_score = sum(os_list.values())

        if total_score > 0:
            if print_output:
                print(f"\n[+] OS Fingerprint Results (IPv{version}):")
                print("-" * 40)
                for os_type, score in sorted(os_list.items(), key=lambda x: x[1], reverse=True):
                    percentage = (score / total_score) * 100
                    if Top_1 == score:
                        print(f"    [+] {os_type:12} : {percentage:5.1f}% (score: {score:.1f})")
                        if os_type in os_that_have_versions_detection:
                            if os_type == "BSD":
                                for b in banner:
                                    bsd = self.detect_freebsd_version(b)
                                    if bsd:
                                        print(f"         --> [-] {bsd}")
                    else:
                        if verbose:
                            print(f"    [+] {os_type:12} : {percentage:5.1f}% (score: {score:.1f})")
            else:
                for os_type, score in sorted(os_list.items(), key=lambda x: x[1], reverse=True):
                    if Top_1 == score:
                        window_scan_os.append(os_type)
        else:
            if print_output:
                print(f"\n[!] No conclusive OS fingerprint detected (IPv{version})")

    def detect_freebsd_version(self, banner):
        version_map = {
            '20170902': '10.4-RELEASE',
            '20160310': '10.3-RELEASE',
            '20140420': '9.3-RELEASE | 10.1,10.2-RELEASE',
            '20140131': '9.2-RELEASE',
            '20130630': '9.1-RELEASE',
            '20121220': '9.0-RELEASE',
            '20120630': '8.3-RELEASE',
            '20111222': '8.2-RELEASE',
            '20110225': '8.1-RELEASE',
            '20101124': '8.0-RELEASE',
            '20091128': '7.2-RELEASE',
            '20090104': '7.1-RELEASE',
            '20080228': '7.0-RELEASE'
        }

        for date_str, version in version_map.items():
            if date_str in banner:
                return f"FreeBSD {version}"

        if "OpenSSH_6.6" in banner:
            return "FreeBSD 9.x | FreeBSD 10.x"
        elif "OpenSSH_7.3" in banner:
            return "FreeBSD 10.4-RELEASE"
        elif "OpenSSH_7.2" in banner:
            return "FreeBSD 10.3-RELEASE"
        elif "OpenSSH_5." in banner:
            return "FreeBSD 8.x"
        elif "OpenSSH_4." in banner:
            return "FreeBSD 7.x"
        elif "OpenSSH" not in banner:
            return None

        if "FreeBSD" in banner:
            return "FreeBSD (unknown version)"
        else:
            return "BSD (unknown version)"

    @staticmethod
    def analyze_options(options, packet_id, version=4):
        if not options:
            return {}

        analysis = {
            'order': [opt[0] for opt in options],
            'mss': None,
            'wscale': None,
            'timestamp': None,
            'sack': False,
            'id': packet_id,
            'version': version
        }

        for opt_name, opt_value in options:
            if opt_name == 'MSS':
                analysis['mss'] = opt_value
            elif opt_name == 'WScale':
                analysis['wscale'] = opt_value
            elif opt_name == 'Timestamp':
                analysis['timestamp'] = opt_value
            elif opt_name == 'SAckOK':
                analysis['sack'] = True

        return analysis

    def match_os_signature(self, analysis, window, hop_limit, banners, Services, version=4):
        scores = {
            'Linux': 0,
            'Windows': 0,
            'Cisco': 0,
            'BSD': 0,
            'Android': 0,
            'MacOS': 0,
            'IOS': 0,
            'Unknown': 0
        }

        signatures = self.ipv6_signatures if version == 6 else self.os_signatures

        option_order = analysis.get('order', [])

        for os_name, signature in signatures.items():
            for common_order in signature.get('common_orders', []):
                if option_order == common_order:
                    scores[os_name] += 8

            if window in signature.get('windows', []):
                scores[os_name] += 5

            hlim_min, hlim_max = signature.get('hlim_range', (0, 0))
            if hlim_min <= hop_limit <= hlim_max:
                scores[os_name] += 3

        if analysis.get('timestamp') and isinstance(analysis['timestamp'], tuple):
            ts_val, _ = analysis['timestamp']
            if ts_val > 100000000:
                scores['Linux'] += 2
                scores['BSD'] += 2

        if analysis.get('mss') == 65495 or analysis.get('mss') == 5840:
            scores['Windows'] += 8
        if analysis.get('mss') == 1380:
            scores['Linux'] += 8
        if analysis.get('mss') == 1460:
            scores['Android'] += 8
            scores['BSD'] += 8
        if version == 4 and analysis.get('id') == 0:
            scores['Android'] += 5

        if analysis.get('wscale') == 8:
            scores['Windows'] += 5
            scores['Linux'] += 2
            scores['Android'] += 3.5
        if analysis.get('wscale') == 13 or analysis.get('wscale') == 7:
            scores['Linux'] += 5
        if analysis.get('wscale') == 6:
            scores['BSD'] += 5

        if version == 6:
            if hop_limit <= 64:
                if window == 65535:
                    scores['Linux'] += 2
                    scores['BSD'] += 2
                    scores['Android'] += 2
                if window in [29200, 14600, 64240]:
                    scores['Android'] += 1.25
                    scores['Linux'] += 3
                if window in [57344, 29200, 16384, 8760, 17520]:
                    scores['BSD'] += 4
                if window in [65160]:
                    scores['Linux'] += 3.5
                elif window in [32768, 16384, 8760]:
                    scores['IOS'] += 4
                else:
                    scores['Linux'] += 2
            if hop_limit == 255:
                scores['Windows'] = 0
                scores['Linux'] = 0
                scores['MacOS'] = 0
                scores['Android'] = 0
                scores['IOS'] = 0
                scores['Cisco'] = 10
        else:
            if hop_limit <= 64:
                if window == 65535:
                    scores['Linux'] += 2
                    scores['BSD'] += 2
                    scores['Android'] += 2
                if window in [29200, 14600, 64240]:
                    scores['Android'] += 1.25
                    scores['Linux'] += 3
                if window in [57344, 29200, 16384, 8760, 17520]:
                    scores['BSD'] += 4
                if window in [65160]:
                    scores['Linux'] += 3.5
                elif window in [32768, 16384, 8760]:
                    scores['IOS'] += 4
                else:
                    scores['Linux'] += 2
            if hop_limit <= 128:
                scores['Windows'] += 8
            if hop_limit == 255:
                scores['Windows'] = 0
                scores['Linux'] = 0
                scores['MacOS'] = 0
                scores['Android'] = 0
                scores['IOS'] = 0
                scores['Cisco'] = 10

        for banner in banners:
            if "freebsd" in banner.lower():
                scores['BSD'] += 15
                for k in ['Linux', 'Android', 'IOS', 'Windows', 'MacOS', 'Cisco']:
                    scores[k] = 0
            if "dnsmasq" in banner.lower():
                scores['Android'] += 15
                scores['Linux'] += 5
                for k in ['IOS', 'Windows', 'MacOS', 'Cisco']:
                    scores[k] = 0
            if "server: microsoft-httpapi" in banner.lower():
                scores['Windows'] += 25
                for k in ['MacOS', 'Cisco', 'Android', 'Linux', 'IOS']:
                    scores[k] = 0
            if "msrpc" in Services:
                scores['Windows'] += 25
                for k in ['MacOS', 'Cisco', 'Android', 'Linux', 'IOS']:
                    scores[k] = 0
            if "microsoft-ds" in Services:
                scores['Windows'] += 12.5
            if "centos" in banner.lower() or "ubuntu" in banner.lower() or "debian" in banner.lower():
                for k in ['Windows', 'Android', 'Cisco', 'IOS', 'MacOS']:
                    scores[k] = 0
                scores['Linux'] = 25
            if "openssh" in banner.lower():
                if "hpn13v11" in banner.lower() or "hpn14v" in banner.lower():
                    scores['BSD'] += 15
                    scores['Linux'] = 0
                else:
                    scores['Linux'] += 10
                    scores['BSD'] += 2.5
            if "microsoft" in banner.lower() or "iis" in banner.lower():
                scores['Windows'] += 15
            if "apache" in banner.lower() or "nginx" in banner.lower():
                scores['Linux'] += 15
            if "vsftpd" in banner.lower() or "Proftpd" in banner.lower() or "pure-ftpd" in banner.lower():
                scores['Linux'] += 15
            if "filezilla" in banner.lower():
                scores['Linux'] += 6
                scores['MacOS'] += 5
                scores['Windows'] += 12
            if "microsoft ftp service" in banner.lower() or "cerberus" in banner.lower():
                scores['Windows'] += 15

        return scores


DB = OS_DB()