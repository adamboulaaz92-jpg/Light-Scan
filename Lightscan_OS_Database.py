from scapy.layers.inet import IP, TCP, sr1
import random

red = "\033[31m"
reset = "\033[0m"
yellow = "\033[33m"

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
                'windows': [5840, 5720, 29200, 65535, 64240, 32120, 65160],
                'ttl_range': (64, 255),
                'timestamp_high': True
            },
            'Windows': {
                'common_orders': [
                    ['MSS', 'NOP', 'WScale', 'NOP', 'NOP', 'SAckOK', 'NOP', 'NOP'],
                    ['MSS','NOP','WScale','NOP','NOP','SAckOK'],
                    ['WScale', 'MSS', 'SAckOK', 'Timestamp'],
                    ['MSS', 'NOP', 'WScale', 'SAckOK', 'NOP', 'NOP', 'Timestamp'],
                    ['MSS', 'NOP', 'WScale', 'SAckOK', 'Timestamp'],
                    ['MSS', 'SAckOK', 'Timestamp', 'WScale']
                ],
                'windows': [64240, 65535, 8192, 16384, 32768, 25600, 51200],
                'ttl_range': (65, 128),
                'timestamp_high': False
            },
            'Cisco': {
                'common_orders': [
                    ['MSS', 'SAckOK'],
                    ['MSS', 'SAckOK', 'Timestamp']
                ],
                'windows': [4128, 9112, 16384, 32768],
                'ttl_range': (255, 255),
                'timestamp_high': False
            },
            'Android': {
                'common_orders': [
                    ['MSS', 'SAckOK', 'Timestamp', 'NOP', 'WScale'],
                    ['MSS', 'SAckOK', 'Timestamp', 'WScale'],
                    ['MSS', 'NOP', 'WScale', 'NOP', 'SAckOK', 'Timestamp']
                ],
                'windows': [65535, 29200, 64240, 14600, 32120],
                'ttl_range': (64, 64),
                'timestamp_high': True
            },
            'MacOS': {
                'common_orders': [
                    ['MSS', 'NOP', 'NOP', 'SAckOK', 'Timestamp', 'NOP', 'WScale'],
                    ['MSS', 'SAckOK', 'Timestamp', 'WScale']
                ],
                'windows': [65535, 32768],
                'ttl_range': (64, 64),
                'timestamp_high': True
            }
        }

    def OS_fingerprint(self, target, open_ports, banner, Services, verbose=False):
            os_list = {
                'Linux': 0,
                'Windows': 0,
                'Cisco': 0,
                'Android': 0,
                'MacOS': 0,
                'IOS': 0,
                'Unknown': 0
            }

            if not open_ports:
                print(f"\n{yellow}[!] Lightscan need at least 1 open port for OS detection{reset}")
                return

            for port in open_ports:
                try:
                    probe = IP(dst=target, id=random.randint(1, 65535), ttl=64) / TCP(
                        dport=port,
                        sport=random.randint(60000, 65535),
                        seq=random.randint(1000000000, 4294967295),
                        window=65535,
                        options=[
                            ('MSS', 1460),
                            ('SAckOK', b''),
                            ('Timestamp', (random.randint(1, 1000000000), 0)),
                            ('WScale', 8)
                        ],
                        flags="S"
                    )

                    resp = sr1(probe, timeout=2, verbose=False)

                    if resp and resp.haslayer(TCP) and resp.haslayer(IP):
                        if resp[TCP].flags & 0x12:
                            ttl = resp[IP].ttl
                            window = resp[TCP].window
                            options = resp[TCP].options

                            if verbose:
                                print(f"\n[+] Response from port {port}:")
                                print(f"    Window: {window}")
                                print(f"    TTL: {ttl}")
                                print(f"    IP ID: {resp[IP].id}")
                                print(f"    TCP Seq: {resp[TCP].seq}")
                                print(f"    Options: {options}")

                            analysis = self.analyze_options(options)
                            port_scores = self.match_os_signature(analysis, window, ttl, banner, Services)

                            for os_type, score in port_scores.items():
                                os_list[os_type] += score

                except Exception as e:
                    if verbose:
                        print(f"{red}[!] OS fingerprint error on port {port}: {e}{reset}")
                    continue

            Top_1 = max(os_list.values())
            total_score = sum(os_list.values())
            if total_score > 0:
                print(f"\n[+] OS Fingerprint Results:")
                print("-" * 40)
                for os_type, score in sorted(os_list.items(), key=lambda x: x[1], reverse=True):
                    percentage = (score / total_score) * 100
                    if verbose:
                        print(f"    [+] {os_type:12} : {percentage:5.1f}% (score: {score:.1f})")
                    if verbose:
                        pass
                    else:
                        if Top_1 == score:
                            print(f"    [+] {os_type:12} : {percentage:5.1f}% (score: {score:.1f})")
                        else:
                            pass
            else:
                print(f"\n{yellow}[!] No conclusive OS fingerprint detected{reset}")

    @staticmethod
    def analyze_options(options):
            if not options:
                return {}

            analysis = {
                'order': [opt[0] for opt in options],
                'mss': None,
                'wscale': None,
                'timestamp': None,
                'sack': False
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


    def match_os_signature(self, analysis, window, ttl, banners, Services):
            scores = {
                'Linux': 0,
                'Windows': 0,
                'Cisco': 0,
                'Android': 0,
                'MacOS': 0,
                'IOS': 0,
                'Unknown': 0
            }

            option_order = analysis.get('order', [])

            for os_name, signature in self.os_signatures.items():
                for common_order in signature.get('common_orders', []):
                    if option_order == common_order:
                        scores[os_name] += 3
                    elif all(opt in option_order for opt in common_order):
                        scores[os_name] += 1.5

                if window in signature.get('windows', []):
                    scores[os_name] += 2

                ttl_min, ttl_max = signature.get('ttl_range', (0, 0))
                if ttl_min <= ttl <= ttl_max:
                    scores[os_name] += 1


            if analysis.get('timestamp') and isinstance(analysis['timestamp'], tuple):
                ts_val, _ = analysis['timestamp']
                if ts_val > 100000000:
                    scores['Linux'] += 2

            if analysis.get('mss') == 65495:
                scores['Windows'] += 25
            if analysis.get('mss') == 1380:
                scores['Linux'] += 8

            if analysis.get('wscale') == 8:
                scores['Windows'] += 3
                scores['Linux'] += 2
                scores['Android'] += 0.25
            if analysis.get('wscale') == 13 or analysis.get('wscale') == 7:
                scores['Linux'] += 5

            if ttl in [50,51,44,42,46,47]:
                scores['Linux'] += 5
            if ttl <= 128:
                scores['Windows'] += 8
            if ttl == 255:
                scores['Windows'] = 0
                scores['Linux'] = 0
                scores['MacOS'] = 0
                scores['Android'] = 0
                scores['IOS'] = 0
                scores['Cisco'] = 10
            if ttl <= 64:
                if window in [65535, 29200, 14600, 64240]:
                    scores['Android'] += 4
                    scores['Linux'] += 1.25
                if window in [65160]:
                    scores['Linux'] += 3.5
                elif window in [32768, 16384, 8760]:
                    scores['IOS'] += 4
                else:
                    scores['Linux'] += 2

            for banner in banners:
                if "dnsmasq-2.51" in banner.lower():
                    scores['Android'] += 25
                    scores['Linux'] += 4
                    scores['IOS'] = 0
                    scores['Windows'] = 0
                    scores['MacOS'] = 0
                    scores['Cisco'] = 0
                if "server: microsoft-httpapi" in banner.lower():
                    scores['Windows'] += 25
                    scores['MacOS'] = 0
                    scores['Cisco'] = 0
                    scores['Android'] = 0
                    scores['Linux'] = 0
                    scores['IOS'] = 0
                if "msrpc" in Services:
                    scores['Windows'] += 25
                    scores['MacOS'] = 0
                    scores['Cisco'] = 0
                    scores['Android'] = 0
                    scores['Linux'] = 0
                    scores['IOS'] = 0
                if "microsoft-ds" in Services:
                    scores['Windows'] += 12.5
                if "centos" in banner.lower():
                    scores['Windows'] = 0
                    scores['Android'] = 0
                    scores['Linux'] = 25
                    scores['Cisco'] = 0
                    scores['IOS'] = 0
                    scores['MacOS'] = 0
                    scores['Unknown'] = 0
                if "vmware authentication daemon version 1.10" in banner.lower():
                    scores['Windows'] += 4
                    scores['Linux'] += 4
                    scores['MacOS'] += 4
                    scores['IOS'] = 0
                    scores['Android'] = 0
                    scores['Cisco'] = 0
                if "vmware authentication daemon version 1.0" in banner.lower():
                    scores['Windows'] += 4
                    scores['Linux'] += 4
                    scores['MacOS'] += 4
                    scores['IOS'] = 0
                    scores['Android'] = 0
                    scores['Cisco'] = 0
                if "openssh" in banner.lower():
                    scores['Linux'] += 15
                if "microsoft" in banner.lower() or "iis" in banner.lower():
                    scores['Windows'] += 10
                if "apache" in banner.lower():
                    scores['Linux'] += 12.5
                if "nginx" in banner.lower():
                    scores['Linux'] += 10

            return scores

DB = OS_DB()
