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
        os_that_have_versions_detection = ['BSD', 'Android','Windows']
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

        Resp = None

        for port in open_ports:
            try:
                probe = self.craft_probe(target, port, version)
                resp = self.send_probe(probe, timeout=2, version=version)
                Resp = resp

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
                            if os_type == "Windows":
                                versions = set()
                                if banner == []:
                                    win = self.detect_windows_version(banner, resp, version)
                                    versions.add(win)
                                else:
                                    for b in banner:
                                        win = self.detect_windows_version(b, resp, version)
                                        versions.add(win)

                                for ver in versions:
                                    print(f"         --> [-] {ver}")
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

    def detect_windows_version(self, banner, resp, version):
        if resp and resp.haslayer(TCP):
            tcp_layer = resp.getlayer(TCP if version == 4 else TCP6)
            ip_layer = resp.getlayer(IPv6 if version == 6 else IP)
            window = tcp_layer.window
            options = tcp_layer.options
            option_order = [opt[0] for opt in options if opt[0] not in ['NOP', 'EOL']]

            if version == 6:
                hlim = ip_layer.hlim
                ttl = hlim
            else:
                ttl = ip_layer.ttl
                hlim = ttl

            mss = None
            wscale = None
            timestamp_present = False
            sack_present = False

            for opt_name, opt_value in options:
                if opt_name == 'MSS':
                    mss = opt_value
                elif opt_name == 'WScale':
                    wscale = opt_value
                elif opt_name == 'Timestamp':
                    timestamp_present = True
                elif opt_name == 'SAckOK':
                    sack_present = True


            if window == 65535 and ttl == 128 and wscale == 8 and mss == 65495:
                if option_order == ['MSS', 'NOP', 'WScale', 'NOP', 'NOP', 'SAckOK']:
                    return "Windows 11 (build 22000+)"
                elif option_order == ['MSS', 'WScale', 'NOP', 'NOP', 'SAckOK', 'NOP', 'NOP']:
                    return "Windows 11 (build 22621+) / Windows Server 2022"
                elif option_order == ['MSS', 'NOP', 'WScale', 'NOP', 'SAckOK', 'NOP', 'Timestamp']:
                    return "Windows 11 (build 22631+)"
                elif option_order == ['MSS', 'SAckOK', 'Timestamp', 'WScale']:
                    return "Windows 11 (build 22000-22621)"

            if window == 5840 and ttl == 128 and wscale == 8 and mss == 65495:
                return "Windows 11 (build 22H2+ - 22621)"


            if wscale == 0 and window == 64000:
                return "Windows 10 (build 19045 - 22H2)"

            if mss == 65495 and ttl == 128 and wscale == 8:
                if window == 65535:
                    if option_order == ['MSS', 'WScale', 'SAckOK']:
                        return "Windows 10 (build +17000)"
                    elif option_order == ['MSS', 'SAckOK', 'Timestamp', 'WScale']:
                        return "Windows 10 (build 1511 - 10586) / Windows 10 (build 1607 - 14393)"
                    elif option_order == ['MSS', 'NOP', 'WScale', 'NOP', 'NOP', 'SAckOK']:
                        return "Windows 10 (build 1709 - 16299) / Windows 10 (build 1803 - 17134)"
                    elif option_order == ['MSS', 'NOP', 'WScale', 'NOP', 'SAckOK', 'NOP', 'Timestamp']:
                        return "Windows 10 (build 1903 - 18362) / Windows 10 (build 1909 - 18363)"
                    elif option_order == ['MSS', 'NOP', 'WScale', 'Timestamp', 'SAckOK']:
                        return "Windows 10 (build 1703 - 15063)"
                    elif option_order == ['MSS', 'NOP', 'WScale', 'NOP', 'SAckOK']:
                        return "Windows 10 (build 1809 - 17763)"
                    elif timestamp_present and option_order == ['MSS', 'WScale', 'Timestamp', 'SAckOK']:
                        return "Windows 10 (build 2004 - 19041)"
                    else:
                        return "Windows 10 (build 1607 or earlier - 14393)"

                elif window == 64240:
                    if option_order == ['MSS', 'WScale', 'SAckOK']:
                        return "Windows 10 (build 10240-10586)"
                    elif option_order == ['MSS', 'NOP', 'WScale', 'NOP', 'NOP', 'SAckOK']:
                        return "Windows 10 (build 15063+)"
                    else:
                        return "Windows 10 (build 1507-1607)"

                elif window == 5840:
                    return "Windows 10 (build 22H2+ - 19045)"

            if window == 8192 and ttl == 128 and wscale == 8 and mss == 65495:
                return "Windows 8 (build 9200)"

            if window == 16384 and ttl == 128 and wscale == 8 and mss == 65495:
                return "Windows 8.1 (build 9600)"

            if window == 65535 and ttl == 128 and wscale == 8 and mss == 65495:
                if option_order == ['MSS', 'WScale', 'NOP', 'NOP', 'SAckOK']:
                    return "Windows 8.1 (build 9600 - Update 1)"

            if window == 64240 and ttl == 128 and wscale == 8 and mss == 65495:
                if option_order == ['MSS', 'WScale', 'SAckOK']:
                    return "Windows 8 (build 9200 - initial)"

            if window == 8192 and ttl == 128 and wscale == 8 and mss == 1460:
                return "Windows 8 / Windows 8.1 (non-default MSS)"

            if window == 65535 and ttl == 128 and wscale is None and mss == 1460:
                if option_order == ['MSS', 'SAckOK', 'Timestamp']:
                    return "Windows 7 (build 7600 - RTM)"
                elif option_order == ['MSS', 'NOP', 'SAckOK', 'Timestamp']:
                    return "Windows 7 (build 7601 - SP1)"
                elif not timestamp_present and sack_present:
                    return "Windows 7 (build 7601 - SP1, no timestamp)"

            if window == 8192 and ttl == 128 and wscale is None and mss == 1460:
                return "Windows 7 (build 7600 - RTM, small window)"

            if window == 65535 and ttl == 128 and wscale == 2 and mss == 1460:
                return "Windows 7 (build 7601 - SP1, wscale enabled)"

            if window == 65535 and ttl == 128 and wscale is None and mss == 1460:
                if option_order == ['MSS', 'NOP', 'SAckOK', 'NOP', 'Timestamp']:
                    return "Windows Vista (build 6000 - RTM)"
                elif option_order == ['MSS', 'SAckOK', 'NOP', 'NOP', 'Timestamp']:
                    return "Windows Vista (build 6001 - SP1)"
                elif option_order == ['MSS', 'NOP', 'SAckOK', 'NOP', 'NOP', 'Timestamp']:
                    return "Windows Vista (build 6002 - SP2)"

            if window == 16384 and ttl == 128 and wscale is None and mss == 1460:
                return "Windows Vista (build 6000 - RTM, default window)"

            if window == 65535 and ttl == 128 and wscale is None and mss == 1460:
                if option_order == ['MSS', 'NOP', 'SAckOK']:
                    return "Windows XP (build 2600 - RTM)"
                elif option_order == ['MSS', 'NOP', 'NOP', 'SAckOK']:
                    return "Windows XP (build 2600 - SP1)"
                elif option_order == ['MSS', 'NOP', 'NOP', 'NOP', 'SAckOK']:
                    return "Windows XP (build 2600 - SP2)"
                elif option_order == ['MSS', 'NOP', 'SAckOK', 'NOP', 'Timestamp']:
                    return "Windows XP (build 2600 - SP3)"

            if window == 16384 and ttl == 128 and wscale is None and mss == 1460:
                return "Windows XP (build 2600 - SP1/SP2, non-default window)"

            if window == 65535 and ttl == 128 and wscale == 2 and mss == 1460:
                return "Windows XP (build 2600 - with TCP window scaling patch)"


            if window == 16384 and ttl == 128 and wscale is None and mss == 1460:
                if option_order == ['MSS', 'NOP', 'SAckOK']:
                    return "Windows 2000 (build 2195 - RTM)"
                elif option_order == ['MSS', 'NOP', 'NOP', 'SAckOK']:
                    return "Windows 2000 (build 2195 - SP1+)"

            if window == 65535 and ttl == 128 and wscale is None and mss == 1460:
                if option_order == ['MSS', 'NOP', 'NOP', 'SAckOK']:
                    return "Windows 2000 (build 2195 - with large window)"

            if window == 65535 and ttl == 128 and wscale == 8 and mss == 65495:
                if option_order == ['MSS', 'WScale', 'NOP', 'NOP', 'SAckOK', 'NOP', 'NOP']:
                    return "Windows Server 2022 (build 20348)"
                elif option_order == ['MSS', 'NOP', 'WScale', 'NOP', 'NOP', 'SAckOK']:
                    return "Windows Server 2022 (build 20348 - Datacenter)"

            if window == 8192 and ttl == 128 and wscale == 8 and mss == 65495:
                return "Windows Server 2019 (build 17763)"

            if window == 65535 and ttl == 128 and wscale == 8 and mss == 65495:
                if option_order == ['MSS', 'NOP', 'WScale', 'NOP', 'SAckOK', 'NOP', 'Timestamp']:
                    return "Windows Server 2019 (build 17763 - Update)"

            if window == 16384 and ttl == 128 and wscale == 8 and mss == 65495:
                return "Windows Server 2016 (build 14393)"

            if window == 65535 and ttl == 128 and wscale == 8 and mss == 65495:
                if option_order == ['MSS', 'SAckOK', 'Timestamp', 'WScale']:
                    return "Windows Server 2016 (build 14393 - Update)"

            if window == 16384 and ttl == 128 and wscale == 8 and mss == 65495:
                return "Windows Server 2012 R2 (build 9600)"

            if window == 8192 and ttl == 128 and wscale == 8 and mss == 65495:
                if option_order == ['MSS', 'WScale', 'SAckOK']:
                    return "Windows Server 2012 R2 (build 9600 - Essentials)"

            if window == 8192 and ttl == 128 and wscale == 8 and mss == 65495:
                return "Windows Server 2012 (build 9200)"

            if window == 65535 and ttl == 128 and wscale == 8 and mss == 65495:
                if option_order == ['MSS', 'WScale', 'SAckOK']:
                    return "Windows Server 2012 (build 9200 - Datacenter)"

            if window == 8192 and ttl == 128 and wscale is None and mss == 1460:
                return "Windows Server 2008 R2 (build 7601)"

            if window == 65535 and ttl == 128 and wscale is None and mss == 1460:
                if option_order == ['MSS', 'SAckOK', 'Timestamp']:
                    return "Windows Server 2008 R2 (build 7601 - SP1)"

            if window == 8192 and ttl == 128 and wscale is None and mss == 1460:
                if option_order == ['MSS', 'NOP', 'SAckOK']:
                    return "Windows Server 2008 (build 6001 - SP1)"
                elif option_order == ['MSS', 'NOP', 'NOP', 'SAckOK']:
                    return "Windows Server 2008 (build 6002 - SP2)"

            if banner and "Microsoft-HTTPAPI/2.0" in banner:
                if "Bad Request" in banner:
                    return "Windows 8/10/11/Server 2012+ (HTTPAPI 2.0)"

            if banner and ("SMB" in banner or "microsoft-ds" in str(banner).lower()):
                if "SMB 3.1.1" in banner:
                    return "Windows 10/11/Server 2016+ (SMB 3.1.1)"
                elif "SMB 3.0" in banner or "SMB 3." in banner:
                    return "Windows 8/Server 2012+ (SMB 3.0)"
                elif "SMB 2.1" in banner:
                    return "Windows 7/Server 2008 R2 (SMB 2.1)"
                elif "SMB 2.0" in banner or "SMB 2." in banner:
                    return "Windows Vista/Server 2008 (SMB 2.0)"
                elif "SMB 1." in banner:
                    return "Windows XP/2000 (SMB 1.x)"

            seq = tcp_layer.seq
            ack = tcp_layer.ack if tcp_layer.ack else 0

            if seq and ack:
                seq_diff = abs(seq - ack) if ack > 0 else 0
                if 1000000 < seq_diff < 2000000000:
                    if timestamp_present:
                        return "Windows 10/11 (modern TCP stack)"
                    else:
                        return "Windows 7/8 (legacy TCP stack)"

            if wscale == 8 and ttl == 128:
                if timestamp_present:
                    return "Windows 10/11 (likely)"
                else:
                    return "Windows 8/10 (likely)"

            if wscale is None and ttl == 128:
                if sack_present and not timestamp_present:
                    return "Windows 7/Server 2008 R2 (likely)"
                elif not sack_present and not timestamp_present:
                    return "Windows Vista/XP/2000 (likely)"

            if ttl == 128:
                return "Windows (NT kernel - unknown version)"

            if banner:
                banner_lower = banner.lower()
                if "windows 11" in banner_lower:
                    return "Windows 11"
                elif "windows 10" in banner_lower:
                    return "Windows 10"
                elif "windows nt 10.0" in banner_lower:
                    return "Windows 10/11 (NT 10.0)"
                elif "windows nt 6.3" in banner_lower:
                    return "Windows 8.1 (NT 6.3 - build 9600)"
                elif "windows nt 6.2" in banner_lower:
                    return "Windows 8 (NT 6.2 - build 9200)"
                elif "windows nt 6.1" in banner_lower:
                    return "Windows 7 (NT 6.1 - build 7601)"
                elif "windows nt 6.0" in banner_lower:
                    return "Windows Vista (NT 6.0 - build 6002)"
                elif "windows nt 5.1" in banner_lower:
                    return "Windows XP (NT 5.1 - build 2600)"
                elif "windows nt 5.0" in banner_lower:
                    return "Windows 2000 (NT 5.0 - build 2195)"
                elif "windows server 2022" in banner_lower:
                    return "Windows Server 2022 (build 20348)"
                elif "windows server 2019" in banner_lower:
                    return "Windows Server 2019 (build 17763)"
                elif "windows server 2016" in banner_lower:
                    return "Windows Server 2016 (build 14393)"
                elif "windows server 2012 r2" in banner_lower:
                    return "Windows Server 2012 R2 (build 9600)"
                elif "windows server 2012" in banner_lower:
                    return "Windows Server 2012 (build 9200)"
                elif "windows server 2008 r2" in banner_lower:
                    return "Windows Server 2008 R2 (build 7601)"
                elif "windows server 2008" in banner_lower:
                    return "Windows Server 2008 (build 6002)"
                elif "microsoft-httpapi" in banner_lower:
                    return "Windows (HTTPAPI - 8/10/11/Server 2012+)"

        if resp and resp.haslayer(TCP):
            return "Windows (version undetermined - modern 8/10/11/Server 2012+)"

        return "Windows (Unknown version)"


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
            if "83 00 00 01 8f" in banner.lower():
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