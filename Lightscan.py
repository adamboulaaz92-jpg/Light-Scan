import scapy.all as scapy
import time
import socket
import argparse
from Services import Lightscan_Service_List, top_1000_ports, top_100_ports, top_10_ports
from LightEngine import Payloads
import pyfiglet
import threading
import warnings
import logging
import random

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
warnings.filterwarnings("ignore", message=".*MAC address to reach destination not found.*")

def handle_thread_exception(args):
    if isinstance(args.exc_value, OSError):
        return
    print(f"Thread exception: {args.exc_type.__name__}: {args.exc_value}")
threading.excepthook = handle_thread_exception

class Lightscan:
    def __init__(self):
        self.speed_presets = {
            'paranoid':{'threads': 1,'timeout': 3},
            'slow': {'threads': 6, 'timeout': 2},
            'normal': {'threads': 30, 'timeout': 1.5},
            'fast': {'threads': 60, 'timeout': 1.5},
            'insane': {'threads': 160, 'timeout': 1},
            'Light-mode': {'threads': 400, 'timeout': 1}
        }
        self.host_ext = {
            '.com', '.org', '.net', '.edu', '.gov', '.mil', '.int',
            '.info', '.biz', '.name', '.pro', '.xyz', '.online', '.site',
            '.tech', '.store', '.app', '.dev', '.io', '.ai', '.cloud',
            '.us', '.uk', '.ca', '.au', '.de', '.fr', '.jp', '.cn', '.in',
            '.br', '.ru', '.mx', '.it', '.es', '.nl', '.se', '.no', '.ch',
            '.at', '.dk', '.fi', '.ie', '.nz', '.za', '.sg', '.kr', '.tw',
            '.hk', '.tr', '.ae', '.sa',
            '.eu', '.asia', '.africa',
            '.academy', '.school', '.college', '.university',
            '.business', '.company', '.co', '.shop', '.market',
            '.media', '.news', '.tv', '.film', '.music', '.games',
            '.law', '.legal', '.medical', '.health', '.finance',
            '.realestate', '.travel', '.restaurant', '.club',
            '.art', '.design', '.blog', '.social', '.space', '.world',
            '.expert', '.guru', '.agency', '.services',
            '.fitness', '.health', '.food', '.travel', '.cars', '.fashion'
        }
        self.Proto = "tcp"
        self.scan_type = "tcp"
        self.version = "1.1.2"
        self.max_threads = 30
        self.socket_timeout = 0.0
        self.targetss = []
        self.ports_to_scan = []
        self.target_results = {}
        self.targets = []
        self.lock = threading.Lock()

    def Banner(self):
        banner = pyfiglet.figlet_format("Lightscan", font="slant")
        print(banner)
        print(f"Version : {self.version} ")

    def initialize_target_results(self, target):
        self.target_results[target] = {
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'open_filtered_ports': [],
            'opened_ports_services': [],
            'closed_ports_services': [],
            'filtered_ports_services': [],
            'open_filtered_ports_services': []
        }

    def _sync_and_deduplicate_ports(self, target):
        if target not in self.target_results:
            return

        def deduplicate_sync(ports, services):
            seen = set()
            unique_ports = []
            unique_services = []

            for port, service in zip(ports, services):
                if port not in seen:
                    seen.add(port)
                    unique_ports.append(port)
                    unique_services.append(service)

            return unique_ports, unique_services

        results = self.target_results[target]

        results['open_ports'], results['opened_ports_services'] = deduplicate_sync(
            results['open_ports'], results['opened_ports_services'])
        results['closed_ports'], results['closed_ports_services'] = deduplicate_sync(
            results['closed_ports'], results['closed_ports_services'])
        results['filtered_ports'], results['filtered_ports_services'] = deduplicate_sync(
            results['filtered_ports'], results['filtered_ports_services'])
        results['open_filtered_ports'], results['open_filtered_ports_services'] = deduplicate_sync(
            results['open_filtered_ports'], results['open_filtered_ports_services'])

    def Firewall_detection(self, target, results):
        total_ports = len(self.ports_to_scan)

        if total_ports == 0:
            return

        filtered = len(results['filtered_ports']) / total_ports
        closed = len(results['closed_ports']) / total_ports
        open_filtered = len(results['open_filtered_ports']) / total_ports

        print(f"\n[!] Firewall Analysis for {target}:\n")
        print(f"    Total ports scanned: {total_ports}")
        print(f"    Open ports: {len(results['open_ports'])}")
        print(f"    Closed ports: {len(results['closed_ports'])}")
        print(f"    Filtered ports: {len(results['filtered_ports'])}")
        print(f"    Open Filtered ports: {len(results['open_filtered_ports'])}\n")

        if len(results['filtered_ports']) == 0 and len(results['open_filtered_ports']) == 0:
            print("    [+] NO FIREWALL DETECTED: no port is filtered\n")
        elif len(results['filtered_ports']) <= 10:
            print("    [+] FIREWALL DETECTED: Significant port filtering\n")
        elif filtered > 0.8 and closed < 0.1:
            print("    [+] STRONG FIREWALL DETECTED: Most ports are filtered\n")
        elif open_filtered > 0.05:
            print("    [+] STRONG FIREWALL DETECTED: Most ports are filtered\n")
        elif filtered > 0.5:
            print("    [+] FIREWALL DETECTED: Significant port filtering\n")
        elif len(results['closed_ports']) > len(results['open_ports']) + len(results['filtered_ports']):
            print("    [-] NO STRONG FIREWALL: Most ports are closed (normal behavior)\n")
        else:
            print("    [?] INCONCLUSIVE: Mixed response patterns\n")

    def args_parse(self):
        self.parser = argparse.ArgumentParser(description="Lightscan Port Scanner")
        self.parser.add_argument("-T", "--target", required=True, help="Target IP or Hostname")
        self.parser.add_argument("-p","--port", required=False, help="Port/s to scan")
        self.parser.add_argument("-s", "--speed", required=False, default="normal",
                                 choices=['paranoid', 'slow', 'normal', 'fast', 'insane', 'Light-mode'],
                                 help="Scan speed preset")
        self.parser.add_argument("-v", "--verbose",action="store_true", help="Show verbose output {True/False}")
        self.parser.add_argument("-st","--scan_type",default="TCP", help="Scan types {TCP,SYN,UDP}")
        self.parser.add_argument("-F",action="store_true",help="Scan The Top 100 ports for fast scanning")
        self.parser.add_argument("-mx","--max_retries",type=int,help="Max number of retries if port show a no response",default=1)
        self.parser.add_argument("-t","--threads",type=int,help="Number of threads to use")
        self.parser.add_argument("-tm","--timeout",type=float,help="Timeout with second")
        self.parser.add_argument("-Rc","--recursively",action="store_true",help="recursively scan host that shown to be down or not responding and more")
        self.parser.add_argument("-f","--fragmente",action="store_true",help="fragmente the sending packet for more stealth ")
        self.parser.add_argument("-Pn","--no_ping",action="store_true",help="Do not ping the target/s")
        self.parser.add_argument("-b","--banner",action="store_true",help="Banner Grabing")
        self.parser.add_argument("-O","--os",action="store_true",help="OS Figerprint ")
        self.args = self.parser.parse_args()

    def target_parse(self):
        if "," in self.args.target:
            try:
                target_list = self.args.target.split(",")
                for target in target_list:
                    self.targets.append(target)
            except Exception as error:
                print(f"\n[!] Unexpected error: {error}")
        elif "/" in self.args.target:
            self.targets = self.parse_multi_target(self.args.target)
        else:
            self.targets.append(self.args.target)

    def parse_multi_target(self, cidr_target):
        try:
            if "/" in cidr_target:
                network = scapy.Net(cidr_target)
                ip_list = []

                num_hosts = len(list(network))

                if num_hosts > 65536:
                    print(f"\n[!] DANGER: Scanning {num_hosts:,} hosts in {cidr_target}")
                    print(f"[!] This is a MASSIVE network scan that will:")
                    print(f"    - Take DAYS or WEEKS to complete")
                    print(f"    - Generate HUGE network traffic")
                    print(f"    - Likely trigger security alerts")
                    print(f"    - Consume significant system resources")
                    confirm = input("[?] Are you ABSOLUTELY sure you want to continue? (YES/NO): ")
                    if confirm.upper() != 'YES':
                        print("[!] Scan cancelled - wise choice!")
                        exit(0)
                elif num_hosts > 256:
                    print(f"\n[!] Warning: Scanning {num_hosts:,} hosts in {cidr_target}")
                    print(f"[!] This will take considerable time and resources")
                    confirm = input("[?] Continue? (Y/N): ")
                    if confirm.lower() != 'Y':
                        print("[!] Scan cancelled")
                        exit(0)

                print(f"\n[+] Expanding {cidr_target} to {num_hosts:,} hosts...")

                count = 0
                for ip in network:
                    ip_list.append(str(ip))
                    count += 1
                    if num_hosts > 1000 and count % 10000 == 0:
                        print(f"    [+] Generated {count:,}/{num_hosts:,} IPs...")

                print(f"[+] CIDR expansion complete: {len(ip_list):,} hosts")
                return ip_list
            else:
                return [cidr_target]

        except Exception as e:
            print(f"\n[!] Invalid CIDR notation: {cidr_target}")
            print(f"[!] Error: {e}")
            exit(1)


    def configure_speed(self):
        if self.args.threads:
            self.max_threads = self.args.threads
            if self.args.timeout:
                self.socket_timeout = self.args.timeout

        elif self.args.timeout:
            self.socket_timeout = self.args.timeout
            if self.args.threads:
                self.max_threads = self.args.threads

        elif self.args.speed in self.speed_presets:
            preset = self.speed_presets[self.args.speed]
            self.max_threads = preset['threads']
            self.socket_timeout = preset['timeout']

        else:
            self.socket_timeout = 1.5


    def service_detection(self, port):
        try:
            service = Lightscan_Service_List(port,self.Proto)
            if service is None:
                try:
                    service = socket.getservbyport(port, 'tcp')
                except:
                    service = "Unknown"
        except:
            try:
                service = socket.getservbyport(port, 'tcp')
            except:
                service = "Unknown"

        if service is None:
            service = "Unknown"

        return service

    def target_validation(self):
        for target in self.targets:
            Target = target.replace(".", "")
            if Target.isdigit():
                try:
                    socket.inet_pton(socket.AF_INET, target)
                except:
                    print("\n[!] Invalid Target IP or Hostname\n")
                    exit(1)
            elif Target.isalpha():
                try:
                    socket.gethostbyname(target)
                except:
                    print("\n[!] Invalid Target IP or Hostname\n")

            elif Target.isalnum():
                 for ext in self.host_ext:
                     if ext in target:
                         try:
                             socket.gethostbyname(target)
                         except:
                             print("\n[!] Invalid Target IP or Hostnamen\n")

                         break
                     else:
                         try:
                             socket.gethostbyname(target)
                         except:
                             print("\n[!] Invalid Target IP or Hostname\n")

            else:
                print("\n[!] Invalid Target IP or Hostname \n")

    def show_network_info(self):
        if len(self.targets) > 1:
            print(f"\n[+] Network Scan Mode Activated")
            print(f"    Total targets: {len(self.targets)} hosts")

    def port_parse(self):
        if self.args.F:
            self.ports_to_scan = top_100_ports

        elif self.args.port is None:
            self.ports_to_scan = top_1000_ports

        elif "-" in self.args.port and "," not in self.args.port:
            try:
                sport , eport = self.args.port.split("-")
                sport = int(sport)
                eport = int(eport)
                self.port_validation_1(sport, eport)
                if type(sport) == int and type(eport) == int:
                    self.ports_to_scan = list(range(int(sport), int(eport) + 1))
                else:
                    print("\n[!] Invalid ports range, Lightscan is going to use default values \n")
                    self.ports_to_scan = top_1000_ports
            except:
                print("\n[!] Invalid ports range, Lightscan is going to use default values \n")
                self.ports_to_scan = top_1000_ports

        elif "," in self.args.port and "-" not in self.args.port:
            try:
                port_list = self.args.port.split(",")
                for port in port_list:
                    port = int(port)
                    self.port_validation_2(port)
                    if type(port) == int :
                        self.ports_to_scan.append(port)
                    else:
                        print(f"\n[!] Invalid port, Lightscan is going to skip that one <{port}>\n")
            except:
                print(f"\n[!] Invalid port, Lightscan is going to skip that one <{port}>\n")
        elif "," in self.args.port and "-" in self.args.port:
            try:
                port_list = self.args.port.split(",")
                for port in port_list:
                    if "-" in port:
                        try:
                            sport, eport = port.split("-")
                            sport = int(sport)
                            eport = int(eport)
                            self.port_validation_1(sport, eport)
                            if type(sport) == int and type(eport) == int:
                                self.ports_to_scan.extend(list(range(int(sport), int(eport) + 1)))
                            else:
                                print("\n[!] Invalid ports range \n")
                                exit(1)
                        except:
                            print("\n[!] Invalid ports range \n")
                            exit(1)
                    else:
                        port = int(port)
                        self.port_validation_2(port)
                        if type(port) == int :
                            self.ports_to_scan.append(port)
                        else:
                            print(f"\n[!] Invalid port, Lightscan is going to skip that one <{port}>\n")
            except:
                print(f"\n[!] Invalid port, Lightscan is going to skip that one <{port}>\n")

        else:
            try:
                self.args.port = int(self.args.port)
                self.port_validation_2(self.args.port)
                if type(self.args.port) == int :
                    self.ports_to_scan.append(int(self.args.port))
                else:
                    print("\n[!] Invalid ports range, Lightscan is going to use default values \n")
                    self.ports_to_scan = top_1000_ports
            except:
                print("\n[!] Invalid ports range, Lightscan is going to use default values \n")
                self.ports_to_scan = top_1000_ports

        if len(self.ports_to_scan) <= 0:
            print("\n[!] Invalid Port/s, Lightscan is going to use default values ")
            self.ports_to_scan = top_1000_ports
        else:
            pass

    def port_validation_1(self,sport,eport):
        if sport < 0:
            print("\n[!] Invalid Starting Port\n")
            exit(1)
        elif eport < 0:
            print("\n[!] Invalid Ending Port\n")
            exit(1)
        elif eport < sport:
            print("\n[!] Invalid Port Range\n")
            exit(1)
        elif eport > 65535:
            print("\n[!] Invalid Ending Port\n")
            exit(1)
        else:
            pass

    def port_validation_2(self,port):
        if port < 0 or port > 65535:
            print("\n[!] Invalid Starting Port\n")
            exit(1)
        elif type(port) != int:
            print("\n[!] Invalid Starting Port\n")
            exit(1)
        else:
            pass


    def udp_scan(self, port, target):
        for attempt in range(self.args.max_retries):
            try:
                self.Proto = "udp"
                self.scan_type = "udp"
                if port == 53:
                    packet = Payloads.dns_payload_udp(target)
                else:
                    packet = scapy.IP(dst=target,id=random.randint(1, 65535),ttl=random.choice([64, 128, 255]),flags="DF") / scapy.UDP(dport=port, sport=random.randint(60000, 65535))
                if self.args.fragmente:
                    if self.args.recursively:
                        response = Payloads.fragementation(packet, self.Proto, self.scan_type, self.args.verbose)
                        if self.args.verbose:
                            print("\n[+] Demo Fragementation (if you find an error while using it leave it in our github for future updates)\n")
                    else:
                        if self.args.verbose:
                            print("\n[+] Fragmentation is Forbiden with UDP packets (if you want use flag -Rc)\n")
                        response = scapy.sr1(packet, timeout=self.socket_timeout, verbose=0)
                else:
                    response = scapy.sr1(packet, timeout=self.socket_timeout, verbose=0)

                service = self.service_detection(port)

                if response is None:
                    if attempt == self.args.max_retries - 1:
                        with self.lock:
                                if target not in self.target_results:
                                    self.initialize_target_results(target)
                                self.target_results[target]['open_filtered_ports'].append(port)
                                self.target_results[target]['open_filtered_ports_services'].append(service)
                    else:
                        if self.args.verbose:
                            print(f"[!] No response from UDP port {port}, retrying... (attempt {attempt + 1}/{self.args.max_retries})")
                        time.sleep(0.1)
                        continue

                elif response.haslayer(scapy.ICMP):
                    icmp_type = response.getlayer(scapy.ICMP).type
                    icmp_code = response.getlayer(scapy.ICMP).code

                    if icmp_type == 3 and icmp_code == 3:
                        with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['closed_ports'].append(port)
                            self.target_results[target]['closed_ports_services'].append(service)
                        break

                    elif icmp_type == 3 and icmp_code in [1,2,9,10,13]:
                        with self.lock:
                                if target not in self.target_results:
                                    self.initialize_target_results(target)
                                self.target_results[target]['filtered_ports'].append(port)
                                self.target_results[target]['filtered_ports_services'].append(service)
                        break

                    else:
                        with self.lock:
                                if target not in self.target_results:
                                    self.initialize_target_results(target)
                                self.target_results[target]['filtered_ports'].append(port)
                                self.target_results[target]['filtered_ports_services'].append(service)
                        break


                elif response.haslayer(scapy.UDP):
                    with self.lock:
                        if target not in self.target_results:
                            self.initialize_target_results(target)
                        self.target_results[target]['open_ports'].append(port)
                        self.target_results[target]['opened_ports_services'].append(service)

                    if self.args.banner:
                        banner = Payloads.banner_grab(
                            target=target,
                            port=port,
                            protocol="udp",
                            timeout=3,
                            verbose=self.args.verbose
                        )

                        if banner:
                            print(f"\n{'=' * 60}")
                            print(f"\n[+] Banner from {target}: Port {port}:\n")
                            print(banner[:1000])
                            print(f"\n{'=' * 60}")
                        else:
                            print(f"[-] No banner from {target}: Port {port}")
                    break
                else:
                    with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['filtered_ports'].append(port)
                            self.target_results[target]['filtered_ports_services'].append(service)
                    break

            except Exception as e:
                if self.args.verbose:
                    print(f"[!] Error scanning port {port}: {e}")
                if attempt == self.args.max_retries - 1:
                    service = self.service_detection(port)
                    with self.lock:
                        if target not in self.target_results:
                            self.initialize_target_results(target)
                        self.target_results[target]['filtered_ports'].append(port)
                        self.target_results[target]['filtered_ports_services'].append(service)
                else:
                    time.sleep(0.1)
                    continue

    def threaded_udp_scan(self):
        self.start_time = time.perf_counter()

        if self.max_threads == 1:
            for Target in self.targets:
                for Port in self.ports_to_scan:
                    self.udp_scan(Port, Target)
        else:
            threads = []
            for Target in self.targetss:
                for Port in self.ports_to_scan:
                    thread = threading.Thread(target=self.udp_scan, args=(Port,Target))
                    threads.append(thread)
                    thread.start()

                    while threading.active_count() >= self.max_threads:
                        time.sleep(0.1)

            for thread in threads:
                thread.join()

        self.end_time = time.perf_counter()

    def tcp_syn_scan(self, port, target):
        for attempt in range(self.args.max_retries):
            try:
                self.Proto = "tcp"
                self.scan_type = "syn"

                packet = scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.choice([64, 128, 255]),flags="DF") / scapy.TCP(dport=port, sport=random.randint(60000, 65535),seq=random.randint(1000000000, 4294967295),window=random.choice([5840, 64240, 65535]),options=[('MSS', random.choice([1260, 1360, 1460])),('WScale', random.randint(2, 14)), ('Timestamp',(random.randint(1, 1000000000), 0)),('SAckOK', '')], flags="S")
                if self.args.fragmente:
                    if self.args.recursively:
                        response = Payloads.fragementation(packet, self.Proto, self.scan_type, self.args.verbose)
                        if self.args.verbose:
                            print("\n[+] Demo Fragementation (if you find an error while using it leave it in our github for future updates)\n")
                    else:
                        if self.args.verbose:
                            print("\n[+] Fragmentation is Forbiden with SYN packets (if you want use flag -Rc)\n")
                        response = scapy.sr1(packet, timeout=self.socket_timeout, verbose=0)
                else:
                    response = scapy.sr1(packet, timeout=self.socket_timeout, verbose=0)

                service = self.service_detection(port)

                if response is None:
                    if attempt == self.args.max_retries - 1:
                            with self.lock:
                                if target not in self.target_results:
                                    self.initialize_target_results(target)
                                self.target_results[target]['filtered_ports'].append(port)
                                self.target_results[target]['filtered_ports_services'].append(service)
                    else:
                        if self.args.verbose:
                            print(f"[!] No response from TCP(SYN) port {port}, retrying... (attempt {attempt + 1}/{self.args.max_retries})")
                        time.sleep(0.1)
                        continue

                elif response.haslayer(scapy.TCP):
                    flags = response.getlayer(scapy.TCP).flags

                    if flags == 0x12:
                        with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['open_ports'].append(port)
                            self.target_results[target]['opened_ports_services'].append(service)

                        if self.args.banner:
                            banner = Payloads.banner_grab(
                                target=target,
                                port=port,
                                protocol="tcp",
                                timeout=3,
                                verbose=self.args.verbose
                            )

                            if banner:
                                print(f"\n{'=' * 60}")
                                print(f"\n[+] Banner from {target}: Port {port}:\n")
                                print(banner[:1000])
                                print(f"\n{'=' * 60}")
                            else:
                                print(f"[-] No banner from {target}: Port {port}")

                        scapy.send(scapy.IP(dst=target) / scapy.TCP(dport=port, flags="R"), verbose=0)
                        break

                    elif flags == 0x14 or flags == 0x04:
                        with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['closed_ports'].append(port)
                            self.target_results[target]['closed_ports_services'].append(service)
                        break

                    else:
                        with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['filtered_ports'].append(port)
                            self.target_results[target]['filtered_ports_services'].append(service)
                        break

                elif response.haslayer(scapy.ICMP):
                    icmp_type = response.getlayer(scapy.ICMP).type

                    if icmp_type == 11:
                        with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['open_filtered_ports'].append(port)
                            self.target_results[target]['open_filtered_ports_services'].append(service)
                        break
                    else:
                        with self.lock:
                                if target not in self.target_results:
                                    self.initialize_target_results(target)
                                self.target_results[target]['filtered_ports'].append(port)
                                self.target_results[target]['filtered_ports_services'].append(service)
                        break

                else:
                    with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['filtered_ports'].append(port)
                            self.target_results[target]['filtered_ports_services'].append(service)
                    break

            except Exception as e:
                if self.args.verbose:
                    print(f"[!] Error scanning port {port}: {e}")
                if attempt == self.args.max_retries - 1:
                    service = self.service_detection(port)
                    with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['filtered_ports'].append(port)
                            self.target_results[target]['filtered_ports_services'].append(service)
                else:
                    time.sleep(0.1)
                    continue

    def tcp_3_ways_handshake(self, port, target):
        for attempt in range(self.args.max_retries):
            try:
                self.Proto = "tcp"
                self.scan_type = "tcp"

                packet = scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.choice([64, 128, 255]),flags="DF") / scapy.TCP(dport=port, sport=random.randint(60000, 65535),seq=random.randint(1000000000, 4294967295),window=random.choice([5840, 64240, 65535]),options=[('MSS', random.choice([1260, 1360, 1460])),('WScale', random.randint(2, 14)), ('Timestamp',(random.randint(1, 1000000000), 0)),('SAckOK', '')], flags="S")
                response = scapy.sr1(packet, timeout=self.socket_timeout, verbose=0)
                service = self.service_detection(port)

                if response is None:
                    if attempt == self.args.max_retries - 1:
                            with self.lock:
                                if target not in self.target_results:
                                    self.initialize_target_results(target)
                                self.target_results[target]['filtered_ports'].append(port)
                                self.target_results[target]['filtered_ports_services'].append(service)
                    else:
                        if self.args.verbose:
                            print(f"[!] No response from TCP(SYN) port {port}, retrying... (attempt {attempt + 1}/{self.args.max_retries})")
                        time.sleep(0.1)
                        continue

                elif response.haslayer(scapy.TCP):
                    flags = response.getlayer(scapy.TCP).flags

                    if flags == 0x12:
                        with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['open_ports'].append(port)
                            self.target_results[target]['opened_ports_services'].append(service)

                        ack_packet = (scapy.IP(dst=target) /
                                    scapy.TCP(dport=port, flags="A",
                                              seq=response[scapy.TCP].ack,
                                              ack=response[scapy.TCP].seq + 1))
                        if self.args.fragmente:
                            ack_responses = Payloads.fragementation(ack_packet, self.Proto, self.scan_type, self.args.verbose)

                            if self.args.verbose:
                                print("[+] Demo Fragementation (if you find an error while using it leave it in our github for future updates)\n")
                                if ack_responses:
                                    print(f"[+] Successfully sent fragemented ACK to {target}, {ack_responses} responses received from {target}\n\n")
                                else:
                                    print(f"[+] Successfully sent fragmented ACK to {target} (no responses)\n\n")

                        else:
                            scapy.send(ack_packet, verbose=False)

                        if self.args.banner:
                            banner = Payloads.banner_grab(
                                target=target,
                                port=port,
                                protocol="tcp",
                                timeout=3,
                                verbose=self.args.verbose
                            )

                            if banner:
                                print(f"\n{'=' * 60}")
                                print(f"\n[+] Banner from {target}: Port {port}:\n")
                                print(banner[:1000])
                                print(f"\n{'=' * 60}")
                            else:
                                print(f"[-] No banner from {target}: Port {port}")

                        scapy.send(scapy.IP(dst=target) / scapy.TCP(dport=port, flags="R"), verbose=0)
                        break

                    elif flags == 0x14 or flags == 0x04:
                        with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['closed_ports'].append(port)
                            self.target_results[target]['closed_ports_services'].append(service)
                        break

                    else:
                        with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['filtered_ports'].append(port)
                            self.target_results[target]['filtered_ports_services'].append(service)
                        break

                elif response.haslayer(scapy.ICMP):
                    icmp_type = response.getlayer(scapy.ICMP).type

                    if icmp_type == 11:
                        with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['open_filtered_ports'].append(port)
                            self.target_results[target]['open_filtered_ports_services'].append(service)
                        break
                    else:
                        with self.lock:
                                if target not in self.target_results:
                                    self.initialize_target_results(target)
                                self.target_results[target]['filtered_ports'].append(port)
                                self.target_results[target]['filtered_ports_services'].append(service)
                        break

                else:
                    with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['filtered_ports'].append(port)
                            self.target_results[target]['filtered_ports_services'].append(service)
                    break

            except Exception as e:
                if self.args.verbose:
                    print(f"[!] Error scanning port {port}: {e}")
                if attempt == self.args.max_retries - 1:
                    service = self.service_detection(port)
                    with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['filtered_ports'].append(port)
                            self.target_results[target]['filtered_ports_services'].append(service)
                else:
                    time.sleep(0.1)
                    continue

    def Tcp_host_discovery(self,Target):
        self.Proto = "tcp"
        for port in top_10_ports:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.socket_timeout)
                result = s.connect_ex((Target, port))
                if self.args.recursively:
                    if len(self.targets) == 1:
                        if result == 0:
                            print(f"\n[+] Host {Target} is up! ")
                            self.targetss.append(Target)
                            break
                        elif result in [61, 111, 10061]:
                            self.targetss.append(Target)
                        else:
                            self.targetss.append(Target)
                        if len(self.ports_to_scan) == 0:
                            print(f"\n[+] Host {Target} is shown to be down or not responding")
                            self.targetss.append(Target)
                            self.ports_to_scan = []
                    else:
                        if self.args.verbose:
                            if result == 0:
                                print(f"\n[+] Host {Target} is up! ")
                                self.targetss.append(Target)
                                break
                            elif result in [61, 111, 10061]:
                                self.targetss.append(Target)
                            else:
                                self.targetss.append(Target)
                            if len(self.ports_to_scan) == 0:
                                print(f"\n[+] Host {Target} is shown to be down or not responding, <Skip it>")
                                self.targetss.append(Target)
                                self.ports_to_scan = []
                        else:
                            if result == 0:
                                print(f"\n[+] Host {Target} is up! ")
                                self.targetss.append(Target)
                                break
                            elif result in [61, 111, 10061]:
                                self.targetss.append(Target)
                            else:
                                self.targetss.append(Target)
                            if len(self.ports_to_scan) == 0:
                                self.targetss.append(Target)
                                self.ports_to_scan = []
                else:
                    if len(self.targets) == 1:
                        if result == 0:
                            print(f"\n[+] Host {Target} is up! ")
                            self.targetss.append(Target)
                            break
                        elif result in [61, 111, 10061]:
                            pass
                        else:
                            pass
                        if len(self.ports_to_scan) == 0:
                            print(f"\n[+] Host {Target} is shown to be down or not responding")
                            self.targetss.append(Target)
                            self.ports_to_scan = []
                    else:
                        if self.args.verbose:
                            if result == 0:
                                print(f"\n[+] Host {Target} is up! ")
                                self.targetss.append(Target)
                                break
                            elif result in [61, 111, 10061]:
                                pass
                            else:
                                pass
                            if len(self.ports_to_scan) == 0:
                                print(f"\n[+] Host {Target} is shown to be down or not responding, <Skip it>")
                                self.ports_to_scan = []
                        else:
                            if result == 0:
                                print(f"\n[+] Host {Target} is up! ")
                                self.targetss.append(Target)
                                break
                            elif result in [61, 111, 10061]:
                                pass
                            else:
                                pass
                            if len(self.ports_to_scan) == 0:
                                self.ports_to_scan = []
        self.targetss = list(set(self.targetss))

    def threded_Tcp_host_discovery(self):
        threads = []
        for Target in self.targets:
            thread = threading.Thread(target=self.Tcp_host_discovery, args=(Target,))
            threads.append(thread)
            thread.start()

            while threading.active_count() >= self.max_threads:
                time.sleep(0.1)

        for thread in threads:
            thread.join()

    def host_discovery(self, Target):
            Echo = scapy.IP(dst=Target) / scapy.ICMP(type=8, code=0)
            response = scapy.sr1(Echo, timeout=self.socket_timeout, verbose=0)
            if self.args.recursively:
                if len(self.targets) == 1:
                    if response:
                        print(f"\n[+] Host {Target} is up! ")
                        self.targetss.append(Target)
                    else:
                        print(f"\n[+] Host {Target} is shown to be down or not responding, <Swithch to TCP Host Discovery>")
                        self.Tcp_host_discovery(Target)
                else:
                    if self.args.verbose:
                        if response:
                            print(f"\n[+] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            print(f"\n[+] Host {Target} is shown to be down or not responding, <Swithch to TCP Host Discovery>")
                            self.Tcp_host_discovery(Target)
                    else:
                        if response:
                            print(f"\n[+] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            self.Tcp_host_discovery(Target)
            else:
                if len(self.targets) == 1:
                    if response:
                        print(f"\n[+] Host {Target} is up! ")
                        self.targetss.append(Target)
                    else:
                        print(f"\n[+] Host {Target} is shown to be down or not responding")
                        self.targetss.append(Target)
                else:
                    if self.args.verbose:
                        if response:
                            print(f"\n[+] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            print(f"\n[+] Host {Target} is shown to be down or not responding, <Skip it>")
                    else:
                        if response:
                            print(f"\n[+] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            pass
            self.targetss = list(set(self.targetss))

    def threaded_host_discovery(self):
        threads = []
        for Target in self.targets:
            thread = threading.Thread(target=self.host_discovery, args=(Target,))
            threads.append(thread)
            thread.start()

            while threading.active_count() >= self.max_threads:
                time.sleep(0.1)

        for thread in threads:
            thread.join()

    def threaded_tcp_3_ways_handshake(self):

        self.start_time = time.perf_counter()

        if self.max_threads == 1:
            for Target in self.targets:
                for Port in self.ports_to_scan:
                    self.tcp_3_ways_handshake(Port, Target)
        else:
            threads = []
            for Target in self.targetss:
                for Port in self.ports_to_scan:
                    thread = threading.Thread(target=self.tcp_3_ways_handshake, args=(Port,Target))
                    threads.append(thread)
                    thread.start()

                    while threading.active_count() >= self.max_threads:
                        time.sleep(0.1)

            for thread in threads:
                thread.join()

        self.end_time = time.perf_counter()

    def threaded_tcp_syn_scan(self):
        self.start_time = time.perf_counter()
        print("\n[!] SYN Scan is going to take long time for accuracy")

        if self.max_threads == 1:
            for Target in self.targets:
                for Port in self.ports_to_scan:
                    self.tcp_syn_scan(Port, Target)
        else:
            threads = []
            for Target in self.targetss:
                for Port in self.ports_to_scan:
                    thread = threading.Thread(target=self.tcp_syn_scan, args=(Port, Target))
                    threads.append(thread)
                    thread.start()

                    while threading.active_count() >= self.max_threads:
                        time.sleep(0.1)

            for thread in threads:
                thread.join()

        self.end_time = time.perf_counter()

    def check_network_config(self):
        try:
            import netifaces
            gateways = netifaces.gateways()
            default_gateway = gateways.get('default', {})

            if not default_gateway:
                print(f"\n[!] Warning: No default gateway found. Network scanning may have issues.")
                print(f"[!] Scapy will use broadcast MAC addresses which may generate warnings.")
        except ImportError:
            pass

    def Scan_details(self):
        duration = self.end_time - self.start_time
        self.Banner()

        for target in self.targetss:
            if target in self.target_results:
                self._sync_and_deduplicate_ports(target)

        print(f"\n[*] Scan completed in {duration:.2f} seconds")



        for target in self.targetss:

            if target not in self.target_results:
                print(f"\n[-] No results for target: {target}")

            results = self.target_results[target]
            print(f"\n{'=' * 60}")
            print(f"Scan result for : {target}")
            print(f"Scan Type: {self.scan_type.upper()} | Protocol: {self.Proto.upper()}")
            print(f"{'=' * 60}")

            print(f"\n[+] Open Ports: {len(results['open_ports'])}")
            if len(results['open_ports']) > 0:
                for i in range(len(results['open_ports'])):
                    print(
                        f"     Port {results['open_ports'][i]} {results['opened_ports_services'][i].lower()}\\{self.Proto}")

            print(f"\n[+] Closed Ports: {len(results['closed_ports'])}")
            if len(results['closed_ports']) <= 10 and len(results['closed_ports']) != 0:
                for i in range(len(results['closed_ports'])):
                    print(
                        f"     Port {results['closed_ports'][i]} {results['closed_ports_services'][i].lower()}\\{self.Proto}")
            elif self.args.verbose:
                for i in range(len(results['closed_ports'])):
                    print(
                        f"     Port {results['closed_ports'][i]} {results['closed_ports_services'][i].lower()}\\{self.Proto}")

            print(f"\n[+] Filtered Ports: {len(results['filtered_ports'])}")
            if len(results['filtered_ports']) <= 10 and len(results['filtered_ports']) != 0:
                for i in range(len(results['filtered_ports'])):
                    print(
                        f"     Port {results['filtered_ports'][i]} {results['filtered_ports_services'][i].lower()}\\{self.Proto}")
            elif self.args.verbose:
                for i in range(len(results['filtered_ports'])):
                    print(
                        f"     Port {results['filtered_ports'][i]} {results['filtered_ports_services'][i].lower()}\\{self.Proto}")

            if self.scan_type == "syn" or self.scan_type == "udp":
                print(f"\n[+] Open | Filtered Ports: {len(results['open_filtered_ports'])}")
                if len(results['open_filtered_ports']) <= 10 and len(results['open_filtered_ports']) != 0:
                    for i in range(len(results['open_filtered_ports'])):
                        print(
                            f"     Port {results['open_filtered_ports'][i]} {results['open_filtered_ports_services'][i].lower()}\\{self.Proto}")
                elif self.args.verbose:
                    for i in range(len(results['open_filtered_ports'])):
                        print(
                            f"     Port {results['open_filtered_ports'][i]} {results['open_filtered_ports_services'][i].lower()}\\{self.Proto}")

            self.Firewall_detection(target, results)
            Payloads.OS_figerprint(target, results['open_ports'])
        print(f"\n[+] Lightscan scanned {len(self.targetss)} target(s) successfully")

    def Start(self):
        self.args_parse()
        self.target_parse()
        self.target_validation()
        self.configure_speed()
        self.port_parse()
        self.check_network_config()

        if len(self.targets) > 1:
            self.show_network_info()

        if self.args.no_ping:
            if self.args.verbose:
                if self.args.recursively:
                    print("\n[!] Skiping flag -Pn because flag -Rc is active ")
                    try:
                        self.threaded_host_discovery()
                    except:
                        self.threded_Tcp_host_discovery()
                else:
                    print(f"\n[!] Disabelling Host discovery")
                    self.targetss = self.targets
            else:
                if self.args.recursively:
                    try:
                        self.threaded_host_discovery()
                    except:
                        self.threded_Tcp_host_discovery()
                else:
                    self.targetss = self.targets
        else:
            try:
                self.threaded_host_discovery()
            except:
                self.threded_Tcp_host_discovery()
        print("\n")

        for target in self.targetss:
            self.initialize_target_results(target)

        if self.args.scan_type == "TCP":
            self.threaded_tcp_3_ways_handshake()
        elif self.args.scan_type == "SYN":
            self.threaded_tcp_syn_scan()
        elif self.args.scan_type == "UDP":
            self.threaded_udp_scan()
        else:
            self.threaded_tcp_3_ways_handshake()
        self.Scan_details()

if __name__ == "__main__":
    try:
        Scanner = Lightscan()
        Scanner.Start()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")

