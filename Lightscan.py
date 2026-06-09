# SPDX-FileCopyrightText: 2026 Adam Boulaaz
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-Repository: https://github.com/adamboulaaz92-jpg/Light-Scan
#
# Light-Scan - Advanced Port Scanner and Network Reconnaissance Tool
# Copyright (C) 2026 Adam Boulaaz
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import scapy.all as scapy
from scapy.config import conf
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import socket
import argparse
from Banner_Grabbing import Banner
from Services import Lightscan_Service_List, top_1000_ports, top_100_ports, top_ports, top_20_tcp_ports, top_20_udp_ports
from LightEngine import Payloads
from Lightscan_OS_Database import DB
import pyfiglet
import sys
import threading
import warnings
import logging
import random
import platform

red = "\033[31m"
reset = "\033[0m"
yellow = "\033[33m"

conf.sniff_promisc = 0
conf.bufsize = 65536
conf.use_bpf = False
conf.L3socket.timeout = 1
conf.debug_dissector = 0
conf.use_pcap = True

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
warnings.filterwarnings("ignore", message=".*MAC address to reach destination not found.*")

def handle_thread_exception(args):
    if isinstance(args.exc_value, OSError):
        return
    print(f"Thread exception: {args.exc_type.__name__}: {args.exc_value}")
threading.excepthook = handle_thread_exception

class Lightscan:
    __slots__ = [
        'speed_presets', 'host_ext', 'Proto', 'scan_type', 'version','lsse_ports_to_scan',
        'max_threads', 'socket_timeout', 'args', 'parser','pp','valid',
        'targetss', 'ports_to_scan', 'target_results', 'targets','dns',
        'start_time', 'end_time','lock','__weakref__','timeout_count','user_os','LSSE',"protocols","saving"
    ]

    def __init__(self):
        self.speed_presets = {
            'paranoid':{'threads': 2,'timeout': 4},
            'slow': {'threads': 30, 'timeout': 3},
            'normal': {'threads': 60, 'timeout': 2.5},
            'fast': {'threads': 120, 'timeout': 2.5},
            'insane': {'threads': 240, 'timeout': 1.25},
            'Light-mode': {'threads': 500, 'timeout': 1.25}
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
        self.lsse_ports_to_scan = []
        self.protocols = []
        self.valid = []
        self.pp = []
        self.saving = None
        self.Proto = "tcp"
        self.scan_type = "tcp"
        self.version = "1.1.5"
        self.dns = None
        self.max_threads = 60
        self.socket_timeout = 0.0
        self.targetss = []
        self.ports_to_scan = []
        self.target_results = {}
        self.targets = []
        self.lock = threading.Lock()
        self.timeout_count = 0
        self.user_os = platform.system()

    def Banner(self):
        banner = pyfiglet.figlet_format("Lightscan", font="slant")
        print(banner)
        print(f"Version : {self.version}")
        print(f"Platform : {self.user_os} \n")



    def initialize_target_results(self, target):
        self.target_results[target] = {
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'defended_ports': [],
            'undefended_ports': [],
            'unfiltered_ports': [],
            'open_filtered_ports': [],
            'null_ports': [],
            'fin_ports':[],
            'opened_ports_services': [],
            'closed_ports_services': [],
            'filtered_ports_services': [],
            'defended_ports_services': [],
            'undefended_ports_services': [],
            'unfiltered_ports_services': [],
            'open_filtered_ports_services': [],
            'null_ports_services': [],
            'fin_ports_services': [],
            'banners': [],
            'banners_ports': [],
            'window_scan_os': [],
            'up': 0,
            'down': 0
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
        results['banners'], results['banners_ports'] = deduplicate_sync(
            results['banners'], results['banners_ports'])


    def Firewall_detection(self, target, results):
        total_ports = len(self.ports_to_scan)

        if total_ports == 0:
            return

        filtered = len(results['filtered_ports']) / total_ports
        closed = len(results['closed_ports']) / total_ports
        open_filtered = len(results['open_filtered_ports']) / total_ports

        print(f"\n[!] Firewall Analysis for {target}:")
        if self.scan_type == "fdd":
            pass
        else:
            print(f"    Total ports scanned: {total_ports}")
            print(f"    Open ports: {len(results['open_ports'])}")
            print(f"    Closed ports: {len(results['closed_ports'])}")
            print(f"    Filtered ports: {len(results['filtered_ports'])}")
        if self.scan_type == "null":
            print(f"    Null Scan (Open | Filtered ports): {len(results['null_ports'])}\n")
        elif self.scan_type == "ack":
            print(f"    Unfiltered ports: {len(results['unfiltered_ports'])}\n")
        elif self.scan_type == "fdd":
            print(f"    Defended ports: {len(results['defended_ports'])}")
            print(f"    Undefended ports: {len(results['undefended_ports'])}")
        else:
            print(f"    Open | Filtered ports: {len(results['open_filtered_ports'])}\n")

        if self.scan_type == "null":
            if len(results['null_ports']) <= 10:
                print("    [+] NO FIREWALL DETECTED: Null scan can get a lop of Open | Filtered ports\n")
            elif len(results['null_ports']) >= 11:
                print("    [+] FIREWALL DETECTED: Significant port filtering\n")
        elif self.scan_type == "fdd":
            if len(results['defended_ports']) < len(results['undefended_ports']):
                print("    [-] NO STRONG FIREWALL: Most ports are undefended (normal behavior)\n")
            else:
                print("    [+] FIREWALL DETECTED: Significant port filtering\n")
        elif self.timeout_count > 0:
            if self.timeout_count == len(results['open_filtered_ports']) or self.timeout_count >= 50:
                print("    [+] NO FIREWALL DETECTED: (Timeout can lead Light-Scan to False-Positive Responses)\n")
        elif len(results['open_filtered_ports']) >= 11:
            if len(results['open_filtered_ports']) >= 21:
                print("    [+] STRONG FIREWALL DETECTED: Most ports are filtered\n")
            else:
                print("    [+] FIREWALL DETECTED: Significant port filtering\n")
        elif len(results['filtered_ports']) >= 11:
            if len(results['filtered_ports']) >= 21:
                print("    [+] STRONG FIREWALL DETECTED: Most ports are filtered\n")
            else:
                print("    [+] FIREWALL DETECTED: Significant port filtering\n")
        elif filtered > 0.8 and closed < 0.1:
            print("    [+] STRONG FIREWALL DETECTED: Most ports are filtered\n")
        elif open_filtered > 0.05:
            print("    [+] STRONG FIREWALL DETECTED: Most ports are filtered\n")
        elif filtered > 0.5:
            print("    [+] FIREWALL DETECTED: Significant port filtering\n")
        elif len(results['closed_ports']) > len(results['open_ports']) + len(results['filtered_ports']):
            print("    [-] NO STRONG FIREWALL: Most ports are closed (normal behavior)\n")
        elif len(results['filtered_ports']) == 0 and len(results['open_filtered_ports']) == 0:
            print("    [+] NO FIREWALL DETECTED : no such filtered or open | filtered ports\n")
        elif self.scan_type == "ack":
            if len(results['filtered_ports']) >= len(results['unfiltered_ports']):
                print("    [+] FIREWALL DETECTED: Significant port filtering\n")
            else:
                print("    [-] NO STRONG FIREWALL: Most ports are closed (normal behavior)\n")
        else:
            print("    [?] INCONCLUSIVE: Mixed response patterns\n")

    def args_parse(self):
        self.parser = argparse.ArgumentParser(description="Lightscan Port Scanner")
        self.parser.add_argument("-T", "--target", required=False, help="Target IP or Hostname")
        self.parser.add_argument("-p","--port", required=False, help="Port/s to scan")
        self.parser.add_argument("-pp","--ping-port",help="Port/s to Ping on it")
        self.parser.add_argument("-s", "--speed", required=False, default="normal",
                                 choices=['paranoid', 'slow', 'normal', 'fast', 'insane', 'Light-mode'],
                                 help="Scan speed preset")
        self.parser.add_argument("-v", "--verbose",action="store_true", help="Show verbose output ")
        self.parser.add_argument("-st","--scan-type",default="TCP", help="Scan types {TCP,SYN,UDP,NULL,FIN,ACK,XMAS,WINDOW,MAIMON,FDD,FTP-BOUNCE}")
        self.parser.add_argument('--ftp-bounce', dest='ftp_server',help='FTP server for bounce scan (e.g., 192.168.1.100)')
        self.parser.add_argument("-F",action="store_true",help="Scan The Top 100 ports for fast scanning")
        self.parser.add_argument("-mx","--max-retries",type=int,help="Max number of retries if port show a no response",default=1)
        self.parser.add_argument("-t","--threads",type=int,help="Number of threads to use")
        self.parser.add_argument("-lst",action="store_true",help="List all targets")
        self.parser.add_argument("-tm","--timeout",type=float,help="Timeout with second")
        self.parser.add_argument("-Rc","--recursively",action="store_true",help="recursively scan host that shown to be down or not responding and disable flags like -v,-Pn,etc ...")
        self.parser.add_argument("-f","--fragmente",action="store_true",help="fragment the sending packet for more stealth ")
        self.parser.add_argument("-Pn","--no-ping",action="store_true",help="Do not ping the target/s")
        self.parser.add_argument("-b","--banner",action="store_true",help="Banner Grabing")
        self.parser.add_argument("-O","--os",action="store_true",help="OS Fingerprint ")
        self.parser.add_argument("-mac",action="store_true",help="Light-Scan will not be capabelle of getting target mac on Local Networks")
        self.parser.add_argument("-Pa","--arp-ping",action="store_true",help="ARP Ping on Local Networks")
        self.parser.add_argument("-Pi","--ip-ping",action="store_true",help="IP Protocol Ping")
        self.parser.add_argument("-Pip",type=str,help="For Specefiy The IP Protocols that -Pi is going to use rather then default")
        self.parser.add_argument("-A","--agressive",action="store_true",help="Agressive scan activate all of OS Fingerprints, Banner Grabing, Insane Speed , SYN Scan and Scan Top 100 Ports")
        self.parser.add_argument("-Pt","--tcp-ping",action="store_true",help="Do a TCP Ping")
        self.parser.add_argument("-Ps","--syn-ping",action="store_true",help="Do a Syn Ping")
        self.parser.add_argument("-Pk","--ack-ping",action="store_true",help="DO a ACK Ping")
        self.parser.add_argument("-Pu","--udp-ping",action="store_true",help="Do a UDP Ping")
        self.parser.add_argument("-PIt","--icmp-timestamp-ping",action="store_true",help="Do scan a ICMP Timestamp Ping")
        self.parser.add_argument("-PA","--icmp-address-ping",action="store_true",help="Do scan a ICMP Address Ping")
        self.parser.add_argument("-Pin","--icmp-information-ping",action="store_true",help="Do scan a ICMP Information Ping")
        self.parser.add_argument("-q","--quiet",action="store_true",help="Quiet mode {does't print the Tool Banner}")
        self.parser.add_argument("--script",type=str,help="LSSE Script ,Ex: --script http-cert")
        self.parser.add_argument("--domain",type=str,help="Domain for http/https and Dns based scripts ")
        self.parser.add_argument("--dns-server",type=str,help="dns server that Light-Scan is going to use (Is Set by Default ")
        self.parser.add_argument("-W","--wordlist",type=str,help="Wordlist for scripts ")
        self.parser.add_argument("--redirect",action="store_true",help="Redirect http/https requests for http scripts")
        self.parser.add_argument("--url",type=str,help="Victime URL")
        self.parser.add_argument("--mxp",help="max pages to get")
        self.parser.add_argument("--mxd", help="max depth to crawl")
        self.parser.add_argument("-sp",help="Port/s that are going to use by scripts")
        self.parser.add_argument("--lsse",action="store_true",help="Use that flag when you want just to performe a script")
        self.args = self.parser.parse_args()


    def list_targets(self):
        for target in self.targets:
            print("Target: " + target)

    def agressive_scan_config(self):
        if self.args.agressive:
            self.args.os = True
            self.args.banner = True
            self.args.speed = "insane"
            self.args.scan_type = "SYN"
            self.args.F = True
        else:
            pass

    def target_parse(self):
        if "," in self.args.target:
            try:
                target_list = self.args.target.split(",")
                for target in target_list:
                    self.targets.append(target)
            except Exception as error:
                print(f"\n{red}[!] Unexpected error: {error}{reset}")
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
            print(f"\n{red}[!] Invalid CIDR notation: {cidr_target}")
            print(f"[!] Error: {e}{reset}")
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

        return service.lower()

    def target_validation(self):

        for target in self.targets:
            Target = target.replace(".", "")
            if Target.isdigit():
                try:
                    socket.inet_pton(socket.AF_INET, target)
                    self.valid.append(target)
                except:
                    print(f"\n{red}[!] Invalid Target IP or Hostname {target}{reset}\n")
                    exit(1)

            elif Target.isalpha():
                try:

                    socket.gethostbyname(target)
                    if self.args.dns_server:
                        self.dns = self.args.dns_server
                    else:
                        self.dns = scapy.conf.route.route("0.0.0.0")[2]

                    packet = (scapy.IP(dst=self.dns, id=random.randint(1, 65535), ttl=random.randint(32, 255),flags="DF") /
                              scapy.UDP(dport=53, sport=random.randint(60000, 65535)) /
                              scapy.DNS(id=random.randint(1, 65535), rd=1, qd=scapy.DNSQR(qname=target, qtype="A")))
                    response = scapy.sr1(packet,timeout=3,verbose=0)
                    if response and response.haslayer(scapy.DNS):
                        dns_layer = response[scapy.DNS]
                        if dns_layer.qr == 1 and dns_layer.ancount > 0:
                            for i in range(1):
                                if dns_layer.an[i].type == 1:
                                    self.valid.append(dns_layer.an[i].rdata)
                    else:
                        print(f"{yellow}\n[!] Failed to resolve ({target}) {reset}")
                except:
                    print(f"{red}\n[!] Invalid Target IP or Hostname {target}{reset}\n")
                    exit(1)

            elif Target.isalnum():

                 for ext in self.host_ext:
                     if ext in target:
                         try:
                             socket.gethostbyname(target)
                             if self.args.dns_server:
                                 dns = self.args.dns_server
                             else:
                                 dns = scapy.conf.route.route("0.0.0.0")[2]

                             packet = (scapy.IP(dst=dns, id=random.randint(1, 65535), ttl=random.randint(32, 255),
                                                flags="DF") /
                                       scapy.UDP(dport=53, sport=random.randint(60000, 65535)) /
                                       scapy.DNS(id=random.randint(1, 65535), rd=1,
                                                 qd=scapy.DNSQR(qname=target, qtype="A")))
                             response = scapy.sr1(packet, timeout=3, verbose=0)
                             if response and response.haslayer(scapy.DNS):
                                 dns_layer = response[scapy.DNS]
                                 if dns_layer.qr == 1 and dns_layer.ancount > 0:
                                     for i in range(1):
                                         if dns_layer.an[i].type == 1:
                                             self.valid.append(dns_layer.an[i].rdata)
                             else:
                                 print(f"{yellow}\n[!] Failed to resolve ({target}) {reset}")
                         except:
                             print(f"{red}\n[!] Invalid Target IP or Hostname {target}{reset}\n")
                             exit(1)

                         break
                     else:
                         try:
                             socket.gethostbyname(target)
                             if self.args.dns_server:
                                 dns = self.args.dns_server
                             else:
                                 dns = scapy.conf.route.route("0.0.0.0")[2]

                             packet = (scapy.IP(dst=dns, id=random.randint(1, 65535), ttl=random.randint(32, 255),
                                                flags="DF") /
                                       scapy.UDP(dport=53, sport=random.randint(60000, 65535)) /
                                       scapy.DNS(id=random.randint(1, 65535), rd=1,
                                                 qd=scapy.DNSQR(qname=target, qtype="A")))
                             response = scapy.sr1(packet, timeout=3, verbose=0)
                             if response and response.haslayer(scapy.DNS):
                                 dns_layer = response[scapy.DNS]
                                 if dns_layer.qr == 1 and dns_layer.ancount > 0:
                                     for i in range(1):
                                         if dns_layer.an[i].type == 1:
                                             self.valid.append(dns_layer.an[i].rdata)
                             else:
                                 print(f"{yellow}\n[!] Failed to resolve ({target}) {reset}")
                         except:
                             print(f"\n{red}[!] Invalid Target IP or Hostname {target}{reset}\n")
                             exit(1)

            else:
                print(f"{red}\n[!] Invalid Target IP or Hostname {target}{reset}\n")
                exit(1)

        self.targets.clear()
        for v in self.valid:
            self.targets.append(v)

    def show_network_info(self):
        if len(self.targets) > 1:
            print(f"[+] Network Scan Mode Activated")
            print(f"    Total targets: {len(self.targets)} hosts\n")

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
                    print(f"{red}\n[!] Invalid ports range, Lightscan is going to use default values {reset}\n")
                    self.ports_to_scan = top_1000_ports
            except:
                print(f"{red}\n[!] Invalid ports range, Lightscan is going to use default values {reset}\n")
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
                        print(f"\n{red}[!] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")
            except:
                print(f"\n{red}[!] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")
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
                                print(f"\n{red}[!] Invalid ports range {reset}\n")
                                exit(1)
                        except:
                            print(f"\n{red}[!] Invalid ports range {reset}\n")
                            exit(1)
                    else:
                        port = int(port)
                        self.port_validation_2(port)
                        if type(port) == int :
                            self.ports_to_scan.append(port)
                        else:
                            print(f"\n{red}[!] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")
            except:
                print(f"\n{red}[!] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")

        else:
            try:
                self.args.port = int(self.args.port)
                self.port_validation_2(self.args.port)
                if type(self.args.port) == int :
                    self.ports_to_scan.append(int(self.args.port))
                else:
                    print(f"\n{red}[!] Invalid ports range, Lightscan is going to use default values {reset}\n")
                    self.ports_to_scan = top_1000_ports
            except:
                print(f"\n{red}[!] Invalid ports range, Lightscan is going to use default values {reset}\n")
                self.ports_to_scan = top_1000_ports

        if len(self.ports_to_scan) <= 0:
            print(f"\n{red}[!] Invalid Port/s, Lightscan is going to use default values {reset}")
            self.ports_to_scan = top_1000_ports
        else:
            pass

    def ip_ping_protocols(self):
        if self.args.Pip == None:
            self.protocols = [1,2,4]

        elif "-" in self.args.Pip and "," not in self.args.Pip:
            try:
                sport , eport = self.args.Pip.split("-")
                sport = int(sport)
                eport = int(eport)
                if sport > eport:
                    self.protocols = [1,2,4]
                if sport <= 0 or eport <= 0:
                    self.protocols = [1,2,4]
                if sport == eport:
                    self.protocols.append(eport)
                if eport > 255:
                    self.protocols = [1,2,4]
                if type(sport) == int and type(eport) == int:
                    self.protocols = list(range(int(sport), int(eport) + 1))
                else:
                    self.protocols = [1,2,4]
            except:
                self.protocols = [1,2,4]

        elif "," in self.args.Pip and "-" not in self.args.Pip:
            try:
                port_list = self.args.Pip.split(",")
                for port in port_list:
                    port = int(port)
                    if port > 255:
                        self.protocols = [1,2,4]
                    if port <= 0:
                        self.protocols = [1,2,4]
                    if type(port) == int :
                        self.protocols.append(port)
                    else:
                        print(f"\n{red}[!] Invalid Protocol, Lightscan is going to skip that one <{port}>{reset}\n")
            except:
                self.protocols = [1,2,4]
        elif "," in self.args.Pip and "-" in self.args.Pip:
            try:
                port_list = self.args.Pip.split(",")
                for port in port_list:
                    if "-" in port:
                        try:
                            sport, eport = port.split("-")
                            sport = int(sport)
                            eport = int(eport)
                            if sport > eport:
                                self.protocols = [1, 2, 4]
                            if sport <= 0 or eport <= 0:
                                self.protocols = [1, 2, 4]
                            if sport == eport:
                                self.protocols.append(eport)
                            if eport > 255:
                                self.protocols = [1, 2, 4]
                            if type(sport) == int and type(eport) == int:
                                self.protocols.extend(list(range(int(sport), int(eport) + 1)))
                            else:
                                self.protocols = [1, 2, 4]
                        except:
                            self.protocols = [1, 2, 4]
                    else:
                        port = int(port)
                        if port > 255:
                            self.protocols = [1, 2, 4]
                        if port <= 0:
                            self.protocols = [1, 2, 4]
                        if type(port) == int:
                            self.protocols.append(port)
                        else:
                            print(f"\n{red}[!] Invalid Protocol, Lightscan is going to skip that one <{port}>{reset}\n")
            except:
                print(f"\n{red}[!] Invalid Protocol, Lightscan is going to skip that one <{port}>{reset}\n")

        else:
            try:
                if self.args.Pip == None:
                    self.protocols = [1,2,4]
                else:
                    self.args.Pip = int(self.args.Pip)
                    if self.args.Pip > 255:
                        self.protocols = [1, 2, 4]
                    if self.args.Pip <= 0:
                        self.protocols = [1, 2, 4]
                    if type(self.args.Pip) == int:
                        self.protocols.append(self.args.Pip)
                    else:
                        self.protocols = [1,2,4]

            except:
                self.protocols = [1,2,4]

        if len(self.protocols) <= 0:
            self.protocols = [1,2,4]
        else:
            pass

    def script_port_parse(self):

        if self.args.sp is None:
            print(f"\n{yellow}[LSSE] No port/s was assagned for the script {reset}\n")
            exit()

        elif "-" in self.args.sp and "," not in self.args.sp:
            try:
                sport , eport = self.args.sp.split("-")
                sport = int(sport)
                eport = int(eport)
                self.port_validation_1(sport, eport)
                if type(sport) == int and type(eport) == int:
                    self.lsse_ports_to_scan = list(range(int(sport), int(eport) + 1))
                else:
                    print(f"\n{red}[LSSE] Invalid ports range {reset}\n")
                    exit()
            except:
                print(f"\n{red}[LSSE] Invalid ports range {reset}\n")
                exit()

        elif "," in self.args.sp and "-" not in self.args.sp:
            try:
                port_list = self.args.sp.split(",")
                for port in port_list:
                    port = int(port)
                    self.port_validation_2(port)
                    if type(port) == int :
                        self.lsse_ports_to_scan.append(port)
                    else:
                        print(f"\n{red}[LSSE] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")
            except:
                print(f"\n{red}[LSSE] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")
        elif "," in self.args.sp and "-" in self.args.sp:
            try:
                port_list = self.args.sp.split(",")
                for port in port_list:
                    if "-" in port:
                        try:
                            sport, eport = port.split("-")
                            sport = int(sport)
                            eport = int(eport)
                            self.port_validation_1(sport, eport)
                            if type(sport) == int and type(eport) == int:
                                self.lsse_ports_to_scan.extend(list(range(int(sport), int(eport) + 1)))
                            else:
                                print(f"\n{red}[LSSE] Invalid ports range {reset}\n")
                                exit()
                        except:
                            print(f"\n{red}[LSSE] Invalid ports range {reset}\n")
                            exit()
                    else:
                        port = int(port)
                        self.port_validation_2(port)
                        if type(port) == int :
                            self.lsse_ports_to_scan.append(port)
                        else:
                            print(f"\n{red}[LSSE] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")
            except:
                print(f"\n{red}[LSSE] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")

        else:
            try:
                self.args.sp = int(self.args.sp)
                self.port_validation_2(self.args.sp)
                if type(self.args.sp) == int :
                    self.lsse_ports_to_scan.append(int(self.args.sp))
                else:
                    print(f"\n{red}[LSSE] Invalid ports range {reset}\n")
                    exit()
            except:
                print(f"\n{red}[LSSE] Invalid ports range {reset}\n")
                exit()

        if len(self.lsse_ports_to_scan) <= 0:
            print(f"\n{yellow}[LSSE] No port/s was assagned for script {reset}\n")
            exit()
        else:
            pass

    def ping_port_parse(self):
        if "-" in self.args.ping_port and "," not in self.args.ping_port:
            try:
                sport , eport = self.args.ping_port.split("-")
                sport = int(sport)
                eport = int(eport)
                self.port_validation_1(sport, eport)
                if type(sport) == int and type(eport) == int:
                    self.pp = list(range(int(sport), int(eport) + 1))
                else:
                    print(f"\n{red}[!] Invalid ports range {reset}\n")
                    exit()
            except:
                print(f"\n{red}[!] Invalid ports range {reset}\n")
                exit()

        elif "," in self.args.ping_port and "-" not in self.args.ping_port:
            try:
                port_list = self.args.ping_port.split(",")
                for port in port_list:
                    port = int(port)
                    self.port_validation_2(port)
                    if type(port) == int :
                        self.pp.append(port)
                    else:
                        print(f"\n{red}[!] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")
            except:
                print(f"\n{red}[!] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")
        elif "," in self.args.ping_port and "-" in self.args.ping_port:
            try:
                port_list = self.args.ping_port.split(",")
                for port in port_list:
                    if "-" in port:
                        try:
                            sport, eport = port.split("-")
                            sport = int(sport)
                            eport = int(eport)
                            self.port_validation_1(sport, eport)
                            if type(sport) == int and type(eport) == int:
                                self.pp.extend(list(range(int(sport), int(eport) + 1)))
                            else:
                                print(f"\n{red}[!] Invalid ports range {reset}\n")
                                exit()
                        except:
                            print(f"\n{red}[!] Invalid ports range {reset}\n")
                            exit()
                    else:
                        port = int(port)
                        self.port_validation_2(port)
                        if type(port) == int :
                            self.pp.append(port)
                        else:
                            print(f"\n{red}[!] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")
            except:
                print(f"\n{red}[!] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")

        else:
            try:
                self.port_validation_2(int(self.args.ping_port))
                self.pp.append(int(self.args.ping_port))
            except:
                print(f"\n{red}[!] Invalid ports range {reset}\n")
                exit()

        if len(self.pp) <= 0:
            print(f"\n{yellow}[!] No port/s was assagned for hostdiscovery {reset}\n")
            exit()
        else:
            pass


    def port_validation_1(self,sport,eport):
        if sport < 0:
            print(f"\n{red}[!] Invalid Starting Port{reset}\n")
            exit(1)
        elif eport < 0:
            print(f"\n{red}[!] Invalid Ending Port{reset}\n")
            exit(1)
        elif eport < sport:
            print(f"\n{red}[!] Invalid Port Range{reset}\n")
            exit(1)
        elif eport > 65535:
            print(f"\n{red}[!] Invalid Ending Port{reset}\n")
            exit(1)
        else:
            pass

    def port_validation_2(self,port):
        if port < 0 or port > 65535:
            print(f"\n{red}[!] Invalid Starting Port{reset}\n")
            exit(1)
        elif type(port) != int:
            print(f"\n{red}[!] Invalid Starting Port{reset}\n")
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
                elif port == 22:
                    packet = Payloads.ssh_payload_udp(target)
                elif port == 21:
                    packet = Payloads.ftp_payload_udp(target)
                else:
                    packet = scapy.IP(dst=target,id=random.randint(1, 65535),ttl=random.choice([64, 128, 255]),flags="DF") / scapy.UDP(dport=port, sport=random.randint(60000, 65535))
                if self.args.fragmente:
                    if self.args.recursively:
                        response = Payloads.fragementation(packet, self.Proto, self.scan_type, self.args.verbose)
                        if self.args.verbose:
                            print("[+] Demo Fragementation (if you find an error while using it leave it in our github for future updates)\n")
                    else:
                        if self.args.verbose:
                            print(f"{yellow}[+] Fragmentation is Forbiden with UDP packets (if you want use flag -Rc){reset}\n")
                        response = scapy.sr1(packet, timeout=self.socket_timeout, verbose=0)
                else:
                    if self.args.timeout:
                        response = scapy.sr1(packet, timeout=self.socket_timeout, verbose=0)
                    else:
                        response = scapy.sr1(packet, timeout=5, verbose=0)

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
                            print(f"{yellow}[!] No response from UDP port {port}, retrying... (attempt {attempt + 1}/{self.args.max_retries}){reset}")
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
                        banner = Banner.banner_grab(
                            target=target,
                            port=port,
                            protocol="udp",
                            timeout=3,
                            verbose=self.args.verbose
                        )

                        if banner:
                            with self.lock:
                                self.target_results[target]['banners'].append(banner)
                                self.target_results[target]['banners_ports'].append(port)

                            Banner.analyse_banner(banner, port, self.target_results[target], self.Proto, self.lock)
                        else:
                            pass
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
                    print(f"{red}[!] Error scanning port {port}: {e}{reset}")
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
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for target in self.targetss:
                    for port in self.ports_to_scan:
                        future = executor.submit(
                            self.udp_scan,port,target
                        )
                        time.sleep(0.02)
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.args.verbose:
                            print(f"{red}[!] UDP scan error: {e}{reset}")

        self.end_time = time.perf_counter()

    def tcp_syn_scan(self, port, target):
        for attempt in range(self.args.max_retries):
            try:
                self.Proto = "tcp"
                self.scan_type = "syn"

                if port == 22:
                    packet = Payloads.ssh_payload_tcp(target)
                elif port == 21:
                    packet = Payloads.ftp_payload_tcp(target)
                else:
                    packet = scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.choice([64, 128, 255]),flags="DF") / scapy.TCP(dport=port, sport=random.randint(60000, 65535),seq=random.randint(1000000000, 4294967295),window=random.choice([5840, 64240, 65535, 29200, 8760]),options=Payloads.Stealth_tcp_options(), flags="S")
                if self.args.fragmente:
                    if self.args.recursively:
                        response = Payloads.fragementation(packet, self.Proto, self.scan_type, self.args.verbose)
                        if self.args.verbose:
                            print("[+] Demo Fragementation (if you find an error while using it leave it in our github for future updates)\n")
                    else:
                        if self.args.verbose:
                            print(f"{yellow}[+] Fragmentation is Forbiden with SYN packets (if you want use flag -Rc){reset}\n")
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
                            print(f"{yellow}[!] No response from TCP(SYN) port {port}, retrying... (attempt {attempt + 1}/{self.args.max_retries}){reset}")
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
                            banner = Banner.banner_grab(
                                target=target,
                                port=port,
                                protocol="tcp",
                                timeout=3,
                                verbose=self.args.verbose
                            )

                            if banner:
                                with self.lock:
                                    self.target_results[target]['banners'].append(banner)
                                    self.target_results[target]['banners_ports'].append(port)
                                Banner.analyse_banner(banner, port, self.target_results[target], self.Proto, self.lock)
                            else:
                                pass

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

                else:
                    with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['filtered_ports'].append(port)
                            self.target_results[target]['filtered_ports_services'].append(service)
                    break

            except Exception as e:
                if self.args.verbose:
                    print(f"{red}[!] Error scanning port {port}: {e}{reset}")
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

                if port == 22:
                    packet = Payloads.ssh_payload_tcp(target)
                elif port == 21:
                    packet = Payloads.ftp_payload_tcp(target)
                else:
                    packet = scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.choice([64, 128, 255]),flags="DF") / scapy.TCP(dport=port, sport=random.randint(60000, 65535),seq=random.randint(1000000000, 4294967295),window=random.choice([5840, 64240, 65535, 29200, 8760]),options=Payloads.Stealth_tcp_options(), flags="S")
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
                            print(f"{yellow}[!] No response from TCP(SYN) port {port}, retrying... (attempt {attempt + 1}/{self.args.max_retries}){reset}")
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
                                if ack_responses:
                                    print(f"[+] Successfully sent fragemented ACK to {target}, {ack_responses} responses received from {target}")
                                else:
                                    print(f"[+] Successfully sent fragmented ACK to {target} (no responses)")

                        else:
                            scapy.send(ack_packet, verbose=False)

                        if self.args.banner:
                            banner = Banner.banner_grab(
                                target=target,
                                port=port,
                                protocol="tcp",
                                timeout=3,
                                verbose=self.args.verbose
                            )

                            if banner:
                                with self.lock:
                                    self.target_results[target]['banners'].append(banner)
                                    self.target_results[target]['banners_ports'].append(port)

                                Banner.analyse_banner(banner, port, self.target_results[target], self.Proto, self.lock)
                            else:
                                pass

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
                        self.timeout_count += 1
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
                    print(f"{red}[!] Error scanning port {port}: {e}{reset}")
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

    def Udp_host_discovery(self,Target,port):
        payloads = ["PING","URGENT","!HHHH","LIGHTSCAN","UDP","TCP","-Pu","KIWI"]
        packet = scapy.IP(dst=Target, id=random.randint(1, 65535), ttl=random.choice([64, 128, 255]),
                          flags="DF") / scapy.UDP(dport=port, sport=random.randint(60000, 65535))/scapy.Raw(load=random.choice(payloads))

        response = scapy.sr1(packet, timeout=self.socket_timeout, verbose=0)
        if len(self.targets) == 1:
            if response:
                    if response.haslayer(scapy.UDP):
                        print(f"[UDP] Host {Target}:{port} is up! ")
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
                    elif response.haslayer(scapy.ICMP):
                        print(f"[UDP] Host {Target}:{port} is up! ")
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
                    else:
                        print(f"[UDP] Host {Target}:{port} is up! ")
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
            else:
                if Target not in self.targetss:
                    self.targetss.append(Target)
        else:
            if response:
                    if response.haslayer(scapy.UDP):
                        print(f"[UDP] Host {Target}:{port} is up! ")
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
                    elif response.haslayer(scapy.ICMP):
                        print(f"[UDP] Host {Target}:{port} is up! ")
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
                    else:
                        print(f"[UDP] Host {Target}:{port} is up! ")
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
            else:
                pass

    def threded_Udp_host_discovery(self):
        if self.max_threads == 1:
            for Target in self.targets:
                if self.args.ping_port:
                    for port in self.pp:
                        self.Udp_host_discovery(Target, port)
                else:
                    for port in top_20_udp_ports:
                        self.Udp_host_discovery(Target,port)

            for target in self.targets:
                if self.target_results[target]['up'] >= 1:
                    pass
                else:
                    print(f"[UDP] Host {target} is shown to be down or not responding")

        else:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for target in self.targets:
                    if self.args.ping_port:
                        for port in self.pp:
                            future = executor.submit(
                                self.Udp_host_discovery, target, port
                            )
                            time.sleep(0.02)
                            futures.append(future)
                    else:
                        for port in top_20_udp_ports:
                            future = executor.submit(
                                self.Udp_host_discovery,target,port
                            )
                            time.sleep(0.02)
                            futures.append(future)


                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.args.verbose:
                            print(f"{red}[!] UDP ping error: {e}{reset}")

        for target in self.targets:
            time.sleep(0.01)
            if self.target_results[target]['up'] >= 1:
                pass
            else:
                print(f"[UDP] Host {target} is shown to be down or not responding")

    def Syn_host_discovery(self,Target, port):
        self.Proto = "tcp"
        packet = scapy.IP(dst=Target, id=random.randint(1, 65535), ttl=random.choice([64, 128, 255]),
                              flags="DF") / scapy.TCP(dport=port, sport=random.randint(60000, 65535),
                                                      seq=random.randint(1000000000, 4294967295),
                                                      window=random.choice([5840, 64240, 65535, 29200, 8760]),
                                                      options=Payloads.Stealth_tcp_options(), flags="S")
        response = scapy.sr1(packet, timeout=self.socket_timeout, verbose=0)
        if len(self.targets) == 1:
            if response:
                    if response.haslayer(scapy.TCP):
                        flags = response.getlayer(scapy.TCP).flags

                        if flags == 0x12:
                            print(f"[SYN] Host {Target}:{port} is up! ")
                            if Target not in self.targetss:
                                self.targetss.append(Target)
                            self.target_results[Target]['up'] += 1
                        else:
                            if Target not in self.targetss:
                                self.targetss.append(Target)
                            self.target_results[Target]['up'] += 1
                    else:
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
            else:
                if Target not in self.targetss:
                    self.targetss.append(Target)
        else:
            if response:
                if response.haslayer(scapy.TCP):
                    flags = response.getlayer(scapy.TCP).flags

                    if flags == 0x12:
                        print(f"[SYN] Host {Target}:{port} is up! ")
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
                    else:
                        pass
                else:
                    pass
            else:
                pass

    def threded_Syn_host_discovery(self):
        if self.max_threads == 1:
            for Target in self.targets:
                if self.args.ping_port:
                    for port in self.pp:
                        self.Syn_host_discovery(Target, port)
                else:
                    for port in top_20_tcp_ports:
                        self.Syn_host_discovery(Target,port)

            for target in self.targets:
                if self.target_results[target]['up'] >= 1:
                    pass
                else:
                    print(f"[SYN] Host {target} is shown to be down or not responding")

        else:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for target in self.targets:
                    if self.args.ping_port:
                        for port in self.pp:
                            future = executor.submit(
                                self.Syn_host_discovery, target, port
                            )
                            time.sleep(0.02)
                            futures.append(future)
                    else:
                        for port in top_20_tcp_ports:
                            future = executor.submit(
                                self.Syn_host_discovery,target,port
                            )
                            time.sleep(0.02)
                            futures.append(future)


                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.args.verbose:
                            print(f"{red}[!] SYN ping error: {e}{reset}")

        for target in self.targets:
            time.sleep(0.01)
            if self.target_results[target]['up'] >= 1:
                pass
            else:
                print(f"[SYN] Host {target} is shown to be down or not responding")

    def Tcp_host_discovery(self,Target,port):
        self.Proto = "tcp"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.socket_timeout)
        result = s.connect_ex((Target, port))
        if self.args.recursively:
            if len(self.targets) == 1:
                if result == 0:
                    print(f"[TCP] Host {Target}:{port} is up! ")
                    if Target not in self.targetss:
                        self.targetss.append(Target)
                    self.target_results[Target]['up'] += 1
                elif result in [61, 111, 10061]:
                    if Target not in self.targetss:
                        self.targetss.append(Target)
                    self.target_results[Target]['up'] += 1
                else:
                    if Target not in self.targetss:
                        self.targetss.append(Target)
                    self.target_results[Target]['up'] += 1

                if len(self.ports_to_scan) == 0:
                    print(f"[TCP] Host {Target} is shown to be down or not responding")
                    if Target not in self.targetss:
                        self.targetss.append(Target)
                    self.target_results[Target]['up'] += 1
                    self.ports_to_scan = []
            else:
                if self.args.verbose:
                    if result == 0:
                        print(f"[TCP] Host {Target}:{port} is up! ")
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
                    elif result in [61, 111, 10061]:
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
                    else:
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
                    if len(self.ports_to_scan) == 0:
                        print(f"[TCP] Host {Target} is shown to be down or not responding, <Skip it>")
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
                        self.ports_to_scan = []
                else:
                    if result == 0:
                        print(f"[TCP] Host {Target}:{port} is up! ")
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
                    elif result in [61, 111, 10061]:
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
                    else:
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
                    if len(self.ports_to_scan) == 0:
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
                        self.ports_to_scan = []
        else:
            if len(self.targets) == 1:
                if result == 0:
                    print(f"[TCP] Host {Target}:{port} is up! ")
                    if Target not in self.targetss:
                        self.targetss.append(Target)
                    self.target_results[Target]['up'] += 1

                elif result in [61, 111, 10061]:
                    pass
                else:
                    pass
                if len(self.ports_to_scan) == 0:
                    print(f"[TCP] Host {Target} is shown to be down or not responding")
                    if Target not in self.targetss:
                        self.targetss.append(Target)
                    self.target_results[Target]['up'] += 1
                    self.ports_to_scan = []
            else:
                if self.args.verbose:
                    if result == 0:
                        print(f"[TCP] Host {Target}:{port} is up! ")
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1

                    elif result in [61, 111, 10061]:
                        pass
                    else:
                        pass
                    if len(self.ports_to_scan) == 0:
                        print(f"[TCP] Host {Target} is shown to be down or not responding, <Skip it>")
                        self.ports_to_scan = []
                else:
                    if result == 0:
                        print(f"[TCP] Host {Target}:{port} is up! ")
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1

                    elif result in [61, 111, 10061]:
                        pass
                    else:
                        pass
                    if len(self.ports_to_scan) == 0:
                        self.ports_to_scan = []

        self.targetss = list(set(self.targetss))

    def threded_Tcp_host_discovery(self):
        if self.max_threads == 1:
            for Target in self.targets:
                if self.args.ping_port:
                    for port in self.pp:
                        self.Tcp_host_discovery(Target, port)
                else:
                    for port in top_20_tcp_ports:
                        self.Tcp_host_discovery(Target,port)
        else:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for target in self.targets:
                    if self.args.ping_port:
                        for port in self.pp:
                            future = executor.submit(
                                self.Tcp_host_discovery, target, port
                            )
                            time.sleep(0.02)
                            futures.append(future)
                    else:
                        for port in top_20_tcp_ports:
                            future = executor.submit(
                                self.Tcp_host_discovery,target,port
                            )
                            time.sleep(0.02)
                            futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.args.verbose:
                            print(f"{red}[!] TCP ping error: {e}{reset}")

        for target in self.targets:
            time.sleep(0.01)
            if self.target_results[target]['up'] >= 1:
                pass
            else:
                print(f"[TCP] Host {target} is shown to be down or not responding")

    def host_discovery_3(self, Target):
            icmp_id = random.randint(1, 65535)
            icmp_seq = random.randint(1, 65535)
            Address = scapy.IP(dst=Target, id=random.randint(1, 65535), ttl=random.choice([64, 128, 255]),flags="DF") / scapy.ICMP(type=15,seq=icmp_seq,id=icmp_id, code=0)
            response = scapy.sr1(Address, timeout=self.socket_timeout, verbose=0)
            if self.args.recursively:
                if len(self.targets) == 1:
                    if response:
                        print(f"[INFO] Host {Target} is up! ")
                        self.targetss.append(Target)
                    else:
                        print(f"[INFO] Host {Target} is shown to be down or not responding, <Swithch to TCP Host Discovery>")
                        self.Tcp_host_discovery(Target)
                else:
                    if self.args.verbose:
                        if response:
                            print(f"[INFO] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            print(f"[INFO] Host {Target} is shown to be down or not responding, <Swithch to TCP Host Discovery>")
                            self.Tcp_host_discovery(Target)
                    else:
                        if response:
                            print(f"[INFO] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            self.Tcp_host_discovery(Target)
            else:
                if len(self.targets) == 1:
                    if response:
                        print(f"[INFO] Host {Target} is up! ")
                        self.targetss.append(Target)
                    else:
                        print(f"[INFO] Host {Target} is shown to be down or not responding")
                        self.targetss.append(Target)
                else:
                    if self.args.verbose:
                        if response:
                            print(f"[INFO] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            print(f"[INFO] Host {Target} is shown to be down or not responding, <Skip it>")
                    else:
                        if response:
                            print(f"[INFO] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            pass
            self.targetss = list(set(self.targetss))

    def host_discovery_2(self, Target):
            icmp_id = random.randint(1, 65535)
            icmp_seq = random.randint(1, 65535)
            Address = scapy.IP(dst=Target, id=random.randint(1, 65535), ttl=random.choice([64, 128, 255]),flags="DF") / scapy.ICMP(type=17,seq=icmp_seq,id=icmp_id, code=0)
            response = scapy.sr1(Address, timeout=self.socket_timeout, verbose=0)
            if self.args.recursively:
                if len(self.targets) == 1:
                    if response:
                        print(f"[ADDR] Host {Target} is up! ")
                        self.targetss.append(Target)
                    else:
                        print(f"[ADDR] Host {Target} is shown to be down or not responding, <Swithch to TCP Host Discovery>")
                        self.Tcp_host_discovery(Target)
                else:
                    if self.args.verbose:
                        if response:
                            print(f"[ADDR] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            print(f"[ADDR] Host {Target} is shown to be down or not responding, <Swithch to TCP Host Discovery>")
                            self.Tcp_host_discovery(Target)
                    else:
                        if response:
                            print(f"[ADDR] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            self.Tcp_host_discovery(Target)
            else:
                if len(self.targets) == 1:
                    if response:
                        print(f"[ADDR] Host {Target} is up! ")
                        self.targetss.append(Target)
                    else:
                        print(f"[ADDR] Host {Target} is shown to be down or not responding")
                        self.targetss.append(Target)
                else:
                    if self.args.verbose:
                        if response:
                            print(f"[ADDR] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            print(f"[ADDR] Host {Target} is shown to be down or not responding, <Skip it>")
                    else:
                        if response:
                            print(f"[ADDR] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            pass
            self.targetss = list(set(self.targetss))

    def host_discovery_1(self, Target):
            icmp_id = random.randint(1, 65535)
            icmp_seq = random.randint(1, 65535)
            TimeStamp = scapy.IP(dst=Target, id=random.randint(1, 65535), ttl=random.choice([64, 128, 255]),flags="DF") / scapy.ICMP(type=13,seq=icmp_seq,id=icmp_id,code=0)
            response = scapy.sr1(TimeStamp, timeout=self.socket_timeout, verbose=0)
            if self.args.recursively:
                if len(self.targets) == 1:
                    if response:
                        print(f"[TIME STAMP] Host {Target} is up! ")
                        self.targetss.append(Target)
                    else:
                        print(f"[TIME STAMP] Host {Target} is shown to be down or not responding, <Swithch to TCP Host Discovery>")
                        self.Tcp_host_discovery(Target)
                else:
                    if self.args.verbose:
                        if response:
                            print(f"[TIME STAMP] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            print(f"[TIME STAMP] Host {Target} is shown to be down or not responding, <Swithch to TCP Host Discovery>")
                            self.Tcp_host_discovery(Target)
                    else:
                        if response:
                            print(f"[TIME STAMP] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            self.Tcp_host_discovery(Target)
            else:
                if len(self.targets) == 1:
                    if response:
                        print(f"[TIME STAMP] Host {Target} is up! ")
                        self.targetss.append(Target)
                    else:
                        print(f"[TIME STAMP] Host {Target} is shown to be down or not responding")
                        self.targetss.append(Target)
                else:
                    if self.args.verbose:
                        if response:
                            print(f"[TIME STAMP] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            print(f"[TIME STAMP] Host {Target} is shown to be down or not responding, <Skip it>")
                    else:
                        if response:
                            print(f"[TIME STAMP] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            pass
            self.targetss = list(set(self.targetss))

    def host_discovery(self, Target):
            icmp_id = random.randint(1, 65535)
            icmp_seq = random.randint(1, 65535)
            Echo = scapy.IP(dst=Target, id=random.randint(1, 65535), ttl=random.choice([64, 128, 255]),flags="DF") / scapy.ICMP(type=8,id=icmp_id,seq=icmp_seq, code=0)
            response = scapy.sr1(Echo, timeout=self.socket_timeout, verbose=0)
            if self.args.recursively:
                if len(self.targets) == 1:
                    if response:
                        print(f"[ECHO] Host {Target} is up! ")
                        self.targetss.append(Target)
                    else:
                        print(f"[ECHO] Host {Target} is shown to be down or not responding, <Swithch to TCP Host Discovery>")
                        self.Tcp_host_discovery(Target)
                else:
                    if self.args.verbose:
                        if response:
                            print(f"[ECHO] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            print(f"[ECHO] Host {Target} is shown to be down or not responding, <Swithch to TCP Host Discovery>")
                            self.Tcp_host_discovery(Target)
                    else:
                        if response:
                            print(f"[ECHO] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            self.Tcp_host_discovery(Target)
            else:
                if len(self.targets) == 1:
                    if response:
                        print(f"[ECHO] Host {Target} is up! ")
                        self.targetss.append(Target)
                    else:
                        print(f"[ECHO] Host {Target} is shown to be down or not responding")
                        self.targetss.append(Target)
                else:
                    if self.args.verbose:
                        if response:
                            print(f"[ECHO] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            print(f"[ECHO] Host {Target} is shown to be down or not responding, <Skip it>")
                    else:
                        if response:
                            print(f"[ECHO] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            pass
            self.targetss = list(set(self.targetss))

    def threaded_host_discovery(self):
        if self.max_threads == 1:
            for Target in self.targets:
                self.host_discovery(Target)
        else:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for target in self.targets:
                        future = executor.submit(
                            self.host_discovery,target
                        )
                        time.sleep(0.02)
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.args.verbose:
                            print(f"{red}[!] ICMP ECHO ping error: {e}{reset}")

    def threaded_host_discovery_1(self):
        if self.max_threads == 1:
            for Target in self.targets:
                self.host_discovery_1(Target)
        else:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for target in self.targets:
                        future = executor.submit(
                            self.host_discovery_1,target
                        )
                        time.sleep(0.02)
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.args.verbose:
                            print(f"{red}[!] ICMP TIMESTAMP ping error: {e}{reset}")

    def threaded_host_discovery_2(self):
        if self.max_threads == 1:
            for Target in self.targets:
                self.host_discovery_2(Target)
        else:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for target in self.targets:
                        future = executor.submit(
                            self.host_discovery_2,target
                        )
                        time.sleep(0.02)
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.args.verbose:
                            print(f"{red}[!] ICMP Address ping error: {e}{reset}")

    def threaded_host_discovery_3(self):
        if self.max_threads == 1:
            for Target in self.targets:
                self.host_discovery_3(Target)
        else:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for target in self.targets:
                        future = executor.submit(
                            self.host_discovery_3,target
                        )
                        time.sleep(0.02)
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.args.verbose:
                            print(f"{red}[!] ICMP Information ping error: {e}{reset}")

    def threaded_tcp_3_ways_handshake(self):

        self.start_time = time.perf_counter()

        if self.max_threads == 1:
            for Target in self.targets:
                for Port in self.ports_to_scan:
                    self.tcp_3_ways_handshake(Port, Target)
        else:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for target in self.targetss:
                    for port in self.ports_to_scan:
                        future = executor.submit(
                            self.tcp_3_ways_handshake, port, target
                        )
                        time.sleep(0.02)
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.args.verbose:
                            print(f"{red}[!] TCP scan error: {e}{reset}")

        self.end_time = time.perf_counter()

    def threaded_tcp_syn_scan(self):
        self.start_time = time.perf_counter()

        if self.max_threads == 1:
            for Target in self.targets:
                for Port in self.ports_to_scan:
                    self.tcp_syn_scan(Port, Target)
        else:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for target in self.targetss:
                    for port in self.ports_to_scan:
                        future = executor.submit(
                            self.tcp_syn_scan, port, target
                        )
                        time.sleep(0.02)
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.args.verbose:
                            print(f"{red}[!] TCP SYN scan error: {e}{reset}")

        self.end_time = time.perf_counter()

    def check_network_config(self):
        try:
            import netifaces
            gateways = netifaces.gateways()
            default_gateway = gateways.get('default', {})

            if not default_gateway:
                print(f"\n{red}[!] Warning: No default gateway found. Network scanning may have issues.")
                print(f"[!] Scapy will use broadcast MAC addresses which may generate warnings.{reset}")
        except ImportError:
            pass

    def Scan_details(self):
        duration = self.end_time - self.start_time


        for target in self.targetss:
            if target in self.target_results:
                self._sync_and_deduplicate_ports(target)

        print(f"\n[*] Scan completed in {duration:.2f} seconds")

        for target in self.targetss:

            if target not in self.target_results:
                print(f"\n[-] No results for target: {target}")

            ip_status = Payloads.is_private_ip(target)
            if ip_status == "Local":
                if self.args.mac:
                    pass
                else:
                    Mac = Payloads.ARP_Scan(target)
            elif ip_status == "Public":
                pass

            results = self.target_results[target]
            print(f"\n{'=' * 60}")
            print(f"[+] Scan result for : {target}")
            print(f"[+] Scan Type: {self.scan_type.upper()} | Protocol: {self.Proto.upper()}")
            if ip_status == "Local":
                print(f"[+] IP Status: {ip_status}")
                if self.args.mac:
                    pass
                else:
                    print(f"[+] Mac Address: {Mac}")
            elif ip_status == "Public":
                print(f"[+] IP Status: {ip_status}")
            print(f"{'=' * 60}")

            if self.scan_type == "null":
                pass
            elif self.scan_type == "fin":
                pass
            elif self.scan_type == "ack":
                pass
            elif self.scan_type == "xmas":
                pass
            elif self.scan_type == "maimon":
                pass
            elif self.scan_type == "fdd":
                pass
            else:
                print(f"\n[+] Open Ports: {len(results['open_ports'])}")
                if len(results['open_ports']) >= 21:
                    for i in range(len(results['open_ports'][:20])):
                        print(
                            f"     Port {results['open_ports'][i]} {results['opened_ports_services'][i].lower()}\\{self.Proto}")
                elif len(results['open_ports']) > 0:
                    for i in range(len(results['open_ports'])):
                        print(
                            f"     Port {results['open_ports'][i]} {results['opened_ports_services'][i].lower()}\\{self.Proto}")
            if self.scan_type == "ack":
                print(f"\n[+] Filtered Ports: {len(results['filtered_ports'])}")
                if len(results['filtered_ports']) <= 10 and len(results['filtered_ports']) != 0:
                    for i in range(len(results['filtered_ports'])):
                        print(
                            f"     Port {results['filtered_ports'][i]} {results['filtered_ports_services'][i].lower()}\\{self.Proto}")
                elif self.args.verbose:
                    for i in range(len(results['filtered_ports'])):
                        print(
                            f"     Port {results['filtered_ports'][i]} {results['filtered_ports_services'][i].lower()}\\{self.Proto}")

                print(f"\n[+] Unfiltered Ports: {len(results['unfiltered_ports'])}")
                if len(results['unfiltered_ports']) >= 21:
                    for i in range(len(results['unfiltered_ports'][:20])):
                        print(
                            f"     Port {results['filtered_ports'][i]} {results['unfiltered_ports_services'][i].lower()}\\{self.Proto}")
                elif len(results['unfiltered_ports']) > 0:
                    for i in range(len(results['unfiltered_ports'])):
                        print(
                            f"     Port {results['unfiltered_ports'][i]} {results['unfiltered_ports_services'][i].lower()}\\{self.Proto}")
            elif self.scan_type == "fdd":
                print(f"\n[+] Defended Ports: {len(results['defended_ports'])}")
                if len(results['defended_ports']) <= 10 and len(results['defended_ports']) != 0:
                    for i in range(len(results['defended_ports'])):
                        print(
                            f"     Port {results['defended_ports'][i]} {results['defended_ports_services'][i].lower()}\\{self.Proto}")
                elif self.args.verbose:
                    for i in range(len(results['defended_ports'])):
                        print(
                            f"     Port {results['defended_ports'][i]} {results['defended_ports_services'][i].lower()}\\{self.Proto}")

                print(f"\n[+] Undefended Ports: {len(results['undefended_ports'])}")
                if len(results['undefended_ports']) >= 21:
                    for i in range(len(results['undefended_ports'][:20])):
                        print(
                            f"     Port {results['undefended_ports'][i]} {results['undefended_ports_services'][i].lower()}\\{self.Proto}")
                elif len(results['undefended_ports']) > 0:
                    for i in range(len(results['undefended_ports'])):
                        print(
                            f"     Port {results['undefended_ports'][i]} {results['undefended_ports_services'][i].lower()}\\{self.Proto}")
            else:
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

            if self.scan_type == "syn" or self.scan_type == "udp" or self.scan_type == "maimon":
                print(f"\n[+] Open | Filtered Ports: {len(results['open_filtered_ports'])}")
                if len(results['open_filtered_ports']) <= 10 and len(results['open_filtered_ports']) != 0:
                    for i in range(len(results['open_filtered_ports'])):
                        print(
                            f"     Port {results['open_filtered_ports'][i]} {results['open_filtered_ports_services'][i].lower()}\\{self.Proto}")
                elif self.args.verbose:
                    for i in range(len(results['open_filtered_ports'])):
                        print(
                            f"     Port {results['open_filtered_ports'][i]} {results['open_filtered_ports_services'][i].lower()}\\{self.Proto}")
            if self.scan_type == "null":
                print(f"\n[+] (NULL Scan) Open | Filtered Ports: {len(results['null_ports'])}")
                if len(results['null_ports']) >= 21:
                    for i in range(len(results['null_ports'][:20])):
                        print(
                            f"     Port {results['null_ports'][i]} {results['null_ports_services'][i].lower()}\\{self.Proto}")
                elif len(results['null_ports']) <= 20 and len(results['null_ports']) > 0:
                    for i in range(len(results['null_ports'])):
                        print(
                            f"     Port {results['null_ports'][i]} {results['null_ports_services'][i].lower()}\\{self.Proto}")
            elif self.scan_type == "fin":
                print(f"\n[+] (FIN Scan) Open | Filtered Ports: {len(results['fin_ports'])}")
                if len(results['fin_ports']) >= 21:
                    for i in range(len(results['fin_ports'][:20])):
                        print(
                            f"     Port {results['fin_ports'][i]} {results['fin_ports_services'][i].lower()}\\{self.Proto}")
                elif len(results['fin_ports']) <= 20 and len(results['fin_ports']) > 0:
                    for i in range(len(results['fin_ports'])):
                        print(
                            f"     Port {results['fin_ports'][i]} {results['fin_ports_services'][i].lower()}\\{self.Proto}")
            elif self.scan_type == "xmas":
                print(f"\n[+] (XMAS Scan) Open | Filtered Ports: {len(results['open_filtered_ports'])}")
                if len(results['open_filtered_ports']) >= 21:
                    for i in range(len(results['open_filtered_ports'][:20])):
                        print(
                            f"     Port {results['open_filtered_ports'][i]} {results['open_filtered_ports_services'][i].lower()}\\{self.Proto}")
                elif len(results['open_filtered_ports']) <= 20 and len(results['open_filtered_ports']) > 0:
                    for i in range(len(results['open_filtered_ports'])):
                        print(
                            f"     Port {results['open_filtered_ports'][i]} {results['open_filtered_ports_services'][i].lower()}\\{self.Proto}")
            self.Firewall_detection(target, results)

            if self.args.banner:
                print(f"\n[+] Captured Banner/s: {len(results['banners'])}\n")
                for i in range(len(results['banners'])):
                    print(f"     [*] Banner from Port {results['banners_ports'][i]}:\n ")
                    print("="*60)
                    print(f"     {results['banners'][i]}")
                    print("="*60)
                    print()

            if self.args.os:
                try:
                    if self.args.verbose:
                        DB.OS_fingerprint(target, results['open_ports'] ,results['banners'],results['opened_ports_services'],results['window_scan_os'],True,True)
                    else:
                        DB.OS_fingerprint(target, results['open_ports'] ,results['banners'],results['opened_ports_services'],results['window_scan_os'],verbose=False,print_output=True)
                except Exception as e:
                    print(f"\n[+] OS Detection Error: {e}")

            if self.args.script:

                from LSSE import lsse
                try:
                    if self.args.script == "dns-subdomain-fuzzing":
                        print(f"\n[+] LSSE Response for {self.args.domain}: ")
                    elif self.args.script == "spider":
                        print(f"\n[+] LSSE Response for {self.args.url}: ")
                    elif self.args.script == "script":
                        print(f"\n[+] LSSE Response for {self.args.url}: ")
                    else:
                        self.script_port_parse()
                        print(f"[+] LSSE Response for {self.args.domain}: ")
                    lsse.Lsse.script_list(self.args.script, ports=self.lsse_ports_to_scan,
                                          redirect=self.args.redirect, domain=self.args.domain,
                                          dns=self.args.dns_server,wordlist=self.args.wordlist,url=self.args.url,
                                          max_pages=self.args.mxp,max_depth=self.args.mxd)
                    print(f"\n[+] LSSE run successfully\n")
                except Exception as e:
                    print(f"\n{red}[+] Script Error with {self.args.script} : {e}{reset}")



        print(f"\n[+] Lightscan scanned {len(self.targetss)} target(s) successfully\n")

    def Start(self):
        self.args_parse()
        if self.args.quiet:
            print()
        else:
            self.Banner()
        if self.args.lsse:
            from LSSE import lsse
            try:
                if self.args.script == "dns-subdomain-fuzzing":
                    print(f"\n[+] LSSE Response for {self.args.domain}: ")
                elif self.args.script == "spider":
                    print(f"\n[+] LSSE Response for {self.args.url}: ")
                elif self.args.script == "script":
                    print(f"\n[+] LSSE Response for {self.args.url}: ")
                else:
                    self.script_port_parse()
                    print(f"[+] LSSE Response for {self.args.domain}: ")
                lsse.Lsse.script_list(self.args.script, ports=self.lsse_ports_to_scan,redirect=self.args.redirect,domain=self.args.domain,dns=self.args.dns_server,wordlist=self.args.wordlist,url=self.args.url,
                                          max_pages=self.args.mxp,max_depth=self.args.mxd)
                print(f"\n[+] LSSE run successfully\n")
            except Exception as e:
                print(f"\n{red}[+] Script Error with {self.args.script} : {e}{reset}")

        else:
            self.agressive_scan_config()
            if self.args.os:
                if self.args.banner:
                    pass
                if self.args.recursively:
                    pass
                if self.args.banner == False and self.args.recursively == False:
                    print(f"\n{yellow}[!] OS Fingerprint need banner grabbing (-b,--banner){reset}\n")
                    exit(1)
            self.target_parse()
            self.target_validation()
            if self.args.lst:
                print()
                self.list_targets()
                print()
                exit(0)
            self.configure_speed()
            self.port_parse()
            if self.args.ping_port:
                self.ping_port_parse()
            self.check_network_config()

            if len(self.targets) > 1:
                self.show_network_info()

            for target in self.targets:
                self.initialize_target_results(target)

            if self.args.no_ping:
                if self.args.verbose:
                    if self.args.recursively:
                        print(f"\n{yellow}[!] Skipping flag -Pn because flag -Rc is active {reset}")
                        try:
                            self.threaded_host_discovery()
                        except:
                            self.threded_Tcp_host_discovery()
                    else:
                        print(f"\n{yellow}[!] Disabeling Host discovery{reset}")
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
                if self.args.tcp_ping:
                    try:
                        self.threded_Tcp_host_discovery()
                    except:
                        print(f"\n{red}[!] Error while TCP Ping <skip>{reset}\n")
                elif self.args.ack_ping:
                    try:
                        Payloads.threaded_ack_ping(self.max_threads,self.targets,self.args.ping_port,self.pp,self.target_results,self.socket_timeout,self.targetss,self.args.verbose,len(self.targets))
                    except:
                        print(f"\n{red}[!] Error while ACK Ping <skip>{reset}\n")
                elif self.args.udp_ping:
                    try:
                        self.threded_Udp_host_discovery()
                    except:
                        print(f"\n{red}[!] Error while UDP Ping <skip>{reset}\n")
                elif self.args.icmp_timestamp_ping:
                    try:
                        self.threaded_host_discovery_1()
                    except:
                        print(f"\n{red}[!] Error while ICMP Timestap Ping <skip>{reset}\n")
                elif self.args.icmp_information_ping:
                    try:
                        self.threaded_host_discovery_3()
                    except:
                        print(f"\n{red}[!] Error while ICMP Information Ping <skip>{reset}\n")
                elif self.args.icmp_address_ping:
                    try:
                        self.threaded_host_discovery_2()
                    except:
                        print(f"\n{red}[!] Error while ICMP Address Ping <skip>{reset}\n")
                elif self.args.syn_ping:
                    try:
                        self.threded_Syn_host_discovery()
                    except:
                        print(f"\n{red}[!] Error while SYN Ping <skip>{reset}\n")
                elif self.args.arp_ping:
                    try:
                        Payloads.threaded_arp_scan(self.max_threads, self.targets ,self.args.verbose,self.targetss,len(self.targets))
                    except Exception as e:
                        print(f"{red}[!] ARP Ping error: {e}{reset}")
                elif self.args.ip_ping:
                    try:
                        self.ip_ping_protocols()
                        Payloads.threaded_ip_ping(self.max_threads,self.args.verbose,self.socket_timeout,self.targets,self.targetss,self.protocols,self.target_results)
                    except Exception as e:
                        print(f"\n{red}[!] IP Ping Error <skip>{e}{reset}\n")
                else:
                    try:
                        self.threaded_host_discovery()
                    except:
                        print(f"\n{red}[!] Error while ICMP Ping <skip>{reset}\n")

            for target in self.targetss:
                self.initialize_target_results(target)

            if self.args.scan_type == "TCP":
                self.threaded_tcp_3_ways_handshake()
            elif self.args.scan_type == "SYN":
                self.threaded_tcp_syn_scan()
            elif self.args.scan_type == "NULL":
                self.start_time = time.perf_counter()
                self.Proto = "tcp"
                self.scan_type = "null"
                Payloads.threaded_null_scan(self.args.max_retries,self.lock,self.args.verbose,self.args.fragmente,self.args.recursively,self.socket_timeout,self.target_results,self.args.banner,self.max_threads,self.targetss,self.ports_to_scan,self.initialize_target_results,self.service_detection)
                self.end_time = time.perf_counter()
            elif self.args.scan_type == 'FTP-BOUNCE':
                if not self.args.ftp_server:
                    print("[!] FTP Bounce scan requires --ftp-bounce <server>")
                    sys.exit(1)
                self.start_time = time.perf_counter()

                Payloads.FTPBounceScan(
                    target=target,
                    ftpserver=self.args.ftp_server,
                    ftp_port=21,
                    port_range=self.ports_to_scan,
                    max_retries=self.args.max_retries if self.args.max_retries else 2,
                    verbose=self.args.verbose,
                    socket_timeout=self.args.timeout if self.args.timeout else 5,
                    lock=self.lock,
                    target_results=self.target_results,
                    initialize_target_results=self.initialize_target_results,
                    service_detection=self.service_detection
                )
                self.end_time = time.perf_counter()
            elif self.args.scan_type == "FIN":
                self.start_time = time.perf_counter()
                self.Proto = "tcp"
                self.scan_type = "fin"
                Payloads.threaded_fin_scan(self.args.max_retries,self.lock,self.args.verbose,self.args.fragmente,self.args.recursively,self.socket_timeout,self.target_results,self.args.banner,self.max_threads,self.targetss,self.ports_to_scan,self.initialize_target_results,self.service_detection)
                self.end_time = time.perf_counter()
            elif self.args.scan_type == "ACK":
                self.start_time = time.perf_counter()
                self.Proto = "tcp"
                self.scan_type = "ack"
                Payloads.threaded_ack_scan(self.args.max_retries,self.lock,self.args.verbose,self.args.fragmente,self.args.recursively,self.socket_timeout,self.target_results,self.args.banner,self.max_threads,self.targetss,self.ports_to_scan,self.initialize_target_results,self.service_detection)
                self.end_time = time.perf_counter()
            elif self.args.scan_type == "WINDOW":
                self.start_time = time.perf_counter()
                self.Proto = "tcp"
                self.scan_type = "window"
                Payloads.threaded_window_scan(self.args.max_retries, self.lock, self.args.verbose, self.args.fragmente,
                                            self.args.recursively, self.socket_timeout, self.target_results,
                                            self.args.banner, self.max_threads, self.targetss, self.ports_to_scan,
                                            self.initialize_target_results, self.service_detection)
                self.end_time = time.perf_counter()
            elif self.args.scan_type == "XMAS":
                self.start_time = time.perf_counter()
                self.Proto = "tcp"
                self.scan_type = "xmas"
                Payloads.threaded_xmas_scan(self.args.max_retries,self.lock,self.args.verbose,self.args.fragmente,self.args.recursively,self.socket_timeout,self.target_results,self.args.banner,self.max_threads,self.targetss,self.ports_to_scan,self.initialize_target_results,self.service_detection)
                self.end_time = time.perf_counter()
            elif self.args.scan_type == "MAIMON":
                self.start_time = time.perf_counter()
                self.Proto = "tcp"
                self.scan_type = "maimon"
                Payloads.threaded_maimon_scan(self.args.max_retries,self.lock,self.args.verbose,self.args.fragmente,self.args.recursively,self.socket_timeout,self.target_results,self.args.banner,self.max_threads,self.targetss,self.ports_to_scan,self.initialize_target_results,self.service_detection)
                self.end_time = time.perf_counter()
            elif self.args.scan_type == "FDD":
                self.start_time = time.perf_counter()
                self.Proto = "tcp"
                self.scan_type = "fdd"
                Payloads.threaded_fdd_scan(self.args.max_retries,self.lock,self.args.verbose,self.args.fragmente,self.args.recursively,self.socket_timeout,self.target_results,self.args.banner,self.max_threads,self.targetss,self.ports_to_scan,self.initialize_target_results,self.service_detection)
                self.end_time = time.perf_counter()
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
        print(f"\n{yellow}[!] Scan interrupted by user{reset}")
    except Exception as e:
        print(f"\n{red}[!] Unexpected error: {e}{reset}")

