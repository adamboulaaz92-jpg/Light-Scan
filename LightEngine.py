import scapy.all as scapy
import random
import time
import ipaddress
from Banner_Grabbing import Banner
from concurrent.futures import ThreadPoolExecutor, as_completed

class Payloads:
    def __init__(self):
        pass

    @staticmethod
    def Stealth_tcp_options():
        options = [
            ('MSS', random.choice([1260, 1360, 1460])),
            ('WScale', random.randint(2, 14)),
            ('Timestamp', (random.randint(1, 1000000000), 0)),
            ('SAckOK', ''),
            ('NOP', None),
            ('NOP', None),
            ('EOL', None)
        ]
        random.shuffle(options)
        for i, opt in enumerate(options):
            if opt[0] == 'MSS':
                options.insert(0, options.pop(i))
                break
        return options

    @staticmethod
    def dns_payload_udp(target):
        query_type = "A"
        domain = random.choice([
            "google.com", "youtube.com", "github.com",
            "microsoft.com", "amazon.com"
        ])
        qtype_map = {
            "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12,
            "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "ANY": 255
        }
        qtype = qtype_map.get(query_type.upper(), 1)

        dns_query = (scapy.IP(dst=target,id=random.randint(1, 65535),ttl=random.choice([64, 128, 255]),flags="DF") /
                     scapy.UDP(dport=53,sport=random.randint(60000,65535)) /
                     scapy.DNS(id=random.randint(1, 65535),rd=1, qd=scapy.DNSQR(qname=domain, qtype=qtype)))

        return dns_query

    @staticmethod
    def ssh_payload_tcp(target):
        ssh_clients = [
            "SSH-2.0-OpenSSH_8.9p1",
            "SSH-2.0-OpenSSH_7.4",
            "SSH-2.0-OpenSSH_7.9",
            "SSH-2.0-libssh2_1.10.0",
            "SSH-2.0-PuTTY_Release_0.78",
        ]
        ssh_banner = random.choice(ssh_clients) + "\r\n"

        packet = (scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.choice([64, 128, 255]), flags="DF") /
                  scapy.TCP(dport=22, sport=random.randint(60000, 65535),seq=random.randint(1000000000, 4294967295),window=random.choice([5840, 64240, 65535, 29200, 8760]),options=Payloads.Stealth_tcp_options(), flags="S") /
                  scapy.Raw(load=ssh_banner))

        return packet

    @staticmethod
    def ssh_payload_udp(target):
        ssh_clients = [
            "SSH-2.0-OpenSSH_8.9p1",
            "SSH-2.0-OpenSSH_7.4",
            "SSH-2.0-OpenSSH_7.9",
            "SSH-2.0-libssh2_1.10.0",
            "SSH-2.0-PuTTY_Release_0.78",
        ]
        ssh_banner = random.choice(ssh_clients) + "\r\n"

        packet = (scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.choice([64, 128, 255]), flags="DF") /
                  scapy.UDP(dport=22, sport=random.randint(60000, 65535)) /
                  scapy.Raw(load=ssh_banner))

        return packet

    @staticmethod
    def fragementation(packet, Proto, scan_type, verbose):

        packet[scapy.IP].flags = "MF"

        fragments = scapy.fragment(packet, fragsize=16)
        sent_count = 0
        for fragment in fragments:
            scapy.send(fragment, verbose=False)
            time.sleep(0.1)
            sent_count += 1

        time.sleep(0.5)

        if Proto == "udp":
            filter_str = f"udp and src host {packet[scapy.IP].dst} and dst port {packet[scapy.UDP].sport}"
            response = scapy.sniff(filter=filter_str, timeout=3, verbose=False)
            if verbose:
                print(f"[+] Fragmentation: {len(fragments)} packets sent, {len(response)} responses received\n")
            return response
        elif Proto == "tcp":
            if scan_type == "tcp":
                if verbose:
                    print(f"[+] Fragmentation: {len(fragments)} packets sent to {packet[scapy.IP].dst}, {sent_count} responses received\n")
                return sent_count
            elif scan_type == "syn":
                filter_str = (f"tcp and src host {packet[scapy.IP].dst} and dst port {packet[scapy.TCP].sport} and "
                                 f"(tcp[13] & 18 != 0 or tcp[13] & 4 != 0 or tcp[13] & 20 != 0)")
                response = scapy.sniff(filter=filter_str, timeout=3, verbose=False)
                if verbose:
                    print(f"[+] Fragmentation: {len(fragments)} packets sent, {len(response)} responses received\n")
                return response
        else:
            print("\n[!] Fragmentation Error: {Protocole is not valide}\n")
            exit(1)

    @staticmethod
    def is_private_ip(target):
        try:
            ip = ipaddress.ip_address(target)
            return "Local"
        except ValueError:
            return "Public"

    @staticmethod
    def ARP_Scan(target):
        try:
            mac = scapy.getmacbyip(target)
            if mac:
                return mac
        except:

            packet = scapy.ARP(pdst=target) / scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

            result = scapy.srp(packet, timeout=5, verbose=0)[0]

            if result:
                for sent, received in result:
                    return received.hwsrc

            else:
                return None

    @staticmethod
    def Null_Scan(target, port, max_retries, fragmente, recursively, verbose, socket_timeout, lock, target_results, banner_option,initialize_target_results,service_detection):
        for attempt in range(max_retries):
            try:
                Proto = "tcp"
                scan_type = "null"


                packet = scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.choice([64, 128, 255]),flags="DF") / scapy.TCP(dport=port, sport=random.randint(60000, 65535),seq=random.randint(1000000000, 4294967295),window=random.choice([5840, 64240, 65535, 29200, 8760]),options=Payloads.Stealth_tcp_options())
                if fragmente:
                    if recursively:
                        response = Payloads.fragementation(packet, Proto, scan_type, verbose)
                        if verbose:
                            print("\n[+] Demo Fragementation (if you find an error while using it leave it in our github for future updates)\n")
                    else:
                        if verbose:
                            print("\n[+] Fragmentation is Forbiden with NULL packets (if you want use flag -Rc)\n")
                        response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)
                else:
                    response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)
                service = service_detection(port)

                if response is None:
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['null_ports'].append(port)
                        target_results[target]['null_ports_services'].append(service)

                    if banner_option:
                        banner = Banner.banner_grab(
                            target=target,
                            port=port,
                            protocol="tcp",
                            timeout=3,
                            verbose=verbose
                        )

                        if banner:
                            with lock:
                                target_results[target]['banners'].append(banner)
                                target_results[target]['banners_ports'].append(port)

                            Banner.analyse_banner(banner, port, target_results[target], Proto, lock)
                        else:
                            pass

                elif response.haslayer(scapy.TCP):
                    flags = response.getlayer(scapy.TCP).flags

                    if flags == 0x14 or flags == 0x04:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['closed_ports'].append(port)
                            target_results[target]['closed_ports_services'].append(service)

                    else:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['null_ports'].append(port)
                            target_results[target]['null_ports_services'].append(service)
                        break

                elif response.haslayer(scapy.ICMP):
                    icmp_type = response.getlayer(scapy.ICMP).type
                    icmp_code = response.getlayer(scapy.ICMP).code

                    if icmp_type == 3 and icmp_code in [1,2,3,9,10,13]:
                        with lock:
                                if target not in target_results:
                                    initialize_target_results(target)
                                target_results[target]['filtered_ports'].append(port)
                                target_results[target]['filtered_ports_services'].append(service)
                        break

                    else:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                else:
                    with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['null_ports'].append(port)
                            target_results[target]['null_ports_services'].append(service)
                    break

            except Exception as e:
                if verbose:
                    print(f"[!] Error scanning port {port}: {e}")
                if attempt == max_retries - 1:
                    service = service_detection(port)
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)
                else:
                    time.sleep(0.1)
                    continue
    @staticmethod
    def threaded_null_scan(max_retries,lock, verbose,fragmente,recursively,socket_timeout,target_results,banner_option,max_threads,targetss,ports_to_scan,i,s):

        if max_threads == 1:
            for target in targetss:
                for port in ports_to_scan:
                    Payloads.Null_Scan(target, port, max_retries, fragmente, recursively,
                                       verbose, socket_timeout, lock, target_results,
                                       banner_option, i, s)
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for target in targetss:
                    for port in ports_to_scan:
                        future = executor.submit(
                            Payloads.Null_Scan,
                            target, port, max_retries, fragmente, recursively,
                            verbose, socket_timeout, lock, target_results,
                            banner_option, i, s
                        )
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"[!] Null scan error: {e}")



