import scapy.all as scapy
import random
import time
import ipaddress
from Banner_Grabbing import Banner
from Lightscan_OS_Database import DB
from concurrent.futures import ThreadPoolExecutor, as_completed
from Services import top_20_tcp_ports

red = "\033[31m"
reset = "\033[0m"
yellow = "\033[33m"

class Payloads:
    def __init__(self):
        pass

    @staticmethod
    def Stealth_tcp_options():
        options = [
            ('MSS', random.randint(1000,1440)),
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

        dns_query = (scapy.IP(dst=target,id=random.randint(1, 65535),ttl=random.randint(32,255),flags="DF") /
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
            "SSH-2.0-LightScan_1.1.5"
        ]
        ssh_banner = random.choice(ssh_clients) + "\r\n"

        packet = (scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.randint(32,255), flags="DF") /
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
            "SSH-2.0-LightScan_1.1.5"
        ]
        ssh_banner = random.choice(ssh_clients) + "\r\n"

        packet = (scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.randint(32,255), flags="DF") /
                  scapy.UDP(dport=22, sport=random.randint(60000, 65535)) /
                  scapy.Raw(load=ssh_banner))

        return packet

    @staticmethod
    def ftp_payload_tcp(target):
        ftp_clients = [
            "220 FTP Server Ready",
            "220 ProFTPD Server",
            "220 Microsoft FTP Service",
            "220 vsFTPd Server",
            "220 FileZilla Server",
            "220 Pure-FTPd Server",
            "220 Welcome to FTP Service",
            "220 Welcome to LightScan FTP Server",
        ]
        ftp_banner = random.choice(ftp_clients) + "\r\n"

        packet = (scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.randint(32,255), flags="DF") /
                  scapy.TCP(dport=21, sport=random.randint(60000, 65535),seq=random.randint(1000000000, 4294967295),window=random.choice([5840, 64240, 65535, 29200, 8760]),options=Payloads.Stealth_tcp_options(), flags="S") /
                  scapy.Raw(load=ftp_banner))

        return packet

    @staticmethod
    def ftp_payload_udp(target):
        ftp_clients = [
            "220 FTP Server Ready",
            "220 ProFTPD Server",
            "220 Microsoft FTP Service",
            "220 vsFTPd Server",
            "220 FileZilla Server",
            "220 Pure-FTPd Server",
            "220 Welcome to FTP Service",
            "220 Welcome to LightScan FTP Server",
        ]
        ftp_banner = random.choice(ftp_clients) + "\r\n"

        packet = (scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.randint(32,255), flags="DF") /
                  scapy.UDP(dport=21, sport=random.randint(60000, 65535)) /
                  scapy.Raw(load=ftp_banner))

        return packet

    @staticmethod
    def fragementation(packet, Proto, scan_type, verbose):
        packet[scapy.IP].flags = "MF"

        fragments = scapy.fragment(packet, fragsize=16)
        sent_count = 0
        for fragment in fragments:
            scapy.send(fragment, verbose=False)
            time.sleep(0.2)
            sent_count += 1

        time.sleep(0.5)

        if Proto == "udp":
            filter_str = f"udp and src host {packet[scapy.IP].dst} and dst port {packet[scapy.UDP].sport}"
            response = scapy.sniff(filter=filter_str, timeout=3)
            if verbose:
                print(f"\n[+] Fragmentation: {len(fragments)} packets sent, {len(response)} responses received\n")

            if response:
                return response[0]
            else:
                return None

        elif Proto == "tcp":
            if scan_type == "tcp":
                if verbose:
                    print(
                        f"\n[+] Fragmentation: {len(fragments)} packets sent to {packet[scapy.IP].dst}, {sent_count} responses received\n")
                return sent_count
            elif scan_type == "syn":
                filter_str = f"tcp and src host {packet[scapy.IP].dst} and dst port {packet[scapy.TCP].sport} and (tcp[13] & 0x12 = 0x12 or tcp[13] & 0x04 = 0x04 or tcp[13] & 0x14 = 0x14)"
                response = scapy.sniff(filter=filter_str, timeout=3)
                if verbose:
                    print(f"[+] Fragmentation: {len(fragments)} packets sent, {len(response)} responses received\n")

                if response:
                    return response[0]
                else:
                    return None
            else:
                filter_str = (f"tcp and src host {packet[scapy.IP].dst} and dst port {packet[scapy.TCP].sport}")
                response = scapy.sniff(filter=filter_str, timeout=3)
                if verbose:
                    print(f"[+] Fragmentation: {len(fragments)} packets sent, {len(response)} responses received\n")
                if response:
                    return response[0]
                else:
                    return None
        else:
            print(f"\n{red}[!] Fragmentation Error: (Protocol is not valid){reset}\n")
            exit(1)

    @staticmethod
    def is_private_ip(target):
        try:
            if target.lower() in ["localhost", "127.0.0.1"]:
                return "Local"

            ip = ipaddress.ip_address(target)
            if ip.is_private:
                return "Local"
            elif ip.is_loopback:
                return "Local"
            elif ip.is_link_local:
                return "Local"
            elif ip.is_multicast:
                return "Local"
            elif ip.is_reserved:
                return "Local"
            elif ip.is_unspecified:
                return "Local"
            else:
                return "Public"

        except ValueError:
            return "Invalid"

    @staticmethod
    def ARP_Scan(target):
        try:
            if target.lower() == "localhost" or target == "127.0.0.1":
                 from getmac import get_mac_address
                 mac = get_mac_address()
                 return mac
            else:
                arp_request = scapy.ARP(pdst=target)
                ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether_frame / arp_request

                answered, unanswered = scapy.srp(packet, timeout=2, verbose=0)
                if answered:
                    for sent, received in answered:
                        return received.hwsrc
                else:
                    return None
        except Exception as e:
            print(f"{red}[!] MAC ADDR error: {e}{reset}")

    @staticmethod
    def arp_Scan(target,targets,targets_num):
        arp_request = scapy.ARP(pdst=target)
        ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether_frame / arp_request

        answered, unanswered = scapy.srp(packet, timeout=2, verbose=0)
        if targets_num == 1:
            if answered:
                for i, (sent, received) in enumerate(answered):
                    print(f"[ARP] Host {received.psrc} is up (MAC: {received.hwsrc})")
                    targets.append(target)
            else:
                print(f"[ARP] Host {target} is shown to be down or not responding")
                targets.append(target)
        else:
            if answered:
                for i, (sent, received) in enumerate(answered):
                    print(f"[ARP] Host {received.psrc} is up (MAC: {received.hwsrc})")
                    targets.append(target)
            else:
                pass


    @staticmethod
    def threaded_arp_scan(max_threads, targets, verbose,Targets,Targets_num):

        if max_threads == 1:
            for target in targets:
                Payloads.arp_Scan(target,Targets,Targets_num)
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for target in targets:
                    future = executor.submit(
                        Payloads.arp_Scan,target,Targets,Targets_num
                    )
                    futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{red}[!] ARP Ping error: {e}{reset}")


    @staticmethod
    def Null_Scan(target, port, max_retries, fragmente, recursively, verbose, socket_timeout, lock, target_results, banner_option,initialize_target_results,service_detection):
        for attempt in range(max_retries):
            try:
                Proto = "tcp"
                scan_type = "null"
                packet = scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.choice([64, 128, 255]),flags="DF") / scapy.TCP(dport=port, sport=random.randint(60000, 65535),seq=random.randint(1000000000, 4294967295),window=random.choice([5840, 64240, 65535, 29200, 8760]),options=Payloads.Stealth_tcp_options(),flags="")
                if fragmente:
                    if recursively:
                        response = Payloads.fragementation(packet, Proto, scan_type, verbose)
                        if verbose:
                            print("\n[+] Demo Fragementation (if you find an error while using it leave it in our github for future updates)\n")
                    else:
                        if verbose:
                            print(f"\n{yellow}[+] Fragmentation is Forbiden with NULL packets (if you want use flag -Rc){reset}\n")
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
                        print(flags)
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
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)

                    break

            except Exception as e:
                if verbose:
                    print(f"{red}[!] Error scanning port {port}: {e}{reset}")
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
                            print(f"{red}[!] Null scan error: {e}{reset}")

    @staticmethod
    def Fin_Scan(target, port, max_retries, fragmente, recursively, verbose, socket_timeout, lock, target_results,banner_option, initialize_target_results, service_detection):
        for attempt in range(max_retries):
            try:
                Proto = "tcp"
                scan_type = "fin"
                packet = scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.choice([64, 128, 255]),
                                  flags="DF") / scapy.TCP(dport=port, sport=random.randint(60000, 65535),
                                                          seq=random.randint(1000000000, 4294967295),
                                                          window=random.choice([5840, 64240, 65535, 29200, 8760]),
                                                          options=Payloads.Stealth_tcp_options(), flags="F")
                if fragmente:
                    if recursively:
                        response = Payloads.fragementation(packet, Proto, scan_type, verbose)
                        if verbose:
                            print(
                                "\n[+] Demo Fragementation (if you find an error while using it leave it in our github for future updates)\n")
                    else:
                        if verbose:
                            print(f"\n{yellow}[+] Fragmentation is Forbiden with FIN packets (if you want use flag -Rc){reset}\n")
                        response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)
                else:
                    response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)
                service = service_detection(port)

                if response is None:

                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['fin_ports'].append(port)
                        target_results[target]['fin_ports_services'].append(service)

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
                        print(flags)
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                elif response.haslayer(scapy.ICMP):
                    icmp_type = response.getlayer(scapy.ICMP).type
                    icmp_code = response.getlayer(scapy.ICMP).code

                    if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
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
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)
                    break

            except Exception as e:
                if verbose:
                    print(f"{red}[!] Error scanning port {port}: {e}{reset}")
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
    def threaded_fin_scan(max_retries,lock, verbose,fragmente,recursively,socket_timeout,target_results,banner_option,max_threads,targetss,ports_to_scan,i,s):

        if max_threads == 1:
            for target in targetss:
                for port in ports_to_scan:
                    Payloads.Fin_Scan(target, port, max_retries, fragmente, recursively,
                                       verbose, socket_timeout, lock, target_results,
                                       banner_option, i, s)
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for target in targetss:
                    for port in ports_to_scan:
                        future = executor.submit(
                            Payloads.Fin_Scan,
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
                            print(f"{red}[!] Fin scan error: {e}{reset}")

    @staticmethod
    def Ack_Scan(target, port, max_retries, fragmente, recursively, verbose, socket_timeout, lock, target_results,banner_option, initialize_target_results, service_detection):
        for attempt in range(max_retries):
            try:
                Proto = "tcp"
                scan_type = "ack"
                packet = scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.choice([64, 128, 255]),
                                  flags="DF") / scapy.TCP(dport=port, sport=random.randint(60000, 65535),
                                                          seq=random.randint(1000000000, 4294967295),
                                                          window=random.choice([5840, 64240, 65535, 29200, 8760]),
                                                          options=Payloads.Stealth_tcp_options(), flags="A")
                if fragmente:
                    if recursively:
                        response = Payloads.fragementation(packet, Proto, scan_type, verbose)
                        if verbose:
                            print(
                                "\n[+] Demo Fragementation (if you find an error while using it leave it in our github for future updates)\n")
                    else:
                        if verbose:
                            print(f"\n{yellow}[+] Fragmentation is Forbiden with ACK packets (if you want use flag -Rc){reset}\n")
                        response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)
                else:
                    response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)
                service = service_detection(port)

                if response is None:

                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)

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
                            target_results[target]['unfiltered_ports'].append(port)
                            target_results[target]['unfiltered_ports_services'].append(service)

                    else:
                        print(flags)
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                elif response.haslayer(scapy.ICMP):
                    icmp_type = response.getlayer(scapy.ICMP).type
                    icmp_code = response.getlayer(scapy.ICMP).code

                    if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
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
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)
                    break

            except Exception as e:
                if verbose:
                    print(f"{red}[!] Error scanning port {port}: {e}{reset}")
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
    def threaded_ack_scan(max_retries,lock, verbose,fragmente,recursively,socket_timeout,target_results,banner_option,max_threads,targetss,ports_to_scan,i,s):

        if max_threads == 1:
            for target in targetss:
                for port in ports_to_scan:
                    Payloads.Ack_Scan(target, port, max_retries, fragmente, recursively,
                                       verbose, socket_timeout, lock, target_results,
                                       banner_option, i, s)
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for target in targetss:
                    for port in ports_to_scan:
                        future = executor.submit(
                            Payloads.Ack_Scan,
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
                            print(f"{red}[!] Ack scan error: {e}{reset}")

    @staticmethod
    def Xmas_Scan(target, port, max_retries, fragmente, recursively, verbose, socket_timeout, lock, target_results,banner_option, initialize_target_results, service_detection):
        for attempt in range(max_retries):
            try:

                Proto = "tcp"
                scan_type = "xmas"
                packet = scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.choice([64, 128, 255]),
                                  flags="DF") / scapy.TCP(dport=port, sport=random.randint(60000, 65535),
                                                          seq=random.randint(1000000000, 4294967295),
                                                          window=random.choice([5840, 64240, 65535, 29200, 8760]),
                                                          options=Payloads.Stealth_tcp_options(), flags="FPU")
                if fragmente:
                    if recursively:
                        response = Payloads.fragementation(packet, Proto, scan_type, verbose)
                        if verbose:
                            print(
                                "\n[+] Demo Fragementation (if you find an error while using it leave it in our github for future updates)\n")
                    else:
                        if verbose:
                            print(f"\n{yellow}[+] Fragmentation is Forbiden with XMAS packets (if you want use flag -Rc){reset}\n")
                        response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)
                else:
                    response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)

                service = service_detection(port)

                if response is None:

                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['open_filtered_ports'].append(port)
                        target_results[target]['open_filtered_ports_services'].append(service)

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
                        print(flags)
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                elif response.haslayer(scapy.ICMP):
                    icmp_type = response.getlayer(scapy.ICMP).type
                    icmp_code = response.getlayer(scapy.ICMP).code

                    if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
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
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)
                    break

            except Exception as e:
                if verbose:
                    print(f"{red}[!] Error scanning port {port}: {e}{reset}")
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
    def threaded_xmas_scan(max_retries,lock, verbose,fragmente,recursively,socket_timeout,target_results,banner_option,max_threads,targetss,ports_to_scan,i,s):

        if max_threads == 1:
            for target in targetss:
                for port in ports_to_scan:
                    Payloads.Xmas_Scan(target, port, max_retries, fragmente, recursively,
                                       verbose, socket_timeout, lock, target_results,
                                       banner_option, i, s)
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for target in targetss:
                    for port in ports_to_scan:
                        future = executor.submit(
                            Payloads.Xmas_Scan,
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
                            print(f"{red}[!] Xmas scan error: {e}{reset}")

    @staticmethod
    def IP_Ping(target,protocol,verbose,socket_timeout,target_results):
        count = 0
        for i in range(2):
            try:
                if protocol == 1:
                    if count >= 1:
                        ttl = 128
                    else:
                        ttl = 64
                    socket_timeout = 3
                else:
                    if count >= 1:
                        ttl = 255
                    else:
                        ttl = 128

                    socket_timeout = 2

                packet = scapy.IP(dst=target, proto=protocol,ttl=ttl,id=random.randint(1, 65535))
                response = scapy.sr1(packet, timeout=socket_timeout,verbose=0)
                if response:
                    if response.haslayer(scapy.ICMP):
                        icmp = response.getlayer(scapy.ICMP)
                        if icmp.type == 3:
                            if icmp.code in [13,1, 2, 9, 10]:
                                target_results[target]['filtered'] += 1
                            elif icmp.code in [3]:
                                target_results[target]['up'] += 1
                            else:
                                target_results[target]['down'] += 1
                        elif icmp.type == 0:
                            target_results[target]['up'] += 1
                        elif icmp.type == 14:
                            target_results[target]['up'] += 1
                        elif icmp.type == 18:
                            target_results[target]['up'] += 1
                        elif icmp.type == 11:
                            target_results[target]['filtered'] += 1
                        else:
                            target_results[target]['up'] += 1
                    elif response.haslayer(scapy.TCP):
                        flags = response.getlayer(scapy.TCP).flags

                        if flags == 0x14 or flags == 0x04 or flags == 0x12:
                            target_results[target]['up'] += 1
                        else:
                            target_results[target]['up'] += 1
                    elif response.haslayer(scapy.UDP):
                        target_results[target]['up'] += 1
                    elif response.proto == protocol:
                        target_results[target]['up'] += 1
                    else:
                        target_results[target]['up'] += 1
                else:
                    target_results[target]['down'] += 1
            except Exception as e:
                if verbose:
                    print(f"{red}[!] IP Ping Error {protocol}: {e}{reset}")
                    target_results[target]['filtered'] += 1
                else:
                    target_results[target]['filtered'] += 1

            count += 1

    @staticmethod
    def threaded_ip_ping(max_threads, verbose, socket_timeout, targets,
                         Target, protocols, target_results):
        for target in targets:
            target_results[target] = {'up': 0, 'down': 0,'filtered': 0}

        if max_threads == 1:
            for target in targets:
                for protocol in protocols:
                    Payloads.IP_Ping(target, protocol, verbose,
                                     socket_timeout, target_results)
        else:
            futures = []
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                for target in targets:
                    for protocol in protocols:
                        future = executor.submit(
                            Payloads.IP_Ping,
                            target, protocol, verbose,
                            socket_timeout, target_results
                        )
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{red}[!] Error: {e}{reset}")

        for target in targets:
            if len(targets) == 1:
                up = target_results[target]['up']
                down = target_results[target]['down']
                filtered = target_results[target]['filtered']

                if up > down and up > filtered:
                    print(f"[IP] Host {target} is up! ({up} up, {down} down)")
                    if target not in Target:
                        Target.append(target)
                elif up < down and down > filtered:
                    print(f"[IP] Host {target} appears down ({up} up, {down} down)")
                    if target not in Target:
                        Target.append(target)
                elif filtered > up and filtered > down:
                    print(f"[IP] Host {target} appears to be not responding ({up} up, {down} down, {filtered} filtered)")
                    if target not in Target:
                        Target.append(target)
                else:
                    print(f"[IP] Host {target}: Inconclusive ({up} up, {down} down, {filtered} filtered)")
                    if target not in Target:
                        Target.append(target)
            else:
                up = target_results[target]['up']
                down = target_results[target]['down']
                filtered = target_results[target]['filtered']

                if up > down and up > filtered:
                    print(f"[IP] Host {target} is up! ({up} up, {down} down)")
                    if target not in Target:
                        Target.append(target)
                elif up < down and down > filtered:
                    print(f"[IP] Host {target} appears down ({up} up, {down} down)")
                elif filtered > up and filtered > down:
                    print(f"[IP] Host {target} appears to be not responding ({up} up, {down} down, {filtered} filtered)")
                else:
                    print(f"[IP] Host {target}: Inconclusive ({up} up, {down} down, {filtered} filtered)")
                    if target not in Target:
                        Target.append(target)


    @staticmethod
    def Window_Scan(target, port, max_retries, fragmente, recursively, verbose, socket_timeout, lock, target_results,banner_option, initialize_target_results, service_detection):
        for attempt in range(max_retries):
            try:
                Services = []
                Proto = "tcp"
                scan_type = "window"
                packet = scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.choice([64, 128, 255]),
                                  flags="DF") / scapy.TCP(dport=port, sport=random.randint(60000, 65535),
                                                          seq=random.randint(1000000000, 4294967295),
                                                          window=random.choice([5840, 64240, 65535, 29200, 8760]),
                                                          options=Payloads.Stealth_tcp_options(), flags="A")
                if fragmente:
                    if recursively:
                        response = Payloads.fragementation(packet, Proto, scan_type, verbose)
                        if verbose:
                            print(
                                "\n[+] Demo Fragementation (if you find an error while using it leave it in our github for future updates)\n")
                    else:
                        if verbose:
                            print(f"\n{yellow}[+] Fragmentation is Forbiden with WINDOW packets (if you want use flag -Rc){reset}\n")
                        response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)
                else:
                    response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)

                service = service_detection(port)

                if response is None:

                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)

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
                        window = response.getlayer(scapy.TCP).window
                        if window == 0:
                            with lock:
                                if target not in target_results:
                                    initialize_target_results(target)
                                target_results[target]['closed_ports'].append(port)
                                target_results[target]['closed_ports_services'].append(service)
                        else:
                            with lock:
                                if target not in target_results:
                                    initialize_target_results(target)
                                target_results[target]['open_ports'].append(port)
                                target_results[target]['opened_ports_services'].append(service)

                    else:
                        print(flags)
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                elif response.haslayer(scapy.ICMP):
                    icmp_type = response.getlayer(scapy.ICMP).type
                    icmp_code = response.getlayer(scapy.ICMP).code

                    if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
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
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)
                    break

            except Exception as e:
                if verbose:
                    print(f"{red}[!] Error scanning port {port}: {e}{reset}")
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
    def threaded_window_scan(max_retries,lock, verbose,fragmente,recursively,socket_timeout,target_results,banner_option,max_threads,targetss,ports_to_scan,i,s):

        if max_threads == 1:
            for target in targetss:
                for port in ports_to_scan:
                    Payloads.Window_Scan(target, port, max_retries, fragmente, recursively,
                                       verbose, socket_timeout, lock, target_results,
                                       banner_option, i, s)
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for target in targetss:
                    for port in ports_to_scan:
                        future = executor.submit(
                            Payloads.Window_Scan,
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
                            print(f"{red}[!] Window scan error: {e}{reset}")

    @staticmethod
    def Ack_ping(target,port,socket_timeout,targets_num,target_results,targetss):
        Proto = "tcp"
        packet = scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.choice([64, 128, 255]),
                          flags="DF") / scapy.TCP(dport=port, sport=random.randint(60000, 65535),
                                                  seq=random.randint(1000000000, 4294967295),
                                                  window=random.choice([5840, 64240, 65535, 29200, 8760]),
                                                  options=Payloads.Stealth_tcp_options(), flags="A")
        response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)
        if len(targets_num) == 1:
            if response:
                if response.haslayer(scapy.TCP):
                    flags = response.getlayer(scapy.TCP).flags
                    print(flags)

                    if flags == 0x04 or flags == 0x14:
                        print(f"[ACK] Host {target}:{port} is up! ")
                        if target not in targetss:
                            targetss.append(target)
                        target_results[target]['up'] += 1
                    else:
                        if target not in targetss:
                            targetss.append(target)
                else:
                    if target not in targetss:
                        targetss.append(target)
            else:
                if target not in targetss:
                    targetss.append(target)

        else:
            if response:
                if response.haslayer(scapy.TCP):
                    flags = response.getlayer(scapy.TCP).flags

                    if flags == 0x04 or flags == 0x14:
                        print(f"[ACK] Host {target}:{port} is up! ")
                        if target not in targetss:
                            targetss.append(target)
                        target_results[target]['up'] += 1
                    else:
                        pass
                else:
                    pass
            else:
                pass

    @staticmethod
    def threaded_ack_ping(max_threads,targets,ping_port,pp,target_results,socket_timeout,targetss,verbose,num):
            if max_threads == 1:
                for Target in targets:
                    if ping_port:
                        for port in pp:
                            Payloads.Ack_ping(Target, port,socket_timeout,num,target_results,targetss)
                    else:
                        for port in top_20_tcp_ports:
                            Payloads.Ack_ping(Target, port,socket_timeout,targets,target_results,targetss)

                for target in targets:
                    if target_results[target]['up'] >= 1:
                        pass
                    else:
                        print(f"[ACK] Host {target} is shown to be down or not responding")

            else:
                with ThreadPoolExecutor(max_workers=max_threads) as executor:
                    futures = []
                    for Target in targets:
                        if ping_port:
                            for port in pp:
                                future = executor.submit(
                                    Payloads.Ack_ping,Target, port,socket_timeout,targets,target_results,targetss
                                )
                                time.sleep(0.02)
                                futures.append(future)
                        else:
                            for port in top_20_tcp_ports:
                                future = executor.submit(
                                    Payloads.Ack_ping,Target, port,socket_timeout,targets,target_results,targetss
                                )
                                time.sleep(0.02)
                                futures.append(future)

                    for future in as_completed(futures):
                        try:
                            future.result()
                        except Exception as e:
                            if verbose:
                                print(f"{red}[!] ACK ping error: {e}{reset}")

            for target in targets:
                time.sleep(0.01)
                if target_results[target]['up'] >= 1:
                    pass
                else:
                    print(f"[ACK] Host {target} is shown to be down or not responding")

    @staticmethod
    def Maimon_Scan(target, port, max_retries, fragmente, recursively, verbose, socket_timeout, lock, target_results,banner_option, initialize_target_results, service_detection):
        for attempt in range(max_retries):
            try:

                Proto = "tcp"
                scan_type = "maimon"
                packet = scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.choice([64, 128, 255]),
                                  flags="DF") / scapy.TCP(dport=port, sport=random.randint(60000, 65535),
                                                          seq=random.randint(1000000000, 4294967295),
                                                          window=random.choice([5840, 64240, 65535, 29200, 8760]),
                                                          options=Payloads.Stealth_tcp_options(), flags="FA")
                if fragmente:
                    if recursively:
                        response = Payloads.fragementation(packet, Proto, scan_type, verbose)
                        if verbose:
                            print(
                                "\n[+] Demo Fragementation (if you find an error while using it leave it in our github for future updates)\n")
                    else:
                        if verbose:
                            print(f"\n{yellow}[+] Fragmentation is Forbiden with MAIMON packets (if you want use flag -Rc){reset}\n")
                        response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)
                else:
                    response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)

                service = service_detection(port)

                if response is None:

                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['open_filtered_ports'].append(port)
                        target_results[target]['open_filtered_ports_services'].append(service)

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
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                elif response.haslayer(scapy.ICMP):
                    icmp_type = response.getlayer(scapy.ICMP).type
                    icmp_code = response.getlayer(scapy.ICMP).code

                    if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
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
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)
                    break

            except Exception as e:
                if verbose:
                    print(f"{red}[!] Error scanning port {port}: {e}{reset}")
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
    def threaded_maimon_scan(max_retries,lock, verbose,fragmente,recursively,socket_timeout,target_results,banner_option,max_threads,targetss,ports_to_scan,i,s):

        if max_threads == 1:
            for target in targetss:
                for port in ports_to_scan:
                    Payloads.Maimon_Scan(target, port, max_retries, fragmente, recursively,
                                       verbose, socket_timeout, lock, target_results,
                                       banner_option, i, s)
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for target in targetss:
                    for port in ports_to_scan:
                        future = executor.submit(
                            Payloads.Maimon_Scan,
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
                            print(f"{red}[!] Maimon scan error: {e}{reset}")

    @staticmethod
    def Fdd_Scan(target, port, max_retries, fragmente, recursively, verbose, socket_timeout, lock, target_results,banner_option, initialize_target_results, service_detection):
        for attempt in range(max_retries):
            try:

                Proto = "tcp"
                scan_type = "fdd"
                packet = scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.choice([64, 128, 255]),
                                  flags="DF") / scapy.TCP(dport=port, sport=random.randint(60000, 65535),
                                                          seq=random.randint(1000000000, 4294967295),
                                                          window=random.choice([5840, 64240, 65535, 29200, 8760]),
                                                          options=Payloads.Stealth_tcp_options(), flags="U")
                if fragmente:
                    if recursively:
                        response = Payloads.fragementation(packet, Proto, scan_type, verbose)
                        if verbose:
                            print(
                                "\n[+] Demo Fragementation (if you find an error while using it leave it in our github for future updates)\n")
                    else:
                        if verbose:
                            print(f"\n{yellow}[+] Fragmentation is Forbiden with FDD packets (if you want use flag -Rc){reset}\n")
                        response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)
                else:
                    response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)

                service = service_detection(port)

                if response is None:

                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['defended_ports'].append(port)
                        target_results[target]['defended_ports_services'].append(service)

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
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['undefended_ports'].append(port)
                        target_results[target]['undefended_ports_services'].append(service)

                elif response.haslayer(scapy.ICMP):
                    icmp_type = response.getlayer(scapy.ICMP).type
                    icmp_code = response.getlayer(scapy.ICMP).code

                    if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['defended_ports'].append(port)
                            target_results[target]['defended_ports_services'].append(service)
                        break

                    else:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['defended_ports'].append(port)
                            target_results[target]['defended_ports_services'].append(service)
                        break

                else:
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['defended_ports'].append(port)
                        target_results[target]['defended_ports_services'].append(service)
                    break

            except Exception as e:
                if verbose:
                    print(f"{red}[!] Error scanning port {port}: {e}{reset}")
                if attempt == max_retries - 1:
                    service = service_detection(port)
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['defended_ports'].append(port)
                        target_results[target]['defended_ports_services'].append(service)
                else:
                    time.sleep(0.1)
                    continue

    @staticmethod
    def threaded_fdd_scan(max_retries,lock, verbose,fragmente,recursively,socket_timeout,target_results,banner_option,max_threads,targetss,ports_to_scan,i,s):

        if max_threads == 1:
            for target in targetss:
                for port in ports_to_scan:
                    Payloads.Fdd_Scan(target, port, max_retries, fragmente, recursively,
                                       verbose, socket_timeout, lock, target_results,
                                       banner_option, i, s)
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for target in targetss:
                    for port in ports_to_scan:
                        future = executor.submit(
                            Payloads.Fdd_Scan,
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
                            print(f"{red}[!] Fdd scan error: {e}{reset}")