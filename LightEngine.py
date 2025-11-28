import scapy.all as scapy
import random
import time
import socket

class Payloads:
    def __init__(self):
        pass

    @staticmethod
    def dns_payload_udp(target):
        dns_query = (scapy.IP(dst=target,id=random.randint(1, 65535),ttl=random.choice([64, 128, 255]),flags="DF") /
                     scapy.UDP(dport=53,sport=random.randint(60000,65535)) /
                     scapy.DNS(rd=1, qd=scapy.DNSQR(qname="google.com", qtype="A")))

        return dns_query

    @staticmethod
    def banner_grab(target, port, protocol="tcp", timeout=5, verbose=False):
        try:
            if verbose:
                print(f"\n[+] Banner grab: {target}: Port {port} ({protocol.upper()})")

            payload = Payloads.banner_grabing_payloads(target, port, protocol)

            if protocol.lower() == "tcp":
                return Payloads._tcp_banner_grab(target, port, payload, timeout, verbose)
            elif protocol.lower() == "udp":
                return Payloads._udp_banner_grab(target, port, payload, timeout, verbose)
            else:
                if verbose:
                    print(f"[!] Unknown protocol: {protocol}")
                return None

        except Exception as e:
            if verbose:
                print(f"\n[!] Banner grab error: {e}")
            return None

    @staticmethod
    def OS_figerprint(target, open_ports):
        L = []
        W = []
        C = []
        for port in open_ports:
            try:
                pkt = scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.choice([64, 128, 255]),flags="DF") / scapy.TCP(dport=port, sport=random.randint(60000, 65535),seq=random.randint(1000000000, 4294967295),window=random.choice([5840, 64240, 65535]),options=[('MSS', random.choice([1260, 1360, 1460])),('WScale', random.randint(2, 14)), ('Timestamp',(random.randint(1, 1000000000), 0)),('SAckOK', '')], flags="S")
                resp = scapy.sr1(pkt, timeout=1, verbose=False)
                if resp:
                    ttl = resp.ttl
                    if ttl <= 64:
                        L.append("Linux/Unix")
                    elif ttl <= 128:
                        W.append("Windows")
                    elif ttl <= 255:
                        C.append("Cisco/Networking Device")

            except:
                continue
        print(f"\n[+] Os Figerprint : \n\n    Linux/Unix : {(len(L) / (len(L) + len(W) + len(C))) * 100}%\n    Windows : {(len(W) / (len(L) + len(W) + len(C))) * 100}%\n    Servers/Networking Device : {(len(C) / (len(L) + len(W) + len(C))) * 100}%\n")

    @staticmethod
    def _tcp_banner_grab(target, port, payload, timeout, verbose):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))

            banner = b""
            try:
                sock.settimeout(2)
                banner = sock.recv(1024)
            except socket.timeout:
                banner = b""
            except Exception as e:
                if verbose:
                    print(f"\n[!] Recv error: {e}")

            if not banner.strip() and payload:
                if verbose:
                    print(f"\n[+] Sending TCP payload: {payload}...")

                sock.settimeout(timeout)
                sock.send(payload)

                try:
                    banner = sock.recv(2048)
                except socket.timeout:
                    banner = b""

            sock.close()

            if banner and banner.strip():
                decoded_banner = banner.decode('utf-8', errors='ignore')
                if verbose:
                    print(f"\n[+] Received TCP banner: {len(decoded_banner)} chars")
                return decoded_banner
            else:
                if verbose:
                    print(f"\n[!] No TCP banner received")
                return None

        except socket.timeout:
            if verbose:
                print(f"\n[!] TCP socket timeout on {target}:{port}")
            return None
        except ConnectionRefusedError:
            if verbose:
                print(f"\n[!] TCP connection refused on {target}:{port}")
            return None
        except Exception as e:
            if verbose:
                print(f"\n[!] TCP socket error: {e}")
            return None

    @staticmethod
    def _udp_banner_grab(target, port, payload, timeout, verbose):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)

            if verbose and payload:
                print(f"\n[+] Sending UDP payload: {payload}...")

            if payload:
                sock.sendto(payload, (target, port))

            try:
                response, addr = sock.recvfrom(2048)
                sock.close()

                if response and response.strip():
                    decoded_banner = response.decode('utf-8', errors='ignore')
                    if verbose:
                        print(f"\n[+] Received UDP banner: {len(decoded_banner)} chars")
                    return decoded_banner
                else:
                    if verbose:
                        print(f"\n[!] Empty UDP response")
                    return None

            except socket.timeout:
                if verbose:
                    print(f"\n[!] UDP socket timeout on {target}: Port {port}")
                sock.close()
                return None

        except Exception as e:
            if verbose:
                print(f"\n[!] UDP socket error: {e}")
            return None

    @staticmethod
    def banner_grabing_payloads(target, port, Proto):
        if port in [80, 443, 8080, 8000]:
            return f"HEAD / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: Mozilla/5.0\r\n\r\n".encode()
        elif port == 21:
            return b"USER anonymous\r\n"
        elif port == 22:
            return b""
        elif port == 25:
            return f"EHLO {target}\r\n".encode()
        elif port == 53:
            if Proto == "tcp":
                return b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01"
            elif Proto == "udp":
                return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01"
        elif port == 110:
            return b"USER test\r\n"
        elif port == 143:
            if Proto == "tcp":
                return b"a001 LOGIN test test\r\n"
            elif Proto == "udp":
                return b"\r\n"
        elif port == 161:
            return bytes.fromhex("302602010104067075626c6963a019020101020100020100300e300c06082b060102010101000500")
        elif port == 389:
            return bytes.fromhex("300c020101600702010304008000")
        elif port == 993:
            return b"a001 CAPABILITY\r\n"
        elif port == 995:
            return b"USER test\r\n"
        elif port == 3306:
            return b"\x0a"
        elif port == 5432:
            return b"\x00\x00\x00\x08\x04\xd2\x16\x2f"
        elif port == 3389:
            return b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
        elif port == 5900:
            return b"RFB 003.003\n"
        elif port == 27017:
            return b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00\x08ismaster\x00\x00"
        else:
            return b"\r\n"

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

