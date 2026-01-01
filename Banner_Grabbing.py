import socket
import random

red = "\033[31m"
reset = "\033[0m"
yellow = "\033[33m"

class Banner:
    def __init__(self):
        pass

    @staticmethod
    def banner_grab(target, port, protocol="tcp", timeout=5, verbose=False):
        try:
            if verbose:
                print(f"\n[+] Banner grab: {target}: Port {port} ({protocol.upper()})")

            payload = Banner.banner_grabing_payloads(target, port, protocol)

            if protocol.lower() == "tcp":
                return Banner._tcp_banner_grab(target, port, payload, timeout, verbose)
            elif protocol.lower() == "udp":
                return Banner._udp_banner_grab(target, port, payload, timeout, verbose)
            else:
                if verbose:
                    print(f"{yellow}[!] Unknown protocol: {protocol}{reset}")
                return None

        except Exception as e:
            if verbose:
                print(f"\n{red}[!] Banner grab error: {e}{reset}")
            return None

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
                    print(f"\n{red}[!] Recv error: {e}{reset}")

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
                    print(f"\n{yellow}[!] No TCP banner received{reset}")
                return None

        except socket.timeout:
            if verbose:
                print(f"\n{red}[!] TCP socket timeout on {target}:{port}{reset}")
            return None
        except ConnectionRefusedError:
            if verbose:
                print(f"\n{red}[!] TCP connection refused on {target}:{port}{reset}")
            return None
        except Exception as e:
            if verbose:
                print(f"\n{red}[!] TCP socket error: {e}{reset}")
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
                        print(f"\n{yellow}[!] Empty UDP response{reset}")
                    return None

            except socket.timeout:
                if verbose:
                    print(f"\n{red}[!] UDP socket timeout on {target}: Port {port}{reset}")
                sock.close()
                return None

        except Exception as e:
            if verbose:
                print(f"\n{red}[!] UDP socket error: {e}{reset}")
            return None

    @staticmethod
    def banner_grabing_payloads(target, port, Proto):
        if port in [80, 443, 8080, 8000, 8443]:
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "curl/7.88.1",
            ]
            payload = (f"GET / HTTP/1.1\r\n"
                       f"Host: {target}\r\n"
                       f"User-Agent: {random.choice(user_agents)}\r\n"
                       f"Accept: */*\r\n"
                       f"Connection: close\r\n\r\n").encode()
            return payload
        elif port == 21:
            return b"USER anonymous\r\n"
        elif port == 22:
            ssh_clients = [
                "SSH-2.0-OpenSSH_8.9p1",
                "SSH-2.0-OpenSSH_7.4",
                "SSH-2.0-OpenSSH_7.9",
                "SSH-2.0-libssh2_1.10.0",
                "SSH-2.0-PuTTY_Release_0.78",
            ]
            ssh_banner = random.choice(ssh_clients) + "\r\n"

            return ssh_banner.encode()
        elif port == 25:
            return f"EHLO {target}\r\n".encode()
        elif port == 53:
            if Proto == "tcp":
                query = b"\x00\x1a"
                query += b"\x12\x34"
                query += b"\x01\x00"
                query += b"\x00\x01"
                query += b"\x00\x00"
                query += b"\x00\x00"
                query += b"\x00\x00"
                query += b"\x07version\x04bind\x00"
                query += b"\x00\x10"
                query += b"\x00\x01"
                return query
            elif Proto == "udp":
                query = b"\x12\x34"
                query += b"\x01\x00"
                query += b"\x00\x01"
                query += b"\x00\x00"
                query += b"\x00\x00"
                query += b"\x00\x00"
                query += b"\x07version\x04bind\x00"
                query += b"\x00\x10"
                query += b"\x00\x03"
                return query
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
        elif port == 3306:
            return b"\x0a"
        elif port == 587:
            return f"EHLO {target}\r\n".encode()
        elif port == 993:
            return b"a001 CAPABILITY\r\n"
        elif port == 995:
            return b"USER test\r\n"
        elif port == 1433:
            return b"\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x00\x00\x00"
        elif port == 6379:
            return b"INFO\r\n"
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
    def analyse_banner(banner, port, target_result, Proto, lock=None):
        if not banner:
            return target_result

        banner_lower = banner.lower()

        service_patterns = {
            "vmware": [
                ("vmware authentication daemon version 1.0", "vmware-auth"),
                ("vmware authentication daemon version 1.10", "ssl/vmware-auth"),
                ("vmware", "vmware-server"),
                ("esxi", "vmware-esxi"),
                ("vsphere", "vmware-vsphere")
            ],
            "ssh": [
                ("ssh", "ssh"),
                ("openssh", "ssh"),
                ("dropbear", "ssh")
            ],
            "https": [
                ("the plain http request was sent to https port","https"),
                ("you're speaking plain http to an ssl-enabled server port","https"),
            ],
            "http": [
                ("server: simplehttp/0.6", "http"),
                ("400 bad request","http"),
            ],
            "database": [
                ("mysql", "mysql"),
                ("mariadb", "mysql"),
                ("postgresql", "postgresql"),
                ("mongodb", "mongodb"),
                ("redis", "redis"),
                ("oracle", "oracle-db")
            ],
            "mail": [
                ("postfix", "smtp"),
                ("exim", "smtp"),
                ("sendmail", "smtp"),
                ("dovecot", "imap"),
                ("courier", "imap"),
                ("microsoft esmtp", "smtp")
            ],
            "ftp": [
                ("vsftpd", "ftp"),
                ("proftpd", "ftp"),
                ("pure-ftpd", "ftp"),
                ("filezilla", "ftp"),
                ("microsoft ftp", "ftp")
            ],
            "dns": [
                ("bind", "dns"),
                ("dnsmasq", "dns"),
                ("microsoft dns", "dns"),
                ("unbound", "dns")
            ],
            "remote": [
                ("vnc", "vnc"),
                ("realvnc", "vnc"),
                ("tigervnc", "vnc"),
                ("rfb", "vnc"),
                ("remote desktop", "rdp"),
                ("x11", "x11")
            ],
            "special": [
                ("docker", "docker"),
                ("kubernetes", "kubernetes"),
                ("jenkins", "jenkins"),
                ("git", "git"),
                ("squid", "squid-proxy"),
                ("haproxy", "haproxy")
            ]
        }

        detected_service = None

        for category, patterns in service_patterns.items():
            for pattern, service_name in patterns:
                if pattern.lower() in banner_lower:
                    detected_service = service_name
                    break
            if detected_service:
                break

        if not detected_service:
            return target_result

        if lock:
            lock.acquire()

        try:
            for i, opened_port in enumerate(target_result["open_ports"]):
                if opened_port == port:
                    target_result["opened_ports_services"][i] = detected_service
                    break
            else:
                pass
        finally:
            if lock:
                lock.release()

            return target_result
