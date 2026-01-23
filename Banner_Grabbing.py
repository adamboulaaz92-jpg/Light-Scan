import socket
import random

red = "\033[31m"
reset = "\033[0m"
yellow = "\033[33m"

class Banner:
    def __init__(self):
        pass

    @staticmethod
    def banner_grab(target, port, protocol="tcp", timeout=5, verbose=False, print_output=True):
        try:
            if verbose:
                if print_output == False:
                    pass
                else:
                    print(f"\n[+] Banner grab: {target}: Port {port} ({protocol.upper()})")

            payload = Banner.banner_grabing_payloads(target, port, protocol)

            if protocol.lower() == "tcp":
                return Banner._tcp_banner_grab(target, port, payload, timeout, verbose,print_output)
            elif protocol.lower() == "udp":
                return Banner._udp_banner_grab(target, port, payload, timeout, verbose,print_output)
            else:
                if verbose:
                    if print_output == False:
                        pass
                    else:
                        print(f"{yellow}[!] Unknown protocol: {protocol}{reset}")
                return None

        except Exception as e:
            if verbose:
                if print_output == False:
                    pass
                else:
                    print(f"\n{red}[!] Banner grab error: {e}{reset}")
            return None

    @staticmethod
    def _tcp_banner_grab(target, port, payload, timeout, verbose,print_output):
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
                    if print_output == False:
                        pass
                    else:
                        print(f"\n{red}[!] Recv error: {e}{reset}")

            if not banner.strip() and payload:
                if verbose:
                    if print_output == False:
                        pass
                    else:
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
                    if print_output == False:
                        pass
                    else:
                        print(f"\n[+] Received TCP banner: {len(decoded_banner)} chars")
                return decoded_banner
            else:
                if verbose:
                    if print_output == False:
                        pass
                    else:
                        print(f"\n{yellow}[!] No TCP banner received{reset}")
                return None

        except socket.timeout:
            if verbose:
                if print_output == False:
                    pass
                else:
                    print(f"\n{red}[!] TCP socket timeout on {target}:{port}{reset}")
            return None
        except ConnectionRefusedError:
            if verbose:
                if print_output == False:
                    pass
                else:
                    print(f"\n{red}[!] TCP connection refused on {target}:{port}{reset}")
            return None
        except Exception as e:
            if verbose:
                if print_output == False:
                    pass
                else:
                    print(f"\n{red}[!] TCP socket error: {e}{reset}")
            return None

    @staticmethod
    def _udp_banner_grab(target, port, payload, timeout, verbose,print_output):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)

            if verbose and payload:
                if print_output == False:
                    pass
                else:
                    print(f"\n[+] Sending UDP payload: {payload}...")

            if payload:
                sock.sendto(payload, (target, port))

            try:
                response, addr = sock.recvfrom(2048)
                sock.close()

                if response and response.strip():
                    decoded_banner = response.decode('utf-8', errors='ignore')
                    if verbose:
                        if print_output == False:
                            pass
                        else:
                            print(f"\n[+] Received UDP banner: {len(decoded_banner)} chars")
                    return decoded_banner
                else:
                    if verbose:
                        if print_output == False:
                            pass
                        else:
                            print(f"\n{yellow}[!] Empty UDP response{reset}")
                    return None

            except socket.timeout:
                if verbose:
                    if print_output == False:
                        pass
                    else:
                        print(f"\n{red}[!] UDP socket timeout on {target}: Port {port}{reset}")
                sock.close()
                return None

        except Exception as e:
            if verbose:
                if print_output == False:
                    pass
                else:
                    print(f"\n{red}[!] UDP socket error: {e}{reset}")
            return None

    @staticmethod
    def banner_grabing_payloads(target, port, Proto):
        if port in [80, 443, 8080, 8000, 8443, 8888]:
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "curl/7.88.1",
                "PostmanRuntime/7.26.0",
                "python-requests/2.25.1"
            ]

            methods = ["GET", "POST", "HEAD", "OPTIONS"]
            method = random.choice(methods)

            if method == "POST":
                payload = (f"POST / HTTP/1.1\r\n"
                           f"Host: {target}\r\n"
                           f"User-Agent: {random.choice(user_agents)}\r\n"
                           f"Accept: */*\r\n"
                           f"Content-Type: application/x-www-form-urlencoded\r\n"
                           f"Content-Length: 7\r\n"
                           f"Connection: close\r\n\r\n"
                           f"test=123").encode()
            else:
                payload = (f"{method} / HTTP/1.1\r\n"
                           f"Host: {target}\r\n"
                           f"User-Agent: {random.choice(user_agents)}\r\n"
                           f"Accept: */*\r\n"
                           f"Connection: close\r\n\r\n").encode()
            return payload

        elif port == 21:
            commands = [
                b"USER anonymous\r\n",
                b"SYST\r\n",
                b"HELP\r\n",
                b"FEAT\r\n"
            ]
            return random.choice(commands)

        elif port == 22:
            ssh_clients = [
                "SSH-2.0-OpenSSH_8.9p1",
                "SSH-2.0-OpenSSH_7.4",
                "SSH-2.0-OpenSSH_7.9",
                "SSH-2.0-libssh2_1.10.0",
                "SSH-2.0-PuTTY_Release_0.78",
                "SSH-2.0-dropbear_2022.83",
                "SSH-2.0-Win32_OpenSSH_8.9"
            ]
            ssh_banner = random.choice(ssh_clients) + "\r\n"
            return ssh_banner.encode()

        elif port in [25, 587, 465]:
            return f"EHLO {target}\r\n".encode()

        elif port == 53:
            if Proto == "tcp":
                query = b"\x00\x1a"
                query += b"\x12\x34"
                query += b"\x01\x00"
                query += b"\x00\x01"
                query += b"\x00\x00\x00\x00\x00\x00"
                query += b"\x07version\x04bind\x00"
                query += b"\x00\x10"
                query += b"\x00\x01"
                return query
            elif Proto == "udp":
                query = b"\x12\x34"
                query += b"\x01\x00"
                query += b"\x00\x01"
                query += b"\x00\x00\x00\x00\x00\x00"
                query += b"\x07version\x04bind\x00"
                query += b"\x00\x10"
                query += b"\x00\x03"
                return query

        elif port == 110:
            commands = [
                b"USER test\r\n",
                b"CAPA\r\n",
                b"STAT\r\n"
            ]
            return random.choice(commands)

        elif port == 143:
            if Proto == "tcp":
                commands = [
                    b"a001 LOGIN test test\r\n",
                    b"a001 CAPABILITY\r\n",
                    b"a001 NOOP\r\n"
                ]
                return random.choice(commands)
            elif Proto == "udp":
                return b"\r\n"

        elif port == 161:
            return bytes.fromhex("302602010104067075626c6963a019020101020100020100300e300c06082b060102010101000500")

        elif port == 389:
            return bytes.fromhex("300c020101600702010304008000")

        elif port == 3306:
            return b"\x0a"

        elif port == 993:
            return b"a001 CAPABILITY\r\n"

        elif port == 995:
            return b"USER test\r\n"

        elif port == 1433:
            return b"\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x00\x00\x00"

        elif port == 6379:
            commands = [
                b"INFO\r\n",
                b"PING\r\n",
                b"CLIENT LIST\r\n",
                b"TIME\r\n"
            ]
            return random.choice(commands)

        elif port == 5432:
            return b"\x00\x00\x00\x08\x04\xd2\x16\x2f"

        elif port == 3389:
            return b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"

        elif port == 5900:
            return b"RFB 003.003\n"

        elif port == 27017:
            return b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00\x08ismaster\x00\x00"

        elif port == 23:
            return b"\xff\xfb\x01\xff\xfb\x03\xff\xfc\x23"

        elif port == 67 or port == 68:
            if Proto == "udp":
                return bytes.fromhex(
                    "01010600aaaaaaaa0000000000000000000000000000000000000000"
                    "00000000000000000000000000000000000000000000000000000000"
                    "638253633501013d0701aaaaaaaa0000000000000000000000000000"
                    "00000000000000000000000000000000000000000000000000000000"
                )

        elif port == 123:
            if Proto == "udp":
                return b"\x17\x00\x03\x2a\x00\x00\x00\x00"

        elif port in [5060, 5061]:
            return f"OPTIONS sip:{target} SIP/2.0\r\n\r\n".encode()

        elif port == 11211:
            return b"stats\r\n"

        elif port == 9200:
            return b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"

        elif port == 5672:
            return b"AMQP\x00\x00\x09\x01"

        elif port == 9042:
            return b"\x04\x00\x00\x00\x01"

        elif port == 2375:
            return b"GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n"

        elif port == 6443:
            return b"GET /api HTTP/1.1\r\nHost: localhost\r\n\r\n"

        elif port == 8080:
            return b"GET /login HTTP/1.1\r\nHost: localhost\r\n\r\n"

        elif port == 9090:
            return b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n"

        elif port == 2003:
            return b"test.metric 123 1234567890\n"

        elif port == 8086:
            return b"GET /ping HTTP/1.1\r\nHost: localhost\r\n\r\n"

        elif port == 2181:
            return b"stat\n"

        elif port == 8500:
            return b"GET /v1/agent/self HTTP/1.1\r\nHost: localhost\r\n\r\n"

        elif port in [2379, 2380]:
            return b"GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n"

        elif port == 111:
            return bytes.fromhex(
                "000000000000000200000186a00000000200000003000000000000000000000000"
            )

        elif port == 137 or port == 138 or port == 139:
            if Proto == "udp" and port in [137, 138]:
                return bytes.fromhex(
                    "0000100001000000000000002045434143434143434143434143434143434141"
                    "4343414343414343414343414343414343414343414343410000210001"
                )
            elif port == 139:
                return bytes.fromhex(
                    "00000054ff534d4272000000001801c00000000000000000000000000000"
                    "ffff000000000000000000000000000000000000000000000000000000"
                    "0041000041002600000002004e544c4d5353500001000000050208a200"
                    "000000000000000000000000000000"
                )

        elif port == 514:
            if Proto == "udp":
                return b"<14>1 2023-01-01T00:00:00Z localhost test - - - Test message\n"

        elif port == 1883:
            return bytes.fromhex("102600044d5154540402003c00136c6f63616c686f73740006636c69656e74")

        elif port == 5683:
            if Proto == "udp":
                return bytes.fromhex("400000396c6f63616c686f73742f74657374")

        elif port == 502:
            return bytes.fromhex("000000000006010300000001")

        elif port == 47808:
            if Proto == "udp":
                return bytes.fromhex("810a001901200fffff0c0c")

        elif port == 2404:
            return bytes.fromhex("68040b000000")

        elif port == 20000:
            return bytes.fromhex("056405c0000164")

        elif port == 102:
            return bytes.fromhex("030008c1020100c0010a")

        elif port == 34964:
            return bytes.fromhex(
                "fefd04000000000000000000000000000000000000000000000000000000"
                "000000000000000000000000000000000000000000000000000000000000"
            )
        elif port == 44818:
            return bytes.fromhex("63000000000000000000000000000000000000000000")
        elif port == 4840:
            return bytes.fromhex(
                "48454c460000000001000000010000009c0000000000000000000000"
                "00000000000000000000000000000000000000000000000000000000"
            )
        else:
            if Proto == "tcp":
                return b"\r\n"
            else:

                return b"PING\r\n"

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
