import ssl
import socket

red = "\033[31m"
reset = "\033[0m"
yellow = "\033[33m"

def tls_ssl_cert_info(host, ports):
    if host == None:
        print(f"\n{yellow}[LSSE] No url was assagned for script {reset}\n")
        exit()
    else:
        pass

    for port in ports:
        print(f"\n [+] TLS/SSL Analysis for {host} on port {port}\n")

        try:
            sock = socket.create_connection((host, port), timeout=5)
            context = ssl.create_default_context()
            context.check_hostname = False
            secure_sock = context.wrap_socket(sock, server_hostname=host)


            cipher = secure_sock.cipher()
            print(f"   [→] Version: {secure_sock.version()}\n")
            print(f"   [→] Cipher: {cipher[0]} ({cipher[2]} bits)\n")

            cert = secure_sock.getpeercert()
            if cert:
                print(f"   [→] Certificate:\n")
                subject = dict(x[0] for x in cert['subject'])
                print(f"       • Subject: {subject.get('commonName', 'N/A')}")

                issuer = dict(x[0] for x in cert['issuer'])
                print(f"       • Issuer: {issuer.get('organizationName', 'N/A')}")
                print(f"       • Valid: {cert['notBefore']} to {cert['notAfter']}")

                if 'subjectAltName' in cert:
                    sans = [name[1] for name in cert['subjectAltName'] if name[0] == 'DNS']
                    if sans:
                        print(f"       • SANs: {', '.join(sans[:5])}{'  ...' if len(sans) > 5 else ''}")

                if 'serialNumber' in cert:
                    print(f"       • Serial: {cert['serialNumber']}")

                if 'keyUsage' in cert:
                    print(f"       • Key Usage: {', '.join(cert['keyUsage'])}")

                if 'extendedKeyUsage' in cert:
                    print(f"       • Extended Usage: {', '.join(cert['extendedKeyUsage'])}")

                if 'crlDistributionPoints' in cert:
                    print(f"       • CRL URLs: {cert['crlDistributionPoints']}")

                if 'authorityInfoAccess' in cert:
                    ocsp_urls = []
                    for access_method, access_location in cert['authorityInfoAccess']:
                        if access_method == 'OCSP':
                            ocsp_urls.append(access_location)
                    if ocsp_urls:
                        print(f"       • OCSP Responder: {ocsp_urls[0]}")

                if 'certificatePolicies' in cert:
                    policies = []
                    for policy in cert['certificatePolicies']:
                        if isinstance(policy, tuple) and len(policy) > 0:
                            policies.append(policy[0])
                    if policies:
                        print(f"       • Policies: {', '.join(policies[:3])}")

                import hashlib
                der_cert = secure_sock.getpeercert(binary_form=True)
                if der_cert:
                    sha1_hash = hashlib.sha1(der_cert).hexdigest()
                    print(f"       • SHA-1 FP: {sha1_hash} ")

                    sha256_hash = hashlib.sha256(der_cert).hexdigest()
                    print(f"       • SHA-256 FP: {sha256_hash} ")
                print()

            print(f"   [→] Testing protocol support:\n")
            supported = []
            for proto_name, proto_const in [("TLSv1.3", ssl.PROTOCOL_TLS),
                                            ("TLSv1.2", ssl.PROTOCOL_TLSv1_2),
                                            ("TLSv1.1", ssl.PROTOCOL_TLSv1_1),
                                            ("TLSv1.0", ssl.PROTOCOL_TLSv1)]:
                try:
                    context = ssl.SSLContext(proto_const)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    test_sock = socket.create_connection((host, port), timeout=5)
                    with context.wrap_socket(test_sock, server_hostname=host):
                        supported.append(proto_name)
                        print(f"       • {proto_name}: ✓")
                except:
                    print(f"       • {proto_name}: ✗")

            if supported:
                weak_protos = [p for p in supported if p in ["SSLv3", "TLSv1.0", "TLSv1.1"]]
                if weak_protos:
                    print(f"\n     [⚠️] Security: Weak protocols enabled: {', '.join(weak_protos)} \n")
                else:
                    print(f"\n     [✓] Security: Strong configuration \n")

            secure_sock.close()


        except Exception as e:
            print(f"     {red}[✗] Error: {e}{reset}\n")

    print(f"\n\n [✓] Analysis complete")