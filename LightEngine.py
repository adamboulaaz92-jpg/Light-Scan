import scapy.all as scapy

class Payloads:
    def __init__(self):
        pass

    @staticmethod
    def dns_payload(target):
        dns_query = (scapy.IP(dst=target) /
                     scapy.UDP(dport=53,sport=65535) /
                     scapy.DNS(rd=1, qd=scapy.DNSQR(qname="google.com", qtype="A")))

        return dns_query
