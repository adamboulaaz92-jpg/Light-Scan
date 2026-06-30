"""
Light-Scan Scripting Engine (LSSE)
Script Name : dns-lookup
Author : Adam Boulaaz
Arguments
--> Required Arguments
----> --domain
--> Optional Arguments
----> --dns-server
Categorie : safe/discovery/dns
"""

from scapy.all import IP, UDP, DNS, DNSQR, sr1, conf

def dns_lookup(domain, dns_server=None):
    if dns_server is None:
        dns_server = conf.route.route("0.0.0.0")[2]

    print(f"\n[*] Looking up {domain} using {dns_server}")

    for qtype, qname in [("A", "IPv4"), ("AAAA", "IPv6")]:
        packet = IP(dst=dns_server) / UDP(dport=53) / DNS(
            rd=1, qd=DNSQR(qname=domain, qtype=qtype)
        )

        resp = sr1(packet, timeout=3, verbose=False)

        if resp and resp.haslayer(DNS):
            for i in range(resp[DNS].ancount):
                rr = resp[DNS].an[i]
                if rr.type == (1 if qtype == "A" else 28):
                    print(f"  {qname:4} → {rr.rdata}")
