"""
Light-Scan Scripting Engine (LSSE)
Script Name : dns-ns
Author : Adam Boulaaz
Arguments
--> Required Arguments
----> --domain
--> Optional Arguments
----> --dns-server
Categorie : safe/discovery/dns
"""

import dns.resolver
import dns.exception
import argparse
import sys

def get_nameservers(domain, dns_server=None):
    try:
        resolver = dns.resolver.Resolver()

        if dns_server:
            resolver.nameservers = [dns_server]

        answers = resolver.resolve(domain, 'NS')

        nameservers = []
        for rdata in answers:
            ns = str(rdata.target)
            if ns.endswith('.'):
                ns = ns[:-1]
            nameservers.append(ns)

        return nameservers

    except dns.resolver.NoAnswer:
        print(f"  [!] No NS records found for {domain}")
        return []
    except dns.resolver.NXDOMAIN:
        print(f"  [!] Domain does not exist: {domain}")
        return []
    except dns.resolver.Timeout:
        print(f"  [!] DNS query timed out")
        return []
    except dns.exception.DNSException as e:
        print(f"  [!] DNS error: {e}")
        return []
    except Exception as e:
        print(f"  [!] Error: {e}")
        return []


def run(domain, dns_server=None):

    print(f"\n[+] NS Record Lookup for {domain}")
    print("-" * 50)

    if dns_server:
        print(f"[*] Using DNS server: {dns_server}")
    else:
        print("[*] Using system default DNS")

    nameservers = get_nameservers(domain, dns_server)

    if not nameservers:
        print("\n[-] No nameservers found")
        return False

    print(f"\n[+] Found {len(nameservers)} nameserver(s):")
    for i, ns in enumerate(nameservers, 1):
        print(f"    {i}. {ns}")


    print("\n[+] NS lookup completed successfully")
    return True
