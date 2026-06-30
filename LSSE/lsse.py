import sys

red = "\033[31m"
reset = "\033[0m"
yellow = "\033[33m"

class LSSE:
    def __init__(self):
        self.scripts_list = ["http-title","http-cookie","http-methods","http-headers","http-cert","http-robots","dns-subdomain-fuzzing","spider","script","http-dir","dns-lookup","dns-zone-transfer","dns-ns"]

    def script_list(self,sname,ports=None,redirect=None,domain=None,dns=None,wordlist=None,url=None,max_pages=None,max_depth=None,extensions=None,status_codes=None):
        if sname in self.scripts_list:
            match sname:
                case "http-title":
                    from LSSE.scripts.safe.analysis.http_https.http_title import threaded_http_title
                    threaded_http_title(domain,ports,redirect)
                case "http-headers":
                    from LSSE.scripts.safe.analysis.http_https.http_headers import run
                    run(domain, port=int(ports[0]), redirect=redirect)
                case "http-cookie":
                    from LSSE.scripts.safe.analysis.http_https.http_cookie import run
                    run(domain, port=int(ports[0]), redirect=redirect)
                case "http-methods":
                    from LSSE.scripts.safe.discovery.http_https.http_methods import run
                    run(domain, port=int(ports[0]))
                case "http-cert":
                    from LSSE.scripts.safe.analysis.https.http_cert import threaded_tls_ssl_cert_info
                    threaded_tls_ssl_cert_info(domain,ports)
                case "http-robots":
                    from LSSE.scripts.safe.extracting.http_https.http_robots import threaded_http_robots
                    threaded_http_robots(domain,ports)
                case "spider":
                    from LSSE.scripts.safe.extracting.http_https.spider import Spider
                    spider = Spider()
                    if max_pages is None:
                        max_pages = 5
                    if max_depth is None:
                        max_depth = 2
                    results = spider.spider(
                        start_url=url,
                        max_pages=int(max_pages),
                        max_depth=int(max_depth)
                    )
                case "dns-subdomain-fuzzing":
                    from LSSE.scripts.medium.discovery.dns.dns_subdomain_fuzzing import main
                    main(domain,dns=dns,wordlist=wordlist)
                case "script":
                    from LSSE.scripts.safe.analysis.http_https.script import Script
                    try:
                        script = Script(url=url)
                        script.start()
                    except Exception as e:
                        print(f"\n{red}[!] {e}{reset}")
                        exit(1)
                case "http-dir":
                    from LSSE.scripts.medium.discovery.http_https.http_dir import HTTPDIR
                    try:
                        script = HTTPDIR(url=url,extensions=extensions,wordlist=wordlist,status_codes=status_codes)
                        script.start()
                    except Exception as e:
                        print(f"\n{red}[!] {e}{reset}")
                        exit(1)
                case "dns-lookup":
                    from LSSE.scripts.safe.discovery.dns.dns_lookup import dns_lookup
                    if dns == None:
                        dns_lookup(domain)
                    else:
                        dns_lookup(domain,dns_server=dns)
                case "dns-zone-transfer":
                    from LSSE.scripts.medium.extracting.dns.dns_zone_transfer import runzon
                    if dns == None:
                        runzon(domain)
                    else:
                        runzon(domain, dns_server=dns)
                case "dns-ns":
                    from LSSE.scripts.safe.discovery.dns.dns_ns import run
                    if dns == None:
                        run(domain)
                    else:
                        run(domain, dns_server=dns)
                case _:
                    print(f"\n{yellow}[!] Script not found {reset}\n")
                    sys.exit(2)
        else:
            print(f"\n{yellow}[!] Script not found {reset}\n")
            sys.exit(3)

Lsse = LSSE()

