import sys

red = "\033[31m"
reset = "\033[0m"
yellow = "\033[33m"

class LSSE:
    def __init__(self):
        self.scripts_list = ["http-title","http-cert","http-robots","dns-subdomain-fuzzing"]

    def script_list(self,sname,url,ports=None,redirect=None,domain=None,dns=None,wordlist=None):
        if sname in self.scripts_list:
            match sname:
                case "http-title":
                    from LSSE.scripts.http_title import threaded_http_title
                    threaded_http_title(url,ports,redirect)
                case "http-cert":
                    from LSSE.scripts.http_cert import threaded_tls_ssl_cert_info
                    threaded_tls_ssl_cert_info(url,ports)
                case "http-robots":
                    from LSSE.scripts.http_robots import threaded_http_robots
                    threaded_http_robots(url,ports)
                case "dns-subdomain-fuzzing":
                    from LSSE.scripts.dns_subdomain_fuzzing import main
                    main(domain,dns=dns,wordlist=wordlist)
                case _:
                    print(f"\n{yellow}[!] Script not found {reset}\n")
                    sys.exit(2)
        else:
            print(f"\n{yellow}[!] Script not found {reset}\n")
            sys.exit(3)

Lsse = LSSE()

