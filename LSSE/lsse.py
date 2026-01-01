import sys

red = "\033[31m"
reset = "\033[0m"
yellow = "\033[33m"

class LSSE:
    def __init__(self):
        self.scripts_list = ["http-title","http-cert","http-robots"]

    def script_list(self,sname,url,ports,redirect):
        if sname in self.scripts_list:
            match sname:
                case "http-title":
                    from LSSE.scripts.http_title import http_title
                    http_title(url,ports,redirect)
                case "http-cert":
                    from LSSE.scripts.http_cert import tls_ssl_cert_info
                    tls_ssl_cert_info(url,ports)
                case "http-robots":
                    from LSSE.scripts.http_robots import http_robots
                    http_robots(url,ports)
                case _:
                    print(f"\n{yellow}[!] Script not found {reset}\n")
                    sys.exit(2)
        else:
            print(f"\n{yellow}[!] Script not found {reset}\n")
            sys.exit(3)

Lsse = LSSE()

