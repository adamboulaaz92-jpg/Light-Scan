import requests
import urllib3
from bs4 import BeautifulSoup

red = "\033[31m"
reset = "\033[0m"
yellow = "\033[33m"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def http_title(host, ports, redirect=False):
    if redirect == None:
        redirect = False
    else:
        pass

    if host == None:
        print(f"\n{yellow}[LSSE] No url was assagned for script {reset}\n")
        exit()
    else:
        pass

    for port in ports:
        print(f"\n  [Port {port}]")

        for protocol in ['http', 'https']:
            url = f"{protocol}://{host}:{port}"

            try:
                response = requests.get(
                    url,
                    allow_redirects=redirect,
                    timeout=5,
                    verify=False,
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                server_header = response.headers.get('Server')

                print(f"     [Protocole] {protocol.upper()} : [Status Code] {response.status_code} : [Server] {server_header} ", end="")

                if response.status_code:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    title = soup.title
                    if title and title.string:
                        print(f"   : [Title] {title.string.strip()[:50]}...")
                    else:
                        print("    : [Title] No title")
                else:
                    print()

            except requests.exceptions.SSLError:
                print(f"     [Protocole] {protocol.upper()}: {red}SSL Error{reset}")
            except requests.exceptions.ConnectionError:
                print(f"     [Protocole] {protocol.upper()}: {yellow}Connection failed{reset}")
            except Exception as e:
                print(f"     [Protocole] {protocol.upper()}: {red}{e}{reset}")
