import requests
import urllib3

red = "\033[31m"
reset = "\033[0m"
yellow = "\033[33m"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def http_robots(host, ports):
    if host == None:
        print(f"\n{yellow}[LSSE] No url was assagned for script {reset}\n")
        exit()
    else:
        pass

    for port in ports:
        print(f"\n  [Port {port}]")

        for protocol in ['http', 'https']:
            url = f"{protocol}://{host}:{port}/robots.txt"

            try:
                response = requests.get(
                    url,
                    allow_redirects=True,
                    timeout=3,
                    verify=False,
                    headers={'User-Agent': 'Mozilla/5.0'}
                )

                if response.status_code == 200:
                    print(f"     [Protocole] {protocol.upper()}: [Status Code] {response.status_code} ")
                    print(f"     [Robots.txt] :\n\n{response.text}\n")
                else:
                    print(f"     [Protocole] {protocol.upper()}: [Status Code] {response.status_code}")
                    print(f"     [Robots.txt] Doesn't exist!\n")
            except requests.exceptions.SSLError:
                print(f"     [Protocole] {protocol.upper()}: {red}SSL Error{reset}")
            except requests.exceptions.ConnectionError:
                print(f"     [Protocole] {protocol.upper()}: {yellow}Connection failed{reset}")
            except Exception as e:
                print(f"     [Protocole] {protocol.upper()}: {red}{e}{reset}")