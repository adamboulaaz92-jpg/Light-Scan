import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

red = "\033[31m"
reset = "\033[0m"
yellow = "\033[33m"
Data = {}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def init(port):
    global Data
    Data[port] = {
        'Data': ''
    }


def analyze_robots_content(content):
    lines = content.strip().split('\n')

    disallowed_entries = []
    commented_disallowed_entries = []
    active_disallows = 0
    active_allows = 0
    allowed_entries = []
    commented_allowed_entries = []
    commented_allows = 0
    commented_disallows = 0

    for line in lines:
        line = line.strip()

        if not line:
            continue

        if line.startswith('Disallow:'):
            active_disallows += 1
            path = line.split('Disallow:', 1)[1].strip()
            disallowed_entries.append(path)

        elif line.startswith('#Disallow:'):
            commented_disallows += 1
            path = line.split('#Disallow:', 1)[1].strip()
            commented_disallowed_entries.append(path)

        elif line.startswith('Allow'):
            active_allows += 1
            path = line.split('Allow:', 1)[1].strip()
            allowed_entries.append(path)

        elif line.startswith('#Allow'):
            commented_allows += 1
            path = line.split('#Allow:', 1)[1].strip()
            commented_allowed_entries.append(path)

    return {
        'disallowed_entries': disallowed_entries,
        'active_disallows': active_disallows,
        'commented_disallows': commented_disallows,
        'commented_disallowed_entries': commented_disallowed_entries,
        'commented_allowed_entries': commented_allowed_entries,
        'allowed_entries': allowed_entries,
        'active_allows': active_allows,
        'commented_allows': commented_allows,
        'total_lines': len(lines)
    }

def http_robots(host, port):
        global Data
        Data[port]['Data'] += f"\n  [Port {port}]\n\n"

        for protocol in ['http', 'https']:
            url = f"{protocol}://{host}:{port}/robots.txt"

            try:
                response = requests.get(
                    url,
                    allow_redirects=True,
                    timeout=5,
                    verify=False,
                    headers={'User-Agent': 'Mozilla/5.0'}
                )

                if response.status_code == 200:
                    Data[port]['Data'] += f"     [Protocole] {protocol.upper()}: [Status Code] {response.status_code} \n\n"
                    analysis = analyze_robots_content(response.text)
                    Data[port]['Data'] += f"     [Analysis] \n\n          [Disallowed Entries ({analysis['active_disallows']})]  {analysis['disallowed_entries']}\n          [Commented Disallows ({analysis['commented_disallows']})] {analysis['commented_disallowed_entries']}\n          [Allows Entries ({analysis['active_allows']})]      {analysis['allowed_entries']}\n          [Commented Allows ({analysis['commented_allows']})]    {analysis['commented_allowed_entries']}\n          [Total Lines] {analysis['total_lines']}\n\n"
                    Data[port]['Data'] += f"     [Robots.txt] :\n\n{response.text}\n\n"
                else:
                    Data[port]['Data'] += f"     [Protocole] {protocol.upper()}: [Status Code] {response.status_code}\n"
                    Data[port]['Data'] += f"     [Robots.txt] Doesn't exist!\n\n"
            except requests.exceptions.SSLError:
                Data[port]['Data'] += f"     [Protocole] {protocol.upper()}: {red}SSL Error{reset}"
            except requests.exceptions.ConnectionError:
                Data[port]['Data'] += f"     [Protocole] {protocol.upper()}: {yellow}Connection failed{reset}"
            except Exception as e:
                Data[port]['Data'] += f"     [Protocole] {protocol.upper()}: {red}{e}{reset}"

def threaded_http_robots(host, ports):
    start = time.time()
    if host == None:
        print(f"\n{yellow}[LSSE] No url was assagned for script {reset}\n")
        exit()
    else:
        pass

    for port in ports:
        init(port)

    with ThreadPoolExecutor(max_workers=60) as executor:
        futures = []
        for port in ports:
            future = executor.submit(http_robots, host, port)
            futures.append(future)

        for future in as_completed(futures):
            try:
                future.result(timeout=10)
            except Exception as e:
                print(f"{red}[!] Error in thread: {e}{reset}")

    for port in sorted(ports):
        print(Data[port]['Data'])

    end = time.time()
    elapsed = end - start
    print(f"\n[+] LSSE Finished in {elapsed:.2f} seconds")
