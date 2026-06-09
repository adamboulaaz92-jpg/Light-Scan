"""
Light-Scan Scripting Engine (LSSE)
Script Name : script
Author : Adam Boulaaz
Arguments
--> Required Arguments
----> --url
Categorie :safe/discovery/http_https
"""

from bs4 import BeautifulSoup
import requests

green = "\033[32m"
reset = "\033[0m"
yellow = "\033[33m"
red = "\033[31m"

class Script:
    def __init__(self, url):
        self.url = url

    def start(self):
        response = requests.get(self.url, timeout=10,allow_redirects=True)
        ns = 1
        print("\n[LSSE] Html Script Detection Script ")
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            scripts = soup.find_all('script')
            if len(scripts) > 0:
                print(f"\n{green}[+] Script/s Detected ")
                print(f"[+] Final Url: {response.url} ")
                print(f"[+] NUmber of Scripts {len(scripts)} \n{reset}")
                for i in scripts:
                    print(f"[#{ns}] {i}\n")
                    ns += 1
            else:
                print(f"\n{yellow}[!] No Script has been Detected.{reset}")
                exit(0)

