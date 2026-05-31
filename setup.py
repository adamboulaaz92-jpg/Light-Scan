import os
import platform

if platform.system() == "Windows":
    print("\n[+] Starting Windows Setup ...\n")
    os.system("python -m venv lvenv")
    os.system("call lvenv\\Scripts\\activate && pip install -r requirements.txt")
elif platform.system() == "Linux":
    import shutil
    if shutil.which("dpkg"):
        print("\n[+] Starting Linux (Debian Based) Setup ...\n")
        os.system("sudo apt install libpcap-dev")
        os.system("sudo apt install python3-venv")
        os.system("python3 -m venv venv")
        os.system("source venv/bin/activate && pip install -r requirements.txt")
    elif shutil.which("pacman"):
        print("\n[+] Starting Linux (Arch Based) Setup ...\n")
        os.system("sudo pacman -S libpcap")
        os.system("python -m venv venv")
        os.system("source venv/bin/activate && pip install -r requirements.txt")
    else:
        print("\n[!] Could Determine the Distro\n")
        exit(1)
elif platform.system() == "Darwin":
    print("\n[+] MacOS and Darwin based OSs are not sepported ...\n")
    exit(0)
else:
    print("\n[+] Unkown Operating System!\n")
    exit(1)

