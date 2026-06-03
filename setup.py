import os
import platform
import subprocess
import sys


def run_command(cmd):
    result = subprocess.run(cmd, shell=True)
    return result.returncode == 0


def setup_windows():
    print("\n[+] Starting Windows Setup ...\n")
    venv_path = "venv"

    if not run_command(f"python -m venv {venv_path}"):
        print("[!] Failed to create virtual environment")
        return False

    pip_path = os.path.join(venv_path, "Scripts", "pip")
    if run_command(f"{pip_path} install -r requirements.txt"):
        print("\n[+] Setup complete! Run: .\\venv\\Scripts\\activate")
        return True
    return False


def setup_linux_debian():
    print("\n[+] Starting Linux (Debian Based) Setup ...\n")
    run_command("sudo apt update")
    run_command("sudo apt install -y libpcap-dev python3-venv")
    return setup_linux_generic()


def setup_linux_arch():
    print("\n[+] Starting Linux (Arch Based) Setup ...\n")
    run_command("sudo pacman -S --noconfirm libpcap")
    return setup_linux_generic()


def setup_linux_generic():
    venv_path = "venv"

    if not run_command(f"python3 -m venv {venv_path}"):
        print("[!] Failed to create virtual environment")
        return False

    pip_path = os.path.join(venv_path, "bin", "pip")
    if run_command(f"{pip_path} install -r requirements.txt"):
        print("\n[+] Setup complete! Run: source venv/bin/activate")
        return True
    return False


def setup_macos():
    print("\n[+] Starting macOS Setup ...\n")

    if not run_command("which brew"):
        print("[!] Homebrew not found. Installing Homebrew...")
        run_command('/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"')

    print("[+] Installing libpcap via Homebrew...")
    run_command("brew install libpcap")

    venv_path = "venv"
    if not run_command(f"python3 -m venv {venv_path}"):
        print("[!] Failed to create virtual environment")
        return False

    pip_path = os.path.join(venv_path, "bin", "pip")
    if run_command(f"{pip_path} install -r requirements.txt"):
        print("\n[+] Setup complete! Run: source venv/bin/activate")
        return True
    return False


def setup_unix_generic():
    print("\n[+] Starting Generic Unix Setup ...\n")

    if run_command("which pkg"):
        print("[+] FreeBSD/BSD detected. Using pkg...")
        run_command("sudo pkg install -y libpcap python3")
    elif run_command("which pkgin"):
        print("[+] NetBSD/SmartOS detected. Using pkgin...")
        run_command("sudo pkgin install libpcap python3")
    elif run_command("which pkg_add"):
        print("[+] OpenBSD detected. Using pkg_add...")
        run_command("sudo pkg_add libpcap python3")
    elif run_command("which yum"):
        print("[+] RHEL/CentOS detected. Using yum...")
        run_command("sudo yum install -y libpcap-devel python3")
    elif run_command("which dnf"):
        print("[+] Fedora detected. Using dnf...")
        run_command("sudo dnf install -y libpcap-devel python3")
    elif run_command("which zypper"):
        print("[+] SUSE detected. Using zypper...")
        run_command("sudo zypper install -y libpcap-devel python3")
    elif run_command("which apk"):
        print("[+] Alpine detected. Using apk...")
        run_command("sudo apk add libpcap-dev python3")
    else:
        print("[!] Could not detect package manager. Please install libpcap manually.")
        return False

    venv_path = "venv"
    if not run_command(f"python3 -m venv {venv_path}"):
        print("[!] Failed to create virtual environment")
        return False

    pip_path = os.path.join(venv_path, "bin", "pip")
    if run_command(f"{pip_path} install -r requirements.txt"):
        print("\n[+] Setup complete! Run: source venv/bin/activate")
        return True
    return False


def main():
    system = platform.system()

    if system == "Windows":
        success = setup_windows()
    elif system == "Linux":
        if shutil.which("dpkg"):
            success = setup_linux_debian()
        elif shutil.which("pacman"):
            success = setup_linux_arch()
        else:
            print("\n[!] Couldn't determine the Linux distribution\n")
            success = False
    elif system == "Darwin":
        success = setup_macos()
    elif system in ["FreeBSD", "OpenBSD", "NetBSD", "SunOS"]:
        success = setup_unix_generic()
    else:
        print(f"\n[+] Unknown Operating System: {system}!\n")
        success = False

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    import shutil

    main()