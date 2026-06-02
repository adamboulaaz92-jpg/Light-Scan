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
        print("\n[+] macOS and Darwin-based OSes are not supported yet ...\n")
        success = False
    else:
        print("\n[+] Unknown Operating System!\n")
        success = False

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    import shutil

    main()