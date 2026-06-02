import subprocess
import platform
import argparse
import time

Version = "1.0.0 Alpha"

parser = argparse.ArgumentParser(description="LightSave : Lightscan Scans Saving Tool")
parser.add_argument("-C", required=True, help="Lightscan command")
args = parser.parse_args()

current = time.localtime()
filename = f"Lightscan_Output_{time.strftime('%Y-%m-%d_%H-%M-%S', current)}.light"

if platform.system() == "Windows":
    cmd = f'powershell -c "{args.C} | tee {filename}"'
    subprocess.run(cmd, shell=True)

