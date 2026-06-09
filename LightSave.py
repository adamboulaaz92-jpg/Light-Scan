# SPDX-FileCopyrightText: 2026 Adam Boulaaz
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-Repository: https://github.com/adamboulaaz92-jpg/Light-Scan
#
# Light-Scan - Advanced Port Scanner and Network Reconnaissance Tool
# Copyright (C) 2026 Adam Boulaaz
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

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
elif system in ["Linux", "Darwin", "FreeBSD", "OpenBSD", "NetBSD"]:
    cmd = f'{args.C} | tee {filename}'
    subprocess.run(cmd, shell=True)
