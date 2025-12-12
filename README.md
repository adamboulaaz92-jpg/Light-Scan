![Python](https://img.shields.io/badge/python-3.13-blue?logo=python&logoColor=white)
![OS](https://img.shields.io/badge/OS-Linux%20%7C%20Windows-lightgrey?logo=linux&logo=windows)
![License](https://img.shields.io/badge/license-GNU-green?logo=gnu)
![Open Source](https://img.shields.io/badge/Open%20Source-✓-brightgreen?logo=github)

# Lightscan - Advanced Port Scanner



Lightscan is a powerful, multi-threaded port scanner built with Python and Scapy, designed for both security professionals and network administrators. It combines speed, accuracy all those features in a single tool.

# Real scan output
## Light-Scan Version 1.0.0
![](image/Light-Scan-Result.png)

## Light-Scan Version 1.1.3 (That version is under developpement)
    [+] Host 127.0.0.1 is up!
    
    
    
        __    _       __    __
       / /   (_)___ _/ /_  / /_______________ _____
      / /   / / __ `/ __ \/ __/ ___/ ___/ __ `/ __ \
     / /___/ / /_/ / / / / /_(__  ) /__/ /_/ / / / /
    /_____/_/\__, /_/ /_/\__/____/\___/\__,_/_/ /_/
            /____/
    
    Version : 1.1.3
    
    
    [*] Scan completed in 0.02 seconds
    
    ============================================================
    Scan result for : 127.0.0.1
    Scan Type: TCP | Protocol: TCP
    ============================================================
    
    [+] Open Ports: 2
         Port 445 microsoft-ds\tcp
         Port 135 msrpc\tcp
    
    [+] Closed Ports: 0
    
    [+] Filtered Ports: 0
    
    [!] Firewall Analysis for 127.0.0.1:
    
        Total ports scanned: 2
        Open ports: 2
        Closed ports: 0
        Filtered ports: 0
        Open Filtered ports: 0
        
        [+] NO FIREWALL DETECTED: no port is filtered
    
    
    [+] Captured Banner/s: 2
    
    [*] Banner from Port 445:
    
        ============================================================
             SNB - Microsoft-DS
        ============================================================
        
    [*] Banner from Port 135:
    
        ============================================================
             Microsoft Windows Remote Procedure Call
        ============================================================
    
    
    [+] OS Fingerprint Results:
    ----------------------------------------
        [+] Windows      :  83.2% (score: 109.0)
    
    [+] Lightscan scanned 1 target(s) successfully

# Features

## High-Performance Scanning

Multi-threaded architecture for fast scans
Multiple scan types: TCP Connect, SYN Stealth, UDP

Configurable speed presets from Paranoid to Light-mode (400 threads)

Smart host discovery with threaded ICMP/TCP detection

## Network Range Support

CIDR notation (/8, /16, /24, etc.) for subnet scanning

Multiple target support via comma-separated lists

Intelligent host filtering - skips non-responsive hosts in network scans

Safety warnings for large network ranges

## Advanced Detection

Service detection with custom and system service databases

Firewall detection with detailed analysis

Port state classification: Open, Closed, Filtered, Open|Filtered

Retry mechanism for unreliable networks

## Professional Features

Flexible port specification: ranges, lists, and top ports

Verbose output for debugging and analysis

Customizable timeouts and thread counts

Clean, organized output with per-target results
    
# Installation

      git clone https://github.com/adamboulaaz92-jpg/Light-Scan.git
  
      cd Light-Scan
      
      pip install -r requirements.txt
      
# Importante

before running Light-Scan you need to install Npcap from https://npcap.com/#download (it's required for Light-Scan to run)
    
# User Guide : 

## Basic Scanning
  
  ### Single Target TCP Scan
  
      python Lightscan.py -T 192.168.1.1
  
  ### SYN Stealth Scan
  
      python Lightscan.py -T 192.168.1.1 -st SYN
  
  ### UDP Scan on Specific Port
  
      python Lightscan.py -T 192.168.1.1 -st UDP -p 53
  
## Network Scanning
  
  ### Scan Entire Subnet
  
      python Lightscan.py -T 192.168.1.0/24 -F
  
  ### Multiple Targets
  
      python Lightscan.py -T 192.168.1.1,192.168.1.50,10.0.0.0/24
  
  ### Fast Network Scan with Top Ports
  
      python Lightscan.py -T 10.0.0.0/16 -F -s fast
  
## Advanced Usage
  
  ### Custom Port Range with Retries
  
      python Lightscan.py -T target.com -p 1-1000 --max_retries 3
  
  ### High-Speed Scan with Custom Threads
  
      python Lightscan.py -T 192.168.1.1 -t 200 -tm 0.5
  
  ### Verbose Output for Debugging
  
      python Lightscan.py -T 192.168.1.1 -v -st SYN
  
## Command Line Options
  
      Lightscan Port Scanner

        options:
          -h, --help            show this help message and exit
          -T, --target TARGET   Target IP or Hostname
          -p, --port PORT       Port/s to scan
          -s, --speed {paranoid,slow,normal,fast,insane,Light-mode}
                                Scan speed preset
          -v, --verbose         Show verbose output {True/False}
          -st, --scan_type SCAN_TYPE
                                Scan types {TCP,SYN,UDP}
          -F                    Scan The Top 100 ports for fast scanning
          -mx, --max_retries MAX_RETRIES
                                Max number of retries if port show a no response
          -t, --threads THREADS
                                Number of threads to use
          -tm, --timeout TIMEOUT
                                Timeout with second
          -Rc, --recursively    recursively scan host that shown to be down or not responding and more
          -f, --fragmente       fragmente the sending packet for more stealth
          -Pn, --no_ping        Do not ping the target/s
          -b, --banner          Banner Grabing
          -O, --os              OS Figerprint
  
  ## Speed Presets
  
paranoid: 2 thread, 3s timeout
  
slow: 6 threads, 2s timeout
  
normal: 30 threads, 1.5s timeout
  
fast: 60 threads, 1.5s timeout
  
insane: 160 threads, 1s timeout
  
Light-mode: 400 threads, 1s timeout
  
## Port Specification Examples
  
  ### Single Port
  
      -p 80
  
  ### Port Range
      
      -p 1-1000
  
  ### Multiple Ports
  
      -p 22,80,443,8080
  
  ### Mixed Ranges and Single Ports
  
      -p 20-25,80,443,8000-9000
  
## Scan Types
  
  ### TCP Connect Scan (-st TCP)

Uses full TCP three-way handshake
  
Most reliable but easily detectable
  
  ### SYN Stealth Scan (-st SYN)
  
Half-open scanning technique
  
Stealthier than TCP connect
  
Sends RST packet to close connection
  
  ### UDP Scan (-st UDP)
  
Connectionless protocol scanning
  
Slower than TCP scans due to timeouts
  
Useful for DNS, DHCP, SNMP services
  
## Network Scanning Features
  CIDR Notation Support
  
  Lightscan supports standard CIDR notation for scanning entire networks:
  
  ### Class C subnet (256 hosts)
      python Lightscan.py -T 192.168.1.0/24
  
  ### Class B subnet (65,536 hosts) - with safety warning
      python Lightscan.py -T 10.0.0.0/16
  
  ### Class A subnet (16.7 million hosts) - extreme warning
      python Lightscan.py -T 10.0.0.0/8
  
## Smart Host Discovery
  
  ### When scanning multiple targets:
  
Performs threaded host discovery first
  
Only scans hosts that respond to discovery probes

Saves time by skipping dead hosts
  
  ### Safety Features
  
Warnings for large network scans
  
Confirmation prompts for massive scans
  
Progress indicators for large expansions
  
## Output Interpretation

  ### Port States
  
Open: Service is listening and accessible
  
Closed: Host is up but no service listening
  
Filtered: Firewall blocking access (no response)
  
Open|Filtered: Unable to determine (common with UDP)
  
  ### Performance Tips
  
Use -F for large networks: Scan top 100 ports instead of top 1000
  
Adjust timeout: Reduce timeout for internal networks (-tm 0.5)
  
Increase threads: Use more threads for faster scanning (-t 100)
  
Reduce retries: Use --max_retries 1 for reliable networks
  
Choose appropriate scan type: SYN for speed, TCP for reliability
  
# Troubleshooting
  
  ## Scan is too slow
  
Reduce timeout: -tm 1.0
  
Increase threads: -t 100
  
Use faster speed preset: -s fast
  
  ## No results from UDP scan
  
UDP is connectionless - timeouts are normal
  
Increase retries: --max_retries 3
  
Check if service is actually running
  
  ## SYN scan not working
  
Ensure you have root/administrator privileges
  
Try TCP connect scan instead: -st TCP
  
  ## Host discovery missing hosts
  
Some hosts block ICMP
  
Use TCP-based discovery (automatic fallback) by  -Rc flag
  
Check firewall rules on target hosts
  
# Legal Disclaimer
  
  ## This tool is intended for:
  
Security professionals conducting authorized assessments
  
Network administrators monitoring their own networks
  
Educational and research purposes
  
  Always ensure you have proper authorization before scanning any network or system. Unauthorized scanning may be illegal in your jurisdiction.
  Contributing
  
  Contributions are welcome! Please feel free to submit pull requests, report bugs, or suggest new features.
  License
  
  This project is licensed under the GNU GENERAL PUBLIC LICENSE - see the LICENSE file for details.

# Update 1.1.2 Features

## adding 1700+ new services for Services.py for both TCP and UDP  
## adding more flags for better experience :

      -Rc, --recursively    recursively scan host that shown to be down or not responding and more
      -f, --fragmente       fragmente the sending packet for more stealth
      -Pn, --no_ping        Do not ping the target/s
      -b, --banner          Banner Grabing
      -O, --os              OS Figerprint
## upgrade LightEngine with new abilitys like :
### Banner Grabbing

    ============================================================

    [+] Banner from scanme.nmap.org: Port 22:
    
    SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
    
    ============================================================
    
    ============================================================
    
    [+] Banner from scanme.nmap.org: Port 80:
    
    HTTP/1.1 200 OK
    Date: Fri, 28 Nov 2025 20:49:32 GMT
    Server: Apache/2.4.7 (Ubuntu)
    Accept-Ranges: bytes
    Vary: Accept-Encoding
    Content-Type: text/html
    
    ============================================================
    
### Fragmentation

    [+] Host scanme.nmap.org is shown to be down or not responding

    [+] Fragmentation: 2 packets sent to 45.33.32.156, 2 responses received
    
    [+] Demo Fragementation (if you find an error while using it leave it in our github for future updates)
    
    [+] Successfully sent fragemented ACK to scanme.nmap.org, 2 responses received from scanme.nmap.org
    
### OS Figerprint

    [+] Os Figerprint :
    
        Linux/Unix : 100.0%
        Windows : 0.0%
        Servers/Networking Device : 0.0
        
