Tool 1: Network Reconnaissance Tool
Overview

The Network Reconnaissance Tool is designed to assist red teamers in gathering detailed information about a target network. It performs various network scanning and enumeration techniques to identify live hosts, open ports, services, and potential vulnerabilities.
Features

    IP Range Scanning: Quickly scan a range of IP addresses to identify live hosts.
    Port Scanning: Discover open ports on identified hosts.
    Service Enumeration: Determine the services running on open ports.
    Version Detection: Identify the software versions of detected services.
    Vulnerability Scanning: Check for common vulnerabilities in identified services.

Usage
bash

# Clone the repository
git clone https://github.com/your-username/network-recon-tool.git
cd network-recon-tool

# Install dependencies
pip install -r requirements.txt

# Run the tool
python recon.py --ip-range 192.168.1.0/24

Example Output
Code

Scanning IP range: 192.168.1.0/24
Live hosts:
  - 192.168.1.1
  - 192.168.1.2
  - 192.168.1.10

Open ports on 192.168.1.1:
  - 22 (SSH)
  - 80 (HTTP)

Service versions:
  - SSH: OpenSSH 7.9p1
  - HTTP: Apache 2.4.41

Potential vulnerabilities:
  - CVE-2020-15778: OpenSSH 7.9p1 (critical)
  - CVE-2019-0211: Apache 2.4.41 (high)

