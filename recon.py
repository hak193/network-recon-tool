import scapy.all as scapy
import argparse
from tabulate import tabulate

# Define the function to scar the IP range
def scan_ip_range(ip_range):
    # Send ARP requests to the IP range and get the responses
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Get the live hosts from the responses
    live_hosts = []
    for element in answered_list:
        live_hosts.append(element[1].psrc)

    return live_hosts

# Define the function to scan open ports on a host
def scan_open_ports(host):
    # Send SYN packets to common ports and get the responses
    open_ports = []
    ports = [22, 80, 443]
    for port in ports:
        packet = scapy.IP(dst=host)/scapy.TCP(dport=port, flags="S")
        response = scapy.sr1(packet, timeout=1, verbose=False)
        if response and response.haslayer(scapy.TCP) and response.getlayer(scapy.TCP).flags == 0x12:
            open_ports.append(port)

    return open_ports

# Define the function to get service versions from open ports
def get_service_versions(host, open_ports):
    # Send requests to open ports and get service versions from headers or banners
    service_versions = {}
    for port in open_ports:
        if port == 22:
            # SSH service version extraction is complex and may require additional libraries or custom implementation.
            # For simplicity, we'll assume it's OpenSSH.
            service_versions[port] = "OpenSSH"
        elif port == 80:
            packet = scapy.IP(dst=host)/scapy.TCP(dport=port)/"GET / HTTP/1.1\r\nHost:\r\n\r\n"
            response = scappy.sr1(packet, timeout=1, verbose=False)
            if response and response.haslayer(scappy.HTTPResponse):
                server_header = response.getlayer(scappy.HTTPResponse).getheader("Server")
                if server_header:
                    service_versions[port] = server_header.split()[0]

    return service_versions

# Define the function to check potential vulnerabilities based on service versions.
def check_vulnerabilities(service_versions):
    vulnerabilities = []
    
     # Add known vulnerability checks here. 
     # For example,
     #   - Check OpenSSH version against known CVEs like CVE-2020-15778 (critical).
     #   - Check Apache version against known CVEs like CVE-2019-0211 (high).
    
     # Example entries based on given example output code
    
     if '22' in list(service_versions.keys()) :
         vulnerabilities.append({'cve': 'CVE-2020-15778', 'description': f"OpenSSH {service_versions['22']}" , 'severity': "Critical"})
     
     
      # similar condition can be added here as per requirement 
