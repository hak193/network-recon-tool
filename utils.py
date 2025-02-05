import ipaddress
import nmap

def ip_range(ip, cidr):
    return ipaddress.ip_network(f"{ip}/{cidr}", strict=False)

def scan_ports(ip, ports):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip, arguments='-sT -p '+ports)
    return nm.get_nmap_last_output()

def detect_service_versions(ip, ports):
    service_versions = []
    nm = nmap.PortScanner()
    nm.scan(hosts=ip, arguments='-sV -p '+ports)
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = sorted(nm[host][proto].keys())
            for port in lport:
                service_version = nm[host][proto][port]['product'] + ' ' + nm[host][proto][port]['version']
                service_versions.append((port, service_version))
    return service_versions

def check_vulnerabilities(service_versions):
    vulnerabilities_detected = []
    # Use a vulnerability database like NVD or CVE to check for vulnerabilities
    # For example:
    cve_database = {
        'OpenSSH 7.9p1': ['CVE-2020-15778', 'high'],
        'Apache 2.4.41': ['CVE-2019-0211', 'medium']
    }
    for port, service_version in service_versions:
        if service_version in cve_database:
            vulnerabilities_detected.append((cve_database[service_version][0], cve_database[service_version][1]))
    return vulnerabilities_detected

def is_live_host(ip):
    import os
    response = os.system("ping -c 1 " + ip)
    if response == 0:
        return True
    else:
        return False

def get_live_hosts(ip_range):
    live_hosts = []
    for ip in ip_range.hosts():
        if is_live_host(str(ip)):
            live_hosts.append(str(ip))
        else:
            print(f"Host {ip} is not live")
    
# Get all hosts 
# filter out only live hosts 

# call other fns on each host 
