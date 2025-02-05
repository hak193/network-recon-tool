import ipaddress
import os
import requests

# Define the ip_range function
def ip_range(ip_range_str):
    network = ipaddress.ip_network(ip_range_str, strict=False)
    return [str(ip) for ip in network]

# Define the ping_sweep function
def ping_sweep(ip_range):
    live_hosts = []
    for ip in ip_range:
        response = os.system("ping -c 1 " + ip)
        if response == 0:
            live_hosts.append(ip)
    return live_hosts

# Define the scan_ports function
def scan_ports(host, port_range):
    open_ports = []
    for port in range(port_range[0], port_range[1] + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

# Define the detect_service_versions function
def detect_service_versions(host, port):
    service_versions = {}
    try:
        response = requests.get(f"http://{host}:{port}")
        service_versions["service"] = response.headers["Server"]
        service_versions["version"] = response.headers["X-Powered-By"]
    except requests.exceptions.RequestException as e:
        print(f"Error detecting service versions: {e}")
    return service_versions

# Define the check_vulnerabilities function
def check_vulnerabilities(nvd_api_key, host, port, service_version):
    vulnerabilities = []
    try:
        response = requests.get(f"https://services.nvd.disa.mil/rest/v2/cve/1.0?apiKey={nvd_api_key}&cpeName={service_version}")
        vulnerabilities.extend(response.json()["result"]["vulnerabilities"])
    except requests.exceptions.RequestException as e:
        print(f"Error checking vulnerabilities: {e}")
    return vulnerabilities

# Main script
if __name__ == "__main__":
    import socket

    # Get user input for IP range and NVD API key
    ip_range_str = input("Enter IP range (e.g., 192.168.1.0/24): ")
    nvd_api_key = "35a5e144-5679-4838-9a50-e4fd6a38d2e2"

    # Calculate IP range using ip_range function
    ip_range_list = ip_range(ip_range_str)

    # Scan for live hosts using ICMP ping sweep
    live_hosts = ping_sweep(ip_range_list)

    # For each live host, scan for open ports using scan_ports function
    for host in live_hosts:
        print(f"Scanning {host}...")
        open_ports = scan_ports(host, (1, 65535))

        # For each open port, detect service versions using detect_service_versions function
        for port in open_ports:
            print(f"Detecting service versions on {host}:{port}...")
            service_versions = detect_service_versions(host, port)

            # Check for potential vulnerabilities using check_vulnerabilities function
            if service_versions:
                print(f"Checking vulnerabilities on {host}:{port}...")
                vulnerabilities = check_vulnerabilities(nvd_api_key, host, port, service_versions["service"])
                if vulnerabilities:
                    print(f"Vulnerabilities found on {host}:{port}:")
                    for vulnerability in vulnerabilities:
                        print(vulnerability["id"])
