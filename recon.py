import argparse
from utils import ip_range, scan_ports, detect_service_versions, check_vulnerabilities

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip-range", required=True)
    args = parser.parse_args()

    ip_range_obj = ip_range(args.ip_range.split("/")[0], args.ip_range.split("/")[1])
    live_hosts = []

    # Perform ICMP ping sweep to find live hosts
    for ip in ip_range_obj.hosts():
        if is_live_host(ip):  # implement is_live_host function using scapy or nmap
            live_hosts.append(ip)

    print("Live hosts:")
    for host in live_hosts:
        print(host)

        # Scan open ports on each live host
        open_ports = scan_ports(host)
        print("Open ports on {}: {}".format(host, open_ports))

        # Detect service versions on each open port
        service_versions = detect_service_versions(host)
        print("Service versions:")
        for port in service_versions:
            print("{} ({}): {}".format(port[0], port[1], port[2]))

        # Check potential vulnerabilities on each service version detected 
        vulnerabilities_detected=check_vulnerabilities(service_versions)
        if len(vulnerabilities_detected)>0 :
          print ("Potential vulnerabilites :")
          i=0 
          while i<len(vulnerabilities_detected) :
            vuln_id=vulnerabilities_detected[i][0]
            vuln_severity=vulnerabilities_detected[i][1]
            vuln_desc=vulnerabilities_detected[i][2]            
            i=i+1  
            print("{} ({})".format(vuln_id,vuln_severity))
        
if __name__ == "__main__":
    main()
import requests

def check_vulnerabilities(service_versions):
    api_url = "https://services.nvd.disa.mil/rest/v1/cve/1.0"
    headers = {"Content-Type": "application/json"}
    params = {"apiKey": "35a5e144-5679-4838-9a50-e4fd6a38d2e2", "cpeName": service_versions}

    response = requests.get(api_url, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json()
        vulnerabilities_detected = []
        for result in data["result"]["vulnerabilities"]:
            vulnerability_id = result["id"]
            severity = result["severity"]
            vulnerabilities_detected.append((vulnerability_id, severity))
        return vulnerabilities_detected
    else:
        return None
