# Automation Script
# Recon and Vulnerability Scanning using Nmap + Nuclei
import subprocess
import json
import os
from datetime import datetime

# config
TARGET = "#"
OUTPUT_DIR = "scan_results"
NMAP_OUTPUT = os.path.join(OUTPUT_DIR, "nmap_output.xml")
NUCLEI_OUTPUT = os.path.join(OUTPUT_DIR, "nuclei_output.json")
PORTS_TO_SCAN = "-p-"

# output dir
os.makedirs(OUTPUT_DIR, exist_ok=True)

def run_nmap(target):
    print(f"[+] Running Nmap on {target}...")
    cmd = [
        "nmap", "-sC", "-sV", "-oX", NMAP_OUTPUT, PORTS_TO_SCAN, target
    ]
    subprocess.run(cmd, check=True)
    print("[+] Nmap scan complete.")

def parse_nmap_http_services():
    import xml.etree.ElementTree as ET
    print("[+] Parsing Nmap output...")
    services = []
    tree = ET.parse(NMAP_OUTPUT)
    root = tree.getroot()

    for host in root.findall('host'):
        address = host.find('address').attrib['addr']
        for port in host.find('ports').findall('port'):
            portid = port.attrib['portid']
            state = port.find('state').attrib['state']
            if state == "open":
                service = port.find('service')
                name = service.attrib.get('name', '')
                if "http" in name:
                    url = f"http://{address}:{portid}"
                    services.append(url)
    print(f"[+] Found {len(services)} HTTP services to scan.")
    return services

def run_nuclei(targets):
    print("[+] Running Nuclei scans...")
    with open("temp_targets.txt", "w") as f:
        for t in targets:
            f.write(t + "\n")

    cmd = [
        "nuclei", "-l", "temp_targets.txt",
        "-o", NUCLEI_OUTPUT, "-json"
    ]
    subprocess.run(cmd, check=True)
    os.remove("temp_targets.txt")
    print(f"[+] Nuclei scan complete. Results saved to {NUCLEI_OUTPUT}")

def main():
    start = datetime.now()
    print(f"[+] Scan started at {start}")

    run_nmap(TARGET)
    services = parse_nmap_http_services()
    if services:
        run_nuclei(services)
    else:
        print("[-] No HTTP services found. Skipping Nuclei scan.")

    end = datetime.now()
    print(f"[+] Scan completed at {end}. Duration: {end - start}")

if __name__ == "__main__":
    main()
