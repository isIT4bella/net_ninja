#!/usr/bin/env python3
import socket
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from termcolor import colored
import json
import os
from datetime import datetime

# Rate limiting configuration
MAX_THREADS = 50  # For port scanning
NETWORK_THREADS = 10  # For IP scanning
REQUEST_DELAY = 0.1  # Seconds between probes to avoid flooding

# Extended list of common ports with their typical authentication requirements
COMMON_PORTS = {
    # Typically require authentication
    20: {"service": "FTP Data", "auth": True, "danger": "High"},
    21: {"service": "FTP Control", "auth": True, "danger": "High"},
    22: {"service": "SSH/SFTP", "auth": True, "danger": "High"},
    23: {"service": "Telnet", "auth": True, "danger": "Critical"},
    25: {"service": "SMTP", "auth": True, "danger": "Medium"},
    110: {"service": "POP3", "auth": True, "danger": "High"},
    143: {"service": "IMAP", "auth": True, "danger": "High"},
    465: {"service": "SMTPS", "auth": True, "danger": "Medium"},
    587: {"service": "SMTP Submission", "auth": True, "danger": "Medium"},
    993: {"service": "IMAPS", "auth": True, "danger": "High"},
    995: {"service": "POP3S", "auth": True, "danger": "High"},
    3389: {"service": "RDP", "auth": True, "danger": "Critical"},
    5432: {"service": "PostgreSQL", "auth": True, "danger": "Critical"},
    27017: {"service": "MongoDB", "auth": True, "danger": "Critical"},
    5984: {"service": "CouchDB", "auth": True, "danger": "High"},
    11211: {"service": "Memcached", "auth": False, "danger": "Critical"},
    5900: {"service": "VNC", "auth": True, "danger": "Critical"},
    3306: {"service": "MySQL", "auth": True, "danger": "Critical"},
    1521: {"service": "Oracle DB", "auth": True, "danger": "Critical"},
    6379: {"service": "Redis", "auth": True, "danger": "Critical"},
    389: {"service": "LDAP", "auth": True, "danger": "High"},
    636: {"service": "LDAPS", "auth": True, "danger": "High"},
    8443: {"service": "HTTPS Alt", "auth": "Maybe", "danger": "Medium"},
    10000: {"service": "Webmin", "auth": True, "danger": "High"},
    
    # Typically don't require authentication
    53: {"service": "DNS", "auth": False, "danger": "Low"},
    67: {"service": "DHCP Server", "auth": False, "danger": "Medium"},
    68: {"service": "DHCP Client", "auth": False, "danger": "Low"},
    69: {"service": "TFTP", "auth": False, "danger": "High"},
    80: {"service": "HTTP", "auth": "Maybe", "danger": "Medium"},
    443: {"service": "HTTPS", "auth": "Maybe", "danger": "Medium"},
    123: {"service": "NTP", "auth": False, "danger": "Low"},
    161: {"service": "SNMP", "auth": "Community", "danger": "High"},
    162: {"service": "SNMP Trap", "auth": "Community", "danger": "High"},
    179: {"service": "BGP", "auth": False, "danger": "High"},
    194: {"service": "IRC", "auth": False, "danger": "Medium"},
    264: {"service": "CheckPoint FW-1", "auth": True, "danger": "High"},
    514: {"service": "Syslog", "auth": False, "danger": "Medium"},
    520: {"service": "RIP", "auth": False, "danger": "High"},
    631: {"service": "IPP", "auth": False, "danger": "Medium"},
    873: {"service": "rsync", "auth": True, "danger": "High"},
    1080: {"service": "SOCKS Proxy", "auth": True, "danger": "High"},
    1194: {"service": "OpenVPN", "auth": True, "danger": "Critical"},
    2049: {"service": "NFS", "auth": False, "danger": "High"},
    2082: {"service": "cPanel", "auth": True, "danger": "High"},
    2083: {"service": "cPanel SSL", "auth": True, "danger": "High"},
    2222: {"service": "DirectAdmin", "auth": True, "danger": "High"},
    2375: {"service": "Docker", "auth": False, "danger": "Critical"},
    2376: {"service": "Docker TLS", "auth": True, "danger": "High"},
    3000: {"service": "Node.js", "auth": "Maybe", "danger": "Medium"},
    3689: {"service": "DAAP", "auth": False, "danger": "Low"},
    4333: {"service": "mSQL", "auth": True, "danger": "Critical"},
    4444: {"service": "Metasploit", "auth": True, "danger": "Critical"},
    4505: {"service": "SaltStack", "auth": True, "danger": "Critical"},
    5000: {"service": "UPnP", "auth": False, "danger": "High"},
    5432: {"service": "PostgreSQL", "auth": True, "danger": "Critical"},
    6000: {"service": "X11", "auth": False, "danger": "High"},
    8000: {"service": "HTTP Alt", "auth": "Maybe", "danger": "Medium"},
    8080: {"service": "HTTP Proxy", "auth": "Maybe", "danger": "Medium"},
    8888: {"service": "HTTP Alt", "auth": "Maybe", "danger": "Medium"},
    9000: {"service": "PHP-FPM", "auth": "Maybe", "danger": "High"},
    47808: {"service": "Kubernetes", "auth": True, "danger": "Critical"}
}

def check_http_auth(ip, port):
    """Check if HTTP service requires authentication"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((str(ip), port))
            s.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            response = s.recv(1024).decode('utf-8', 'ignore')
            if "401 Unauthorized" in response or "403 Forbidden" in response:
                return True
            return False
    except:
        return None

def check_ssh_auth(ip, port):
    """Check if SSH service allows password authentication"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((str(ip), port))
            banner = s.recv(1024).decode('utf-8', 'ignore')
            if "SSH" in banner:
                # SSH requires auth by default, but we can check for weak configurations
                return True
            return False
    except:
        return None

def check_ftp_auth(ip, port):
    """Check if FTP allows anonymous login"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((str(ip), port))
            banner = s.recv(1024).decode('utf-8', 'ignore')
            if "220" in banner:
                s.send(b"USER anonymous\r\n")
                response = s.recv(1024).decode('utf-8', 'ignore')
                if "331" in response:
                    s.send(b"PASS anonymous\r\n")
                    response = s.recv(1024).decode('utf-8', 'ignore')
                    if "230" in response:
                        return False  # Anonymous login allowed
                return True  # Auth required
            return None
    except:
        return None

def scan_port(ip, port, timeout=2):
    """Scan a specific port on an IP address with enhanced auth checking"""
    time.sleep(REQUEST_DELAY)  # Rate limiting
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((str(ip), port))
            if result == 0:
                try:
                    service_name = socket.getservbyport(port)
                except:
                    service_name = "Unknown"
                
                port_info = COMMON_PORTS.get(port, {
                    "service": service_name,
                    "auth": "Unknown",
                    "danger": "Unknown"
                })
                
                # Enhanced auth checking for specific protocols
                auth_status = port_info["auth"]
                if port == 80 or port == 443 or port == 8080 or port == 8000 or port == 8888:
                    http_auth = check_http_auth(ip, port)
                    if http_auth is not None:
                        auth_status = "Yes" if http_auth else "No"
                elif port == 22:
                    ssh_auth = check_ssh_auth(ip, port)
                    if ssh_auth is not None:
                        auth_status = "Yes" if ssh_auth else "No"
                elif port == 21:
                    ftp_auth = check_ftp_auth(ip, port)
                    if ftp_auth is not None:
                        auth_status = "No" if ftp_auth == False else "Yes"
                
                # Determine color based on auth and danger level
                if auth_status in [True, "Yes"]:
                    color = "red"
                elif auth_status in [False, "No"]:
                    color = "green"
                else:
                    color = "yellow"
                
                danger = port_info["danger"]
                return {
                    "port": port,
                    "service": port_info["service"],
                    "auth": auth_status,
                    "danger": danger,
                    "color": color,
                    "ip": str(ip)
                }
    except:
        return None
    return None

def scan_ip(ip, ports_to_scan):
    """Scan multiple ports on a single IP address"""
    open_ports = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports_to_scan}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    return open_ports

def network_scan(network_cidr, ports_to_scan):
    """Scan a network range for open ports"""
    try:
        network = ipaddress.ip_network(network_cidr)
        print(f"\nScanning network: {network}")
        
        results = []
        with ThreadPoolExecutor(max_workers=NETWORK_THREADS) as executor:
            futures = {executor.submit(scan_ip, ip, ports_to_scan): ip for ip in network.hosts()}
            for future in as_completed(futures):
                ip = futures[future]
                open_ports = future.result()
                if open_ports:
                    print(f"\nHost: {ip}")
                    for port_info in sorted(open_ports, key=lambda x: x["port"]):
                        display_str = f"Port {port_info['port']}: {port_info['service']} (Auth: {port_info['auth']}, Danger: {port_info['danger']})"
                        print(f"  {colored(display_str, port_info['color'])}")
                    results.extend(open_ports)
        
        return results
    except ValueError as e:
        print(f"Invalid network range: {e}")
        return []

def save_results(results, format="json"):
    """Save scan results to a file"""
    if not results:
        print("No results to save.")
        return
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_results_{timestamp}"
    
    if format == "json":
        filename += ".json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {filename}")
    else:
        filename += ".txt"
        with open(filename, 'w') as f:
            for result in results:
                f.write(f"IP: {result['ip']}\n")
                f.write(f"Port: {result['port']}\n")
                f.write(f"Service: {result['service']}\n")
                f.write(f"Authentication: {result['auth']}\n")
                f.write(f"Danger Level: {result['danger']}\n")
                f.write("-"*40 + "\n")
        print(f"\nResults saved to {filename}")

def get_target_from_user():
    """Prompt user for target IP or network range"""
    while True:
        print("\n" + "="*50)
        print("Network Port Scanner - Authentication Check")
        print("="*50)
        print("Examples of valid inputs:")
        print(" - Single IP: 192.168.1.1")
        print(" - Network range: 192.168.1.0/24")
        print(" - Multiple IPs: 192.168.1.1-192.168.1.10")
        print("="*50)
        
        target = input("Enter target IP or network range to scan: ").strip()
        
        try:
            # Check for IP range (e.g., 192.168.1.1-192.168.1.10)
            if '-' in target:
                start_ip, end_ip = target.split('-')
                start = int(ipaddress.IPv4Address(start_ip))
                end = int(ipaddress.IPv4Address(end_ip))
                if start > end:
                    print("Error: Start IP must be lower than end IP")
                    continue
                return target
            # Check if it's a single IP or network range
            ipaddress.ip_network(target if '/' in target else target + '/32')
            return target
        except ValueError:
            print("Invalid IP address or network range. Please try again.")

def get_save_preference():
    """Ask user if they want to save results"""
    while True:
        choice = input("\nSave results to file? (json/txt/no): ").strip().lower()
        if choice in ['json', 'txt', 'no']:
            return choice
        print("Please enter 'json', 'txt', or 'no'")

if __name__ == "__main__":
    print("Network Port Scanner - Authentication Check")
    print("="*50)
    print("Legend:")
    print(colored("  Red", "red") + ": Password required")
    print(colored("  Green", "green") + ": No password needed")
    print(colored("  Yellow", "yellow") + ": Check authentication status")
    print("\nDanger Levels: Critical, High, Medium, Low")
    print("="*50)
    
    target = get_target_from_user()
    ports_to_scan = list(COMMON_PORTS.keys())
    
    results = network_scan(target, ports_to_scan)
    
    if results:
        save_choice = get_save_preference()
        if save_choice != 'no':
            save_results(results, save_choice)
    
    print("\nScan completed.")