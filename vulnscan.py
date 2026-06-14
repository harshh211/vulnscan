#!/usr/bin/env python3
"""
vulnscan.py — Simple Vulnerability Scanner
Author: Harshvardhan Kamble
Features: Port Scanning, Banner Grabbing, CVE Lookup via NVD API
"""

import socket
import requests
import argparse
import sys
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = "YOUR_NVD_API_KEY_HERE"  # Get free key at https://nvd.nist.gov/developers/request-an-api-key
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                 3306, 3389, 5900, 8080, 8443]
TIMEOUT = 2
MAX_THREADS = 50
BANNER_TIMEOUT = 2


# ─────────────────────────────────────────
# COLORS
# ─────────────────────────────────────────
class Color:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    RESET  = "\033[0m"
    BOLD   = "\033[1m"


def print_banner():
    print(f"""
{Color.CYAN}{Color.BOLD}
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{Color.RESET}
{Color.YELLOW}  Port Scanner + Banner Grabber + CVE Lookup via NVD API{Color.RESET}
{Color.BLUE}  Author: Harshvardhan Kamble{Color.RESET}
    """)


# ─────────────────────────────────────────
# PORT SCANNER
# ─────────────────────────────────────────
def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((target, port))
        sock.close()
        return (port, result == 0)
    except socket.error:
        return (port, False)


def scan_ports(target, ports):
    print(f"\n{Color.BLUE}[*] Scanning {target} for open ports...{Color.RESET}")
    open_ports = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(scan_port, target, port): port for port in ports}
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
    return sorted(open_ports)


# ─────────────────────────────────────────
# BANNER GRABBER
# ─────────────────────────────────────────
def grab_banner(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(BANNER_TIMEOUT)
        sock.connect((target, port))

        if port in [80, 8080, 8443, 443]:
            sock.send(b"HEAD / HTTP/1.0\r\nHost: " + target.encode() + b"\r\n\r\n")
        else:
            sock.send(b"\r\n")

        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()

        lines = [l.strip() for l in banner.split("\n") if l.strip()]
        if lines:
            for line in lines:
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()
            return lines[0][:100]
    except Exception:
        pass

    known = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
        139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt"
    }
    return known.get(port, "Unknown")


# ─────────────────────────────────────────
# SMART SEARCH TERM EXTRACTOR
# ─────────────────────────────────────────
def extract_search_terms(banner):
    """
    Returns a list of search terms to try in order:
    [specific version, product only]
    This allows fallback if specific version returns no CVEs.
    """
    if not banner:
        return []

    terms = []

    # OpenSSH: "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13"
    if "OpenSSH" in banner:
        try:
            version = banner.split("OpenSSH_")[1].split(" ")[0].split("p")[0]
            terms.append(f"OpenSSH {version}")
        except IndexError:
            pass
        terms.append("OpenSSH")
        return terms

    # Apache: "Apache/2.4.7 (Ubuntu)"
    if "Apache" in banner:
        try:
            version = banner.split("Apache/")[1].split(" ")[0]
            terms.append(f"Apache httpd {version}")
        except IndexError:
            pass
        terms.append("Apache httpd")
        return terms

    # nginx: "nginx/1.18.0"
    if "nginx" in banner.lower():
        try:
            version = banner.lower().split("nginx/")[1].split(" ")[0]
            terms.append(f"nginx {version}")
        except IndexError:
            pass
        terms.append("nginx")
        return terms

    # IIS: "Microsoft-IIS/10.0"
    if "IIS" in banner:
        try:
            version = banner.split("IIS/")[1].split(" ")[0]
            terms.append(f"Microsoft IIS {version}")
        except IndexError:
            pass
        terms.append("Microsoft IIS")
        return terms

    # MySQL
    if "MySQL" in banner:
        try:
            version = banner.split(" ")[0]
            terms.append(f"MySQL {version}")
        except IndexError:
            pass
        terms.append("MySQL")
        return terms

    # Generic fallback
    term = banner.split("/")[0].split(" ")[0]
    if len(term) > 2 and term not in ["SSH", "FTP", "HTTP", "SMTP", "Unknown"]:
        terms.append(term)

    return terms


# ─────────────────────────────────────────
# CVE LOOKUP
# ─────────────────────────────────────────
def lookup_cves(keyword, max_results=3, retries=2):
    """Search NVD API with API key, retry on empty results."""
    if not keyword:
        return []

    headers = {"apiKey": NVD_API_KEY}
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results
    }

    for attempt in range(retries):
        try:
            response = requests.get(
                NVD_API_URL,
                params=params,
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                cves = []

                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "N/A")

                    score = "N/A"
                    severity = "N/A"
                    metrics = cve.get("metrics", {})

                    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        if version in metrics and metrics[version]:
                            cvss_data = metrics[version][0].get("cvssData", {})
                            score = cvss_data.get("baseScore", "N/A")
                            severity = metrics[version][0].get("baseSeverity",
                                       cvss_data.get("baseSeverity", "N/A"))
                            break

                    descriptions = cve.get("descriptions", [])
                    description = "No description available"
                    for desc in descriptions:
                        if desc.get("lang") == "en":
                            description = desc.get("value", "")[:120] + "..."
                            break

                    cves.append({
                        "id": cve_id,
                        "score": score,
                        "severity": severity,
                        "description": description
                    })

                if cves:
                    return cves

            # Wait before retry
            if attempt < retries - 1:
                time.sleep(1)

        except requests.exceptions.RequestException:
            if attempt < retries - 1:
                time.sleep(1)

    return []


def lookup_cves_with_fallback(banner):
    """Try multiple search terms, return first successful CVE results."""
    search_terms = extract_search_terms(banner)

    for term in search_terms:
        print(f"    {Color.BLUE}[*] Searching CVEs for: {term}{Color.RESET}")
        cves = lookup_cves(term)
        if cves:
            return cves, term
        time.sleep(0.5)  # small delay between fallback attempts

    return [], None


# ─────────────────────────────────────────
# SEVERITY COLOR
# ─────────────────────────────────────────
def severity_color(severity, score):
    severity = str(severity).upper()
    if severity == "CRITICAL":
        return Color.RED
    elif severity == "HIGH":
        return Color.YELLOW
    elif severity == "MEDIUM":
        return Color.CYAN
    else:
        return Color.GREEN

# ─────────────────────────────────────────
# RESOLVE TARGET
# ─────────────────────────────────────────
def resolve_target(target):
    try:
        ip = socket.gethostbyname(target)
        if ip != target:
            print(f"{Color.BLUE}[*] Resolved {target} → {ip}{Color.RESET}")
        return ip
    except socket.gaierror:
        print(f"{Color.RED}[!] Could not resolve host: {target}{Color.RESET}")
        sys.exit(1)


# ─────────────────────────────────────────
# MAIN SCAN
# ─────────────────────────────────────────
def run_scan(target, ports, cve_lookup=True):
    print_banner()

    ip = resolve_target(target)

    print(f"{Color.BOLD}Target    :{Color.RESET} {target} ({ip})")
    print(f"{Color.BOLD}Ports     :{Color.RESET} {len(ports)} ports")
    print(f"{Color.BOLD}CVE Lookup:{Color.RESET} {'Enabled' if cve_lookup else 'Disabled'}")
    print(f"{Color.BOLD}Started   :{Color.RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("─" * 60)

    open_ports = scan_ports(ip, ports)

    if not open_ports:
        print(f"\n{Color.YELLOW}[!] No open ports found.{Color.RESET}")
        return

    print(f"\n{Color.GREEN}[+] Found {len(open_ports)} open port(s){Color.RESET}\n")
    print("─" * 60)

    results = []

    for port in open_ports:
        print(f"\n{Color.GREEN}[+] Port {port} OPEN{Color.RESET}", end="")

        banner = grab_banner(ip, port)
        if banner:
            print(f" — {Color.CYAN}{banner}{Color.RESET}")
        else:
            print()

        port_result = {"port": port, "banner": banner, "cves": []}

        if cve_lookup and banner:
            cves, matched_term = lookup_cves_with_fallback(banner)

            if cves:
                print(f"    {Color.YELLOW}CVEs found:{Color.RESET}")
                for cve in cves:
                    color = severity_color(cve["severity"], cve["score"])
                    print(f"    {color}► {cve['id']}{Color.RESET} | "
                          f"CVSS: {color}{cve['score']}{Color.RESET} | "
                          f"Severity: {color}{cve['severity']}{Color.RESET}")
                    print(f"      {cve['description']}")
                port_result["cves"] = cves
            else:
                print(f"    {Color.GREEN}[-] No CVEs found{Color.RESET}")

        results.append(port_result)

    print(f"\n{'─' * 60}")
    print(f"{Color.BOLD}SCAN SUMMARY{Color.RESET}")
    print(f"{'─' * 60}")
    print(f"Target      : {target} ({ip})")
    print(f"Open Ports  : {', '.join(str(p) for p in open_ports)}")
    total_cves = sum(len(r["cves"]) for r in results)
    print(f"CVEs Found  : {total_cves}")
    print(f"Completed   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("─" * 60)


# ─────────────────────────────────────────
# ARGUMENT PARSER
# ─────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="vulnscan — Port Scanner + Banner Grabber + CVE Lookup",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 vulnscan.py scanme.nmap.org
  python3 vulnscan.py 192.168.1.1 -p 22,80,443
  python3 vulnscan.py scanme.nmap.org -p 1-1000
  python3 vulnscan.py 192.168.1.1 --no-cve
        """
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", help="Ports to scan (e.g. 22,80,443 or 1-1000)",
                        default=None)
    parser.add_argument("--no-cve", action="store_true",
                        help="Skip CVE lookup (faster scan)")
    return parser.parse_args()


def parse_ports(port_str):
    ports = []
    if not port_str:
        return DEFAULT_PORTS
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


# ─────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────
if __name__ == "__main__":
    args = parse_args()
    ports = parse_ports(args.ports)
    run_scan(args.target, ports, cve_lookup=not args.no_cve)