import argparse
import json
from datetime import datetime
import os
from core.os_fingerprint import os_fingerprint
from core.cve_checker import check_cve
from core.shodan_lookup import shodan_lookup

import socket
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init

init(autoreset=True)


def banner():
    print(Fore.CYAN + """
=========================================================
        ADVANCED MINI VAPT SCANNER
        Port Scan | CVE | OS | Shodan | Report
        Author: Krunal Patel
=========================================================
""" + Style.RESET_ALL)


def scan_port(target, port, results):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.7)
        if sock.connect_ex((target, port)) == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"

            cves = check_cve(service)

            results.append({
                "port": port,
                "service": service,
                "cves": cves,
                "risk": "HIGH" if cves and "CVE" in str(cves) else "MEDIUM"
            })

            print(Fore.GREEN + f"[OPEN] {port}/tcp ({service})")
        sock.close()
    except:
        pass

def scan_ports(target, threads):
    print(Fore.YELLOW + f"\n[+] Scanning ports on {target}\n")
    results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for port in range(1, 1025):
            executor.submit(scan_port, target, port, results)

    return results


def generate_html(report):
    with open("templates/report_template.html", "r") as f:
        template = f.read()

    html = template.replace("{{DATA}}", json.dumps(report, indent=4))

    with open("reports/report.html", "w") as f:
        f.write(html)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Mini VAPT Scanner")
    parser.add_argument("--target", required=True, help="Target IP or Domain")
    parser.add_argument("--threads", type=int, default=200)
    parser.add_argument("--shodan-key", help="Shodan API Key (optional)")
    args = parser.parse_args()

    banner()
    start_time = datetime.now()

    os.makedirs("reports", exist_ok=True)

    print(Fore.YELLOW + "\n[+] Starting scan...\n")

    report = {
        "target": args.target,
        "scan_time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "open_ports": scan_ports(args.target, args.threads),
        "os_fingerprint": os_fingerprint(args.target),
        "scan_duration": None
    }


    if args.shodan_key:
        report["shodan"] = shodan_lookup(args.target, args.shodan_key)
    else:
        report["shodan"] = "Not used"

    report["scan_duration"] = str(datetime.now() - start_time)


    with open("reports/report.json", "w") as f:
        json.dump(report, f, indent=4)


    generate_html(report)

    print(Fore.CYAN + "\n[✓] Scan completed")
    print(Fore.CYAN + "[✓] JSON Report: reports/report.json")
    print(Fore.CYAN + "[✓] HTML Report: reports/report.html")
