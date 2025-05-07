#!/usr/bin/env python3
import os
import sys
import time
import ipaddress
import shutil
import argparse
import subprocess

# Colores
RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
WHITE = "\033[97m"
MAGENTA = "\033[95m"
DARK_GRAY = "\033[90m"
LIGHT_GRAY = "\033[37m"

OUTPUT_DIR = "dogscan_output"

def print_signature():
    print(DARK_GRAY + "═" * 65 + RESET)
    print(LIGHT_GRAY + "[*] version: " + CYAN + "dogscan 1.0.2" + RESET)
    print(LIGHT_GRAY + "[*] Developer: " + CYAN + "siemprearmando" + RESET)
    print(LIGHT_GRAY + "[*] GitHub: " + CYAN + "https://github.com/siemprearmando" + RESET)
    print(DARK_GRAY + "═" * 65 + RESET)


def check_nmap():
    if shutil.which("nmap") is None:
        print(RED + "[-] Nmap is not installed. Please install it first." + RESET)
        sys.exit(1)

def run_scan(ip):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_file = os.path.join(OUTPUT_DIR, "all_ports.txt")
    
    print(LIGHT_GRAY + f"[*] Running full port scan on {ip}..." + RESET)

    try:
        subprocess.run(
            ["nmap", "-Pn", "-p-", "-T4", "--min-rate=1000", "-oN", output_file, ip],
            check=True
        )
    except subprocess.CalledProcessError as e:
        print(RED + f"[-] Nmap scan failed: {e}" + RESET)
        sys.exit(1)

    print(GREEN + f"[+] Scan complete. Output saved to {output_file}" + RESET)
    return output_file


def parse_open_ports(filename):
    open_ports = []
    with open(filename, "r") as f:
        for line in f:
            if "/tcp" in line and "open" in line:
                port = line.split("/")[0].strip()
                open_ports.append(port)
    return open_ports

def run_targeted_scan(ip, open_ports):
    if not open_ports:
        print(RED + "[-] No open ports found." + RESET)
        return

    ports_str = ",".join(open_ports)
    output_file = os.path.join(OUTPUT_DIR, "targeted.txt")
    print(LIGHT_GRAY + f"[*] Running targeted scan on ports: " + CYAN + f"{ports_str}" + RESET)
    
    try:
        subprocess.run(
            ["nmap", "-sC", "-sV", "-p", ports_str, "-oN", output_file, ip],
            check=True
        )
        print(GREEN + f"[+] Targeted scan complete. Output saved to {output_file}" + RESET)
    except subprocess.CalledProcessError as e:
        print(RED + f"[-] Targeted scan failed: {e}" + RESET)

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print(RED + "[-] Invalid IP address." + RESET)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="dogscan - simple nmap wrapper")
    parser.add_argument("ip", help="Target IP address")
    args = parser.parse_args()

    validate_ip(args.ip)
    print_signature()
    check_nmap()
    all_ports_file = run_scan(args.ip)
    open_ports = parse_open_ports(all_ports_file)
    
    run_targeted_scan(args.ip, open_ports)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + RED + "[!] Scan cancelled by user." + RESET)
        print(CYAN + "[-] dogs are coming home. 🐶" + RESET)
        sys.exit(0)
