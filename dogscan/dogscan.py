#!/usr/bin/env python3
import os
import sys
import time
import ipaddress
import shutil
import argparse
import subprocess
import json

from modules  import  ftp , ssh
# ===================== COLORES =====================
RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
WHITE = "\033[97m"
MAGENTA = "\033[95m"
DARK_GRAY = "\033[90m"
LIGHT_GRAY = "\033[37m"
YELLOW = "\033[93m"

OUTPUT_DIR = "nmap_output"


MODULE_MAP = {
    "21": ftp.enumerate_ftp,
    "22": ssh.enumerate_ssh,}


# ===================== ASCII ART =====================
def ascii_art():
    print(GREEN + r"""
        |`-.__  
        /   _/
       ****`  ________                                        
      /    } ____ __  \____________ ___________________ _______ 
     /  \ /____  / / /_  __ \_  __ `/_  ___/  ___/  __ `/_  __ \  
 \ /`   \\\   / /_/ / / /_/ /  /_/ /_(__  )/ /__ / /_/ /_  / / /
  `\    /_\\ \_____/  \____/_\__, / /____/ \___/ \__,_/ /_/ /_/ 
   `~~~~~``~`               /____/                          
    """ + RESET)


# ===================== FIRMA =====================
def print_signature():
    print(DARK_GRAY + "═" * 65 + RESET)
    print(LIGHT_GRAY + "[*] version: " + CYAN + "dogscan 1.1.0" + RESET)
    print(LIGHT_GRAY + "[*] Developer: " + CYAN + "jorgearma" + RESET)
    print(LIGHT_GRAY + "[*] GitHub: " + CYAN + "https://github.com/jorgearma" + RESET)
    print(DARK_GRAY + "═" * 65 + RESET)


# ===================== CHECKEO =====================
def check_nmap():
    if shutil.which("nmap") is None:
        print(RED + "[-] Nmap is not installed. Install it first." + RESET)
        sys.exit(1)



def check_searchsploit():
    if shutil.which("searchsploit") is None:
        print(YELLOW + "[!] searchsploit not found. Exploit detection limited." + RESET)
        return False
    return True


# ===================== SCAN COMPLETO =====================
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

    print(GREEN + f"[+] Scan complete → {output_file}" + RESET)
    return output_file


# ===================== PARSEAR PUERTOS =====================
def parse_open_ports(filename):
    open_ports = []
    with open(filename, "r") as f:
        for line in f:
            if "/tcp" in line and "open" in line:
                port = line.split("/")[0].strip()
                open_ports.append(port)
    return open_ports


# ===================== SCAN DIRIGIDO =====================
def run_targeted_scan(ip, open_ports):
    if not open_ports:
        print(RED + "[-] No open ports found." + RESET)
        return

    ports_str = ",".join(open_ports)
    output_file = os.path.join(OUTPUT_DIR, "targeted.txt")

    print(LIGHT_GRAY + f"[*] Running targeted scan on: " + CYAN + ports_str + RESET)

    try:
        subprocess.run(
            ["nmap", "-sC", "-sV", "-p", ports_str, "-oN", output_file, ip],
            check=True
        )
        print(GREEN + f"[+] Targeted scan saved → {output_file}" + RESET)

    except subprocess.CalledProcessError as e:
        print(RED + f"[-] Targeted scan failed: {e}" + RESET)


# ===================== SEARCHSPLOIT =====================
def search_exploits(service_banner):
    try:
        result = subprocess.run(
            ["searchsploit", "-j", service_banner],
            capture_output=True,
            text=True
        )
        data = json.loads(result.stdout)
        return data.get("RESULTS_EXPLOIT", [])
    except Exception:
        return []


# ===================== EXTRAER BANNER =====================
def extract_banner_from_targeted(port):
    targeted_file = os.path.join(OUTPUT_DIR, "targeted.txt")

    if not os.path.exists(targeted_file):
        return None

    with open(targeted_file, "r") as f:
        for line in f:
            if line.startswith(port + "/tcp") and "open" in line:
                parts = line.split()
                if len(parts) >= 4:
                    return " ".join(parts[3:]).strip()

    return None


# ===================== ANALISIS DE VULNERABILIDADES =====================
def run_vulnerability_scan(ip, open_ports):
    print(MAGENTA + "\n====== VULNERABILITY ANALYSIS ======" + RESET)
    searchsploit_available = check_searchsploit()

    WEB_PORTS = ["80", "443", "8080", "8000", "8443"]

    for port in open_ports:
        print(CYAN + f"\n[*] Analyzing port {port}..." + RESET)

        # 🔹 Definir siempre output_file
        output_file = os.path.join(OUTPUT_DIR, f"vuln_{port}.txt")

        # ========== AUTO ENUMERATION (Metasploit-Style Modules) ==========
        if port in MODULE_MAP:
            module = MODULE_MAP[port](ip, port)
            run_nmap_scripts(ip, port, module["scripts"], module["name"])

        # ========== TU ENUMERACIÓN ORIGINAL SIGUE FUNCIONANDO ==========
        if port == "22":
            scripts = "vulners"
            print(LIGHT_GRAY + "[→] Using clean Vulners scan (SSH mode)" + RESET)
            script_args = "--script-args=mincvss=9.8"

        elif port in WEB_PORTS:
            scripts = "http-title,http-server-header,http-methods,http-enum,http-csrf,http-headers"
            print(LIGHT_GRAY + "[→] Using lightweight HTTP scripts" + RESET)
            script_args = ""

        else:
            scripts = "vuln"
            print(LIGHT_GRAY + "[→] Using full vuln scan" + RESET)
            script_args = ""

        # ========== EJECUTAR NMAP SCRIPT NORMAL ==========

        try:
            cmd = [
                "nmap", "-Pn", "-sV", "-p", port,
                f"--script={scripts}",
                "--script-timeout=20s"
            ]

            if script_args:
                cmd.append(script_args)

            cmd += ["-oN", output_file, ip]

            subprocess.run(cmd, check=True)

            print(GREEN + f"[+] Scan saved → {output_file}" + RESET)

        except subprocess.CalledProcessError as e:
            print(RED + f"[-] Error scanning port {port}: {e}" + RESET)


        banner = extract_banner_from_targeted(port)

        if banner:
            print(f"{CYAN}[→] Detected service:{RESET} {WHITE}{banner}{RESET}")

            if searchsploit_available:
                exploits = search_exploits(banner)

                if exploits:
                    print(RED + "[+] Exploits encontrados en searchsploit:" + RESET)
                    for e in exploits:
                        title = e.get("Title", "Unknown")
                        path = e.get("Path", "")
                        print(f"   - {RED}{title}{RESET} {DARK_GRAY}({path}){RESET}")
                else:
                    print(YELLOW + "[!] No exploits found." + RESET)



def run_nmap_scripts(ip, port, scripts, module_name):
    output_file = os.path.join(OUTPUT_DIR, f"module_{module_name.replace(' ', '_').lower()}_{port}.txt")

    scripts_str = ",".join(scripts)
    
    print(f"{CYAN}[*] Running module: {module_name} (port {port}){RESET}")
    print(f"{LIGHT_GRAY}    Scripts: {scripts_str}{RESET}")
    
    try:
        subprocess.run(
            [
                "nmap", "-Pn", "-p", port,
                f"--script={scripts_str}",
                "--script-timeout=35s",
                "-oN", output_file,
                ip
            ],
            check=True
        )
        print(f"{GREEN}[+] Saved → {output_file}{RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{RED}[-] Error in module {module_name}: {e}{RESET}")


# ===================== MAIN =====================
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

    ascii_art()
    validate_ip(args.ip)
    print_signature()
    check_nmap()

    all_ports_file = run_scan(args.ip)
    open_ports = parse_open_ports(all_ports_file)

    run_targeted_scan(args.ip, open_ports)
    run_vulnerability_scan(args.ip, open_ports)
    print(CYAN + "[-] dogs are coming home. 🐶" + RESET)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + RED + "[!] Scan cancelled by user." + RESET)
        print(CYAN + "[-] dogs are coming home. 🐶" + RESET)
        sys.exit(0)
