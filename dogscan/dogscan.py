#!/usr/bin/env python3
import os
import sys
import time
import ipaddress
import shutil
import argparse
import subprocess
import json

from modules  import  ftp , ssh , smb 
from modules import osdetec
from modules.barradecarga import barra_carga

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

BASE_DIR = os.getcwd()
OUTPUT_DIR = os.path.join(BASE_DIR, f"nmap_output")



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

MODULE_MAP = {
    "21": ftp.enumerate_ftp,
    "22": ssh.enumerate_ssh,
    "2222": ssh.enumerate_ssh,
    "445": smb.enumerate_smb,
    }

def prepare_output_dir():
    # Bloquear symlinks (hardening básico)
    if os.path.islink(OUTPUT_DIR):
        print(RED + "[-] OUTPUT_DIR is a symlink. Aborting." + RESET)
        sys.exit(1)

    # Crear directorio con permisos seguros
    os.makedirs(OUTPUT_DIR, mode=0o700, exist_ok=True)

    # Verificar que es un directorio real
    if not os.path.isdir(OUTPUT_DIR):
        print(RED + "[-] OUTPUT_DIR is not a directory." + RESET)
        sys.exit(1)

def check_searchsploit():
    if shutil.which("searchsploit") is None:
        print(YELLOW + "[!] searchsploit not found. Exploit detection limited." + RESET)
        return False
    return True


# ===================== SCAN COMPLETO =====================
import os
import re
import sys
import subprocess
import threading


# Regex para capturar porcentaje REAL de Nmap
PERCENT_RE = re.compile(r"About\s+([\d.]+)%\s+done")


def run_scan(ip):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_file = os.path.join(OUTPUT_DIR, "all_ports.txt")
    print(f"{MAGENTA}══════════════ Port Discovery Scan ═════════════{RESET} ")
    print(f"{WHITE}[*] Running full port scan on {CYAN}{ip}{RESET}")


    stop_event = threading.Event()
    progress_ref = {"percent": None}

    loader = threading.Thread(
        target=barra_carga,
        args=("NMAP", stop_event, progress_ref),
        daemon=True
    )
    loader.start() 

    try:
        proc = subprocess.Popen(
            [
                "nmap", "-Pn", "-p-", "-T4",
                "--min-rate=1000",
                "-oN", output_file,
                ip
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        while True:
            line = proc.stdout.readline()

            if not line:
                if proc.poll() is not None:
                    break
                continue

            match = PERCENT_RE.search(line)
            if match:
                progress_ref["percent"] = float(match.group(1))

    finally:
        stop_event.set()
        loader.join()

    # Validación fuerte
    if not os.path.exists(output_file):
        raise RuntimeError("Nmap output file was not created")

    print( GREEN +"[+] Scan complete\n" + RESET)

    with open(output_file, "r") as f:
        for line in f:
            line = line.rstrip()

            if not line:
                continue
            if line.startswith("#"):
                continue
            if line.startswith("Nmap scan report for"):
                continue
            if line.startswith("Host is up"):
                continue
            if line.startswith("Not shown:"):
                continue

            print(line)

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
        return None

    ports_str = ",".join(open_ports)
    output_file = os.path.join(OUTPUT_DIR, "targeted.txt")
    print(f"{MAGENTA}\n══════════════════ Target Scan  ═════════════════{RESET} ")
    print(f"{WHITE}[*] Running targeted scan on ports {CYAN}{ports_str}{RESET}")

    stop_event = threading.Event()
    progress_ref = {"percent": None}

    loader = threading.Thread(
        target=barra_carga,
        args=("NMAP", stop_event, progress_ref),
        daemon=True
    )
    loader.start()

    try:
        proc = subprocess.Popen(
            [
                "nmap", "-sC", "-sV",
                "-p", ports_str,
                "-oN", output_file,
                ip
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        while True:
            line = proc.stdout.readline()

            if not line:
                if proc.poll() is not None:
                    break
                continue

            # Captura de progreso real
            match = PERCENT_RE.search(line)
            if match:
                progress_ref["percent"] = float(match.group(1))

    finally:
        stop_event.set()
        loader.join()

    # Validación fuerte
    if not os.path.exists(output_file):
        raise RuntimeError("Targeted Nmap output file was not created")

    print(GREEN + "[+] Targeted scan complete\n" + RESET)

    # Mostrar salida limpia
    with open(output_file, "r") as f:
        for line in f:
            line = line.rstrip()

            if not line:
                continue
            if line.startswith("#"):
                continue
            if line.startswith("Nmap scan report for"):
                continue
            if line.startswith("Host is up"):
                continue
            if line.startswith("Not shown:"):
                continue
            if line.startswith("service"):
                continue        
            print(line)

    return output_file



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
import re

def print_clean_vuln_summary(filename):
    cves = set()
    exploit_count = 0
    in_vulners = False

    with open(filename, "r") as f:
        for line in f:
            line = line.rstrip()

            # Detectar inicio de vulners
            if "| vulners:" in line:
                in_vulners = True
                continue

            if in_vulners:
                # Fin del bloque vulners
                if not line.startswith("|"):
                    in_vulners = False
                    continue

                # Capturar CVEs
                cve_match = re.search(r"(CVE-\d{4}-\d+)", line)
                if cve_match:
                    cves.add(cve_match.group(1))

                # Contar exploits públicos
                if "*EXPLOIT*" in line:
                    exploit_count += 1

    # ============================
    #  SALIDA LIMPIA
    # ============================
    if cves:
        print(f"{YELLOW}[!] Vulnerabilities detected:{RESET}")
        for cve in sorted(cves):
            print(f"    └─ {cve}")

        if exploit_count:
            print(f"    └─ {exploit_count} public exploits available")

        print(f"\n{GREEN}[→] Full vulnerability details saved to:{RESET}")
        print(f"    {filename}")

    else:
        print(f"{GREEN}[+] No known vulnerabilities detected by Nmap scripts{RESET}")
        print(f"{CYAN}[→] Full scan output saved to:{RESET}")
        print(f"    {filename}")


def run_vulnerability_scan(ip, open_ports):
    searchsploit_available = check_searchsploit()
    WEB_PORTS = ["80", "443", "8080", "8000", "8443"]

    for port in open_ports:
        print(MAGENTA + f"\n======= VULNERABILITY ANALYSIS PORT {port} =======" + RESET)

        output_file = os.path.join(OUTPUT_DIR, f"vuln_{port}.txt")

        # -----------------------------
        # Selección de scripts
        # -----------------------------
        if port == "22":
            scripts = "vulners"
            script_args = "--script-args=mincvss=9.9"
            print(WHITE + f"[→] Running full vuln scan on {CYAN}{ip}:{port}" + RESET)

        elif port in WEB_PORTS:
            scripts = (
                "http-title,http-server-header,http-methods,"
                "http-enum,http-csrf,http-headers"
            )
            script_args = ""
            print(WHITE + "[→] Using lightweight HTTP scripts" + RESET)

        else:
            scripts = "vuln"
            script_args = "--script-args=mincvss=9.9"
            print(WHITE + f"[→] Running full vuln scan on {CYAN}{ip}{WHITE} (port:{port})" + RESET)

        # -----------------------------
        # Barra de progreso
        # -----------------------------
        stop_event = threading.Event()
        progress_ref = {"percent": None}

        loader = threading.Thread(
            target=barra_carga,
            args=(f"VULN:{port}", stop_event, progress_ref),
            daemon=True
        )
        loader.start()

        try:
            cmd = [
                "nmap", "-Pn", "-sV", "-p", port,
                f"--script={scripts}",
                "--script-timeout=20s"
            ]

            if script_args:
                cmd.append(script_args)

            cmd += ["-oN", output_file, ip]

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            while True:
                line = proc.stdout.readline()

                if not line:
                    if proc.poll() is not None:
                        break
                    continue

                # Progreso real si aparece
                match = PERCENT_RE.search(line)
                if match:
                    progress_ref["percent"] = float(match.group(1))

        finally:
            stop_event.set()
            loader.join()

        # -----------------------------
        # Validación fuerte
        # -----------------------------
        if not os.path.exists(output_file):
            print(RED + f"[-] Vuln scan failed on port {port}" + RESET)
            continue


        # -----------------------------
        # Mostrar salida limpia
        # -----------------------------
        print_clean_vuln_summary(output_file)

        # ============================
        #   2️⃣   BANNER & SEARCHSPLOIT
        # ============================

        banner = extract_banner_from_targeted(port)

        if banner:
            print(f"\n{CYAN}[→] Detected service:{RESET} {WHITE}{banner}{RESET}")

            if searchsploit_available:
                exploits = search_exploits(banner)

                if exploits:
                    print(RED + "[+] Exploits encontrados en searchsploit:" + RESET , "\n" )
                    for e in exploits:
                        title = e.get("Title", "Unknown")
                        path = e.get("Path", "")
                        print(f"   - {RED}{title}{RESET} {DARK_GRAY}({path}){RESET}")
                else:
                    print(YELLOW + "[!] No exploits found." + RESET, "\n")

        # ============================
        #   3️⃣   MODULOS DE ENUMERACION
        # ============================

        if port in MODULE_MAP:

            # SMB necesita lista de puertos
            if port == "445":
                module = MODULE_MAP[port](ip, [int(port)], OUTPUT_DIR)
            else:
                module = MODULE_MAP[port](ip, port, OUTPUT_DIR)


            # correr scripts si el módulo los define
            if module["scripts"]:
                run_nmap_scripts(ip, port, module["scripts"], module["name"])






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

    parser.add_argument(
        "--mode",
        choices=["fast", "medium", "deep"],
        default="deep"
    )

    args = parser.parse_args()
    prepare_output_dir() 

    ascii_art()
    validate_ip(args.ip)
    print_signature()
    check_nmap()

    # ====== OS DETECTION AL PRINCIPIO ======
    if not osdetec.check_host_alive(args.ip):
        sys.exit(1)
        
    print(MAGENTA + "═════════════════ OS DETECTION ═════════════════" + RESET)
    print(LIGHT_GRAY + "[→] Detecting OS on " + CYAN + args.ip + "\n" + RESET)
    os_info = osdetec.detect_os(args.ip)
    osdetec.print_os_detection(args.ip, os_info)

    all_ports_file = run_scan(args.ip)
    open_ports = parse_open_ports(all_ports_file)

    if args.mode in ("medium", "deep"):
        run_targeted_scan(args.ip, open_ports)

    if args.mode == "deep":
        run_vulnerability_scan(args.ip, open_ports)

    print(CYAN + "\n[-] dogs are coming home. 🐶" + RESET)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + RED + "[!] Scan cancelled by user." + RESET)
        print(CYAN + "[-] dogs are coming home. 🐶" + RESET)
        sys.exit(0)


