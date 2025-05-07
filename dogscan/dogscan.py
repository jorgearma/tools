import os
import time
import shutil
import sys
import threading
import subprocess

# Definimos colores ANSI
RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
WHITE = "\033[97m"
MAGENTA = "\033[95m"
DARK_GRAY = "\033[90m"
LIGHT_GRAY = "\033[37m"

def print_signature():
    print(DARK_GRAY + "═" * 65 + RESET)
    print(LIGHT_GRAY + "[*] version: " + CYAN + "dogscan 1.0.1" + RESET)
    print(LIGHT_GRAY + "[*] Developer: " + CYAN + "siemprearmando" + RESET)
    print(LIGHT_GRAY + "[*] GitHub: " + CYAN + "https://github.com/siemprearmando" + RESET)
    print(DARK_GRAY + "═" * 65 + RESET)

def spinner_task(stop_event, message):
    spinner = ["|", "/", "-", "\\"]
    i = 0
    while not stop_event.is_set():
        print(f"\r{LIGHT_GRAY}[*] {message}... {spinner[i % len(spinner)]}{RESET}", end="", flush=True)
        time.sleep(0.2)
        i += 1
    print("\r" + " " * (len(message) + 10), end="\r")  # Limpia línea

def ascii_art():
    print(GREEN + r"""
        |`-.__  
        /   _/
       ****`  ________                                        
      /    } ____ __  \____________ ___________________ _______ 
     /  \ /____  / / /_  __ \_  __ `/_  ___/  ___/  __ `/_  __ \  
 \ /`   \\\   / /_/ / / /_/ /  /_/ /_(__  )/ /__ / /_/ /_  / / /
  `\    /_\\ \_____/  \____/_\__, / /____/ \___/ \__,_/ /_/ /_/ 
   `~~~~~``~`               /____/                           """ + RESET)
   

def check_nmap():
    spinner = ["|", "/", "-", "\\"]
    message = LIGHT_GRAY + "[*] Checking if nmap is installed... " + RESET

    print(message, end="", flush=True)

    nmap_installed = shutil.which("nmap")  # Hace la comprobación inmediatamente

    # Ahora mueve el spinner al final de la línea
    start_time = time.time()
    i = 0
    while time.time() - start_time < 2:
        print(f"\r{message}{spinner[i % len(spinner)]}", end="", flush=True)
        time.sleep(0.1)
        i += 1

    # Después de girar, limpia spinner y muestra resultado limpio
    print("\r" + " " * (len(message) + 2), end="\r")  # Borra línea

    if nmap_installed:
        print(GREEN + "[+] Nmap is installed!" + RESET)
    else:
        print(RED + "[-] Nmap is not installed!" + RESET)
        choice = input(CYAN + "[?] Do you want to install nmap? (y/n): " + RESET).strip().lower()
        if choice == 'y':
            print(LIGHT_GRAY + "[*] Installing nmap..." + RESET)
            time.sleep(1)
            os.system("sudo apt update && sudo apt install -y nmap")
            print(GREEN + "[+] Nmap installation complete!" + RESET)
        else:
            print(RED + "[-] Nmap will not be installed. Exiting..." + RESET)
            exit(1)

def run_scan(ip):
    print(LIGHT_GRAY + f"[*] Running scan on {ip}..." + RESET)

    # Prepara el spinner
    stop_spinner = threading.Event()
    spinner_thread = threading.Thread(target=spinner_task, args=(stop_spinner, "Running full port scan"))

    # Lanza el spinner
    spinner_thread.start()

    # Ejecuta nmap
    command = f"nmap -Pn -p- -T4 --min-rate=1000 -oN all_ports.txt {ip}"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process.wait()

    # Detiene el spinner y espera a que termine el hilo
    stop_spinner.set()
    spinner_thread.join()

    print(GREEN + "[+] Scan complete. Output saved to all_ports.txt" + RESET)

def parse_open_ports():
    try:
        with open("all_ports.txt", "r") as file:
            lines = file.readlines()
            print(CYAN + "[*] Open ports found:" + RESET)
            for line in lines:
                if "/tcp" in line and "open" in line:
                    print(GREEN + "    " + line.strip() + RESET)
    except FileNotFoundError:
        print(RED + "[-] all_ports.txt not found. Did the scan run correctly?" + RESET)

def main():
    if len(sys.argv) != 2:
        print(RED + "Usage: python3 dogscan.py <IP_ADDRESS>" + RESET)
        sys.exit(1)

    ip = sys.argv[1]
    ascii_art()
    print_signature()
    check_nmap()
    run_scan(ip)
    parse_open_ports()

    # Leer el archivo all_ports.txt para obtener los puertos abiertos
    open_ports = []
    with open("all_ports.txt", "r") as file:
        for line in file:
            if "/tcp" in line and "open" in line:
                port = line.split("/")[0].strip()
                open_ports.append(port)

    if open_ports:
        ports_str = ",".join(open_ports)
        print(LIGHT_GRAY + f"[*] Running targeted scan on ports: {ports_str}..." + RESET)
        command = f"sudo nmap -sC -sV -p {ports_str} -oN targeted.txt {ip}"
        os.system(command)
        print(GREEN + "[+] Targeted scan complete. Output saved to targeted.txt" + RESET)
    else:
        print(RED + "[-] No open ports found in the initial scan." + RESET)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + RED + "[!] Scan cancelled by user." + RESET)
        print(CYAN + "[-] dogs are coming home. 🐶" + RESET)
        sys.exit(0)
