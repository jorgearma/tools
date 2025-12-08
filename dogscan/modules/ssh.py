import subprocess
import os

RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
WHITE = "\033[97m"
MAGENTA = "\033[95m"
DARK_GRAY = "\033[90m"
LIGHT_GRAY = "\033[37m"
YELLOW = "\033[93m"

OUTPUT_DIR = "ssh_output"


def enumerate_ssh(ip, port="22"):
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    out_file = os.path.join(OUTPUT_DIR, f"ssh_enum_{ip}.txt")

    print(MAGENTA + "\n====== SSH ENUMERATION ======" + RESET)
    print(f"{CYAN}[→] Target: {ip}:{port}{RESET}")

    with open(out_file, "w") as f:
        f.write(f"SSH ENUMERATION FOR {ip}\n")

    # --------------------------
    # 1) Banner grabbing
    # --------------------------
    print(f"{CYAN}[→] Grabbing SSH banner...{RESET}")
    cmd = f"nc -nv {ip} {port} -w 3"
    banner = subprocess.run(["bash", "-c", cmd], stdout=subprocess.PIPE, text=True).stdout

    if banner.strip():
        print(f"{GREEN}[+] Banner: {banner.strip()}{RESET}")
    else:
        print(f"{DARK_GRAY}[-] No banner received.{RESET}")

    # --------------------------
    # 2) SSH version detection
    # --------------------------
    print(f"{CYAN}[→] Detecting SSH version with nmap...{RESET}")
    subprocess.run([
        "nmap", "-Pn", "-sV",
        "-p", port,
        "--script=ssh2-enum-algos,ssh-hostkey,ssh-auth-methods",
        "-oN", out_file,
        ip
    ])

    print(f"{GREEN}[+] SSH enumeration saved → {out_file}{RESET}")

    return {
        "name": "SSH Enumeration",
        "scripts": []  # vacío porque ya ejecutamos los scripts en el módulo
    }

