import subprocess
import os
import re
import time
import random
import threading

from modules.barradecarga import barra_carga

# ─── ANSI COLORS ─────────────────────────────────────────────
RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
WHITE = "\033[97m"
MAGENTA = "\033[95m"
DARK_GRAY = "\033[90m"
YELLOW = "\033[93m"
LIGHT_GRAY = "\033[37m"


# ─────────────────────────────────────────────────────────────
# MAIN SSH ENUMERATION
# ─────────────────────────────────────────────────────────────
def enumerate_ssh(ip, port="22", base_output_dir="nmap_output"):


    ssh_output_dir = os.path.join(base_output_dir, "ssh")
    os.makedirs(ssh_output_dir, mode=0o700, exist_ok=True)

    out_file = os.path.join(ssh_output_dir, f"ssh_enum_{ip}.txt")


    print(MAGENTA + "============  SSH ENUMERATION =============" + RESET)
    with open(out_file, "w") as f:
        f.write(f"==== SSH ENUMERATION FOR {ip}:{port} ====\n\n")


    # ── SSH SCRIPT SCAN WITH PROGRESS BAR ────────────────────
    print(f"{WHITE}[→] Running SSH script scan on {CYAN}{ip}{WHITE} (port:{port}) {RESET}")

    stop_event = threading.Event()
    progress_ref = {"percent": None}

    loader = threading.Thread(
        target=barra_carga,
        args=("SSH", stop_event, progress_ref),
        daemon=True
    )
    loader.start()

    try:
        proc = subprocess.Popen(
            [
                "nmap", "-Pn", "-sV", "-p", str(port),
                "--script=ssh2-enum-algos,ssh-hostkey,ssh-auth-methods",
                "-oN", out_file,
                ip
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        # Consumir stdout para evitar bloqueos
        for _ in proc.stdout:
            pass

        proc.wait()

    finally:
        stop_event.set()
        loader.join()

    print(f"{GREEN}[+] SSH scripts completed.{RESET}")

        # ── SSH AUTH METHODS (IMPORTANT) ─────────────────────────
    auth_methods = parse_ssh_auth_methods(out_file)

    if auth_methods:
        print(MAGENTA + "\n============ SSH AUTHENTICATION ============" + RESET)
        print(f"{GREEN}[✓] Supported authentication methods:{RESET}")

        for m in auth_methods:
            print(f"{CYAN}    - {m}{RESET}")

        if "password" in auth_methods:
            print(f"{YELLOW}[→] Password-based authentication is ENABLED{RESET}")

        if "publickey" in auth_methods:
            print(f"{YELLOW}[→] Public key authentication is ENABLED{RESET}")


    # ── UNAUTHENTICATED LOGIN TEST ───────────────────────────
    unauth_info = test_unauthenticated_login(ip, port, out_file)

    if not unauth_info["info_leak"]:
        print(f"{DARK_GRAY}[!] No auth leak → enumeration unlikely{RESET}")

    # ── USER ENUMERATION ─────────────────────────────────────
    test_username_enumeration(ip, port, out_file)

    return {
        "name": "SSH Enumeration",
        "scripts": []
    }


# ─────────────────────────────────────────────────────────────
# UNAUTHENTICATED LOGIN BEHAVIOR
# ─────────────────────────────────────────────────────────────
def test_unauthenticated_login(ip, port, out_file):

    print(f"{CYAN}[→] Testing unauthenticated login behavior...{RESET}\n")

    cmd = (
        f"ssh -o BatchMode=yes "
        f"-o StrictHostKeyChecking=no "
        f"-o PreferredAuthentications=none "
        f"-o PubkeyAuthentication=no "
        f"-o ConnectTimeout=3 "
        f"-p {port} {ip}"
    )

    result = subprocess.run(
        ["bash", "-c", cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    output = (result.stdout + result.stderr).lower()

    info = {"info_leak": False}

    print(f"{MAGENTA} ── Server Response:{RESET}")

    if "no supported methods remain" in output:
        info["info_leak"] = True
        print(f"{YELLOW}     [!] Server reveals auth methods (INFO LEAK){RESET}")
    else:
        print(f"{DARK_GRAY}     [-] No auth info leak detected{RESET}")

    with open(out_file, "a") as f:
        f.write("\n=== UNAUTHENTICATED LOGIN TEST ===\n")
        f.write(output + "\n")

    print(f"\n{GREEN}[+] Unauthenticated test completed.{RESET}\n")
    return info

# ─────────────────────────────────────────────────────────────
# USERNAME ENUMERATION (SAFE)
# ─────────────────────────────────────────────────────────────
def test_username_enumeration(ip, port, out_file):

    print(f"{CYAN}[→] Checking possible SSH username enumeration...{RESET}\n")

    usernames = ["root", "admin", "test", "www-data", "ubuntu", "nobody"]

    findings = []

    def get_response(user):
        result = subprocess.run(
            [
                "ssh", f"-p{port}", f"{user}@{ip}",
                "-oBatchMode=yes",
                "-oStrictHostKeyChecking=no",
                "-oPasswordAuthentication=no",
                "-oConnectTimeout=3"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stderr.lower()

    for user in usernames:

        print(f"{MAGENTA} ── Testing user: {WHITE}{user}{RESET}")

        stderr = get_response(user)

        if any(k in stderr for k in [
            "invalid user", "unknown user", "no such user"
        ]):
            msg = f"{DARK_GRAY}     [-] Invalid user{RESET}"
            print(msg)
            findings.append(msg)
        else:
            msg = f"{YELLOW}     [?] No conclusive evidence (likely patched SSH){RESET}"
            print(msg)
            findings.append(msg)

        time.sleep(random.uniform(0.4, 0.8))

    with open(out_file, "a") as f:
        f.write("\n=== SSH USER ENUMERATION RESULTS ===\n")
        for i in findings:
            f.write(re.sub(r"\x1b\[[0-9;]*m", "", i) + "\n")

    print(f"\n{GREEN}[✔] SSH enumeration completed and saved. → {LIGHT_GRAY} {out_file} {RESET}\n")




# ─────────────────────────────────────────────────────────────
# PARSE SSH AUTH METHODS (STRICT)
# ─────────────────────────────────────────────────────────────
def parse_ssh_auth_methods(nmap_file):

    valid_methods = {
        "publickey",
        "password",
        "keyboard-interactive",
        "gssapi-with-mic"
    }

    methods = []
    inside_auth_block = False

    try:
        with open(nmap_file, "r") as f:
            for line in f:

                # Entrar solo cuando empieza ssh-auth-methods
                if line.strip().startswith("| ssh-auth-methods"):
                    inside_auth_block = True
                    continue

                if inside_auth_block:

                    # Fin del bloque
                    if line.strip().startswith("|_"):
                        candidate = line.replace("|_", "").strip()
                        if candidate in valid_methods:
                            methods.append(candidate)
                        break

                    # Líneas normales del bloque
                    if line.strip().startswith("|"):
                        candidate = line.replace("|", "").strip()

                        # Ignorar encabezados
                        if "Supported authentication methods" in candidate:
                            continue

                        if candidate in valid_methods:
                            methods.append(candidate)

    except Exception:
        pass

    return methods
