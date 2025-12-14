import subprocess
import os
import re

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

    # --------------------------
    # PREPARACIÓN
    # --------------------------
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    out_file = os.path.join(OUTPUT_DIR, f"ssh_enum_{ip}.txt")

    print(MAGENTA + "====== SSH ENUMERATION ======\n" + RESET)
    print(f"{WHITE}[→] Target: {ip}:{port}{RESET}")

    with open(out_file, "w") as f:
        f.write(f"==== SSH ENUMERATION FOR {ip}:{port} ====\n\n")

    
    # --------------------------
    # 1) Nmap SSH scripts
    # --------------------------
    print(f"{CYAN}[→] Running SSH script scan (algos, auth, hostkeys)...{RESET}")

    nmap_cmd = [
        "nmap", "-Pn", "-sV",
        "-p", port,
        "--script=ssh2-enum-algos,ssh-hostkey,ssh-auth-methods",
        "-oN", out_file,
        ip
    ]

    subprocess.run(nmap_cmd)
    print(f"{GREEN}[+] SSH enumeration saved → {out_file}{RESET}")


    # --------------------------
    # 2) Unauthenticated login test (PRIMERO SIEMPRE)
    # --------------------------
    login_info = test_unauthenticated_login(ip, port, out_file)


    # --------------------------
    # 3) Decision: ¿vale la pena enumerar usuarios?
    # --------------------------
    # --------------------------
# 3) Decision: ejecutar siempre la enumeración
# --------------------------
    can_enum = (
        login_info["publickey_enabled"] or
        login_info["keyboard_interactive_enabled"] or
        login_info["info_leak"]
    )

    if can_enum:
        print(f"{YELLOW}[→] Server behavior suggests username enumeration MAY BE POSSIBLE.{RESET}")
    else:
        print(f"{YELLOW}[→] Forcing username enumeration even without authentication leaks.{RESET}")

    test_username_enumeration(ip, port, out_file)


    return {
        "name": "SSH Enumeration",
        "scripts": []
    }




# -----------------------------------------------------------
# USERNAME ENUMERATION
# -----------------------------------------------------------
# -----------------------------------------------------------
# USERNAME ENUMERATION
# -----------------------------------------------------------
import time
import random
import subprocess
import re

import subprocess
import time
import random

# Colores (ajusta si usas otros)
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"
DARK_GRAY = "\033[90m"
RESET = "\033[0m"


def test_username_enumeration(ip, port, out_file):
    print(f"\n{CYAN}[→] Checking possible SSH username enumeration...{RESET}\n")

    usernames = [
        "root", "admin", "test", "www-data", "ubuntu"
        , "nobody"
    ]

    findings = []

    # -----------------------------------------------------
    # UTILITY 1: capture stderr response from SSH
    # -----------------------------------------------------
    def get_ssh_response(user):
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

        stderr = result.stderr.lower().strip()

        noise_patterns = [
            "warning", "permanently added",
            "known hosts", "connection closed",
            "connection reset"
        ]
        for n in noise_patterns:
            stderr = stderr.replace(n, "")

        return stderr.strip()

    # -----------------------------------------------------
    # UTILITY 2: measure median SSH timing
    # -----------------------------------------------------
    def measure_ssh_timing(user, attempts=5):
        times = []
        for _ in range(attempts):
            start = time.time()
            subprocess.run(
                [
                    "ssh", f"-p{port}", f"{user}@{ip}",
                    "-oBatchMode=yes",
                    "-oStrictHostKeyChecking=no",
                    "-oPasswordAuthentication=no",
                    "-oConnectTimeout=3"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            elapsed = time.time() - start

            # descartar jitter extremo (HTB, THM)
            if elapsed < 1.0:
                times.append(elapsed)

            time.sleep(random.uniform(0.25, 0.55))

        if not times:
            return None

        times.sort()
        return times[len(times) // 2]

    # -----------------------------------------------------
    # BASELINE TIMING
    # -----------------------------------------------------
    print(f"{CYAN}[→] Establishing timing baseline...{RESET}")
    baseline = measure_ssh_timing("thisuserdoesnotexist123456")

    if baseline is None:
        baseline = 0.30

    print(f"{DARK_GRAY}Baseline SSH response time (median): {baseline:.3f}s{RESET}\n")

    # -----------------------------------------------------
    # ENUMERATION LOOP
    # -----------------------------------------------------
    for user in usernames:

        print(f"{MAGENTA} ── Testing user: {WHITE}{user}{RESET}")

        # ---------------------------
        # STEP 1: Nmap method
        # ---------------------------
        cmd = [
            "nmap", "-p", port,
            "--script", "ssh-user-enum",
            "--script-args", f"user={user}",
            ip
        ]

        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out = result.stdout.lower()

        if "valid" in out:
            msg = f"{RED}     [!] VALID USERNAME (Nmap){RESET}"
            print(msg)
            findings.append(msg)
            continue
        elif "invalid" in out:
            msg = f"{DARK_GRAY}     [-] Invalid (Nmap){RESET}"
            print(msg)
            findings.append(msg)
            continue

        print(f"{YELLOW}     [?] Nmap inconclusive → response analysis...{RESET}")

        # ---------------------------
        # STEP 2: Response-based analysis
        # ---------------------------
        stderr_output = get_ssh_response(user)

        keywords_valid = [
            "permission denied",                  # user válido, auth fallida
            "publickey",                          # aparece solo si user existe
            "keyboard-interactive"                # algunos SSH solo lo exponen a users válidos
        ]

        keywords_invalid = [
            "invalid user",                       # metasploitable2 clásico
            "unknown user",
            "no such user",
            "user does not exist"
        ]

        # Evaluación basada en contenido
        if any(k in stderr_output for k in keywords_invalid):
            msg = f"{DARK_GRAY}     [-] Invalid (response-based){RESET}"
            print(msg)
            findings.append(msg)
            continue

        if any(k in stderr_output for k in keywords_valid):
            msg = f"{RED}     [!] VALID USERNAME (response-based){RESET}"
            print(msg)
            findings.append(msg)
            continue

        print(f"{YELLOW}     [?] Response inconclusive → timing analysis...{RESET}")

        # ---------------------------
        # STEP 3: Timing analysis
        # ---------------------------
        user_median = measure_ssh_timing(user)

        if user_median is None:
            msg = f"{YELLOW}     [?] No timing obtained{RESET}"
            print(msg)
            findings.append(msg)
            continue

        diff = user_median - baseline

        if diff > 0.12:
            msg = f"{RED}     [!] VALID USERNAME (Timing Δ+{diff:.3f}s){RESET}"
        else:
            msg = f"{DARK_GRAY}     [-] Invalid ({user_median:.3f}s){RESET}"

        print(msg)
        findings.append(msg)
        time.sleep(random.uniform(0.30, 0.90))

    # -----------------------------------------------------
    # OUTPUT FILE
    # -----------------------------------------------------
    with open(out_file, "a") as f:
        f.write("\nSSH Username Enumeration Results:\n")
        for item in findings:
            f.write(item + "\n")

    print(f"\n{GREEN}[✔] SSH enumeration completed.{RESET}\n")





# -----------------------------------------------------------
# UNAUTHENTICATED LOGIN BEHAVIOR
# -----------------------------------------------------------
def test_unauthenticated_login(ip, port, out_file):

    print(f"{CYAN}[→] Testing unauthenticated login behavior...{RESET}\n")

    cmd = (
        f"ssh "
        f"-o BatchMode=yes "
        f"-o StrictHostKeyChecking=no "
        f"-o UserKnownHostsFile=/dev/null "
        f"-o PreferredAuthentications=none "
        f"-o PubkeyAuthentication=no "
        f"-o RequestTTY=no "
        f"-o LogLevel=ERROR "
        f"-o ConnectTimeout=3 "
        f"-o ConnectionAttempts=1 "
        f"-p {port} {ip}"
    )

    try:
        result = subprocess.run(
            ["bash", "-c", cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=4
        )

        output = (result.stdout + result.stderr).lower()

    except subprocess.TimeoutExpired:
        print(f"{RED}     [!] SSH server did NOT respond within timeout.{RESET}")
        print(f"{DARK_GRAY}         → Possible firewall, tarpitting, rate-limit or slow host.{RESET}")

        # Guardar en archivo
        with open(out_file, "a") as f:
            f.write("=== UNAUTHENTICATED LOGIN TEST ===\n")
            f.write("SSH server did NOT respond (timeout).\n")
            f.write("Possible firewall, tarpitting, or sshd config issue.\n\n")

        return {
            "publickey_enabled": False,
            "keyboard_interactive_enabled": False,
            "info_leak": False,
            "timeout": True
        }

    except Exception as e:
        print(f"{RED}     [!] Unexpected SSH error: {e}{RESET}")

        with open(out_file, "a") as f:
            f.write("=== UNAUTHENTICATED LOGIN TEST ===\n")
            f.write(f"Unexpected error: {str(e)}\n\n")

        return {
            "publickey_enabled": False,
            "keyboard_interactive_enabled": False,
            "info_leak": False,
            "timeout": False
        }

    # --------- ANÁLISIS NORMAL SI NO HAY ERRORES ----------
    issues = []
    info = {
        "publickey_enabled": False,
        "keyboard_interactive_enabled": False,
        "info_leak": False,
        "timeout": False
    }

    print(f"{MAGENTA} ── Server Response:{RESET}")

    if "permission denied" in output:
        issues.append(f"{GREEN}     [+] Standard 'Permission denied' → OK{RESET}")

    if "no supported methods remain" in output:
        info["info_leak"] = True
        issues.append(f"{YELLOW}     [!] Server reveals available auth methods → INFO LEAK{RESET}")

    if "publickey" in output:
        info["publickey_enabled"] = True
        issues.append(f"{RED}     [!] PublicKey enabled → username enumeration possible{RESET}")

    if "keyboard-interactive" in output:
        info["keyboard_interactive_enabled"] = True
        issues.append(f"{RED}     [!] Keyboard-interactive enabled → BRUTEFORCE vector{RESET}")

    if not issues:
        issues.append(f"{DARK_GRAY}     [-] No relevant info leak detected.{RESET}")

    # imprimir
    for i in issues:
        print(i)

    print(f"\n{GREEN}[+] Unauthenticated login test completed.{RESET}\n")

    # guardar limpio
    with open(out_file, "a") as f:
        f.write("=== UNAUTHENTICATED LOGIN TEST ===\n")
        for i in issues:
            clean = re.sub(r"\x1b\[[0-9;]*m", "", i)
            f.write(clean + "\n")
        f.write("\n")

    return info

