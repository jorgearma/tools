import os
import subprocess
import threading

from modules.barradecarga import barra_carga

RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
WHITE = "\033[97m"
MAGENTA = "\033[95m"
DARK_GRAY = "\033[90m"
LIGHT_GRAY = "\033[37m"
YELLOW = "\033[93m"


def enumerate_ftp(ip, port, base_output_dir):

    ftp_output_dir = os.path.join(base_output_dir, "ftp")
    os.makedirs(ftp_output_dir, mode=0o700, exist_ok=True)

    output_file = os.path.join(ftp_output_dir, f"ftp_enum_{port}.txt")


    scripts = [
        "ftp-anon",
        "ftp-syst",
        "ftp-brute",
        "ftp-libopie",
        "ftp-vuln-cve2010-4221",
        "ftp-proftpd-backdoor",
        "ftp-vsftpd-backdoor"
    ]

    scripts_str = ",".join(scripts)

    print(MAGENTA + "\n====== FTP ENUMERATION ANALYSIS ======" + RESET)
    print(f"{WHITE}[→] Running FTP enumeration on port {port}...{RESET}")

    # ── PROGRESS BAR (IGUAL QUE SSH) ─────────────────────────
    stop_event = threading.Event()
    progress_ref = {"percent": None}

    loader = threading.Thread(
        target=barra_carga,
        args=("FTP", stop_event, progress_ref),
        daemon=True
    )
    loader.start()

    try:
        proc = subprocess.Popen(
            [
                "nmap", "-Pn",
                "-p", str(port),
                f"--script={scripts_str}",
                "--script-timeout=40s",
                "-oN", output_file,
                ip
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        # 🔒 MISMO COMPORTAMIENTO QUE SSH
        for _ in proc.stdout:
            pass

        proc.wait()

    finally:
        stop_event.set()
        loader.join()

    print(f"{GREEN}[+] FTP scripts completed.{RESET}")

    # ── INTELLIGENT ANALYSIS (POST-SCAN) ─────────────────────
    valid_creds = test_default_ftp_credentials(ip, port)
    try_ftp_download(ip, port, valid_creds, ftp_output_dir)


    detect_ftps(ip, port)
    analyze_ftp_output(output_file)

    print(f"{GREEN}[+] FTP enumeration saved → {output_file}{RESET}")

    return {
        "name": "FTP Enumeration",
        "scripts": []
    }





def analyze_ftp_output(filepath):

    anon_enabled = False
    proftpd_backdoor = False
    vsftpd_backdoor = False
    cve_2010_4221 = False
    brute_success = False

    with open(filepath, "r") as f:
        for line in f:

            # Anonymous Login
            if "Anonymous FTP login allowed" in line or "Anonymous FTP login permitted" in line:
                anon_enabled = True

            # VSFTPD 2.3.4 Backdoor
            if "vsftpd-backdoor" in line and "VULNERABLE" in line:
                vsftpd_backdoor = True

            # ProFTPD Backdoor
            if "proftpd-backdoor" in line and "VULNERABLE" in line:
                proftpd_backdoor = True

            # CVE-2010-4221
            if "CVE-2010-4221" in line and "VULNERABLE" in line:
                cve_2010_4221 = True

            # Brute-force success
            if "login: " in line and "password:" in line:
                brute_success = True

    # ============================
    #  RESULTADOS INTELIGENTES
    # ============================


    if anon_enabled:
        print(f"{RED}[+] Anonymous login ENABLED → HIGH RISK{RESET}")
    else:
        print(f"{DARK_GRAY}[-] Anonymous login disabled{RESET}")

    if brute_success:
        print(f"{RED}[+] Valid credentials found via brute force!{RESET}")

    if vsftpd_backdoor:
        print(f"{RED}[!!!] VSFTPD 2.3.4 BACKDOOR DETECTED → FULL SHELL POSSIBLE{RESET}")

    if proftpd_backdoor:
        print(f"{RED}[!!!] PROFTPD BACKDOOR DETECTED → REMOTE ROOT{RESET}")

    if cve_2010_4221:
        print(f"{RED}[!!!] Vulnerable to CVE-2010-4221 (ProFTPD) → Remote Command Execution{RESET}")

    if not (anon_enabled or brute_success or vsftpd_backdoor or proftpd_backdoor or cve_2010_4221):
        print(f"{LIGHT_GRAY}[*] No critical FTP vulnerabilities detected.{RESET}")


DEFAULT_CREDS = [
    ("anonymous", "anonymous"),
    ("ftp", "ftp"),
    ("admin", "admin"),
    ("root", "root"),
    ("test", "test"),
    ("user", "user"),
    ("guest", "guest"),
    ("administrator", "administrator"),
]


def test_default_ftp_credentials(ip, port):
    print(f"{WHITE}[→] Testing common FTP credentials on", CYAN + f"{ip}:{port}...{RESET}")

    valid_credentials = []

    for user, passwd in DEFAULT_CREDS:
        cmd = (
            f"printf 'user {user} {passwd}\nquit\n' | ftp -inv {ip} {port} 2>/dev/null"
        )

        result = subprocess.run(
            ["bash", "-c", cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        out = result.stdout.lower()

        # Indicadores típicos de login válido
        if (
            "230 login successful" in out
            or "logged in" in out
            or "successful" in out
        ):
            print(f"{RED}[+] VALID FTP CREDENTIALS FOUND → {user}:{passwd}{RESET}")
            valid_credentials.append((user, passwd))

        # Detección sutil (OSCP machines a veces ocultan mensajes)
        elif "230" in out:
            print(f"{RED}[+] POSSIBLE VALID FTP CREDENTIALS → {user}:{passwd}{RESET}")
            valid_credentials.append((user, passwd))

    if not valid_credentials:
        print(f"{DARK_GRAY}[-] No default credentials worked.{RESET}")

    return valid_credentials








def try_ftp_download(ip, port, creds, ftp_output_dir):
    """
    creds = lista de tuplas [(user, pass), ...]
    output_dir = carpeta donde se guardarán los archivos extraídos
    """
    download_dir = os.path.join(ftp_output_dir, "downloads")
    os.makedirs(download_dir, mode=0o700, exist_ok=True)

    if not creds:
        print(f"{DARK_GRAY}[-] No credentials available for file download.{RESET}")
        return

    if not os.path.exists(download_dir):
        os.makedirs(download_dir)

    print(f"\n{CYAN}[→] Checking if files can be listed / downloaded...{RESET}\n")

    for user, passwd in creds:

        print(f"{MAGENTA} ── Credentials: {WHITE}{user}:{passwd}{RESET}")

        # 1) LISTAR ARCHIVOS
        cmd_list = (
            f"printf 'user {user} {passwd}\nls -la\nquit\n' | ftp -inv {ip} {port}"
        )

        result = subprocess.run(
            ["bash", "-c", cmd_list],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        out = result.stdout.lower()

        # 2) ¿Se pudo listar?
        if "226" in out or "drwx" in out or "-rw" in out:
            print(f"     {GREEN}[+] Listing enabled → Files are visible.{RESET}")

            # Guardar el listing
            listing_file = os.path.join(download_dir, f"{ip}_{port}_listing.txt")
            with open(listing_file, "w") as f:
                f.write(result.stdout)

            print(f"     {GREEN}[+] Directory listing saved → {DARK_GRAY}{listing_file}{RESET}")

            # 3) Intento de descarga RECURSIVA (mirror completo)
            print(f"     {CYAN}[→] Starting recursive download...{RESET}")
            
            wget_cmd = (
                f"wget -m --no-passive ftp://{user}:{passwd}@{ip}:{port} "
                f"-P {download_dir} 2>/dev/null"
            )

            subprocess.run(["bash", "-c", wget_cmd])

            print(f"     {GREEN}[+] Download completed →{DARK_GRAY}{download_dir}{RESET}\n")

        else:
            print(f"     {RED}[-] Listing blocked for {user}:{passwd}{RESET}\n")




def detect_ftps(ip, port):
    cmd = f"echo '' | openssl s_client -connect {ip}:{port} -starttls ftp 2>/dev/null"
    result = subprocess.run(["bash", "-c", cmd], stdout=subprocess.PIPE, text=True)

    if "Certificate" in result.stdout:
        print(f"{YELLOW}[!] FTPS detected (TLS enabled){RESET}")
    else:
        print(f"{DARK_GRAY}[-] No FTPS detected{RESET}")
