import os
import subprocess

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
# Esto asume que tienes un archivo colors.py con tus colores.
# Si no, puedo generarlo.



def enumerate_ftp(ip, port):
    module_name = "FTP Enumeration"
    output_file = os.path.join(OUTPUT_DIR, f"ftp_enum_{port}.txt")

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

    print(MAGENTA + "\n====== FTP ENUMERATION ANALYSIS ====== \n" + RESET)
    print(f"{CYAN}[→] Running {module_name} on port {port}...{RESET}")

    # Ejecutar nmap + scripts
    try:
        subprocess.run(
            [
                "nmap", "-Pn",
                "-p", port,
                f"--script={scripts_str}",
                "--script-timeout=40s",
                "-oN", output_file,
                ip
            ],
            check=True
        )

    except subprocess.CalledProcessError as e:
        print(f"{RED}[-] FTP enumeration failed: {e}{RESET}")
        return

    # ============================
    #  ANALISIS INTELIGENTE
    # ============================
    valid_creds = test_default_ftp_credentials(ip, port)
    try_ftp_download(ip, port, valid_creds)

    detect_ftps(ip,port)



    analyze_ftp_output(output_file)
    print(f"{GREEN}[+] FTP enumeration saved → {output_file}{RESET}")


    # 🔙 DEVOLVER UN DICCIONARIO PARA QUE EL CORE NO ROMPA
    return {
        "name": "FTP Enumeration",
        "scripts": []  # vacío porque ya ejecutamos los scripts en el módulo
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








def try_ftp_download(ip, port, creds, output_dir="ftp_download"):
    """
    creds = lista de tuplas [(user, pass), ...]
    output_dir = carpeta donde se guardarán los archivos extraídos
    """

    if not creds:
        print(f"{DARK_GRAY}[-] No credentials available for file download.{RESET}")
        return

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

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
            listing_file = os.path.join(output_dir, f"{ip}_{port}_listing.txt")
            with open(listing_file, "w") as f:
                f.write(result.stdout)

            print(f"     {GREEN}[+] Directory listing saved → {listing_file}{RESET}")

            # 3) Intento de descarga RECURSIVA (mirror completo)
            print(f"     {CYAN}[→] Starting recursive download...{RESET}")
            
            wget_cmd = (
                f"wget -m --no-passive ftp://{user}:{passwd}@{ip}:{port} "
                f"-P {output_dir} 2>/dev/null"
            )

            subprocess.run(["bash", "-c", wget_cmd])

            print(f"     {GREEN}[+] Download completed → {output_dir}{RESET}\n")

        else:
            print(f"     {RED}[-] Listing blocked for {user}:{passwd}{RESET}\n")




def detect_ftps(ip, port):
    cmd = f"echo '' | openssl s_client -connect {ip}:{port} -starttls ftp 2>/dev/null"
    result = subprocess.run(["bash", "-c", cmd], stdout=subprocess.PIPE, text=True)

    if "Certificate" in result.stdout:
        print(f"{YELLOW}[!] FTPS detected (TLS enabled){RESET}")
    else:
        print(f"{DARK_GRAY}[-] No FTPS detected{RESET}")
