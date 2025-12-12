import os
import re
import subprocess

# Colores DogScan
RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
WHITE = "\033[97m"
MAGENTA = "\033[95m"
YELLOW = "\033[93m"
DARK_GRAY = "\033[90m"

OUTPUT_DIR = "smb_output"
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

def strip_colors(text: str) -> str:
    return ANSI_RE.sub("", text)


def enumerate_smb(ip: str, ports=None):
    if isinstance(ports, str):
        ports = [int(ports)]
    if ports is None:
        ports = [445]

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    out_file = os.path.join(OUTPUT_DIR, f"smb_enum_{ip}.txt")

    print(MAGENTA + "\n====== SMB ENUMERATION ======" + RESET)
    print(f"{WHITE}[→] Target: {ip} (ports: {', '.join(map(str, ports))}){RESET}")

    with open(out_file, "w") as f:
        f.write(f"==== SMB ENUMERATION FOR {ip} ====\n\n")

    # 1) FINGERPRINTING SMB
    banner_info = smb_fingerprint_nmap(ip, ports, out_file)

    # 2) ENUMERAR SHARES
    shares = smb_enum_shares(ip, out_file)

    # 3) ANALIZAR ACCESO
    smb_check_shares_access(ip, shares, out_file)

    # 4) ENUMERAR USUARIOS
    smb_enum_users(ip, out_file)

    # 5) DETECTAR POSIBLES CVEs
    smb_detect_possible_cves(banner_info, out_file)

    print(f"\n{GREEN}[✔] SMB enumeration completed → {out_file}{RESET}\n")

    return {
        "name": "...",
        "scripts": []
    }



# --------------------------------------------------------------------
# 1) SMB FINGERPRINTING (Nmap)
# --------------------------------------------------------------------
def smb_fingerprint_nmap(ip, ports, out_file):
    print(f"{CYAN}[→] Running SMB fingerprinting (Nmap)...{RESET}")

    port_args = ",".join(map(str, ports))

    scripts = [
        "smb-os-discovery",
        "smbv2-enabled",
        "smb-protocols",
        "smb2-security-mode",
        "smb2-time",
    ]

    cmd = [
        "nmap","-Pn","-p", port_args,
        "--script=" + ",".join(scripts),
        "-sV",
        ip
    ]

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out = result.stdout
        print(f"{GREEN}[+] SMB fingerprint collected.{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error executing Nmap: {e}{RESET}")
        out = f"Nmap error: {e}"

    with open(out_file, "a") as f:
        f.write("=== SMB FINGERPRINT (Nmap) ===\n")
        f.write(out + "\n\n")

    return out



# --------------------------------------------------------------------
# 2) ENUMERAR SHARES (smbclient -L)
# --------------------------------------------------------------------
def smb_enum_shares(ip, out_file):
    print(f"{CYAN}[→] Enumerating SMB shares (null session)...{RESET}")

    shares = []

    cmd = ["smbclient", "-L", f"//{ip}/", "-N"]

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out = result.stdout + result.stderr
    except Exception as e:
        print(f"{RED}[!] smbclient error: {e}{RESET}")
        with open(out_file, "a") as f:
            f.write("=== SMB SHARE ENUM ERROR ===\n" + strip_colors(str(e)) + "\n\n")
        return shares

    with open(out_file, "a") as f:
        f.write("=== SMB SHARE ENUMERATION (smbclient -L) ===\n")
        f.write(out + "\n")

    for line in out.splitlines():
        if "Disk" in line or "Printer" in line:
            parts = line.split()
            if not parts:
                continue
            name = parts[0]
            share_type = "SPECIAL" if name.upper() in ["IPC$", "ADMIN$", "C$", "PRINT$"] else "DISK"
            shares.append({"name": name, "type": share_type, "access": "UNKNOWN"})

    if shares:
        print(f"{GREEN}[+] Shares discovered:{RESET}")
        for s in shares:
            print(f"   - {s['name']} ({s['type']})")
    else:
        print(f"{YELLOW}[!] No shares found (may require auth).{RESET}")

    with open(out_file, "a") as f:
        f.write("\nParsed shares:\n")
        for s in shares:
            f.write(f"- {s['name']} ({s['type']})\n")
        f.write("\n")

    return shares



# --------------------------------------------------------------------
# 3) COMPROBAR ACCESO A SHARES (READ/WRITE)
# --------------------------------------------------------------------
def smb_check_shares_access(ip, shares, out_file):
    print(f"{CYAN}[→] Checking access to shares...{RESET}")

    test_dir = "__dogscan_test__"

    with open(out_file, "a") as f:
        f.write("=== SMB SHARE ACCESS CHECK ===\n")

    for share in shares:
        name = share["name"]
        if name.upper() in ["IPC$", "ADMIN$", "C$"]:
            continue

        print(f"{MAGENTA} ── Testing share: {WHITE}{name}{RESET}")

        list_cmd = ["smbclient", f"//{ip}/{name}", "-N", "-c", "ls"]

        try:
            result = subprocess.run(list_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
            out = result.stdout + result.stderr
        except Exception as e:
            msg = f"[!] Listing error: {e}"
            print(RED + msg + RESET)
            share["access"] = "ERROR"
            with open(out_file, "a") as f:
                f.write(strip_colors(msg) + "\n")
            continue

        if "NT_STATUS_ACCESS_DENIED" in out:
            print(f"{DARK_GRAY}     [-] Access denied (null session).{RESET}")
            share["access"] = "NO NULL ACCESS"
            continue

        print(f"{GREEN}     [+] Read access detected! (ls OK){RESET}")
        share["access"] = "READ"

        # Intentar escribir
        write_cmd = ["smbclient", f"//{ip}/{name}", "-N", "-c", f"mkdir {test_dir}; rmdir {test_dir}"]

        try:
            w = subprocess.run(write_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            wout = w.stdout + w.stderr
        except Exception:
            continue

        if "NT_STATUS_ACCESS_DENIED" in wout:
            print(f"{YELLOW}     [!] Read-only share (write denied).{RESET}")
        else:
            print(f"{RED}     [!] READ/WRITE share detected!{RESET}")
            share["access"] = "READ/WRITE"

    with open(out_file, "a") as f:
        f.write("\nShare access summary:\n")
        for s in shares:
            f.write(f"- {s['name']}: {s['access']}\n")
        f.write("\n")



# --------------------------------------------------------------------
# 4) ENUMERACIÓN DE USUARIOS (rpcclient)
# --------------------------------------------------------------------
def smb_enum_users(ip, out_file):
    print(f"{CYAN}[→] Enumerating users via rpcclient...{RESET}")

    try:
        proc = subprocess.Popen(
            ["rpcclient", "-U", "", "-N", ip],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    except FileNotFoundError:
        print(f"{YELLOW}[!] rpcclient not installed. Skipping.{RESET}")
        return

    try:
        stdout, stderr = proc.communicate("enumdomusers\nquit\n", timeout=10)
    except subprocess.TimeoutExpired:
        print(f"{YELLOW}[!] rpcclient timed out.{RESET}")
        stdout = stderr = ""

    full_out = stdout + stderr

    with open(out_file, "a") as f:
        f.write("=== SMB USER ENUM (rpcclient) ===\n")
        f.write(full_out + "\n\n")

    users = []
    for line in full_out.splitlines():
        m = re.search(r"user:\[(.+?)\]", line)
        if m:
            users.append(m.group(1))

    if users:
        print(f"{GREEN}[+] Users discovered:{RESET}")
        for u in users:
            print("   - " + u)
    else:
        print(f"{YELLOW}[!] No users found (null session likely disabled).{RESET}")



# --------------------------------------------------------------------
# 5) HEURÍSTICA DE POSIBLES CVEs
# --------------------------------------------------------------------
def smb_detect_possible_cves(banner_text, out_file):
    print(f"{CYAN}[→] Checking banner for CVE hints...{RESET}")

    findings = []
    b = banner_text.lower()

    # Samba usermap script RCE
    m = re.search(r"samba\s+([0-9]+\.[0-9]+\.[0-9]+)", b)
    if m:
        version = m.group(1)
        findings.append(f"Samba version detected: {version}")

        vuln_versions = ["3.0.20", "3.0.21", "3.0.22", "3.0.23", "3.0.24", "3.0.25"]
        if any(version.startswith(v) for v in vuln_versions):
            findings.append("Possible CVE-2007-2447 (Samba usermap script RCE)")

    # Windows 7/2008 (MS17-010)
    if "windows server 2008" in b or "windows 6.1" in b or "windows 7" in b:
        findings.append("Possible MS17-010 (EternalBlue) host → verify with smb-vuln-ms17-010")

    if not findings:
        findings.append("No obvious CVE patterns detected (heuristic only).")

    with open(out_file, "a") as f:
        f.write("=== SMB HEURISTIC CVE HINTS ===\n")
        for x in findings:
            f.write(x + "\n")
        f.write("\n")

    print(f"{GREEN}[+] CVE hints written to report.{RESET}")





