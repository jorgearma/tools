import subprocess

RESET = "\033[0m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RED = "\033[91m"
YELLOW = "\033[93m"
LIGHT_GRAY = "\033[37m"
DARK_GRAY = "\033[90m"
WHITE = "\033[97m"


def detect_os(ip):
    try:
        result = subprocess.run(
            ["nmap", "-O", "--osscan-guess", ip],
            capture_output=True,
            text=True
        )
    except Exception:
        return {"os": "Unknown", "confidence": "low", "reason": "Nmap execution error"}

    output = result.stdout.lower()

    if "linux" in output:
        return {"os": "Linux", "confidence": "high", "reason": "Nmap OS fingerprint"}

    if "windows" in output:
        return {"os": "Windows", "confidence": "high", "reason": "Nmap OS fingerprint"}

    ttl = _extract_ttl(output)
    if ttl:
        if ttl <= 64:
            return {"os": "Linux", "confidence": "medium", "reason": f"TTL={ttl} typical Linux"}
        if ttl >= 100:
            return {"os": "Windows", "confidence": "medium", "reason": f"TTL={ttl} typical Windows"}

    if "445/tcp" in output or "smb" in output:
        return {"os": "Windows", "confidence": "medium", "reason": "SMB service detected"}

    if "22/tcp" in output and "ssh" in output:
        return {"os": "Linux", "confidence": "medium", "reason": "SSH typical Linux configuration"}

    return {"os": "Unknown", "confidence": "low", "reason": "No reliable fingerprint"}


def print_os_detection(ip, os_info):


    os_name = os_info["os"]
    confidence = os_info["confidence"].capitalize()
    reason = os_info["reason"]

    if os_name == "Unknown":
        print(YELLOW + "[!] Operating System : Unknown" + RESET)
    else:
        print(GREEN + f"[+] Operating System : {os_name}" + RESET)

    print(GREEN + f"[+] Confidence        : {confidence}" + RESET)
    print(LIGHT_GRAY + f"[→] Detection method  : {reason}\n" + RESET)



# ---------------------------
# Extrae TTL del output Nmap
# ---------------------------
def _extract_ttl(nmap_output):
    for line in nmap_output.split("\n"):
        if "ttl" in line:
            parts = line.replace(",", " ").split()
            for p in parts:
                if p.isdigit():
                    return int(p)
    return None


def check_host_alive(ip):
    """
    Verifica si el host está activo realizando 3 pings ICMP.
    Devuelve True si al menos uno responde, False en caso contrario.
    """

    print(WHITE + f"[*] Checking if host is alive..." + RESET)

    try:
        proc = subprocess.run(
            ["ping", "-c", "3", "-W", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        if proc.returncode == 0:
            print(GREEN + f"[✓] Host is alive — {WHITE}the dog has caught the scent 🐕\n" + RESET)
            return True
        else:
            print(RED + "[-] Host did not respond to ICMP ping." + RESET)
            print(LIGHT_GRAY + "[!] The dog found no trail. Aborting scan.\n" + RESET)
            return False

    except FileNotFoundError:
        print(RED + "[-] Ping command not found on this system." + RESET)
        return False
