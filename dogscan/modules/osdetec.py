import subprocess

RESET = "\033[0m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RED = "\033[91m"
YELLOW = "\033[93m"
LIGHT_GRAY = "\033[37m"
DARK_GRAY = "\033[90m"


def detect_os(ip):
    """
    Detecta si el objetivo es Windows o Linux usando:
      - nmap -O
      - análisis de TTL
      - heurísticas por puertos/servicios

    Devuelve:
      {
        "os": "Linux" | "Windows" | "Unknown",
        "confidence": "high" | "medium" | "low",
        "reason": "...explicación..."
      }
    """

    print(LIGHT_GRAY + f"[→] Detecting OS on", CYAN +  f"{ip}..." + RESET)

    try:
        result = subprocess.run(
            ["nmap", "-O", "--osscan-guess", ip],
            capture_output=True,
            text=True
        )
    except Exception as e:
        print(RED + f"[-] OS detection failed: {e}" + RESET)
        return {"os": "Unknown", "confidence": "low", "reason": "Nmap execution error"}

    output = result.stdout.lower()

    # ====================================================================
    #   1) ANÁLISIS DIRECTO DE NMAP (más preciso)
    # ====================================================================
    if "linux" in output:
        print(GREEN + "[+] OS detected: Linux (from Nmap)" + RESET)
        return {"os": "Linux", "confidence": "high", "reason": "Nmap OS fingerprint"}

    if "windows" in output:
        print(GREEN + "[+] OS detected: Windows (from Nmap)" + RESET)
        return {"os": "Windows", "confidence": "high", "reason": "Nmap OS fingerprint"}

    # ====================================================================
    #   2) TTL HEURISTICS (muy usado en pentesting real)
    # ====================================================================
    ttl = _extract_ttl(output)

    if ttl:
        if ttl <= 64:
            print(YELLOW + "[*] TTL suggests Linux" + RESET)
            return {"os": "Linux", "confidence": "medium", "reason": f"TTL={ttl} typical Linux"}

        if ttl >= 100:
            print(YELLOW + "[*] TTL suggests Windows" + RESET)
            return {"os": "Windows", "confidence": "medium", "reason": f"TTL={ttl} typical Windows"}

    # ====================================================================
    #   3) Heurísticas por puertos comunes
    # ====================================================================
    if "445/tcp" in output or "smb" in output:
        print(YELLOW + "[*] SMB detected → Windows likely" + RESET)
        return {"os": "Windows", "confidence": "medium", "reason": "SMB port or service detected"}

    if "22/tcp" in output and "ssh" in output:
        print(YELLOW + "[*] SSH Linux fingerprint → likely Linux" + RESET)
        return {"os": "Linux", "confidence": "medium", "reason": "SSH typical Linux configuration"}

    # ====================================================================
    #   4) Si no detecta nada concluyente
    # ====================================================================
    print(DARK_GRAY + "[-] Could not determine OS." + RESET)
    return {"os": "Unknown", "confidence": "low", "reason": "No reliable fingerprint"}


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
