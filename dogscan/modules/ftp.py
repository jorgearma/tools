def enumerate_ftp(ip, port):
    return {
        "name": "FTP Enumeration",
        "scripts": [
            "ftp-anon",                  # Anonymous login
            "ftp-syst",                  # SYST command
            "ftp-brute",                 # Brute-force (opcional)
            "ftp-libopie",               # One-time password systems
            "ftp-vuln-cve2010-4221",     # ProFTPD vulnerability
            "ftp-proftpd-backdoor",      # ProFTPD Backdoor
            "ftp-vsftpd-backdoor"        # VSFTPD 2.3.4 Backdoor
        ]
    }
