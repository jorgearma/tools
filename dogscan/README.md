# 🐕 dogscan

**dogscan** is an offensive enumeration tool designed for *pentesting* and OSCP-style workflows. It acts as an **intelligent Nmap wrapper**, adding analysis logic, service-specific modules (FTP, SSH, SMB), and clean, structured output.

The goal of dogscan is **not to replace Nmap**, but to **speed up enumeration**, reduce noise, and highlight exploitable findings quickly and clearly.

---

## ✨ Key Features

* 🔎 **Automatic port discovery** (full port scan)
* 🎯 **Targeted scanning** only on open ports
* 🧠 **Service-aware intelligent enumeration**

  * FTP (anonymous login, default creds, backdoors, downloads)
  * SSH (auth methods, info leaks, safe user enumeration)
  * SMB (shares, access checks, users, CVE heuristics)
* 🧬 **Vulnerability detection** using Nmap scripts (`vuln`, `vulners`, HTTP scripts)
* 🧰 **Optional SearchSploit integration**
* 🖥️ **Clean, readable console output**
* 📁 **Structured output directory** (`nmap_output/`)
* ⏳ **Real-time progress bars**

---

## 📦 Requirements

* Python **3.9+**
* `nmap`
* Optional (recommended):

  * `searchsploit`
  * `ftp`
  * `smbclient`
  * `rpcclient`
  * `openssl`

Most of these are preinstalled on Kali Linux.

---

## 🚀 Installation

```bash
git clone https://github.com/jorgearma/tools/dogscan.git
cd dogscan
chmod +x dogscan.py
```

No additional Python dependencies are required.

---

## 🧪 Basic Usage

```bash
./dogscan.py <IP>
```

Example:

```bash
./dogscan.py 10.10.10.10
```

---

## ⚙️ Execution Modes

```bash
./dogscan.py <IP> --mode <fast|medium|deep>
```

| Mode   | Description                                      |
| ------ | ------------------------------------------------ |
| fast   | Port discovery + OS detection                    |
| medium | + Targeted scan (`-sC -sV`)                      |
| deep   | + Vulnerability scan + service modules (default) |

---

## 📂 Output Structure

All results are written to the directory from which the tool is executed:

```text
nmap_output/
├── all_ports.txt
├── targeted.txt
├── vuln_22.txt
├── ftp/
│   ├── ftp_enum_21.txt
│   └── downloads/
├── ssh/
│   └── ssh_enum_10.10.10.10.txt
└── smb/
    └── smb_enum_10.10.10.10.txt
```

Each module writes **only inside its own subdirectory**.

---

## 🔬 Supported Modules

### FTP

* `ftp-anon`, `ftp-syst`, `ftp-brute`
* Detection of:

  * Anonymous login
  * Default credentials
  * VSFTPD 2.3.4 backdoor
  * ProFTPD backdoor
  * CVE-2010-4221
* Automatic file download when access is available

### SSH

* Algorithm and hostkey enumeration
* Authentication info-leak detection
* Safe (non-intrusive) username enumeration

### SMB

* Full SMB fingerprinting (Nmap)
* Share enumeration (null session)
* READ / WRITE access checks
* User enumeration (`rpcclient`)
* Common CVE heuristics (MS17-010, Samba usermap)

---

## 🧠 Project Philosophy

* Enumerate **only what matters**
* Highlight **exploitable findings**, not raw noise
* Human-readable output by default
* **Modular and extensible** codebase

This is not a toy script — it is built for **OSCP / HTB / THM-style workflows**.

---

## 🔐 Security Notice

* Uses active scanning techniques → **authorized targets only**
* Some checks (FTP brute, SMB access tests) may generate logs on the target
* Run as root only when strictly necessary

---

## 🧩 Extending dogscan

Adding new modules is straightforward:

1. Create `modules/http.py`
2. Implement `enumerate(ip, ports, base_output_dir)`
3. Register the module in `MODULE_MAP`

---

## 👤 Author

* **jorgearma**
* GitHub: [https://github.com/jorgearma](https://github.com/jorgearma)

---

## 📄 License

This project is released under the MIT License.

---

> "Let the dog sniff first." 🐕
