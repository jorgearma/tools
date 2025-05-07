#!/usr/bin/env python3
import sys
import time
import random
import re
import os
import shutil
import itertools

plantilla = """# 🛡️ Penetration Testing Report — Hack The Box

**Target Machine:** `MachineName`  
**IP Address:** `IP_ADDRESS_HERE`  
**Date:** `DATE_HERE`  
**Author:** `YOUR_NAME`

---

## 📁 Table of Contents
1. Introduction  
2. Scope and Methodology  
3. Reconnaissance  
   - Network Scanning  
   - Service Enumeration  
   - Directory Enumeration  
4. Exploitation  
   - Vulnerability Identification  
   - Exploitation Steps  
5. Post-Exploitation  
   - Privilege Escalation  
   - Data Extraction  
6. Mitigations & Recommendations  
7. Conclusion  
8. Appendix  
9. References  

---

## 1. 🔍 Introduction
Provide a general description of the penetration test performed on the target machine. Include a brief overview of the nature of the environment (e.g., Hack The Box lab) and the objective of the exercise.

---

## 2. 🎯 Scope and Methodology
**Scope:**  
- IP: `INSERT_TARGET_IP`  
- Define any rules of engagement and boundaries for the assessment.

**Methodology:**  
- Type of approach (e.g., black-box)  
- Tools and techniques used (Nmap, Gobuster, Burp Suite, Metasploit, etc.)

---

## 3. 🔎 Reconnaissance
### Network Scanning
```bash
# Nmap command used
```
**Open Ports:**
- ...

### Service Enumeration
- Services and versions identified
- Any notable information from banners or responses

### Directory Enumeration
```bash
# Gobuster or equivalent tool command
```
**Directories discovered:**
- ...

---

## 4. 💥 Exploitation
### Vulnerability Identification
- Describe any vulnerabilities identified
- Include proof-of-concepts if applicable

### Exploitation Steps
- Detail the exploitation process
- Commands used and access gained

---

## 5. 🧠 Post-Exploitation
### Privilege Escalation
- Techniques used
- Files/services that enabled escalation

### Data Extraction
- Sensitive files retrieved
- Databases or other critical data accessed

---

## 6. 🔧 Mitigations & Recommendations
- Software patching
- Input validation and sanitation
- File permission hardening
- Best practice configurations (e.g., SSH settings)

---

## 7. ✅ Conclusion
Summarize the most important findings and associated risks. Assess the overall impact and provide suggestions for immediate remediation steps.

---

## 8. 📌 Appendix
- Output files (Nmap scans, scripts, screenshots)
- Supporting data and evidence

---

## 9. 📚 References
- Official documentation of tools used
- OWASP materials, CVE references, etc.


"""

enumplantilla = """
ip:
titulo:
CMS:
frameworks:
lenguaje/backend:
hostname:
servidorweb:



comportamientos inusuales:


mensajes de error:"""

def fake_terminal_prompt(prompt="root@oscp:~# ", duration=5):
    cursor = "_"
    end_time = time.time() + duration
    visible = True

    while time.time() < end_time:
        sys.stdout.write(f"\r{prompt}{cursor if visible else ' '}")
        sys.stdout.flush()
        visible = not visible
        time.sleep(0.5)
    print()  # salto de línea al terminar


def terminal_prompt_with_typing(prompt, mensaje, min_delay=0.005, max_delay=0.02,
                                 delay_antes_whoami=0.5, delay_antes_mensaje=0.5):
    # Mostrar el prompt
    sys.stdout.write(f"\n{prompt}")
    sys.stdout.flush()

    # Pequeña pausa antes de empezar a tipear "whoami"
    time.sleep(delay_antes_whoami)

    # Tipear "whoami"
    falso = "whoami"
    for char in falso:
        print(char, end='', flush=True)
        time.sleep(random.uniform(min_delay, max_delay))

    # Pausa breve como si pensara "meh, no..."
    time.sleep(0.5)

    # Borrar "whoami" uno a uno
    for _ in falso:
        sys.stdout.write('\b \b')
        sys.stdout.flush()
        time.sleep(0.1)

    # Pausa antes del mensaje real
    time.sleep(delay_antes_mensaje)

    for char in mensaje:
        print(char, end='', flush=True)
        if char in ".!?":
            time.sleep(random.uniform(0.15, 0.3))
        elif char in ",;:":
            time.sleep(random.uniform(0.07, 0.15))
        elif char == " ":
            time.sleep(random.uniform(0.005, 0.01))
        else:
            time.sleep(random.uniform(min_delay, max_delay))

    print()  # salto de línea




class Color:
    red = '\033[91m'
    gold = '\033[93m'
    blue = '\033[36m'
    green = '\033[92m'
    purple = '\033[35m'
    bold = '\033[1m'
    reset = '\033[0m'

def print_dragon():
    dragon = r"""  
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣤⣤⣤⣤⡼⠀⢀⡀⣀⢱⡄⡀⠀⠀⠀⢲⣤⣤⣤⣤⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣾⣿⣿⣿⣿⣿⡿⠛⠋⠁⣤⣿⣿⣿⣧⣷⠀⠀⠘⠉⠛⢻⣷⣿⣽⣿⣿⣷⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣴⣞⣽⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠠⣿⣿⡟⢻⣿⣿⣇⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣟⢦⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣠⣿⡾⣿⣿⣿⣿⣿⠿⣻⣿⣿⡀⠀⠀⠀⢻⣿⣷⡀⠻⣧⣿⠆⠀⠀⠀⠀⣿⣿⣿⡻⣿⣿⣿⣿⣿⠿⣽⣦⡀⠀⠀⠀⠀
⠀⠀⠀⠀⣼⠟⣩⣾⣿⣿⣿⢟⣵⣾⣿⣿⣿⣧⠀⠀⠀⠈⠿⣿⣿⣷⣈⠁⠀⠀⠀⠀⣰⣿⣿⣿⣿⣮⣟⢯⣿⣿⣷⣬⡻⣷⡄⠀⠀⠀
⠀⠀⢀⡜⣡⣾⣿⢿⣿⣿⣿⣿⣿⢟⣵⣿⣿⣿⣷⣄⠀⣰⣿⣿⣿⣿⣿⣷⣄⠀⢀⣼⣿⣿⣿⣷⡹⣿⣿⣿⣿⣿⣿⢿⣿⣮⡳⡄⠀⠀
⠀⢠⢟⣿⡿⠋⣠⣾⢿⣿⣿⠟⢃⣾⢟⣿⢿⣿⣿⣿⣾⡿⠟⠻⣿⣻⣿⣏⠻⣿⣾⣿⣿⣿⣿⡛⣿⡌⠻⣿⣿⡿⣿⣦⡙⢿⣿⡝⣆⠀
⠀⢯⣿⠏⣠⠞⠋⠀⣠⡿⠋⢀⣿⠁⢸⡏⣿⠿⣿⣿⠃⢠⣴⣾⣿⣿⣿⡟⠀⠘⢹⣿⠟⣿⣾⣷⠈⣿⡄⠘⢿⣦⠀⠈⠻⣆⠙⣿⣜⠆
⢀⣿⠃⡴⠃⢀⡠⠞⠋⠀⠀⠼⠋⠀⠸⡇⠻⠀⠈⠃⠀⣧⢋⣼⣿⣿⣿⣷⣆⠀⠈⠁⠀⠟⠁⡟⠀⠈⠻⠀⠀⠉⠳⢦⡀⠈⢣⠈⢿⡄
⣸⠇⢠⣷⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⠿⠿⠋⠀⢻⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢾⣆⠈⣷
⡟⠀⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣶⣤⡀⢸⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⡄⢹
⡇⠀⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠈⣿⣼⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠃⢸
⢡⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⠶⣶⡟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡼⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀              
"""

    print(dragon)
_ansi_escape = re.compile(r'\x1b\[[0-9;]*m')

def mensaje_con_spinner(mensaje, color=Color.reset, duracion=0.5, ancho_ref=53):
    """
    Muestra `mensaje` y un spinner alineado siempre en la columna `ancho_ref+1`,
    pero recortando `ancho_ref` al ancho real de la terminal menos 1.
    """
    # 1) calculamos ancho de terminal
    columns = shutil.get_terminal_size().columns
    # 2) limitamos nuestra referencia para que no sobrepase pantalla
    ref = min(ancho_ref, columns - 2)
    
    # 3) construimos el texto coloreado
    full_msg = f"{color}{mensaje}{Color.reset}"
    # 4) medimos sólo los caracteres “visibles”
    visible_len = len(_ansi_escape.sub('', full_msg))
    # 5) cuantos espacios necesitamos para llegar a ref
    padding = max(ref - visible_len, 0)

    spinner = itertools.cycle(['|', '/', '-', '\\'])
    end_time = time.time() + duracion

    # 6) bucle de animación, siempre sobreescribiendo la misma línea
    while time.time() < end_time:
        spin = next(spinner)
        line = full_msg + (' ' * padding) + spin
        sys.stdout.write('\r' + line)
        sys.stdout.flush()
        time.sleep(0.1)

    # 7) impresión final con '|'
    final = full_msg + (' ' * padding) + '|'
    sys.stdout.write('\r' + final + '\n')
    sys.stdout.flush()

def typewriter(texto, delay=0.01, color=Color.reset):
    for linea in texto.splitlines():
        print(color, end='')
        for char in linea:
            print(char, end='', flush=True)
            time.sleep(delay)
        print(Color.reset)
      

def obtener_nombre_carpeta():
    if len(sys.argv) > 1:
        return sys.argv[1]
    else:
        return input(f"{Color.blue}📁 Nombre para la carpeta principal: {Color.reset}")

def crear_archivo(ruta, contenido=""):
    with open(ruta, 'w') as f:
        f.write(contenido)

# 🛠 Lógica principal
def crear_directorios():
    print_dragon()
    print(f"{Color.green}═════════════╣ Initializing Operation ╠═════════════{Color.reset}\n")

    carpeta_principal = obtener_nombre_carpeta()
    subdirectorios = [ "exploits", "content"]

    if not os.path.exists(carpeta_principal):
        os.makedirs(carpeta_principal)
        ruta = os.path.join(carpeta_principal)
        mensaje_con_spinner(f"{Color.green}[+] Carpeta creada: {Color.blue}{carpeta_principal}{Color.reset}", Color.green)
        crear_archivo(os.path.join(ruta, f"{carpeta_principal}_report.md"), plantilla)
        mensaje_con_spinner(f"{Color.green}[+] Archivo de reporte creado: {Color.blue}{carpeta_principal}_report.md{Color.reset}", Color.green)
        crear_archivo(os.path.join(ruta, "README.md"), "Este es un archivo de texto de ejemplo.\n")
        crear_archivo(os.path.join(ruta, "notas.txt"), "Animo, you can do it.\n")
    else:
        mensaje_con_spinner(f"{Color.gold}[!] Carpeta ya existente:{Color.blue}{carpeta_principal}{Color.reset}", Color.gold)

    for sub in subdirectorios:
        ruta = os.path.join(carpeta_principal, sub)
        if not os.path.exists(ruta):
            os.makedirs(ruta)
            mensaje_con_spinner(f"{Color.green}[+] Subdirectorio creado: {Color.blue}{sub}{Color.reset}", Color.green)
        else:
            mensaje_con_spinner(f"{Color.gold}[!] Subdirectorio ya existía: {Color.blue}{sub}{Color.reset}", Color.gold)

        if sub == "content":
            
            crear_archivo(os.path.join(ruta, "enum.txt"), enumplantilla)
            os.mkdir(os.path.join(ruta, "screenshots"))
            mensaje_con_spinner(f"{Color.green}[+] Archivos creados:{Color.reset} enum.txt ")

        if sub == "nmap":
            crear_archivo(os.path.join(ruta, "nmap_report.txt"), "nmap reports.\n")

        if sub == "exploits":
            crear_archivo(os.path.join(ruta, "exploits_notes.txt"), "exploits notes.\n")    

    mensaje_con_spinner(f"{Color.blue}[*] Preparación del entorno OSCP finalizada", Color.blue, duracion=1)
    
    terminal_prompt_with_typing("root@oscp:~# ", "El camino OSCP es duro, pero tú lo eres más.🧠")


# ▶️ Ejecutar
if __name__ == "__main__":
    crear_directorios()
