# 🧰 MKS 

Este script está diseñado para crear automáticamente una estructura de carpetas y archivos organizada, ideal para comenzar el análisis y reporte de máquinas en entornos de hacking ético como Hack The Box (HTB), Proving Grounds o durante la preparación del examen OSCP.

---

## 🚀 ¿Qué hace este script?

Al ejecutarlo, el script:

- Crea una carpeta principal con el nombre de la máquina o proyecto.
- Dentro de ella, genera subdirectorios comunes:
  - `exploits/`: Para guardar scripts de explotación o exploits personalizados.
  - `content/`: Donde se almacena la enumeración (`enum.txt`) y capturas (`screenshots/`).
- Crea un informe inicial en formato Markdown con plantilla profesional.
- Añade archivos auxiliares como `README.md` y `notas.txt`.
- Muestra animaciones visuales tipo terminal para una experiencia más inmersiva.

---

## 🏗️ Estructura generada

```
MachineName/
│
├── MachineName_report.md     # Plantilla de reporte técnico
├── README.md                 # Descripción básica del proyecto
├── notas.txt                 # Archivo de motivación o notas personales
│
├── exploits/
│   └── exploits_notes.txt    # Notas sobre scripts o exploits
│
└── content/
    ├── enum.txt              # Plantilla para notas de enumeración
    └── screenshots/          # Carpeta para imágenes o capturas
```

---

## 📦 Requisitos

Este script está escrito en Python 3 y no requiere librerías externas.

---

## 🧪 Cómo usarlo

```bash
python3 crear_entorno.py NombreDeLaMaquina
```

Si no se pasa ningún argumento, el script pedirá el nombre de la carpeta de forma interactiva.

---

## 🎨 Extras

- Animaciones de spinner y efecto de "máquina de escribir".
- Un pequeño dragón ASCII como bienvenida ☁️🐉
- Mensaje motivacional final para animarte en tu camino al OSCP 💪

---

## ✍️ Autor

Hecho con 🧠 y café para ayudarte a mantenerte organizado durante tus pentests.

---
