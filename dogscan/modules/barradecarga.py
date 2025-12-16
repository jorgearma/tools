# modulos/barradecarga.py
import sys
import time
import itertools
import shutil
import re
from wcwidth import wcswidth

# ─── ANSI COLORS ─────────────────────────────────────────────
GREEN = "\033[92m"
RESET = "\033[0m"
BOLD = "\033[1m"
CLEAR_LINE = "\033[2K"
CURSOR_START = "\r"

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def visible_width(text: str) -> int:
    """Calcula ancho REAL en terminal (sin ANSI, con Unicode correcto)."""
    clean = ANSI_RE.sub("", text)
    return wcswidth(clean)


def barra_carga(label, stop_event, progress_ref, width=20, speed=0.15):

    messages = itertools.cycle([
        "Patience…",
        "The dogs are searching",
        "Following the scent",
        "Sniffing open ports",
        "Tracking service responses",
        "Analyzing network traces",
        "Probing the perimeter",
        "Mapping the attack surface",
        "Enumerating exposed services",
        "Correlating fingerprints",
        "Listening for weak signals",
        "Hunting for misconfigurations",
        "Parsing protocol behavior",
        "Identifying response patterns",
        "Scanning for anomalies",
        "Following the trail",
        "Waiting for the target to slip",
    ])


    cycle = 1
    message = next(messages)

    while not stop_event.is_set():
        percent = progress_ref.get("percent")

        # ── barra / porcentaje ─────────────────────────
        if percent is not None:
            filled_len = int(width * percent / 100)
            percent_txt = f"{percent:5.1f}%"
        else:
            filled_len = cycle % width
            percent_txt = "🐕"

        filled = "#" * filled_len
        empty = "-" * (width - filled_len)

        # ── detectar ancho de consola ──────────────────
        term_width = shutil.get_terminal_size(fallback=(80, 20)).columns

        # línea SIN mensaje
        line_no_msg = (
            f"{GREEN}{BOLD}[{label}]{RESET} "
            f"{GREEN}[{filled}{empty}]{RESET} "
            f"{GREEN}{percent_txt}{RESET}"
        )

        # decidir si el mensaje cabe
        if visible_width(line_no_msg + " " + message) < term_width:
            suffix = f" {message}"
        else:
            suffix = ""

        # ── render final ───────────────────────────────
        sys.stdout.write(
            f"{CURSOR_START}{CLEAR_LINE}"
            f"{line_no_msg}{GREEN}{suffix}{RESET}"
        )
        sys.stdout.flush()

        time.sleep(speed)
        cycle += 1
        message = next(messages)

    # limpiar línea al terminar
    sys.stdout.write(f"{CURSOR_START}{CLEAR_LINE}")
    sys.stdout.flush()
