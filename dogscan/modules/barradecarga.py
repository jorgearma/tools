# modulos/barradecarga.py
import sys
import time
import itertools

# ─── ANSI COLORS ─────────────────────────────────────────────
GREEN = "\033[92m"
RESET = "\033[0m"
BOLD = "\033[1m"
CLEAR_LINE = "\033[2K"
CURSOR_START = "\r"


def barra_carga(label, stop_event, progress_ref, width=30, speed=0.05):
    import sys, time, itertools

    GREEN = "\033[92m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    CLEAR_LINE = "\033[2K"
    CURSOR_START = "\r"

    messages = itertools.cycle([
        "Paciencia...",
        "Enumerando puertos...",
        "Analizando servicios...",
        "Forzando respuestas..."
    ])

    cycle = 1
    message = next(messages)

    while not stop_event.is_set():
        percent = progress_ref["percent"]

        if percent is not None:
            filled_len = int(width * percent / 100)
            filled = "#" * filled_len
            empty = "-" * (width - filled_len)
            percent_txt = f"{percent:.2f}%"
        else:
            # modo animado normal
            filled_len = (cycle % width)
            filled = "#" * filled_len
            empty = "-" * (width - filled_len)
            percent_txt = "?"

        sys.stdout.write(
            f"{CURSOR_START}{CLEAR_LINE}"
            f"{GREEN}{BOLD}[{label}]{RESET} "
            f"{GREEN}[{filled}{empty}]{RESET} "
            f"{GREEN}{percent_txt} {message}{RESET}"
        )
        sys.stdout.flush()

        time.sleep(speed)
        cycle += 1
        message = next(messages)

    sys.stdout.write(f"{CURSOR_START}{CLEAR_LINE}")
    sys.stdout.flush()
 