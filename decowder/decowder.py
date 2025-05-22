import argparse
import base64
import binascii
import itertools
import logging
import re
import sys
import time
from pathlib import Path
from typing import Tuple

RESET = "\033[0m"
DARK_GRAY = "\033[90m"
RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
WHITE = "\033[97m"
MAGENTA = "\033[95m"
DARK_GRAY = "\033[90m"
LIGHT_GRAY = "\033[37m"

B64_REGEX = re.compile(rb'^[A-Za-z0-9+/]+={0,2}$')

def asci_art():
    print(GREEN +r"""
                      ,     ,
                  ___('-&&&-')__
                 '.__./     \__.'
     _     _     _ .-'  6  6 \
   /` `--'( ('--` `\         |
  /        ) )      \ \ _   _|
 |        ( (        | (0_._0)    _       ____ _____        __  _                  
 |         ) )       |/ '---'  __| | ___ / ___/ _ \ \      / /_| | ___ _ __ 
 |        ( (        |\_      / _` |/ _ \ |  | | | \ \ /\ / / _` |/ _ \ '__|
 |         ) )       |( \,   | (_| |  __/ |__| |_| |\ V  V / (_| |  __/ |   	
  \       ((`       / )__/    \__,_|\___|\____\___/  \_/\_/ \__,_|\___|_|  
"""+ RESET)

def is_base64(data: bytes) -> bool:
    if not B64_REGEX.fullmatch(data):
        return False
    try:
        base64.b64decode(data, validate=True)
        return True
    except (binascii.Error, ValueError):
        return False

def clean_base64(data: bytes) -> bytes:
    return re.sub(rb'\s+', b'', data)

def decode_layers(data: bytes, max_iter: int = 50) -> Tuple[bytes, int]:
    spinner = itertools.cycle(['|', '/', '-', '\\'])
    layers = 0
    while layers < max_iter:
        clean = clean_base64(data)
        if not is_base64(clean):
            break

        msg = f"[+] Decodificando capa " + CYAN + f"{layers+1}/{max_iter}" + RESET
        for _ in range(4):
            sys.stdout.write('\r' + msg + next(spinner))
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write('\r' + msg + GREEN +" ✔\n" + RESET)
        sys.stdout.flush()

        try:
            data = base64.b64decode(clean, validate=True)
            layers += 1
            logging.debug(f"Decoded layer {layers}, size now {len(data)} bytes.")
        except Exception as e:
            logging.error(f"Error decoding at layer {layers}: {e}")
            break

    return data, layers

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Iteratively decode nested Base64-encoded files with estilo hacker."
    )
    parser.add_argument(
        'input',
        type=Path,
        help='Path to the input file containing Base64-encoded data'
    )
    parser.add_argument(
        '-o', '--output',
        type=Path,
        default=None,
        help='Optional path to write the decoded result (default: stdout)'
    )
    parser.add_argument(
        '-m', '--max-iterations',
        type=int,
        default=50,
        help='Maximum number of Base64 decoding passes'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable debug output'
    )
    args = parser.parse_args()
    asci_art()
    print(DARK_GRAY + "═" * 75 + RESET)

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format='%(levelname)s: %(message)s')

    raw_data = args.input.read_bytes()
    decoded, count = decode_layers(raw_data, args.max_iterations)

    try:
        text = decoded.decode('utf-8')
    except UnicodeDecodeError:
        text = decoded  
    print(DARK_GRAY + "═" * 75 + RESET)
    logging.info(  GREEN + f"[-] Número de capas decodificadas: {count}" + RESET)

    if args.output:
        if isinstance(text, bytes):
            args.output.write_bytes(text)
        else:
            args.output.write_text(text, encoding='utf-8')
        logging.info(f"Resultado escrito en: {args.output}")
    else:
        
        print(f"\n🔓 Resultado final:\033[93m {text}\033[0m")



if __name__ == '__main__':
    main()
