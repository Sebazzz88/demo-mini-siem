"""CLI para recoger y normalizar logs locales."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Callable, Iterable

from .models import NormalizedEvent
from .parsers import parse_firewall_line, parse_ssh_line, parse_web_line
from .simulator import generate_demo_logs

Parser = Callable[[str], NormalizedEvent | None]


def collect_file(path: Path, parser: Parser) -> tuple[list[NormalizedEvent], int]:
    """Lee un archivo y devuelve eventos válidos y líneas que no reconoció."""
    events: list[NormalizedEvent] = []
    skipped = 0
    with path.open("r", encoding="utf-8", errors="replace") as log_file:
        for line in log_file:
            event = parser(line)
            if event is None:
                skipped += 1
            else:
                events.append(event)
    return events, skipped


def write_jsonl(events: Iterable[NormalizedEvent], output: Path) -> int:
    """Guarda un evento por línea para facilitar la siguiente etapa del SIEM."""
    output.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with output.open("w", encoding="utf-8") as output_file:
        for event in events:
            output_file.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
            count += 1
    return count


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Recolecta logs locales y los normaliza a JSONL para Mini-SIEM."
    )
    parser.add_argument(
        "--auth-log",
        action="append",
        type=Path,
        default=[],
        metavar="ARCHIVO",
        help="Archivo auth.log con eventos de SSH. Puede repetirse.",
    )
    parser.add_argument(
        "--web-log",
        action="append",
        type=Path,
        default=[],
        metavar="ARCHIVO",
        help="Access log de Apache o Nginx en formato combined. Puede repetirse.",
    )
    parser.add_argument(
        "--firewall-log",
        action="append",
        type=Path,
        default=[],
        metavar="ARCHIVO",
        help="Log UFW con conexiones observadas. Puede repetirse.",
    )
    parser.add_argument(
        "--simulate",
        type=Path,
        metavar="CARPETA",
        help="Genera registros falsos en esta carpeta y los recolecta.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Semilla del simulador para resultados repetibles (por defecto: 42).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("normalized_events.jsonl"),
        metavar="ARCHIVO",
        help="Archivo JSONL de salida (por defecto: normalized_events.jsonl).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)
    auth_logs = list(args.auth_log)
    web_logs = list(args.web_log)
    firewall_logs = list(args.firewall_log)

    if args.simulate:
        auth_demo, web_demo, firewall_demo = generate_demo_logs(args.simulate, seed=args.seed)
        auth_logs.append(auth_demo)
        web_logs.append(web_demo)
        firewall_logs.append(firewall_demo)
        print(f"Logs de demostración creados en: {args.simulate}")

    if not auth_logs and not web_logs and not firewall_logs:
        print("Indica --auth-log, --web-log, --firewall-log o --simulate. Consulta --help.", file=sys.stderr)
        return 2

    all_events: list[NormalizedEvent] = []
    total_skipped = 0
    for path in auth_logs:
        try:
            events, skipped = collect_file(path, parse_ssh_line)
        except OSError as error:
            print(f"No se pudo leer {path}: {error}", file=sys.stderr)
            return 1
        all_events.extend(events)
        total_skipped += skipped
        print(f"SSH  {path}: {len(events)} eventos, {skipped} líneas omitidas")

    for path in web_logs:
        try:
            events, skipped = collect_file(path, parse_web_line)
        except OSError as error:
            print(f"No se pudo leer {path}: {error}", file=sys.stderr)
            return 1
        all_events.extend(events)
        total_skipped += skipped
        print(f"WEB  {path}: {len(events)} eventos, {skipped} líneas omitidas")

    for path in firewall_logs:
        try:
            events, skipped = collect_file(path, parse_firewall_line)
        except OSError as error:
            print(f"No se pudo leer {path}: {error}", file=sys.stderr)
            return 1
        all_events.extend(events)
        total_skipped += skipped
        print(f"UFW  {path}: {len(events)} eventos, {skipped} líneas omitidas")

    all_events.sort(key=lambda event: event.timestamp)
    written = write_jsonl(all_events, args.output)
    print(f"Listo: {written} eventos normalizados en {args.output}.")
    if total_skipped:
        print("Nota: se omitieron líneas que no eran eventos SSH/web reconocidos.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
