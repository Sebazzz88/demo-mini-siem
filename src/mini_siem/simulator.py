"""Generador de registros falsos para demostraciones locales."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import random


def _syslog_time(value: datetime) -> str:
    return value.strftime("%b %e %H:%M:%S")


def _web_time(value: datetime) -> str:
    return value.strftime("%d/%b/%Y:%H:%M:%S %z")


def generate_demo_logs(directory: Path, seed: int = 42) -> tuple[Path, Path, Path]:
    """Crea logs inocuos que imitan comportamientos útiles para futuras reglas.

    No se generan solicitudes ni conexiones de red: solo texto local con IPs
    reservadas para documentación.
    """
    directory.mkdir(parents=True, exist_ok=True)
    randomizer = random.Random(seed)
    # auth.log no guarda una zona horaria. Usar la zona local para ambos tipos
    # de registros hace que su orden temporal sea coherente al normalizarlos.
    local_timezone = datetime.now().astimezone().tzinfo or timezone.utc
    base_time = datetime(2026, 1, 15, 12, 0, 0, tzinfo=local_timezone)

    auth_lines: list[str] = []
    brute_force_ip = "198.51.100.77"
    for attempt in range(10):
        time = base_time + timedelta(seconds=attempt * 20)
        port = randomizer.randint(30000, 60000)
        auth_lines.append(
            f"{_syslog_time(time)} lab-vm sshd[{1800 + attempt}]: "
            f"Failed password for invalid user admin from {brute_force_ip} "
            f"port {port} ssh2"
        )
    auth_lines.append(
        f"{_syslog_time(base_time + timedelta(minutes=5))} lab-vm sshd[1900]: "
        "Accepted publickey for student from 192.0.2.10 port 45210 ssh2"
    )

    web_lines: list[str] = []
    fuzzing_ip = "203.0.113.44"
    for request in range(12):
        time = base_time + timedelta(minutes=10, seconds=request * 12)
        path = f"/hidden/demo-{request}.txt"
        web_lines.append(
            f'{fuzzing_ip} - - [{_web_time(time)}] "GET {path} HTTP/1.1" 404 153 "-" "MiniSIEM-Demo"'
        )

    injection_ip = "198.51.100.23"
    injection_path = "/products?id=1%27%20OR%201%3D1--"
    web_lines.append(
        f'{injection_ip} - - [{_web_time(base_time + timedelta(minutes=15))}] '
        f'"GET {injection_path} HTTP/1.1" 200 824 "-" "MiniSIEM-Demo"'
    )

    firewall_lines: list[str] = []
    scanner_ip = "203.0.113.99"
    for offset, port in enumerate((22, 80, 443, 8080, 3306, 5432)):
        time = base_time + timedelta(minutes=20, seconds=offset * 8)
        firewall_lines.append(
            f"{_syslog_time(time)} lab-vm kernel: [UFW BLOCK] IN=eth0 OUT= "
            f"SRC={scanner_ip} DST=192.0.2.20 LEN=60 PROTO=TCP "
            f"SPT={randomizer.randint(30000, 60000)} DPT={port}"
        )

    web_lines.append(
        f'192.0.2.10 - - [{_web_time(base_time + timedelta(minutes=25))}] '
        '"GET /index.html HTTP/1.1" 200 1200 "-" "Mozilla/5.0"'
    )

    auth_path = directory / "demo_auth.log"
    web_path = directory / "demo_access.log"
    firewall_path = directory / "demo_ufw.log"
    auth_path.write_text("\n".join(auth_lines) + "\n", encoding="utf-8")
    web_path.write_text("\n".join(web_lines) + "\n", encoding="utf-8")
    firewall_path.write_text("\n".join(firewall_lines) + "\n", encoding="utf-8")
    return auth_path, web_path, firewall_path
