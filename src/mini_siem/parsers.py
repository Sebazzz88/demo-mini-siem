"""Lectores de líneas SSH y de access logs web."""

from __future__ import annotations

from datetime import datetime
import re

from .models import NormalizedEvent


SYSLOG_PREFIX = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+\S+(?:\[\d+\])?:\s+(?P<message>.*)$"
)
SSH_FAILURE = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<username>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
SSH_SUCCESS = re.compile(
    r"Accepted (?:password|publickey) for (?P<username>\S+) from (?P<ip>\S+) "
    r"port (?P<port>\d+)"
)
WEB_ACCESS = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[^\"]+"\s+'
    r"(?P<status>\d{3})\s+\S+(?:\s+.*)?$"
)
DESTINATION_PORT = re.compile(r"\bdst_port=(?P<port>\d{1,5})\b")
FIREWALL_CONNECTION = re.compile(
    r"\bSRC=(?P<ip>\S+).*?\b(?:SPT=(?P<source_port>\d+)\s+)?DPT=(?P<target_port>\d+)"
)


def _parse_syslog_timestamp(value: str, now: datetime | None = None) -> datetime:
    """Añade el año y la zona local que los logs syslog suelen omitir."""
    current_time = now or datetime.now().astimezone()
    # Añadimos el año antes de interpretar la fecha. Además de reflejar la
    # información que falta en syslog, evita depender de un comportamiento de
    # Python que cambiará para fechas sin año.
    parsed = datetime.strptime(
        f"{current_time.year} {value}", "%Y %b %d %H:%M:%S"
    )
    return parsed.replace(tzinfo=current_time.tzinfo)


def parse_ssh_line(line: str, now: datetime | None = None) -> NormalizedEvent | None:
    """Convierte una línea sshd de éxito o fallo en un evento común.

    Las líneas auxiliares de sshd, como "Invalid user", no se emiten por sí
    solas: el posterior "Failed password" contiene el intento completo y evita
    contar dos veces el mismo login fallido.
    """
    raw = line.rstrip("\n")
    prefix = SYSLOG_PREFIX.match(raw)
    if not prefix:
        return None

    message = prefix.group("message")
    failure = SSH_FAILURE.search(message)
    success = SSH_SUCCESS.search(message)
    match = failure or success
    if not match:
        return None

    return NormalizedEvent(
        timestamp=_parse_syslog_timestamp(prefix.group("timestamp"), now=now),
        source="ssh",
        event_type="ssh_login",
        ip=match.group("ip"),
        username=match.group("username"),
        outcome="failed" if failure else "success",
        source_port=int(match.group("port")),
        raw=raw,
    )


def parse_web_line(line: str) -> NormalizedEvent | None:
    """Convierte una línea Apache/Nginx en formato combined a un evento común."""
    raw = line.rstrip("\n")
    match = WEB_ACCESS.match(raw)
    if not match:
        return None

    try:
        timestamp = datetime.strptime(
            match.group("timestamp"), "%d/%b/%Y:%H:%M:%S %z"
        )
    except ValueError:
        return None

    port_match = DESTINATION_PORT.search(raw)
    return NormalizedEvent(
        timestamp=timestamp,
        source="web",
        event_type="web_request",
        ip=match.group("ip"),
        method=match.group("method"),
        path=match.group("path"),
        status=int(match.group("status")),
        target_port=int(port_match.group("port")) if port_match else None,
        raw=raw,
    )


def parse_firewall_line(line: str, now: datetime | None = None) -> NormalizedEvent | None:
    """Lee líneas UFW que incluyen la IP fuente y el puerto destino observado."""
    raw = line.rstrip("\n")
    prefix = SYSLOG_PREFIX.match(raw)
    if not prefix:
        return None
    connection = FIREWALL_CONNECTION.search(prefix.group("message"))
    if not connection:
        return None

    return NormalizedEvent(
        timestamp=_parse_syslog_timestamp(prefix.group("timestamp"), now=now),
        source="firewall",
        event_type="network_connection",
        ip=connection.group("ip"),
        outcome="blocked" if "UFW BLOCK" in prefix.group("message") else "unknown",
        source_port=(
            int(connection.group("source_port"))
            if connection.group("source_port")
            else None
        ),
        target_port=int(connection.group("target_port")),
        raw=raw,
    )
