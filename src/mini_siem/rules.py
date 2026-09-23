"""Reglas transparentes de detección basadas en ventanas de tiempo."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
from typing import Any, Iterable
from urllib.parse import unquote_plus
import re


@dataclass(frozen=True)
class AlertCandidate:
    rule_id: str
    attack_type: str
    source_ip: str
    severity: str
    timestamp: datetime
    detail: str
    fingerprint: str


def _make_alert(
    rule_id: str,
    attack_type: str,
    source_ip: str,
    severity: str,
    timestamp: datetime,
    detail: str,
) -> AlertCandidate:
    identity = "|".join((rule_id, source_ip, timestamp.isoformat(), detail))
    fingerprint = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return AlertCandidate(
        rule_id=rule_id,
        attack_type=attack_type,
        source_ip=source_ip,
        severity=severity,
        timestamp=timestamp,
        detail=detail,
        fingerprint=fingerprint,
    )


def _time(event: dict[str, Any]) -> datetime:
    return datetime.fromisoformat(str(event["timestamp"]))


def _events_by_time(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(events, key=_time)


def detect_ssh_brute_force(events: Iterable[dict[str, Any]]) -> list[AlertCandidate]:
    """Cinco fallos SSH desde una IP en cinco minutos generan una alerta alta."""
    threshold = 5
    interval = timedelta(minutes=5)
    windows: dict[str, deque[datetime]] = defaultdict(deque)
    alerts: list[AlertCandidate] = []

    for event in _events_by_time(events):
        if event.get("event_type") != "ssh_login" or event.get("outcome") != "failed":
            continue
        time = _time(event)
        window = windows[str(event["ip"])]
        while window and time - window[0] > interval:
            window.popleft()
        window.append(time)
        if len(window) == threshold:
            alerts.append(
                _make_alert(
                    "ssh_brute_force",
                    "Fuerza bruta SSH",
                    str(event["ip"]),
                    "alta",
                    time,
                    f"{threshold} inicios de sesión SSH fallidos en {int(interval.total_seconds() / 60)} minutos.",
                )
            )
    return alerts


def detect_port_scan(events: Iterable[dict[str, Any]]) -> list[AlertCandidate]:
    """Cinco puertos destino distintos vistos desde una IP en tres minutos."""
    threshold = 5
    interval = timedelta(minutes=3)
    windows: dict[str, deque[tuple[datetime, int]]] = defaultdict(deque)
    alerts: list[AlertCandidate] = []

    for event in _events_by_time(events):
        target_port = event.get("target_port")
        if event.get("event_type") != "network_connection" or target_port is None:
            continue
        time = _time(event)
        ip = str(event["ip"])
        window = windows[ip]
        while window and time - window[0][0] > interval:
            window.popleft()
        window.append((time, int(target_port)))
        ports = {port for _, port in window}
        if len(ports) == threshold:
            alerts.append(
                _make_alert(
                    "port_scan",
                    "Escaneo de puertos",
                    ip,
                    "alta",
                    time,
                    f"Se observaron {threshold} puertos destino distintos en {int(interval.total_seconds() / 60)} minutos: {', '.join(map(str, sorted(ports)))}.",
                )
            )
    return alerts


def detect_404_spike(events: Iterable[dict[str, Any]]) -> list[AlertCandidate]:
    """Ocho respuestas 404 de la misma IP en cinco minutos indican posible fuzzing."""
    threshold = 8
    interval = timedelta(minutes=5)
    windows: dict[str, deque[datetime]] = defaultdict(deque)
    alerts: list[AlertCandidate] = []

    for event in _events_by_time(events):
        if event.get("event_type") != "web_request" or event.get("status") != 404:
            continue
        time = _time(event)
        ip = str(event["ip"])
        window = windows[ip]
        while window and time - window[0] > interval:
            window.popleft()
        window.append(time)
        if len(window) == threshold:
            alerts.append(
                _make_alert(
                    "web_404_spike",
                    "Pico de errores 404",
                    ip,
                    "media",
                    time,
                    f"{threshold} respuestas HTTP 404 desde la misma IP en {int(interval.total_seconds() / 60)} minutos.",
                )
            )
    return alerts


SQLI_PATTERNS = (
    re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE),
    re.compile(r"\bor\b\s+\d+\s*=\s*\d+", re.IGNORECASE),
    re.compile(r"(?:--|/\*)"),
    re.compile(r"\bdrop\s+table\b", re.IGNORECASE),
)


def detect_sql_injection(events: Iterable[dict[str, Any]]) -> list[AlertCandidate]:
    """Marca URLs con señales frecuentes de inyección SQL, incluso codificadas."""
    alerts: list[AlertCandidate] = []
    for event in _events_by_time(events):
        if event.get("event_type") != "web_request" or not event.get("path"):
            continue
        decoded_path = unquote_plus(str(event["path"]))
        if not any(pattern.search(decoded_path) for pattern in SQLI_PATTERNS):
            continue
        time = _time(event)
        alerts.append(
            _make_alert(
                "sql_injection",
                "Posible inyección SQL",
                str(event["ip"]),
                "alta",
                time,
                f"La URL contiene un patrón SQL sospechoso: {decoded_path[:180]}",
            )
        )
    return alerts


def evaluate_rules(events: Iterable[dict[str, Any]]) -> list[AlertCandidate]:
    """Ejecuta todas las reglas de este proyecto y devuelve candidatas a alerta."""
    event_list = list(events)
    return [
        *detect_ssh_brute_force(event_list),
        *detect_port_scan(event_list),
        *detect_404_spike(event_list),
        *detect_sql_injection(event_list),
    ]

