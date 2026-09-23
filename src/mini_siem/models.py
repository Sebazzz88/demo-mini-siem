"""Modelo común para los eventos que llegan de fuentes diferentes."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class NormalizedEvent:
    """Una entrada de log convertida a una estructura que el SIEM entiende."""

    timestamp: datetime
    source: str
    event_type: str
    ip: str
    username: str | None = None
    outcome: str = "unknown"
    source_port: int | None = None
    target_port: int | None = None
    method: str | None = None
    path: str | None = None
    status: int | None = None
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Devuelve una versión segura para guardar como JSON."""
        event = asdict(self)
        event["timestamp"] = self.timestamp.isoformat()
        return event

