"""Persistencia local del Mini-SIEM mediante SQLite."""

from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Iterator, Sequence

from .models import NormalizedEvent
from .rules import AlertCandidate


class SiemDatabase:
    """Una pequeña capa de datos; SQLite queda en un único archivo local."""

    def __init__(self, path: Path) -> None:
        self.path = path

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.executescript(
                """
                PRAGMA foreign_keys = ON;

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint TEXT NOT NULL UNIQUE,
                    timestamp TEXT NOT NULL,
                    source TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    username TEXT,
                    outcome TEXT NOT NULL,
                    source_port INTEGER,
                    target_port INTEGER,
                    method TEXT,
                    path TEXT,
                    status INTEGER,
                    raw TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_ip_timestamp ON events(ip, timestamp);

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint TEXT NOT NULL UNIQUE,
                    rule_id TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    severity TEXT NOT NULL CHECK(severity IN ('baja', 'media', 'alta')),
                    timestamp TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
                """
            )

    @staticmethod
    def _event_fingerprint(event: NormalizedEvent) -> str:
        payload = json.dumps(event.to_dict(), sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def insert_events(self, events: Sequence[NormalizedEvent]) -> int:
        """Guarda solo entradas nuevas; volver a leer un log no duplica el histórico."""
        inserted = 0
        with self._connection() as connection:
            for event in events:
                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO events (
                        fingerprint, timestamp, source, event_type, ip, username,
                        outcome, source_port, target_port, method, path, status, raw
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self._event_fingerprint(event),
                        event.timestamp.isoformat(),
                        event.source,
                        event.event_type,
                        event.ip,
                        event.username,
                        event.outcome,
                        event.source_port,
                        event.target_port,
                        event.method,
                        event.path,
                        event.status,
                        event.raw,
                    ),
                )
                inserted += cursor.rowcount
        return inserted

    def events_for_detection(self, limit: int = 20000) -> list[dict[str, Any]]:
        """Devuelve los eventos en orden temporal para las reglas de ventana."""
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM (
                    SELECT * FROM events ORDER BY id DESC LIMIT ?
                ) ORDER BY timestamp, id
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def recent_events(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def insert_alerts(self, alerts: Sequence[AlertCandidate]) -> list[AlertCandidate]:
        """Añade alertas no vistas y devuelve únicamente las realmente nuevas."""
        created: list[AlertCandidate] = []
        with self._connection() as connection:
            for alert in alerts:
                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO alerts (
                        fingerprint, rule_id, attack_type, source_ip, severity,
                        timestamp, detail
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert.fingerprint,
                        alert.rule_id,
                        alert.attack_type,
                        alert.source_ip,
                        alert.severity,
                        alert.timestamp.isoformat(),
                        alert.detail,
                    ),
                )
                if cursor.rowcount:
                    created.append(alert)
        return created

    def recent_alerts(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def dashboard_data(self) -> dict[str, Any]:
        """Calcula contadores y series que consume el panel web."""
        events = self.events_for_detection()
        with self._connection() as connection:
            alert_rows = connection.execute(
                "SELECT * FROM alerts ORDER BY timestamp ASC, id ASC"
            ).fetchall()
        alerts = [dict(row) for row in alert_rows]

        severity_counts = Counter(alert["severity"] for alert in alerts)
        hourly = Counter()
        daily = Counter()
        for alert in alerts:
            event_time = datetime.fromisoformat(alert["timestamp"])
            hourly[event_time.strftime("%Y-%m-%d %H:00")] += 1
            daily[event_time.strftime("%Y-%m-%d")] += 1

        ip_counts = Counter(event["ip"] for event in events)
        attack_counts = Counter(alert["attack_type"] for alert in alerts)

        def series(counter: Counter[str]) -> dict[str, list[Any]]:
            labels = sorted(counter)
            return {"labels": labels, "values": [counter[label] for label in labels]}

        top_ips = ip_counts.most_common(10)
        return {
            "total_events": len(events),
            "total_alerts": len(alerts),
            "severity": {
                "alta": severity_counts.get("alta", 0),
                "media": severity_counts.get("media", 0),
                "baja": severity_counts.get("baja", 0),
            },
            "activity": {"hourly": series(hourly), "daily": series(daily)},
            "top_ips": {
                "labels": [ip for ip, _ in top_ips],
                "values": [count for _, count in top_ips],
            },
            "attack_types": series(attack_counts),
        }

