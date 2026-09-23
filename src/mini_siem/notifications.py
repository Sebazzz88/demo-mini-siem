"""Notificaciones opcionales para alertas de severidad alta."""

from __future__ import annotations

import json
import os
from typing import Iterable
from urllib.request import Request, urlopen

from .rules import AlertCandidate


class TelegramNotifier:
    """Envía avisos solo si el usuario configuró explícitamente su bot local."""

    def __init__(self, bot_token: str | None, chat_id: str | None) -> None:
        self.bot_token = bot_token
        self.chat_id = chat_id

    @classmethod
    def from_environment(cls) -> "TelegramNotifier":
        return cls(
            os.environ.get("MINISIEM_TELEGRAM_BOT_TOKEN"),
            os.environ.get("MINISIEM_TELEGRAM_CHAT_ID"),
        )

    @property
    def configured(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    def notify_high_alerts(self, alerts: Iterable[AlertCandidate]) -> tuple[int, list[str]]:
        """Envía una alerta por mensaje; si no hay token, no realiza ninguna red."""
        high_alerts = [alert for alert in alerts if alert.severity == "alta"]
        if not high_alerts or not self.configured:
            return 0, []

        sent = 0
        errors: list[str] = []
        for alert in high_alerts:
            body = {
                "chat_id": self.chat_id,
                "text": (
                    "🚨 Mini-SIEM · Alerta alta\n"
                    f"Tipo: {alert.attack_type}\n"
                    f"IP: {alert.source_ip}\n"
                    f"Hora: {alert.timestamp.isoformat()}\n"
                    f"Detalle: {alert.detail}"
                ),
            }
            request = Request(
                f"https://api.telegram.org/bot{self.bot_token}/sendMessage",
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urlopen(request, timeout=8) as response:
                    if 200 <= response.status < 300:
                        sent += 1
                    else:
                        errors.append(f"Telegram respondió HTTP {response.status}.")
            except OSError as error:
                errors.append(f"No se pudo enviar a Telegram: {error}")
        return sent, errors

