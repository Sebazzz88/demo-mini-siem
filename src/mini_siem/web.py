"""Interfaz web local del Mini-SIEM."""

from __future__ import annotations

from functools import wraps
import hmac
import os
from pathlib import Path
import secrets
from typing import Any, Callable

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for

from .collector import collect_file
from .database import SiemDatabase
from .models import NormalizedEvent
from .notifications import TelegramNotifier
from .parsers import parse_firewall_line, parse_ssh_line, parse_web_line
from .rules import evaluate_rules
from .simulator import generate_demo_logs


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    """Crea el panel, la base SQLite y las rutas locales de Mini-SIEM."""
    app = Flask(__name__)
    configured_password = os.environ.get("MINISIEM_PASSWORD", "cambia-esta-clave")
    configured_roots = os.environ.get("MINISIEM_LOG_DIRECTORIES", "/var/log")
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("MINISIEM_SECRET_KEY", secrets.token_hex(32)),
        USERNAME=os.environ.get("MINISIEM_USERNAME", "admin"),
        PASSWORD=configured_password,
        DEFAULT_PASSWORD=configured_password == "cambia-esta-clave",
        DATA_DIRECTORY=PROJECT_ROOT / "instance",
        ALLOWED_LOG_DIRECTORIES=[Path(root) for root in configured_roots.split(os.pathsep) if root],
    )
    if test_config:
        app.config.update(test_config)

    data_directory = Path(app.config["DATA_DIRECTORY"])
    data_directory.mkdir(parents=True, exist_ok=True)
    database = SiemDatabase(data_directory / "mini_siem.db")
    database.initialize()
    notifier = TelegramNotifier.from_environment()
    app.extensions["siem_database"] = database

    def login_required(view: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view)
        def wrapped_view(*args: Any, **kwargs: Any) -> Any:
            if session.get("user") != app.config["USERNAME"]:
                return redirect(url_for("login"))
            return view(*args, **kwargs)

        return wrapped_view

    def allowed_log_path(value: str) -> Path | None:
        """Solo permite rutas que el usuario configuró como fuentes de logs."""
        if not value:
            return None
        try:
            candidate = Path(value).expanduser().resolve()
            for root in app.config["ALLOWED_LOG_DIRECTORIES"]:
                try:
                    candidate.relative_to(Path(root).expanduser().resolve())
                    return candidate
                except ValueError:
                    continue
        except OSError:
            return None
        return None

    def ingest(events: list[NormalizedEvent]) -> tuple[int, int, int, list[str]]:
        """Guarda eventos, reevalúa reglas y notifica únicamente alertas nuevas."""
        new_events = database.insert_events(events)
        candidates = evaluate_rules(database.events_for_detection())
        new_alerts = database.insert_alerts(candidates)
        sent, notification_errors = notifier.notify_high_alerts(new_alerts)
        return new_events, len(new_alerts), sent, notification_errors

    @app.get("/login")
    def login() -> str:
        if session.get("user") == app.config["USERNAME"]:
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    @app.post("/login")
    def login_submit() -> Any:
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user_matches = hmac.compare_digest(username, app.config["USERNAME"])
        password_matches = hmac.compare_digest(password, app.config["PASSWORD"])
        if not (user_matches and password_matches):
            flash("Usuario o contraseña incorrectos.", "error")
            return redirect(url_for("login"))

        session.clear()
        session["user"] = username
        return redirect(url_for("dashboard"))

    @app.post("/logout")
    @login_required
    def logout() -> Any:
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    @login_required
    def dashboard() -> str:
        return render_template(
            "dashboard.html",
            dashboard=database.dashboard_data(),
            events=database.recent_events(12),
            alerts=database.recent_alerts(10),
            default_password=app.config["DEFAULT_PASSWORD"],
            telegram_configured=notifier.configured,
        )

    @app.post("/demo")
    @login_required
    def create_demo() -> Any:
        auth_path, web_path, firewall_path = generate_demo_logs(data_directory / "demo_logs")
        ssh_events, _ = collect_file(auth_path, parse_ssh_line)
        web_events, _ = collect_file(web_path, parse_web_line)
        firewall_events, _ = collect_file(firewall_path, parse_firewall_line)
        new_events, new_alerts, sent, errors = ingest(ssh_events + web_events + firewall_events)
        flash(f"Demo procesada: {new_events} eventos nuevos y {new_alerts} alertas nuevas.", "success")
        if sent:
            flash(f"Telegram recibió {sent} notificaciones de severidad alta.", "success")
        for error in errors:
            flash(error, "error")
        return redirect(url_for("dashboard"))

    @app.post("/collect")
    @login_required
    def collect_logs() -> Any:
        requested_sources = (
            ("SSH", request.form.get("auth_log_path", ""), parse_ssh_line),
            ("web", request.form.get("web_log_path", ""), parse_web_line),
            ("firewall", request.form.get("firewall_log_path", ""), parse_firewall_line),
        )
        events: list[NormalizedEvent] = []
        valid_source_requested = False
        for source_name, raw_path, parser in requested_sources:
            if not raw_path.strip():
                continue
            path = allowed_log_path(raw_path.strip())
            if path is None:
                flash(f"La ruta de {source_name} no pertenece a una carpeta permitida.", "error")
                continue
            valid_source_requested = True
            try:
                collected, skipped = collect_file(path, parser)
            except OSError as error:
                flash(f"No se pudo leer {path}: {error}", "error")
                continue
            events.extend(collected)
            flash(f"{source_name}: {len(collected)} eventos leídos; {skipped} líneas omitidas.", "success")

        if not any(value.strip() for _, value, _ in requested_sources):
            flash("Indica al menos un archivo de log o usa la demo.", "error")
        elif events:
            new_events, new_alerts, sent, errors = ingest(events)
            flash(f"Histórico actualizado: {new_events} eventos y {new_alerts} alertas nuevas.", "success")
            if sent:
                flash(f"Telegram recibió {sent} notificaciones de severidad alta.", "success")
            for error in errors:
                flash(error, "error")
        elif valid_source_requested:
            flash("No se encontraron líneas reconocidas en los archivos indicados.", "error")
        return redirect(url_for("dashboard"))

    @app.get("/api/dashboard")
    @login_required
    def api_dashboard() -> Any:
        return jsonify({"dashboard": database.dashboard_data(), "alerts": database.recent_alerts(15), "events": database.recent_events(20)})

    return app

