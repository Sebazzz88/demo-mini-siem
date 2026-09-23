"""Arranca el panel web local del Mini-SIEM."""

from pathlib import Path
import os
import sys

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from mini_siem.web import create_app  # noqa: E402


def load_local_environment() -> None:
    """Carga un .env simple sin añadir otra dependencia a este proyecto."""
    env_file = PROJECT_ROOT / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        os.environ.setdefault(name.strip(), value.strip().strip('"').strip("'"))


if __name__ == "__main__":
    load_local_environment()
    print("DEBUG usuario:", os.environ.get("MINISIEM_USERNAME"))
    print("DEBUG password:", os.environ.get("MINISIEM_PASSWORD"))
    app = create_app()
    port = int(os.environ.get("MINISIEM_PORT", "5000"))
    # 127.0.0.1 limita el panel al propio equipo. No se publica en la red.
    app.run(host="127.0.0.1", port=port, debug=False)
