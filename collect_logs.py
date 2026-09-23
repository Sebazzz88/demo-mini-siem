"""Punto de entrada del recolector del Módulo 1."""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from mini_siem.collector import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())

