from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from mini_siem.collector import collect_file
from mini_siem.database import SiemDatabase
from mini_siem.parsers import parse_firewall_line, parse_ssh_line, parse_web_line
from mini_siem.rules import evaluate_rules
from mini_siem.simulator import generate_demo_logs


class RulesAndDatabaseTests(unittest.TestCase):
    def test_demo_triggers_four_rules_and_preserves_history_without_duplicates(self):
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            auth_path, web_path, firewall_path = generate_demo_logs(root / "logs")
            ssh_events, _ = collect_file(auth_path, parse_ssh_line)
            web_events, _ = collect_file(web_path, parse_web_line)
            firewall_events, _ = collect_file(firewall_path, parse_firewall_line)
            database = SiemDatabase(root / "mini_siem.db")
            database.initialize()

            self.assertEqual(database.insert_events(ssh_events + web_events + firewall_events), 31)
            candidates = evaluate_rules(database.events_for_detection())
            created = database.insert_alerts(candidates)

            self.assertEqual(
                {alert.attack_type for alert in created},
                {
                    "Fuerza bruta SSH",
                    "Escaneo de puertos",
                    "Pico de errores 404",
                    "Posible inyección SQL",
                },
            )
            self.assertEqual(len(created), 4)
            self.assertEqual(database.insert_events(ssh_events), 0)
            self.assertEqual(database.insert_alerts(candidates), [])

            dashboard = database.dashboard_data()
            self.assertEqual(dashboard["total_events"], 31)
            self.assertEqual(dashboard["severity"]["alta"], 3)
            self.assertEqual(dashboard["severity"]["media"], 1)


if __name__ == "__main__":
    unittest.main()
