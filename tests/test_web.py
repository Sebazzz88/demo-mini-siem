from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from mini_siem.web import create_app


class WebTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = TemporaryDirectory()
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret",
                "USERNAME": "student",
                "PASSWORD": "safe-test-password",
                "DEFAULT_PASSWORD": False,
                "DATA_DIRECTORY": Path(self.temporary_directory.name),
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temporary_directory.cleanup()

    def login(self):
        return self.client.post(
            "/login",
            data={"username": "student", "password": "safe-test-password"},
            follow_redirects=True,
        )

    def test_dashboard_requires_login(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_demo_is_visible_in_api_after_login(self):
        response = self.login()
        self.assertIn(b"Centro de seguridad", response.data)

        self.client.post("/demo", follow_redirects=True)
        api_response = self.client.get("/api/dashboard")
        data = api_response.get_json()

        self.assertEqual(data["dashboard"]["total_events"], 31)
        self.assertEqual(data["dashboard"]["total_alerts"], 4)
        self.assertEqual(len(data["events"]), 20)
        self.assertIn("firewall", {event["source"] for event in data["events"]})


if __name__ == "__main__":
    unittest.main()
