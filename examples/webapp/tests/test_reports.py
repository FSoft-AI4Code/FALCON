import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.routes import handle  # noqa: E402


class ReportsTest(unittest.TestCase):
    def test_lists_stored_reports(self):
        status, body = handle("GET", "/reports")
        self.assertEqual(status, 200)
        self.assertIn("q3-summary.txt", body["reports"])

    def test_unknown_path_is_404(self):
        status, _ = handle("GET", "/missing")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
