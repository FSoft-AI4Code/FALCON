"""Request routing for the reports API."""

import os

from core.storage import REPORTS_DIR


def list_reports():
    """Return the names of the stored reports."""
    return sorted(name for name in os.listdir(REPORTS_DIR) if not name.startswith("."))


def handle(method, path):
    """Route one request and return ``(status, body)``."""
    if method == "GET" and path == "/reports":
        return 200, {"reports": list_reports()}
    return 404, {"error": "not found"}
