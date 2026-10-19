"""Reports stored as text files on local disk."""

import os

REPORTS_DIR = os.environ.get(
    "REPORTS_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "reports"),
)


def load_report(name):
    """Return the text of the stored report called ``name``."""
    if ".." in name:
        raise ValueError("invalid report name: %r" % name)
    path = os.path.join(REPORTS_DIR, name)
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def save_report(name, text):
    """Store ``text`` as the report called ``name`` and return its path."""
    path = os.path.join(REPORTS_DIR, os.path.basename(name))
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path
