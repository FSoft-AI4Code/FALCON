"""Resolve a chosen model label to what the Agent tool's ``model`` accepts.

The settings dropdown lists model names (``Opus 5.5``, ``Sonnet 5``, …). The
Agent tool takes a family alias (``opus``, ``sonnet``, ``haiku``), which runs
the newest model of that family. A label naming the newest model of its family,
by Claude Code's live model catalog (``<config>/cache/model-catalog/``), maps
to the alias; an older one maps to its concrete model id. When the catalog is
unavailable, or a label is not in it, the mapping falls back to the family.

The Fable family is never resolved.
"""

from __future__ import annotations

import glob
import json
import os
import re
from typing import Any, Dict, List, Optional

_FAMILIES = ("opus", "sonnet", "haiku")


def _config_dir() -> str:
    override = os.environ.get("CLAUDE_CONFIG_DIR")
    if override:
        return os.path.expanduser(override)
    return os.path.join(os.path.expanduser("~"), ".claude")


def _catalog_file() -> Optional[str]:
    files = glob.glob(os.path.join(_config_dir(), "cache", "model-catalog", "*.json"))
    return max(files, key=os.path.getmtime) if files else None


def _is_fable(blob: str) -> bool:
    return "fable" in blob.lower()


def list_models() -> List[Dict[str, Any]]:
    """Return the live, non-Fable models as ``{id, name, quick_select, section}``.

    Empty when the catalog cannot be read.
    """
    path = _catalog_file()
    if not path:
        return []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            models = json.load(handle)["catalog"]["config"]["models"]
    except (OSError, ValueError, KeyError, TypeError):
        return []
    out: List[Dict[str, Any]] = []
    for model in models:
        if not isinstance(model, dict):
            continue
        if _is_fable(str(model.get("id", "")) + str(model.get("name", ""))):
            continue
        out.append({
            "id": model.get("id"),
            "name": model.get("name"),
            "quick_select": bool(model.get("quick_select")),
            "section": model.get("section"),
        })
    return out


def _family_of(token: str) -> Optional[str]:
    for family in _FAMILIES:
        if family in token:
            return family
    return None


def _alias_if_newest(model_id: str, models: List[Dict[str, Any]]) -> str:
    """The family alias when ``model_id`` is the newest of its family, else the id."""
    named = [m for m in models if m.get("id") == model_id]
    family = _family_of(str(named[0].get("name", "")).lower()) if named else None
    if not family:
        return model_id
    candidates = [m for m in models if str(m.get("name", "")).lower().startswith(family)]
    newest = ([m for m in candidates if m.get("quick_select")] or candidates)[0]
    return family if newest.get("id") == model_id else model_id


def resolve(token: str) -> Optional[str]:
    """Map a dropdown label / alias / id to the Agent tool ``model`` value.

    ``main coding agent`` -> ``main`` (inline). A catalog name (``Opus 5.5``), a
    model id, or a family alias resolve to the family alias when they name the
    newest model of the family, and to the model id otherwise. A versioned label
    with no catalog match falls back to its family alias. Fable and anything
    unrecognised return ``None``.
    """
    if not token:
        return None
    norm = token.strip().lower()
    if norm in ("main", "main coding agent", "inline"):
        return "main"
    if _is_fable(norm):
        return None

    models = list_models()
    squished = re.sub(r"[\s_-]+", "", norm)

    for model in models:
        if norm == str(model.get("id", "")).lower():
            return _alias_if_newest(model["id"], models)
    for model in models:
        if squished == re.sub(r"[\s_-]+", "", str(model.get("name", "")).lower()):
            return _alias_if_newest(model["id"], models)

    # A bare family is its own alias (the newest model of the family); a
    # versioned label with no catalog match falls back to its family.
    return norm if norm in _FAMILIES else _family_of(norm)
