import os
import json
from datetime import datetime, timezone
from typing import List, Dict, Any

# Stored inside a named Docker volume so history survives container restarts
STORAGE_PATH = os.environ.get("SCAN_HISTORY_PATH", "/app/data/scan_history.json")


def _normalize(repo_url: str) -> str:
    """Normalize repo URL to use as a stable dictionary key."""
    return repo_url.strip().lower().rstrip("/")


def _load() -> Dict[str, Any]:
    if not os.path.exists(STORAGE_PATH):
        return {}
    try:
        with open(STORAGE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save(data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(STORAGE_PATH), exist_ok=True)
    with open(STORAGE_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def get_history(repo_url: str) -> List[Dict[str, str]]:
    """Return all past AI review entries for this repo (oldest first)."""
    data = _load()
    return data.get(_normalize(repo_url), [])


def append_review(repo_url: str, ai_output: str) -> None:
    """Save a new AI review entry for this repo."""
    data = _load()
    key = _normalize(repo_url)
    if key not in data:
        data[key] = []
    data[key].append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ai_output": ai_output,
    })
    _save(data)


def get_all_history() -> Dict[str, Any]:
    """Return a dict mapping each repo URL to its list of reviews."""
    return _load()
