import os
import json
from datetime import datetime, timezone
from typing import List, Dict, Any

STORAGE_PATH = os.environ.get("SCAN_HISTORY_PATH", "/app/data/scan_history.json")
VULN_HISTORY_PATH = os.environ.get("VULN_HISTORY_PATH", "/app/data/vuln_history.json")


def _normalize(repo_url: str) -> str:
    return repo_url.strip().lower().rstrip("/")


def _load(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save(path: str, data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# ── AI Review History ─────────────────────────────────────────────────────────

def get_history(repo_url: str) -> List[Dict[str, str]]:
    data = _load(STORAGE_PATH)
    return data.get(_normalize(repo_url), [])


def append_review(repo_url: str, ai_output: str) -> None:
    data = _load(STORAGE_PATH)
    key = _normalize(repo_url)
    if key not in data:
        data[key] = []
    data[key].append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ai_output": ai_output,
    })
    _save(STORAGE_PATH, data)


def get_all_history() -> Dict[str, Any]:
    return _load(STORAGE_PATH)


def delete_repo(repo_url: str) -> bool:
    data = _load(STORAGE_PATH)
    key = _normalize(repo_url)
    if key not in data:
        return False
    del data[key]
    _save(STORAGE_PATH, data)
    return True


# ── Vulnerability History ─────────────────────────────────────────────────────

def append_vuln_scan(repo_url: str, vulnerabilities: List[Dict], project_types: List[str]) -> None:
    data = _load(VULN_HISTORY_PATH)
    key = _normalize(repo_url)
    if key not in data:
        data[key] = []
    data[key].append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "project_types": project_types,
        "vulnerabilities": vulnerabilities,
    })
    _save(VULN_HISTORY_PATH, data)


def get_all_vuln_history() -> Dict[str, Any]:
    return _load(VULN_HISTORY_PATH)


def delete_vuln_repo(repo_url: str) -> bool:
    data = _load(VULN_HISTORY_PATH)
    key = _normalize(repo_url)
    if key not in data:
        return False
    del data[key]
    _save(VULN_HISTORY_PATH, data)
    return True
