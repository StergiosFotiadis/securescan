import os
import json
import re
import shutil
import subprocess
import uuid
from typing import List, Optional, Tuple

# pyrefly: ignore [missing-import]
import httpx
# pyrefly: ignore [missing-import]
from anthropic import AsyncAnthropic

from app.schemas.pr_scan import PRFinding


GITHUB_API = "https://api.github.com"
DEFAULT_KB_REPO = "TechFlow-Labs/ai-library"


async def fetch_pr_diff(repo: str, pr_number: int, token: Optional[str]) -> str:
    headers = {"Accept": "application/vnd.github.diff"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"{GITHUB_API}/repos/{repo}/pulls/{pr_number}"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
        return resp.text


def clone_kb(kb_repo: str, token: str) -> str:
    temp_dir = f"/tmp/securescan_kb_{uuid.uuid4().hex}"
    clone_url = f"https://{token}@github.com/{kb_repo}.git"
    subprocess.run(
        ["git", "clone", "--depth", "1", clone_url, temp_dir],
        check=True,
        capture_output=True,
    )
    return temp_dir


def read_kb_files(kb_path: str) -> str:
    parts: List[str] = []
    for root, _dirs, files in os.walk(kb_path):
        if ".git" in root.split(os.sep):
            continue
        for f in files:
            if not f.endswith(".md"):
                continue
            full = os.path.join(root, f)
            try:
                with open(full, "r", encoding="utf-8") as fp:
                    rel = os.path.relpath(full, kb_path)
                    parts.append(f"--- {rel} ---\n{fp.read()}")
            except Exception:
                continue
    return "\n\n".join(parts)


def cleanup(path: Optional[str]) -> None:
    if path and os.path.exists(path):
        shutil.rmtree(path, ignore_errors=True)


def build_prompt(diff: str, kb_content: str) -> str:
    kb_section = (
        f"\n\n== KNOWLEDGE BASE ==\nUse these rules as your reference for what to flag:\n\n{kb_content}\n"
        if kb_content
        else ""
    )
    return f"""You are a security code reviewer. Analyze the pull request diff below and identify security issues.{kb_section}

Return ONLY a JSON array. No markdown fences, no prose, no explanation. Each element must have:
- "file": string — file path from the diff
- "line": integer or null — line number where the issue occurs (best guess from the diff hunk)
- "severity": one of "low", "medium", "high", "critical"
- "issue": string — concise description of the problem
- "suggestion": string — concrete fix or mitigation the developer should apply

If the diff has no security issues, return an empty array: []

== PR DIFF ==
{diff}
"""


def parse_findings(raw: str) -> Tuple[List[PRFinding], Optional[str]]:
    cleaned = raw.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        return [], f"Claude returned non-JSON output (first 200 chars): {raw[:200]}"

    if not isinstance(data, list):
        return [], "Claude returned a JSON value that is not an array"

    findings: List[PRFinding] = []
    for item in data:
        try:
            findings.append(PRFinding(**item))
        except Exception:
            continue
    return findings, None


async def scan_pr(repo: str, pr_number: int) -> dict:
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip().strip("'\"")
    if not api_key:
        return {
            "status": "failed",
            "findings": [],
            "kb_used": False,
            "error": "ANTHROPIC_API_KEY is not set",
        }

    github_token = os.environ.get("GITHUB_TOKEN", "").strip() or None
    kb_repo = os.environ.get("KNOWLEDGE_BASE_REPO", DEFAULT_KB_REPO).strip() or DEFAULT_KB_REPO

    try:
        diff = await fetch_pr_diff(repo, pr_number, github_token)
    except httpx.HTTPStatusError as e:
        return {
            "status": "failed",
            "findings": [],
            "kb_used": False,
            "error": f"Failed to fetch PR diff (HTTP {e.response.status_code}): {e.response.text[:200]}",
        }
    except Exception as e:
        return {
            "status": "failed",
            "findings": [],
            "kb_used": False,
            "error": f"Failed to fetch PR diff: {e}",
        }

    kb_content = ""
    kb_used = False
    kb_path: Optional[str] = None
    if github_token:
        try:
            kb_path = clone_kb(kb_repo, github_token)
            kb_content = read_kb_files(kb_path)
            kb_used = bool(kb_content)
        except Exception:
            kb_content = ""
            kb_used = False
        finally:
            cleanup(kb_path)

    prompt = build_prompt(diff, kb_content)
    client = AsyncAnthropic(api_key=api_key)

    try:
        response = await client.messages.create(
            model="claude-haiku-4-5",
            max_tokens=4000,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response.content[0].text
    except Exception as e:
        return {
            "status": "failed",
            "findings": [],
            "kb_used": kb_used,
            "error": f"Claude call failed: {e}",
        }

    findings, parse_err = parse_findings(raw)
    return {
        "status": "completed",
        "findings": findings,
        "kb_used": kb_used,
        "error": parse_err,
    }
