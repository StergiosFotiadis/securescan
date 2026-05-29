import os
import re
import shutil
import subprocess
import uuid
from typing import List, Optional, Tuple

# pyrefly: ignore [missing-import]
import httpx
# pyrefly: ignore [missing-import]
from langchain_anthropic import ChatAnthropic  # type: ignore[import-untyped]
from pydantic import BaseModel

from app.schemas.pr_scan import PRFinding


GITHUB_API = "https://api.github.com"
DEFAULT_KB_REPO = "TechFlow-Labs/techflowlabs-knowledge"
KB_SECURITY_SUBPATH = os.path.join("Software Dev", "Security")

IGNORED_DIFF_EXTENSIONS = {
    ".lock", ".css", ".scss", ".sass", ".less",
    ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp",
    ".md", ".txt", ".rst", ".pdf", ".map",
}

IGNORED_DIFF_FILENAMES = {
    "package-lock.json", "yarn.lock", "poetry.lock",
    "Gemfile.lock", "Cargo.lock", "go.sum",
}


class _FindingsList(BaseModel):
    findings: List[PRFinding]


async def fetch_pr_diff(repo: str, pr_number: int, token: Optional[str]) -> str:
    headers = {"Accept": "application/vnd.github.diff"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"{GITHUB_API}/repos/{repo}/pulls/{pr_number}"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
        return resp.text


def filter_diff(diff: str) -> str:
    sections = re.split(r"(?=^diff --git )", diff, flags=re.MULTILINE)
    kept = []
    for section in sections:
        if not section.strip():
            continue
        match = re.match(r"^diff --git a/(.+?) b/", section)
        if not match:
            kept.append(section)
            continue
        filepath = match.group(1)
        filename = os.path.basename(filepath)
        ext = os.path.splitext(filename)[1].lower()
        if ext in IGNORED_DIFF_EXTENSIONS or filename in IGNORED_DIFF_FILENAMES:
            continue
        kept.append(section)
    return "".join(kept)


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
    security_path = os.path.join(kb_path, KB_SECURITY_SUBPATH)
    if not os.path.isdir(security_path):
        return ""
    parts: List[str] = []
    for root, _dirs, files in os.walk(security_path):
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
    return f"""You are a security code reviewer. Analyze the pull request diff below and identify security issues. For each issue provide the file path, line number if identifiable, severity (low/medium/high/critical), a concise description of the problem, and a concrete suggestion to fix it. If there are no issues return an empty findings list.{kb_section}

== PR DIFF ==
{diff}
"""


async def _call_claude(prompt: str, api_key: str) -> Tuple[List[PRFinding], Optional[str]]:
    model = ChatAnthropic(
        model="claude-haiku-4-5",
        max_tokens=4000,
        api_key=api_key,
    ).with_structured_output(_FindingsList)
    try:
        result = await model.ainvoke(prompt)
        return result.findings, None
    except Exception as e:
        return [], str(e)


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
        raw_diff = await fetch_pr_diff(repo, pr_number, github_token)
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

    diff = filter_diff(raw_diff)
    if not diff.strip():
        return {"status": "completed", "findings": [], "kb_used": False, "error": None}

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
    findings, error = await _call_claude(prompt, api_key)

    return {
        "status": "completed" if error is None else "failed",
        "findings": findings,
        "kb_used": kb_used,
        "error": error,
    }
