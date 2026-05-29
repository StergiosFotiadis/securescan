import os
import re
import json
import glob
from typing import List, Tuple, Optional
# pyrefly: ignore [missing-import]
from anthropic import AsyncAnthropic
from app.schemas.scan import ModuleResult, AIFinding

async def review(repo_path: str, project_types: List[str]) -> ModuleResult:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return ModuleResult(status="error", error="ANTHROPIC_API_KEY is not set")

    api_key = api_key.strip().strip("'\"")
    if not api_key:
        return ModuleResult(status="error", error="ANTHROPIC_API_KEY is not set")

    client = AsyncAnthropic(api_key=api_key)

    target_files = []

    patterns = [
        "**/auth*", "**/login*", "**/jwt*",
        "**/routes*", "**/api*", "**/endpoints*",
        "**/.env*", "**/config*", "**/settings*"
    ]

    for pattern in patterns:
        matches = glob.glob(os.path.join(repo_path, pattern), recursive=True)
        for match in matches:
            if os.path.isfile(match) and "node_modules" not in match and ".git" not in match:
                target_files.append(match)

    if not target_files:
        for pattern in ["**/database*", "**/db*", "**/models*", "**/middleware*"]:
            matches = glob.glob(os.path.join(repo_path, pattern), recursive=True)
            for match in matches:
                if os.path.isfile(match) and "node_modules" not in match and ".git" not in match:
                    target_files.append(match)

    files_content = ""
    for file_path in target_files[:10]:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                rel_path = os.path.relpath(file_path, repo_path)
                files_content += f"\n\n--- File: {rel_path} ---\n\n{content}"
        except Exception:
            continue

    if not files_content:
        return ModuleResult(status="done", ai_output="No sensitive files found to review.", ai_findings=[])

    prompt = f"""You are a security code reviewer. Analyze the following source files and identify security vulnerabilities such as hardcoded credentials, SQL injection, XSS, weak secrets, insecure configurations, and missing input validation.

Return ONLY a JSON array. No markdown fences, no prose, no explanation. Each element must have:
- "file": string — relative file path
- "line": integer or null — best estimate of the vulnerable line number
- "severity": one of "critical", "high", "medium", "low"
- "category": string — e.g. "Hardcoded Secret", "SQL Injection", "XSS", "Weak Cryptography", "Insecure Configuration"
- "description": string — specific description of the vulnerability
- "evidence": string — exact code snippet or pattern that is vulnerable
- "cwe_id": string or null — e.g. "CWE-89" for SQL injection, null if unsure
- "remediation": string — concrete 1-3 sentence fix

If no security issues are found, return an empty array: []

== SOURCE FILES ==
{files_content}
"""

    try:
        response = await client.messages.create(
            model="claude-haiku-4-5",
            max_tokens=4000,
            messages=[{"role": "user", "content": prompt}]
        )

        raw = response.content[0].text
        findings, parse_err = _parse_findings(raw)
        ai_output = _format_as_text(findings) if findings else (parse_err or "No security issues found.")

        return ModuleResult(
            status="done",
            ai_output=ai_output,
            ai_findings=findings,
            error=parse_err if not findings and parse_err else None,
        )

    except Exception as e:
        return ModuleResult(status="error", error=str(e))


def _parse_findings(raw: str) -> Tuple[List[AIFinding], Optional[str]]:
    cleaned = raw.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        return [], f"Claude returned non-JSON output: {raw[:200]}"

    if not isinstance(data, list):
        return [], "Claude returned a JSON value that is not an array"

    findings = []
    for item in data:
        try:
            findings.append(AIFinding(**item))
        except Exception:
            continue
    return findings, None


def _format_as_text(findings: List[AIFinding]) -> str:
    if not findings:
        return "No security issues found."
    lines = [f"Found {len(findings)} issue(s):\n"]
    for i, f in enumerate(findings, 1):
        line_ref = f"line {f.line}" if f.line else "unknown line"
        lines.append(f"{i}. [{f.severity.upper()}] {f.category} — {f.file}:{line_ref}")
        lines.append(f"   {f.description}")
        if f.remediation:
            lines.append(f"   Fix: {f.remediation}")
        lines.append("")
    return "\n".join(lines)
