import os
from typing import List, Dict
from anthropic import AsyncAnthropic
from app.schemas.scan import ModuleResult


async def plan(
    project_types: List[str],
    vulnerabilities: List[Dict],
    ai_review_output: str,
) -> ModuleResult:
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip().strip("'\"")
    if not api_key:
        return ModuleResult(status="error", error="ANTHROPIC_API_KEY is not set")

    has_vulns = len(vulnerabilities) > 0
    has_review = bool(ai_review_output and ai_review_output.strip())
    if not has_vulns and not has_review:
        return ModuleResult(status="done", ai_output=None)

    client = AsyncAnthropic(api_key=api_key)

    vuln_lines = ""
    if has_vulns:
        by_severity = {"critical": [], "high": [], "medium": [], "low": []}
        for v in vulnerabilities:
            sev = (v.get("severity") or "low").lower()
            bucket = by_severity.get(sev, by_severity["low"])
            line = f"  - {v.get('package_name')} v{v.get('version')} [{sev.upper()}]"
            if v.get("cve_id"):
                line += f" ({v['cve_id']})"
            if v.get("scanner_type"):
                line += f" via {v['scanner_type']}"
            bucket.append(line)
        parts = []
        for sev in ("critical", "high", "medium", "low"):
            if by_severity[sev]:
                parts.append(f"{sev.upper()} ({len(by_severity[sev])}):\n" + "\n".join(by_severity[sev]))
        vuln_lines = "\n\n".join(parts)

    sections = []
    if has_vulns:
        sections.append(f"VULNERABLE PACKAGES ({len(vulnerabilities)} total):\n{vuln_lines}")
    if has_review:
        sections.append(f"AI CODE REVIEW FINDINGS:\n{ai_review_output[:3000]}")

    prompt = f"""You are a senior security engineer. Create a concise, prioritized remediation plan based on these scan results for a {', '.join(project_types)} project.

{chr(10).join(sections)}

Format your response exactly like this:

## Overview
One sentence summarising the security posture.

## Priority Actions
Numbered list of the most critical steps to take first.

## Package Fixes
For each vulnerable package group, the exact upgrade/patch command and any migration note. If there are no package vulnerabilities, skip this section.

## Code Fixes
Specific remediation steps for each code issue found in the review. If there are no code issues, skip this section.

## Verification Checklist
Short checklist (checkboxes) to confirm all fixes have been applied.

Keep every bullet tight and actionable. No marketing language."""

    try:
        response = await client.messages.create(
            model="claude-haiku-4-5",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}],
        )
        return ModuleResult(status="done", ai_output=response.content[0].text)
    except Exception as e:
        return ModuleResult(status="error", error=str(e))
