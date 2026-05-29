import os
import shutil
import uuid
import subprocess
from typing import List, Dict
# pyrefly: ignore [missing-import]
from fastapi import APIRouter, HTTPException
from app.schemas.scan import ScanRequest, ScanResponse, PreviousReview, BonusInsights, AIFinding
from app import storage
from app.scanners import (
    detector,
    node_scanner,
    python_scanner,
    java_scanner,
    php_scanner,
    ruby_scanner,
    go_scanner,
    rust_scanner,
    ai_reviewer,
    remediation_planner,
)

router = APIRouter()

# Registry maps ecosystem name → scanner module.
# To add a new ecosystem: create a scanner module and add it here.
SCANNER_REGISTRY = {
    "node":   node_scanner,
    "python": python_scanner,
    "java":   java_scanner,
    "php":    php_scanner,
    "ruby":   ruby_scanner,
    "go":     go_scanner,
    "rust":   rust_scanner,
}


def clone_repo(repo_url: str, token: str = None) -> str:
    temp_dir = f"/tmp/securescan_{uuid.uuid4().hex}"
    
    # Inject token for private repo support if provided
    clone_url = repo_url
    if token:
        if repo_url.startswith("https://"):
            clone_url = repo_url.replace("https://", f"https://{token}@")

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", clone_url, temp_dir],
            check=True,
            capture_output=True,
        )
        return temp_dir
    except subprocess.CalledProcessError as e:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        raise HTTPException(
            status_code=400,
            detail=(
                f"Failed to clone repository. Make sure it's public. "
                f"Error: {e.stderr.decode() if e.stderr else str(e)}"
            ),
        )


def _compute_bonus_insights(
    all_vulns: List[Dict],
    ai_findings: List[AIFinding],
    project_types: List[str],
) -> BonusInsights:
    secret_keywords = {"secret", "credential", "api key", "token", "password", "hardcoded", "private key"}
    secret_found = any(
        any(kw in (f.category or "").lower() or kw in (f.description or "").lower() for kw in secret_keywords)
        for f in ai_findings
    )

    severities = {v.get("severity", "low").lower() for v in all_vulns}
    if "critical" in severities or "high" in severities:
        dep_risk = "HIGH"
    elif "medium" in severities:
        dep_risk = "MEDIUM"
    else:
        dep_risk = "LOW"

    total_dep = len(all_vulns)
    total_code = len(ai_findings)
    critical_dep = sum(1 for v in all_vulns if v.get("severity", "").lower() == "critical")
    surface = (
        f"Scanned a {', '.join(project_types) if project_types else 'unknown'} project. "
        f"Found {total_dep} dependency vulnerabilities ({critical_dep} critical) "
        f"and {total_code} code-level issue(s) from AI review."
    )

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    top_code = min(ai_findings, key=lambda f: order.get(f.severity.lower(), 4), default=None)
    top_dep = min(all_vulns, key=lambda v: order.get(v.get("severity", "low").lower(), 4), default=None)

    if top_code and top_dep:
        if order.get(top_code.severity.lower(), 4) <= order.get(top_dep.get("severity", "low").lower(), 4):
            priority = f"[CODE] {top_code.severity.upper()}: {top_code.description} in {top_code.file}"
        else:
            priority = f"[DEP] {top_dep.get('severity','high').upper()}: {top_dep.get('package_name')} v{top_dep.get('version')} — {top_dep.get('cve_id','')}"
    elif top_code:
        priority = f"[CODE] {top_code.severity.upper()}: {top_code.description} in {top_code.file}"
    elif top_dep:
        priority = f"[DEP] {top_dep.get('severity','high').upper()}: {top_dep.get('package_name')} v{top_dep.get('version')} — {top_dep.get('cve_id','')}"
    else:
        priority = "No issues found."

    return BonusInsights(
        dependency_risk_score=dep_risk,
        secret_exposure_detected=secret_found,
        attack_surface_summary=surface,
        recommended_priority_fix=priority,
    )


def cleanup(repo_path: str) -> None:
    if os.path.exists(repo_path):
        shutil.rmtree(repo_path)


@router.get("/history")
async def get_all_review_history():
    """Return all stored AI review histories for every scanned repo."""
    raw = storage.get_all_history()
    return {
        "repos": [
            {"repo_url": url, "reviews": reviews}
            for url, reviews in raw.items()
        ]
    }


@router.delete("/history")
async def delete_repo_history(repo_url: str):
    """Delete all stored AI reviews for a specific repo."""
    deleted = storage.delete_repo(repo_url)
    if not deleted:
        raise HTTPException(status_code=404, detail="No history found for this repo")
    return {"deleted": True}


@router.get("/vuln-history")
async def get_all_vuln_history():
    """Return all stored vulnerability scan histories for every scanned repo."""
    raw = storage.get_all_vuln_history()
    return {
        "repos": [
            {"repo_url": url, "scans": scans}
            for url, scans in raw.items()
        ]
    }


@router.delete("/vuln-history")
async def delete_vuln_repo_history(repo_url: str):
    """Delete all stored vulnerability scans for a specific repo."""
    deleted = storage.delete_vuln_repo(repo_url)
    if not deleted:
        raise HTTPException(status_code=404, detail="No vulnerability history found for this repo")
    return {"deleted": True}


@router.post("/scan", response_model=ScanResponse)
async def run_scan(request: ScanRequest):
    # Load previous AI reviews for this repo before cloning
    history = storage.get_history(request.repo_url)
    previous_reviews = [PreviousReview(**entry) for entry in history]

    repo_path = clone_repo(request.repo_url, request.github_token)

    try:
        project_types = detector.detect_project_type(repo_path)

        results = {}

        # Run every detected ecosystem through its registered scanner
        for ecosystem, scanner_module in SCANNER_REGISTRY.items():
            if ecosystem in project_types:
                results[ecosystem] = await scanner_module.scan(repo_path)

        # AI code review always runs — it is language-agnostic
        results["ai_review"] = await ai_reviewer.review(repo_path, project_types)

        # Collect all vulnerabilities for remediation planning
        all_vulns = []
        for ecosystem in SCANNER_REGISTRY:
            if ecosystem in project_types:
                module_result = results.get(ecosystem)
                if module_result and module_result.vulnerabilities:
                    for v in module_result.vulnerabilities:
                        all_vulns.append({
                            "package_name": v.package_name,
                            "version": v.version,
                            "severity": v.severity,
                            "description": v.description,
                            "cve_id": v.cve_id,
                            "scanner_type": v.scanner_type,
                        })

        # Generate remediation plan
        ai_review_output = (results["ai_review"].ai_output or "") if results["ai_review"].status == "done" else ""
        remediation_result = await remediation_planner.plan(
            project_types=project_types,
            vulnerabilities=all_vulns,
            ai_review_output=ai_review_output,
        )

        # Persist AI review and plan together
        if results["ai_review"].status == "done" and results["ai_review"].ai_output:
            plan_text = remediation_result.ai_output if remediation_result.status == "done" else None
            storage.append_review(request.repo_url, results["ai_review"].ai_output, plan_text)

        # Persist vulnerability results
        storage.append_vuln_scan(request.repo_url, all_vulns, project_types)

        ai_findings = results["ai_review"].ai_findings if results["ai_review"].status == "done" else []
        bonus_insights = _compute_bonus_insights(all_vulns, ai_findings, project_types)

        return ScanResponse(
            project_types=project_types,
            results=results,
            remediation_plan=remediation_result,
            previous_reviews=previous_reviews,
            bonus_insights=bonus_insights,
        )

    finally:
        cleanup(repo_path)
