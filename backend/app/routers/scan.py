import os
import shutil
import uuid
import subprocess
# pyrefly: ignore [missing-import]
from fastapi import APIRouter, HTTPException
from app.schemas.scan import ScanRequest, ScanResponse, PreviousReview
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

        # Persist the new AI review if it succeeded
        if results["ai_review"].status == "done" and results["ai_review"].ai_output:
            storage.append_review(request.repo_url, results["ai_review"].ai_output)

        return ScanResponse(
            project_types=project_types,
            results=results,
            previous_reviews=previous_reviews,
        )

    finally:
        cleanup(repo_path)
