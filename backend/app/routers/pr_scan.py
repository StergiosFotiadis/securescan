import os
# pyrefly: ignore [missing-import]
from fastapi import APIRouter, Depends, Header, HTTPException

from app.schemas.pr_scan import PRScanRequest, PRScanResponse
from app.scanners import pr_scanner

router = APIRouter()


def verify_api_key(x_api_key: str = Header(default=None, alias="X-API-Key")):
    expected = os.environ.get("SCAN_API_KEY")
    if not expected:
        raise HTTPException(status_code=500, detail="SCAN_API_KEY not configured")
    if not x_api_key or x_api_key != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


@router.post("/scan/pr", response_model=PRScanResponse)
async def scan_pr(
    req: PRScanRequest,
    _: None = Depends(verify_api_key),
):
    result = await pr_scanner.scan_pr(req.repo, req.pr_number)
    return PRScanResponse(
        status=result["status"],
        repo=req.repo,
        pr_number=req.pr_number,
        findings=result["findings"],
        kb_used=result["kb_used"],
        error=result["error"],
    )
