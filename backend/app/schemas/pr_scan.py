# pyrefly: ignore [missing-import]
from pydantic import BaseModel
from typing import List, Optional


class PRScanRequest(BaseModel):
    repo: str
    pr_number: int


class PRFinding(BaseModel):
    file: str
    line: Optional[int] = None
    severity: str
    issue: str
    suggestion: Optional[str] = None


class PRScanResponse(BaseModel):
    status: str
    repo: str
    pr_number: int
    findings: List[PRFinding] = []
