# pyrefly: ignore [missing-import]
from pydantic import BaseModel
from typing import List, Dict, Optional, Any

class ScanRequest(BaseModel):
    repo_url: str
    github_token: Optional[str] = None

class Vulnerability(BaseModel):
    package_name: str
    version: str
    severity: str
    description: str
    cve_id: Optional[str] = None
    scanner_type: Optional[str] = None

class ModuleResult(BaseModel):
    status: str
    vulnerabilities: List[Vulnerability] = []
    error: Optional[str] = None
    ai_output: Optional[str] = None

class ScanResponse(BaseModel):
    project_types: List[str]
    results: Dict[str, ModuleResult]
