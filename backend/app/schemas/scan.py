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

class AIFinding(BaseModel):
    file: str
    line: Optional[int] = None
    severity: str
    category: str
    description: str
    evidence: Optional[str] = None
    cwe_id: Optional[str] = None
    remediation: Optional[str] = None

class BonusInsights(BaseModel):
    dependency_risk_score: str  # LOW | MEDIUM | HIGH
    secret_exposure_detected: bool
    attack_surface_summary: str
    recommended_priority_fix: str

class ModuleResult(BaseModel):
    status: str
    vulnerabilities: List[Vulnerability] = []
    error: Optional[str] = None
    ai_output: Optional[str] = None
    ai_findings: List[AIFinding] = []

class PreviousReview(BaseModel):
    timestamp: str
    ai_output: str
    plan_output: Optional[str] = None

class ScanResponse(BaseModel):
    project_types: List[str]
    results: Dict[str, ModuleResult]
    remediation_plan: Optional[ModuleResult] = None
    previous_reviews: List[PreviousReview] = []
    bonus_insights: Optional[BonusInsights] = None
