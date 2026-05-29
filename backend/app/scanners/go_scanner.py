import json
import subprocess
from app.schemas.scan import ModuleResult, Vulnerability


def _osv_severity(osv: dict) -> str:
    # Prefer explicit severity label from database_specific (Go vuln DB convention)
    db_sev = osv.get("database_specific", {}).get("severity", "")
    if isinstance(db_sev, str) and db_sev.lower() in ("critical", "high", "medium", "low"):
        return db_sev.lower()
    # Fall back to CVSS impact heuristic from severity array
    for entry in osv.get("severity", []):
        score = entry.get("score", "")
        if score:
            return _cvss_vector_to_severity(score)
    return "high"


def _cvss_vector_to_severity(vector: str) -> str:
    parts = {}
    for segment in vector.split("/"):
        if ":" in segment:
            k, v = segment.split(":", 1)
            parts[k] = v
    c, i, a = parts.get("C", "N"), parts.get("I", "N"), parts.get("A", "N")
    highs = sum(1 for x in (c, i, a) if x == "H")
    if highs == 3:
        return "critical"
    if highs >= 1:
        return "high"
    if any(x == "M" for x in (c, i, a)):
        return "medium"
    return "low"


async def scan(repo_path: str) -> ModuleResult:
    """Scan Go projects for vulnerabilities using govulncheck."""
    try:
        # Download dependencies first so govulncheck can analyse the call graph
        subprocess.run(
            ["go", "mod", "download"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=120,
        )

        process = subprocess.run(
            ["govulncheck", "-json", "./..."],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=180,
        )

        output = process.stdout
        if not output and process.returncode != 0:
            return ModuleResult(status="error", error=f"govulncheck failed: {process.stderr}")
        if not output:
            return ModuleResult(status="done", vulnerabilities=[])

        # govulncheck emits newline-delimited JSON (one object per line)
        osv_map: dict = {}   # id -> osv object
        findings: list = []

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            if "osv" in obj:
                osv = obj["osv"]
                osv_map[osv["id"]] = osv

            if "finding" in obj:
                findings.append(obj["finding"])

        vulns = []
        seen = set()
        for finding in findings:
            osv_id = finding.get("osv")
            if osv_id in seen:
                continue
            seen.add(osv_id)

            osv = osv_map.get(osv_id, {})
            aliases = osv.get("aliases", [])
            cve_id = next((a for a in aliases if a.startswith("CVE-")), osv_id)

            # Extract affected module + version from trace
            trace = finding.get("trace", [{}])
            module_info = trace[0] if trace else {}
            module_path = module_info.get("module", "unknown")
            version = module_info.get("version", "unknown")

            severity = _osv_severity(osv)
            vulns.append(
                Vulnerability(
                    package_name=module_path,
                    version=version,
                    severity=severity,
                    description=osv.get("details", "No description available")[:500],
                    cve_id=cve_id,
                    scanner_type="govulncheck"
                )
            )

        return ModuleResult(status="done", vulnerabilities=vulns)

    except FileNotFoundError:
        return ModuleResult(status="error", error="govulncheck or go is not installed on the system")
    except subprocess.TimeoutExpired:
        return ModuleResult(status="error", error="govulncheck timed out")
    except Exception as e:
        return ModuleResult(status="error", error=str(e))
