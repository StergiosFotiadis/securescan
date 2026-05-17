import os
import subprocess
import json
from app.schemas.scan import ModuleResult, Vulnerability

async def scan(repo_path: str) -> ModuleResult:
    """Scan Java projects for vulnerabilities using Trivy."""
    try:
        # Check for Java manifest files recursively (up to 2 levels)
        found_java = False
        for root, dirs, files in os.walk(repo_path):
            if any(f in ["pom.xml", "build.gradle", "build.gradle.kts"] for f in files):
                found_java = True
                break
            # Limit depth
            depth = root[len(repo_path):].count(os.sep)
            if depth >= 2:
                dirs[:] = []
        
        if not found_java:
            return ModuleResult(status="skipped", vulnerabilities=[])

        # Trivy fs scan is recursive by default, so pointing it at repo_path is enough
        cmd = ["trivy", "fs", "--format", "json", repo_path]
        
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300 # Java projects can be large
        )

        if process.returncode != 0:
            return ModuleResult(status="error", error=f"Trivy scan failed: {process.stderr}")

        data = json.loads(process.stdout)
        vulns = []

        # Parse Trivy's results
        for result in data.get("Results", []):
            for v in result.get("Vulnerabilities", []):
                severity = v.get("Severity", "high").lower()
                vulns.append(
                    Vulnerability(
                        package_name=v.get("PkgName", "unknown"),
                        version=v.get("InstalledVersion", "unknown"),
                        severity=severity,
                        description=v.get("Title") or v.get("Description") or "No description available",
                        cve_id=v.get("VulnerabilityID"),
                        scanner_type="trivy"
                    )
                )

        return ModuleResult(status="done", vulnerabilities=vulns)

    except FileNotFoundError:
        return ModuleResult(status="error", error="trivy is not installed on the system")
    except subprocess.TimeoutExpired:
        return ModuleResult(status="error", error="trivy scan timed out")
    except Exception as e:
        return ModuleResult(status="error", error=str(e))
