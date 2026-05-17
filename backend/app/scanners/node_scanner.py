import os
import json
import subprocess
from app.schemas.scan import ModuleResult, Vulnerability

async def scan(repo_path: str) -> ModuleResult:
    # Run npm audit
    try:
        if not os.path.exists(os.path.join(repo_path, "package-lock.json")) and not os.path.exists(os.path.join(repo_path, "npm-shrinkwrap.json")):
            subprocess.run(
                ["npm", "install", "--package-lock-only"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=120
            )

        process = subprocess.run(
            ["npm", "audit", "--json"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        output = process.stdout
        if not output and process.returncode != 0:
            return ModuleResult(status="error", error=f"npm audit failed: {process.stderr}")
        if not output:
            return ModuleResult(status="done", vulnerabilities=[])

        try:
            audit_data = json.loads(output)
        except json.JSONDecodeError:
            return ModuleResult(status="error", error=f"Failed to parse npm audit output: {output}")

        vulns = []
        if "vulnerabilities" in audit_data:
            for pkg_name, details in audit_data["vulnerabilities"].items():
                severity = details.get("severity", "low")
                # map severities if needed
                if "via" in details and isinstance(details["via"], list) and len(details["via"]) > 0:
                    via = details["via"][0]
                    if isinstance(via, dict):
                        description = via.get("title", f"Vulnerability in {pkg_name}")
                        cve = via.get("url", "")
                    else:
                        description = f"Vulnerability in {pkg_name} via {via}"
                        cve = None
                else:
                    description = f"Vulnerability in {pkg_name}"
                    cve = None
                    
                vulns.append(Vulnerability(
                    package_name=pkg_name,
                    version=details.get("range", "unknown"),
                    severity=severity,
                    description=description,
                    cve_id=cve,
                    scanner_type="npm-audit"
                ))
                
        return ModuleResult(status="done", vulnerabilities=vulns)

    except FileNotFoundError:
        return ModuleResult(status="error", error="npm is not installed on the system")
    except subprocess.TimeoutExpired:
        return ModuleResult(status="error", error="npm audit timed out")
    except Exception as e:
        return ModuleResult(status="error", error=str(e))
