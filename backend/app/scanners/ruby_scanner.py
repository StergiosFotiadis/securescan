import os
import json
import subprocess
from app.schemas.scan import ModuleResult, Vulnerability


async def scan(repo_path: str) -> ModuleResult:
    """Scan Ruby projects for vulnerabilities using bundler-audit."""
    try:
        # Generate Gemfile.lock if missing
        if not os.path.exists(os.path.join(repo_path, "Gemfile.lock")):
            subprocess.run(
                ["bundle", "lock"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=60,
            )

        # Update advisory database first
        subprocess.run(
            ["bundle-audit", "update"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        process = subprocess.run(
            ["bundle-audit", "check", "--format=json"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=60,
        )

        output = process.stdout
        if not output and process.returncode != 0:
            return ModuleResult(status="error", error=f"Bundle audit failed: {process.stderr}")
        if not output:
            return ModuleResult(status="done", vulnerabilities=[])

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return ModuleResult(status="error", error=f"Failed to parse bundle-audit output: {output}")

        vulns = []
        for finding in data.get("results", []):
            # bundle-audit JSON uses snake_case: "unpatched_gem"
            if finding.get("type", "").lower() not in ("unpatched_gem", "unpatchedgem"):
                continue

            gem = finding.get("gem", {})
            advisory = finding.get("advisory", {})

            criticality = (advisory.get("criticality") or "unknown").lower()
            # Map criticality to severity
            severity_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
            severity = severity_map.get(criticality, "high")

            cve = advisory.get("cve") or advisory.get("ghsa") or advisory.get("id")

            vulns.append(
                Vulnerability(
                    package_name=gem.get("name", "unknown"),
                    version=gem.get("version", "unknown"),
                    severity=severity,
                    description=advisory.get("title", "No description available"),
                    cve_id=cve,
                    scanner_type="bundle-audit"
                )
            )

        return ModuleResult(status="done", vulnerabilities=vulns)

    except FileNotFoundError:
        return ModuleResult(status="error", error="bundler-audit or bundle is not installed on the system")
    except subprocess.TimeoutExpired:
        return ModuleResult(status="error", error="bundle-audit timed out")
    except Exception as e:
        return ModuleResult(status="error", error=str(e))
