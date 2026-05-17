import os
import json
import subprocess
from app.schemas.scan import ModuleResult, Vulnerability


def _cvss_to_severity(cvss_str: str | None) -> str:
    """Derive a severity label from a CVSS v3 vector string score."""
    if not cvss_str:
        return "high"
    # CVSS string format: "CVSS:3.1/AV:N/AC:L/..." — no score embedded here.
    # cargo-audit sometimes omits numeric score; default to high.
    return "high"


async def scan(repo_path: str) -> ModuleResult:
    """Scan Rust projects for vulnerabilities using cargo audit."""
    try:
        if not os.path.exists(os.path.join(repo_path, "Cargo.lock")):
            subprocess.run(
                ["cargo", "generate-lockfile"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=120,
            )

        process = subprocess.run(
            ["cargo", "audit", "--json"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=120,
        )

        output = process.stdout
        if not output and process.returncode != 0:
            return ModuleResult(status="error", error=f"Cargo audit failed: {process.stderr}")
        if not output:
            return ModuleResult(status="done", vulnerabilities=[])

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return ModuleResult(status="error", error=f"Failed to parse cargo audit output: {output}")

        vuln_section = data.get("vulnerabilities", {})
        if not vuln_section.get("found", False):
            return ModuleResult(status="done", vulnerabilities=[])

        vulns = []
        for item in vuln_section.get("list", []):
            advisory = item.get("advisory", {})
            package = item.get("package", {})

            aliases = advisory.get("aliases", [])
            cve_id = next((a for a in aliases if a.startswith("CVE-")), advisory.get("id"))

            severity = _cvss_to_severity(advisory.get("cvss"))

            vulns.append(
                Vulnerability(
                    package_name=package.get("name", advisory.get("package", "unknown")),
                    version=package.get("version", "unknown"),
                    severity=severity,
                    description=advisory.get("title", "No description available"),
                    cve_id=cve_id,
                    scanner_type="cargo-audit"
                )
            )

        return ModuleResult(status="done", vulnerabilities=vulns)

    except FileNotFoundError:
        return ModuleResult(status="error", error="cargo is not installed on the system")
    except subprocess.TimeoutExpired:
        return ModuleResult(status="error", error="cargo audit timed out")
    except Exception as e:
        return ModuleResult(status="error", error=str(e))
