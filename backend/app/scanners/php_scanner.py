import os
import json
import subprocess
from app.schemas.scan import ModuleResult, Vulnerability


async def scan(repo_path: str) -> ModuleResult:
    """Scan PHP projects for vulnerabilities using local-php-security-checker."""
    try:
        # Check for composer.lock or composer.json
        if not os.path.exists(os.path.join(repo_path, "composer.lock")):
            if os.path.exists(os.path.join(repo_path, "composer.json")):
                # Generate lock file if missing so checker can run
                subprocess.run(
                    ["composer", "lock", "--no-interaction"],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
            else:
                return ModuleResult(status="skipped", vulnerabilities=[])

        # Run local-php-security-checker
        # It returns returncode=1 when vulnerabilities are found, returncode=0 when none
        process = subprocess.run(
            ["local-php-security-checker", "--format=json"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=60,
        )

        output = process.stdout
        
        # returncode=1 is expected when vulns are found. 
        # Only error if output is empty and returncode is non-zero
        if not output and process.returncode != 0:
            return ModuleResult(status="error", error=f"PHP security checker failed: {process.stderr}")
        
        if not output:
            return ModuleResult(status="done", vulnerabilities=[])

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return ModuleResult(status="error", error=f"Failed to parse PHP security checker output: {output}")

        vulns = []
        
        # The tool returns a JSON object where keys are package names
        for pkg_name, pkg_data in data.items():
            # Support both the older format and the one described in the spec
            advisories = pkg_data.get("advisories", []) if isinstance(pkg_data, dict) else []
            version = pkg_data.get("version", "unknown") if isinstance(pkg_data, dict) else "unknown"
            
            for advisory in advisories:
                vulns.append(
                    Vulnerability(
                        package_name=advisory.get("packageName", pkg_name),
                        version=advisory.get("affectedVersions", version),
                        severity=advisory.get("severity", "high"),
                        description=advisory.get("title", "Vulnerability detected"),
                        cve_id=advisory.get("cve") or advisory.get("advisoryId"),
                        scanner_type="php-security-checker"
                    )
                )

        return ModuleResult(status="done", vulnerabilities=vulns)

    except FileNotFoundError:
        return ModuleResult(status="error", error="local-php-security-checker or composer is not installed on the system")
    except subprocess.TimeoutExpired:
        return ModuleResult(status="error", error="PHP security scan timed out")
    except Exception as e:
        return ModuleResult(status="error", error=str(e))
