import os
import subprocess
import json
from app.schemas.scan import ModuleResult, Vulnerability

async def scan(repo_path: str) -> ModuleResult:
    """Scan Python projects for vulnerabilities using pip-audit."""
    try:
        # Base command with no progress to keep stdout clean for JSON
        cmd = ["pip-audit", "-f", "json", "--progress-spinner", "off"]
        
        # Check for various requirement sources
        req_paths = []
        if os.path.exists(os.path.join(repo_path, "requirements.txt")):
            req_paths.append("requirements.txt")
        elif not os.path.exists(os.path.join(repo_path, "pyproject.toml")) and \
             not os.path.exists(os.path.join(repo_path, "setup.py")):
            # Only search for requirements*.txt if no standard config exists
            for root, dirs, files in os.walk(repo_path):
                for file in files:
                    if file.startswith("requirements") and file.endswith(".txt"):
                        req_paths.append(os.path.relpath(os.path.join(root, file), repo_path))
                break

        if req_paths:
            for path in req_paths:
                cmd.extend(["-r", path])

        process = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=180
        )
        
        output = process.stdout.strip()
        
        if not output:
            if process.returncode != 0:
                return ModuleResult(status="error", error=f"pip-audit failed: {process.stderr}")
            return ModuleResult(status="done", vulnerabilities=[])

        # Robust JSON extraction
        try:
            audit_data = json.loads(output)
        except json.JSONDecodeError:
            # If direct load fails, try to find the JSON block
            # (pip-audit sometimes prepends/appends non-JSON messages)
            try:
                start_chars = ('[', '{')
                end_chars = (']', '}')
                
                start_idx = min([output.find(c) for c in start_chars if output.find(c) != -1] or [0])
                end_idx = max([output.rfind(c) for c in end_chars if output.rfind(c) != -1] or [len(output)])
                
                if end_idx > start_idx:
                    audit_data = json.loads(output[start_idx:end_idx+1])
                else:
                    raise ValueError("No JSON block found")
            except Exception as e:
                return ModuleResult(status="error", error=f"JSON parsing failed: {str(e)}. Output: {output[:100]}...")

        vulns = []
        # Support both list-style and dict-style output
        items = audit_data if isinstance(audit_data, list) else audit_data.get("dependencies", [])
        
        for dep in items:
            dep_name = dep.get("name", "unknown")
            version = dep.get("version", "unknown")
            
            for v in dep.get("vulns", []):
                raw_sev = (v.get("severity") or "high").lower()
                severity = raw_sev if raw_sev in ("critical", "high", "medium", "low") else "high"
                vulns.append(Vulnerability(
                    package_name=dep_name,
                    version=version,
                    severity=severity,
                    description=v.get("description", "Vulnerability detected"),
                    cve_id=v.get("id", "Unknown"),
                    scanner_type="pip-audit"
                ))
                    
        return ModuleResult(status="done", vulnerabilities=vulns)

    except FileNotFoundError:
        return ModuleResult(status="error", error="pip-audit not found")
    except Exception as e:
        return ModuleResult(status="error", error=str(e))
