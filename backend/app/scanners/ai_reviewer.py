import os
import glob
from typing import List
# pyrefly: ignore [missing-import]
from anthropic import AsyncAnthropic
from app.schemas.scan import ModuleResult

async def review(repo_path: str, project_types: List[str]) -> ModuleResult:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return ModuleResult(status="error", error="ANTHROPIC_API_KEY is not set")
    
    # Strip any accidental whitespaces or quotes
    api_key = api_key.strip().strip("'\"")
    if not api_key:
         return ModuleResult(status="error", error="ANTHROPIC_API_KEY is not set")
         
    client = AsyncAnthropic(api_key=api_key)
    
    # Select files based on priority
    target_files = []
    
    patterns = [
        "**/auth*", "**/login*", "**/jwt*", 
        "**/routes*", "**/api*", "**/endpoints*", 
        "**/.env*", "**/config*", "**/settings*"
    ]
    
    for pattern in patterns:
        matches = glob.glob(os.path.join(repo_path, pattern), recursive=True)
        for match in matches:
            if os.path.isfile(match) and not "node_modules" in match and not ".git" in match:
                target_files.append(match)
                
    # If no files found, add some generic files
    if not target_files:
        patterns_2 = ["**/database*", "**/db*", "**/models*", "**/middleware*"]
        for pattern in patterns_2:
            matches = glob.glob(os.path.join(repo_path, pattern), recursive=True)
            for match in matches:
                if os.path.isfile(match) and not "node_modules" in match and not ".git" in match:
                    target_files.append(match)
    
    # Read files to send
    files_content = ""
    for file_path in target_files[:10]:  # Limit to 10 files to avoid huge requests
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                rel_path = os.path.relpath(file_path, repo_path)
                files_content += f"\n\n--- File: {rel_path} ---\n\n{content}"
        except Exception:
            continue
            
    if not files_content:
         return ModuleResult(status="done", ai_output="No highly sensitive files found to review.")

    prompt = f"""
    You are a security expert. Review the following code files from a repository and identify potential security vulnerabilities like hardcoded credentials, SQL injection, XSS, weak secrets, missing input validation, etc.
    Return your analysis highlighting specific files and lines where issues are found. Keep it concise.
    
    Code:
    {files_content}
    """
    
    try:
        response = await client.messages.create(
            model="claude-3-5-sonnet-20240620",
            max_tokens=4000,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        return ModuleResult(status="done", ai_output=response.content[0].text)
        
    except Exception as e:
        return ModuleResult(status="error", error=str(e))
