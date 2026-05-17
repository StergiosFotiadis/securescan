import os

def detect_project_type(repo_path: str) -> list[str]:
    """
    Detect which ecosystems are present in the cloned repository
    by checking for well-known manifest files recursively (up to 2 levels deep).
    """
    detected = set()
    
    # Map of manifest files to ecosystem types
    manifests = {
        "package.json": "node",
        "requirements.txt": "python",
        "pyproject.toml": "python",
        "setup.py": "python",
        "pom.xml": "java",
        "build.gradle": "java",
        "build.gradle.kts": "java",
        "composer.json": "php",
        "Gemfile": "ruby",
        "go.mod": "go",
        "Cargo.toml": "rust",
        "Dockerfile": "docker"
    }

    # Walk up to 2 levels deep
    base_depth = repo_path.rstrip(os.path.sep).count(os.path.sep)
    
    for root, dirs, files in os.walk(repo_path):
        current_depth = root.rstrip(os.path.sep).count(os.path.sep)
        if current_depth - base_depth > 2:
            # Skip deeper directories to avoid performance hits on massive repos
            dirs[:] = [] # stop recursion
            continue
            
        for file in files:
            if file in manifests:
                detected.add(manifests[file])

    return list(detected)
