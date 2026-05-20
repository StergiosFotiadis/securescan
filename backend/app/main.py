import os
# pyrefly: ignore [missing-import]
from fastapi import FastAPI
# pyrefly: ignore [missing-import]
from fastapi.middleware.cors import CORSMiddleware
from app.routers import scan

app = FastAPI(title="SecureScan API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health_check():
    key = os.environ.get("ANTHROPIC_API_KEY")
    return {
        "status": "ok",
        "has_api_key": key is not None,
        "api_key_length": len(key) if key else 0
    }

app.include_router(scan.router)
