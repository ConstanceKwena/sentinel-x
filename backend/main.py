
from fastapi import FastAPI

app = FastAPI(
    title="Sentinel-X",
    description="AI-powered attack-chain detection and security operations platform.",
    version="0.1.0",
)


@app.get("/")
def root():
    return {
        "project": "Sentinel-X",
        "status": "online",
        "message": "Sentinel-X API is running.",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
    }