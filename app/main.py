from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.findings import router as findings_router
from app.api.mulerun import router as mulerun_router

app = FastAPI(
    title="OpenShomer API",
    description="Autonomous Agentic Security Engineer for LLM prompts, agent configs, tool definitions, and MCP servers.",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(findings_router)
app.include_router(mulerun_router)


@app.get("/health", tags=["system"])
def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "OpenShomer", "version": "0.1.0"}

