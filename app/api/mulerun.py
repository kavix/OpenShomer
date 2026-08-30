import os
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request

from app.mulerun.runtime import MuleRunRuntime

router = APIRouter(prefix="/mulerun", tags=["mulerun"])
runtime_instance = MuleRunRuntime()


@router.post("/webhook")
async def handle_github_webhook(
    request: Request,
    x_github_event: str = Header(default="push"),
    x_hub_signature_256: str | None = Header(default=None),
) -> dict[str, Any]:
    """MuleRun GitHub webhook ingestion endpoint."""
    raw_body = await request.body()
    secret = os.getenv("GITHUB_WEBHOOK_SECRET", "")

    try:
        payload = await request.json() if raw_body else {}
    except Exception:
        payload = {}

    payload["event"] = x_github_event

    try:
        result = runtime_instance.process_webhook_event(
            webhook_payload=payload,
            raw_bytes=raw_body,
            secret=secret,
            signature=x_hub_signature_256,
        )
        return {
            "status": "accepted",
            "runtime": "MuleRun",
            "latency_ms": result["latency_ms"],
            "data": result,
        }
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))


@router.get("/telemetry")
def get_live_telemetry():
    """Retrieve runtime telemetry events history."""
    return {
        "count": len(runtime_instance.telemetry_history),
        "events": runtime_instance.telemetry_history[-50:],
    }
