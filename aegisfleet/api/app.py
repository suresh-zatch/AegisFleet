"""AegisFleet FastAPI REST backend.

Provides production-ready endpoints for SCC finding ingestion,
scenario simulations, incident queries, and idempotent HITL containment authorization.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
import os
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from aegisfleet.agents.swarm import AegisFleetSwarm
from aegisfleet.config import configure_logging, get_config
from aegisfleet.models.schemas import (
    HITLApprovalRequest,
    SCCFinding,
    ThreatSeverity,
)
from aegisfleet.storage.session_store import get_incident_store

logger = logging.getLogger("aegisfleet.api")

# Initialize configuration
cfg = get_config()
configure_logging(level=cfg.log_level, json_format=cfg.json_logs)

# Initialize FastAPI application
app = FastAPI(
    title="AegisFleet SOC Responder",
    description="Enterprise-grade autonomous Google Cloud Tier 1 SOC response fleet.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Secure CORS Middleware Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=cfg.cors_origins,
    allow_credentials=True if "*" not in cfg.cors_origins else False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Mount static files for dashboard UI
static_dir = os.path.join(os.path.dirname(__file__), "..", "ui", "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Singleton swarm and persistent store
swarm = AegisFleetSwarm(config=cfg)
store = get_incident_store()


@app.on_event("startup")
async def startup_event() -> None:
    """Validate runtime environment and initialize singleton services."""
    try:
        cfg.validate_startup()
        logger.info(
            "AegisFleet SOC API started | project=%s region=%s sandbox=%s model=%s",
            cfg.gcp_project_id,
            cfg.gcp_region,
            cfg.sandbox_mode,
            cfg.gemini_model,
        )
    except Exception as exc:
        logger.critical("Startup validation failed: %s", exc)
        raise exc


# ---------------------------------------------------------------------------
# Dashboard UI
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse, summary="Serve SOC Command Center UI")
async def root() -> HTMLResponse:
    index_path = os.path.join(
        os.path.dirname(__file__), "..", "ui", "static", "index.html"
    )
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(
        content="<h1>AegisFleet SOC — Dashboard HTML file not found</h1>",
        status_code=status.HTTP_404_NOT_FOUND,
    )


# ---------------------------------------------------------------------------
# Health & Diagnostics
# ---------------------------------------------------------------------------

@app.get("/health", summary="Health check endpoint for Cloud Run container probes")
async def health_check() -> Dict[str, Any]:
    return {
        "status": "healthy",
        "service": "aegisfleet-soc",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sandbox_mode": cfg.sandbox_mode,
    }


# ---------------------------------------------------------------------------
# Ingestion & Swarm Investigation
# ---------------------------------------------------------------------------

@app.post(
    "/api/findings/ingest",
    summary="Ingest Google Cloud Security Command Center (SCC) finding",
    status_code=status.HTTP_200_OK,
)
async def ingest_finding(finding: SCCFinding) -> Dict[str, Any]:
    try:
        report = await swarm.investigate(finding)
        return report.model_dump(mode="json")
    except Exception as exc:
        logger.error("Error during finding investigation: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Investigation failed: {exc}",
        )


# ---------------------------------------------------------------------------
# Threat Simulations
# ---------------------------------------------------------------------------

SCENARIOS: Dict[str, Dict[str, Any]] = {
    "compromised_key": {
        "category": "Persistence: New Service Account Key Created",
        "resource_name": (
            "//iam.googleapis.com/projects/aegisfleet-prod/serviceAccounts/"
            "compromised-sa@aegisfleet-prod.iam.gserviceaccount.com/keys/abc123"
        ),
        "severity": ThreatSeverity.CRITICAL,
        "principal_email": "compromised-sa@aegisfleet-prod.iam.gserviceaccount.com",
        "project_id": "aegisfleet-prod",
    },
    "privilege_escalation": {
        "category": "Privilege Escalation: IAM Policy Modified",
        "resource_name": "//cloudresourcemanager.googleapis.com/projects/aegisfleet-prod",
        "severity": ThreatSeverity.CRITICAL,
        "principal_email": "suspicious-user@external-domain.com",
        "project_id": "aegisfleet-prod",
    },
    "data_exfiltration": {
        "category": "Exfiltration: Cloud Storage Data Accessed",
        "resource_name": "//storage.googleapis.com/customer-pii-prod",
        "severity": ThreatSeverity.CRITICAL,
        "principal_email": "data-pipeline-sa@aegisfleet-prod.iam.gserviceaccount.com",
        "project_id": "aegisfleet-prod",
    },
    "crypto_miner": {
        "category": "Malware: Cryptomining Activity",
        "resource_name": (
            "//compute.googleapis.com/projects/aegisfleet-prod/"
            "zones/us-central1-a/instances/suspicious-gpu-instance"
        ),
        "severity": ThreatSeverity.HIGH,
        "principal_email": "compromised-dev@aegisfleet-prod.iam.gserviceaccount.com",
        "project_id": "aegisfleet-prod",
    },
}


@app.post("/api/simulate/{scenario}", summary="Trigger real-time SOC threat simulation")
async def simulate_scenario(scenario: str) -> Dict[str, Any]:
    if scenario not in SCENARIOS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown simulation scenario '{scenario}'. Available options: {list(SCENARIOS.keys())}",
        )

    finding = SCCFinding(**SCENARIOS[scenario])
    try:
        report = await swarm.investigate(finding)
        return report.model_dump(mode="json")
    except Exception as exc:
        logger.error("Simulation error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Simulation error: {exc}",
        )


# ---------------------------------------------------------------------------
# Incident Management
# ---------------------------------------------------------------------------

@app.get("/api/incidents", summary="List historical and active SOC incidents")
async def list_incidents() -> List[Dict[str, Any]]:
    incidents = await store.list_incidents()
    return [inc.model_dump(mode="json") for inc in incidents]


@app.get("/api/incidents/{incident_id}", summary="Retrieve complete incident dossier")
async def get_incident(incident_id: str) -> Dict[str, Any]:
    incident = await store.get_incident(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )
    return incident.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Idempotent HITL Containment Authorization
# ---------------------------------------------------------------------------

@app.post(
    "/api/containment/authorize",
    summary="Authorize and execute staged containment remediation",
)
async def authorize_containment(request: HITLApprovalRequest) -> Dict[str, Any]:
    try:
        response = await swarm.authorize_containment(
            incident_id=request.incident_id,
            command_ids=request.command_ids,
            token=request.authorization_token or "",
        )
        return response.model_dump(mode="json")
    except Exception as exc:
        logger.error("Containment authorization failure: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Containment execution error: {exc}",
        )


# ---------------------------------------------------------------------------
# Swarm Trace Inspection
# ---------------------------------------------------------------------------

@app.get("/api/swarm/status/{incident_id}", summary="Fetch real-time agent execution trace")
async def get_swarm_status(incident_id: str) -> Dict[str, Any]:
    incident = await store.get_incident(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )
    return {
        "incident_id": incident_id,
        "threat_severity": incident.threat_severity,
        "swarm_trace": incident.swarm_trace,
    }


# ---------------------------------------------------------------------------
# Local Server Execution
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=cfg.port)
