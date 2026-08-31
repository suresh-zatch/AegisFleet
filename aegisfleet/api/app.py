"""AegisFleet FastAPI REST backend (v1.0 -> v2.1 Complete Enterprise Suite).

Endpoints:
- Ingestion & Simulation: GCP, AWS, Azure, Multi-Cloud lateral movement
- HITL Containment: Idempotent authorization & execution
- v1.1 ChatOps: Interactive Slack Block Kit & MS Teams Adaptive Cards with HMAC verification
- v2.1 Rollback: One-click post-containment cloud state restoration
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import os
from typing import Any, Dict, List, Optional

from fastapi import Body, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from aegisfleet.agents.swarm import AegisFleetSwarm
from aegisfleet.config import configure_logging, get_config
from aegisfleet.integrations.slack_teams import (
    generate_slack_block_kit,
    generate_teams_adaptive_card,
    verify_slack_signature,
)
from aegisfleet.models.schemas import (
    CloudProvider,
    HITLApprovalRequest,
    RollbackRequest,
    RollbackResponse,
    SCCFinding,
    ThreatSeverity,
)
from aegisfleet.storage.session_store import get_incident_store

logger = logging.getLogger("aegisfleet.api")

cfg = get_config()
configure_logging(level=cfg.log_level, json_format=cfg.json_logs)

app = FastAPI(
    title="AegisFleet Enterprise Multi-Cloud SOC",
    description="Autonomous Google Cloud, AWS & Azure Tier 1 SOC response fleet with Slack ChatOps & Rollback Engine.",
    version="2.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=cfg.cors_origins,
    allow_credentials=True if "*" not in cfg.cors_origins else False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

static_dir = os.path.join(os.path.dirname(__file__), "..", "ui", "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

swarm = AegisFleetSwarm(config=cfg)
store = get_incident_store()


@app.on_event("startup")
async def startup_event() -> None:
    """Validate runtime environment and log enterprise configuration."""
    cfg.validate_startup()
    logger.info(
        "AegisFleet SOC API started | version=2.1.0 project=%s sandbox=%s",
        cfg.gcp_project_id,
        cfg.sandbox_mode,
    )


# ---------------------------------------------------------------------------
# Dashboard UI & Health Probes
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


@app.get("/health", summary="Health check endpoint for Cloud Run container probes")
async def health_check() -> Dict[str, Any]:
    return {
        "status": "healthy",
        "service": "aegisfleet-soc",
        "version": "2.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sandbox_mode": cfg.sandbox_mode,
        "features": {
            "v1.0_core_swarm": True,
            "v1.1_slack_teams_chatops": True,
            "v2.0_multi_cloud_fabric": True,
            "v2.1_post_containment_rollback": True,
        },
    }


# ---------------------------------------------------------------------------
# Finding Ingestion & Investigations
# ---------------------------------------------------------------------------

@app.post("/api/findings/ingest", summary="Ingest Security Command Center or Multi-Cloud finding")
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
# Threat Simulation Scenarios (GCP + Multi-Cloud AWS & Azure)
# ---------------------------------------------------------------------------

SCENARIOS: Dict[str, Dict[str, Any]] = {
    # v1.0 Core GCP Scenarios
    "compromised_key": {
        "provider": CloudProvider.GCP,
        "category": "Persistence: New Service Account Key Created",
        "resource_name": "//iam.googleapis.com/projects/aegisfleet-prod/serviceAccounts/compromised-sa@aegisfleet-prod.iam.gserviceaccount.com/keys/abc123",
        "severity": ThreatSeverity.CRITICAL,
        "principal_email": "compromised-sa@aegisfleet-prod.iam.gserviceaccount.com",
        "project_id": "aegisfleet-prod",
    },
    "privilege_escalation": {
        "provider": CloudProvider.GCP,
        "category": "Privilege Escalation: IAM Policy Modified",
        "resource_name": "//cloudresourcemanager.googleapis.com/projects/aegisfleet-prod",
        "severity": ThreatSeverity.CRITICAL,
        "principal_email": "suspicious-user@external-domain.com",
        "project_id": "aegisfleet-prod",
    },
    "data_exfiltration": {
        "provider": CloudProvider.GCP,
        "category": "Exfiltration: Cloud Storage Data Accessed",
        "resource_name": "//storage.googleapis.com/customer-pii-prod",
        "severity": ThreatSeverity.CRITICAL,
        "principal_email": "data-pipeline-sa@aegisfleet-prod.iam.gserviceaccount.com",
        "project_id": "aegisfleet-prod",
    },
    "crypto_miner": {
        "provider": CloudProvider.GCP,
        "category": "Malware: Cryptomining Activity",
        "resource_name": "//compute.googleapis.com/projects/aegisfleet-prod/zones/us-central1-a/instances/suspicious-gpu-instance",
        "severity": ThreatSeverity.HIGH,
        "principal_email": "compromised-dev@aegisfleet-prod.iam.gserviceaccount.com",
        "project_id": "aegisfleet-prod",
    },
    # v2.0 Multi-Cloud Fabric Scenarios
    "multi_cloud_lateral_pivot": {
        "provider": CloudProvider.MULTI_CLOUD,
        "category": "Cross-Cloud Lateral Movement: AWS IAM to GCP Workload Identity",
        "resource_name": "arn:aws:iam::123456789012:user/devops-admin",
        "severity": ThreatSeverity.CRITICAL,
        "principal_email": "devops-admin",
        "project_id": "aegisfleet-prod",
    },
    "azure_token_abuse": {
        "provider": CloudProvider.AZURE,
        "category": "Microsoft Entra ID Credential Compromise & Storage Key Extraction",
        "resource_name": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/prod-rg/storageAccounts/prodcustomerdata",
        "severity": ThreatSeverity.HIGH,
        "principal_email": "compromised-admin@company.onmicrosoft.com",
        "project_id": "aegisfleet-prod",
    },
}


@app.post("/api/simulate/{scenario}", summary="Trigger SOC Threat Simulation")
async def simulate_scenario(scenario: str) -> Dict[str, Any]:
    if scenario not in SCENARIOS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown scenario '{scenario}'. Available options: {list(SCENARIOS.keys())}",
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
# Incident Dossiers & Status
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
        "provider": incident.provider,
        "threat_severity": incident.threat_severity,
        "swarm_trace": incident.swarm_trace,
    }


# ---------------------------------------------------------------------------
# HITL Containment Authorization (Idempotent)
# ---------------------------------------------------------------------------

@app.post("/api/containment/authorize", summary="Authorize and execute containment commands")
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
# v2.1: Automated Post-Containment Rollback Engine
# ---------------------------------------------------------------------------

@app.post("/api/containment/rollback", summary="Execute automated rollback of containment mutations")
async def rollback_containment(request: RollbackRequest) -> Dict[str, Any]:
    try:
        response = await swarm.rollback_containment(request)
        return response.model_dump(mode="json")
    except Exception as exc:
        logger.error("Rollback execution error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Rollback error: {exc}",
        )


# ---------------------------------------------------------------------------
# v1.1: Slack & Microsoft Teams ChatOps Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/integrations/slack/preview/{incident_id}", summary="Preview Slack Block Kit JSON card")
async def get_slack_preview(incident_id: str) -> Dict[str, Any]:
    incident = await store.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return generate_slack_block_kit(incident)


@app.get("/api/integrations/teams/preview/{incident_id}", summary="Preview MS Teams Adaptive Card JSON")
async def get_teams_preview(incident_id: str) -> Dict[str, Any]:
    incident = await store.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return generate_teams_adaptive_card(incident)


@app.post("/api/integrations/slack/interactive", summary="Handle interactive Slack Block Kit button callbacks")
async def handle_slack_interactive(
    request: Request,
    x_slack_signature: Optional[str] = Header(None),
    x_slack_request_timestamp: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """Handle interactive Block Kit callbacks with HMAC signature verification."""
    body_bytes = await request.body()
    body_str = body_bytes.decode("utf-8")

    signing_secret = os.getenv("SLACK_SIGNING_SECRET", "")
    is_valid = verify_slack_signature(
        signing_secret=signing_secret,
        timestamp=x_slack_request_timestamp or "",
        body=body_str,
        signature=x_slack_signature or "",
    )

    if not is_valid:
        logger.warning("Rejected unauthenticated Slack interactive request.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Slack signature.")

    # Parse Slack interactive payload (form-urlencoded 'payload={...}')
    try:
        from urllib.parse import parse_qs
        parsed_form = parse_qs(body_str)
        payload_raw = parsed_form.get("payload", ["{}"])[0]
        payload = json.loads(payload_raw)

        actions = payload.get("actions", [])
        if actions:
            action_val = json.loads(actions[0].get("value", "{}"))
            incident_id = action_val.get("incident_id")
            action_type = action_val.get("action")

            if action_type == "AUTHORIZE_ALL" and incident_id:
                incident = await store.get_incident(incident_id)
                if incident:
                    cmd_ids = [c.command_id for c in incident.staged_gcloud_commands]
                    await swarm.authorize_containment(incident_id, cmd_ids, token="SLACK-HITL-VERIFIED-TOKEN")
                    return {"text": f"✅ Successfully executed {len(cmd_ids)} containment commands for incident *{incident_id}*."}

            elif action_type == "ROLLBACK_ALL" and incident_id:
                rollback_req = RollbackRequest(incident_id=incident_id, reason="Triggered via Slack Block Kit Button")
                rollback_resp = await swarm.rollback_containment(rollback_req)
                return {"text": f"🔄 Containment rolled back for incident *{incident_id}*. Status: {rollback_resp.status}."}

    except Exception as exc:
        logger.error("Error processing Slack interactive payload: %s", exc)

    return {"text": "AegisFleet SOC acknowledged callback."}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=cfg.port)
