"""AegisFleet Pytest Integration & Unit Test Suite."""

import asyncio
from datetime import datetime, timezone
import os
import sys
import pytest

from aegisfleet.agents.swarm import AegisFleetSwarm
from aegisfleet.config import get_config
from aegisfleet.integrations.slack_teams import generate_slack_block_kit, generate_teams_adaptive_card, verify_slack_signature
from aegisfleet.models.schemas import CloudProvider, ContainmentStatus, RollbackRequest, SCCFinding, ThreatSeverity
from aegisfleet.tools.rollback_tool import derive_rollback_command


@pytest.mark.asyncio
async def test_threat_triage_and_mermaid_generation():
    """Verify autonomous triage generates valid incident dossier and Mermaid attack graph."""
    swarm = AegisFleetSwarm()
    finding = SCCFinding(
        provider=CloudProvider.GCP,
        category="Persistence: New Service Account Key Created",
        resource_name="//iam.googleapis.com/projects/aegisfleet-prod/serviceAccounts/compromised-sa@aegisfleet-prod.iam.gserviceaccount.com/keys/abc123",
        severity=ThreatSeverity.CRITICAL,
        principal_email="compromised-sa@aegisfleet-prod.iam.gserviceaccount.com",
    )
    report = await swarm.investigate(finding)
    assert report.incident_id.startswith("INC-")
    assert report.provider == CloudProvider.GCP
    assert len(report.staged_gcloud_commands) >= 1
    assert "graph" in report.mermaid_diagram


@pytest.mark.asyncio
async def test_multi_cloud_lateral_correlation():
    """Verify AWS to GCP cross-cloud correlation (v2.0)."""
    swarm = AegisFleetSwarm()
    finding = SCCFinding(
        provider=CloudProvider.MULTI_CLOUD,
        category="Cross-Cloud Lateral Movement: AWS IAM to GCP Workload Identity",
        resource_name="arn:aws:iam::123456789012:user/devops-admin",
        severity=ThreatSeverity.CRITICAL,
        principal_email="devops-admin",
    )
    report = await swarm.investigate(finding)
    assert report.provider == CloudProvider.MULTI_CLOUD
    assert len(report.attack_path) >= 2


@pytest.mark.asyncio
async def test_hitL_containment_and_anti_replay():
    """Verify HITL containment authorization and anti-replay defense."""
    swarm = AegisFleetSwarm()
    finding = SCCFinding(
        provider=CloudProvider.GCP,
        category="Privilege Escalation: IAM Policy Modified",
        resource_name="//cloudresourcemanager.googleapis.com/projects/aegisfleet-prod",
        severity=ThreatSeverity.CRITICAL,
        principal_email="suspicious-user@external-domain.com",
    )
    report = await swarm.investigate(finding)
    cmd_ids = [c.command_id for c in report.staged_gcloud_commands]

    # First authorization: Must succeed
    resp1 = await swarm.authorize_containment(report.incident_id, cmd_ids, "TOKEN-123")
    assert resp1.status == "COMPLETED"
    assert len(resp1.approved_commands) == len(cmd_ids)

    # Second authorization (Replay): Must reject duplicates
    resp2 = await swarm.authorize_containment(report.incident_id, cmd_ids, "TOKEN-123")
    assert len(resp2.rejected_commands) == len(cmd_ids)


@pytest.mark.asyncio
async def test_rollback_engine():
    """Verify pre-computed reverse command derivation and rollback execution (v2.1)."""
    swarm = AegisFleetSwarm()
    finding = SCCFinding(
        provider=CloudProvider.GCP,
        category="Malware: Cryptomining Activity",
        resource_name="//compute.googleapis.com/projects/aegisfleet-prod/zones/us-central1-a/instances/suspicious-gpu-instance",
        severity=ThreatSeverity.HIGH,
        principal_email="compromised-dev@aegisfleet-prod.iam.gserviceaccount.com",
    )
    report = await swarm.investigate(finding)
    cmd_ids = [c.command_id for c in report.staged_gcloud_commands]

    # Authorize
    await swarm.authorize_containment(report.incident_id, cmd_ids, "TOKEN-123")

    # Rollback
    rollback_req = RollbackRequest(incident_id=report.incident_id, reason="Unit test rollback drill")
    rollback_resp = await swarm.rollback_containment(rollback_req)
    assert rollback_resp.status == "COMPLETED"
    assert len(rollback_resp.rolled_back_commands) == len(cmd_ids)


def test_slack_hmac_signature_verification():
    """Verify cryptographic HMAC-SHA256 signature verification (v1.1)."""
    secret = "test_signing_secret"
    ts = str(int(datetime.now(timezone.utc).timestamp()))
    body = "payload={}"

    import hashlib
    import hmac
    sig_basestring = f"v0:{ts}:{body}".encode("utf-8")
    valid_sig = "v0=" + hmac.new(secret.encode("utf-8"), sig_basestring, hashlib.sha256).hexdigest()

    assert verify_slack_signature(secret, ts, body, valid_sig) is True
    assert verify_slack_signature(secret, ts, body, "v0=forged_signature") is False


def test_derive_rollback_commands():
    """Test deterministic derivation of rollback CLI commands."""
    gcloud_disable = "gcloud iam service-accounts disable my-sa@proj.iam.gserviceaccount.com --project=proj"
    rb1 = derive_rollback_command(gcloud_disable)
    assert "enable" in rb1

    compute_stop = "gcloud compute instances stop my-vm --zone=us-central1-a"
    rb2 = derive_rollback_command(compute_stop)
    assert "start" in rb2
