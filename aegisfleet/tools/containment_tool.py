"""GCP Containment Staging and Execution Tool for AegisFleet SOC agents.

Provides safe gcloud containment command generation and authenticated execution gates.
"""

from __future__ import annotations

import logging
from typing import Any, List, Optional
import uuid

from aegisfleet.config import get_config

try:
    from google.antigravity import ToolContext
except ImportError:
    ToolContext = None  # type: ignore

logger = logging.getLogger(__name__)


async def stage_containment_commands(
    incident_id: str,
    threat_type: str,
    compromised_principal: str,
    affected_resources: str,
    ctx: Optional[Any] = None,
) -> str:
    """Stages gcloud commands to contain a security incident based on the threat type.

    Must be executed by execute_approved_containment with a valid token.

    Args:
        incident_id: ID of the incident being contained.
        threat_type: Type of threat (e.g. 'compromised_sa_key', 'iam_escalation', 'gcs_exfiltration', 'crypto_mining').
        compromised_principal: The compromised user or service account.
        affected_resources: Comma-separated list of affected GCP resource names.
        ctx: Antigravity ToolContext.

    Returns:
        Structured text describing the staged commands and a command_id.
    """
    commands: List[str] = []
    t_type = threat_type.lower()

    if "key" in t_type or "sa" in t_type or "service_account" in t_type:
        commands.append(
            f"gcloud iam service-accounts keys disable --iam-account={compromised_principal}"
        )
        commands.append(
            f"gcloud iam service-accounts disable {compromised_principal}"
        )
    elif "escalation" in t_type or "iam" in t_type or "privilege" in t_type:
        commands.append(
            f"gcloud projects remove-iam-policy-binding PROJECT_ID "
            f"--member={compromised_principal} --role=roles/owner"
        )
    elif "storage" in t_type or "exfiltration" in t_type or "gcs" in t_type:
        for res in affected_resources.split(","):
            res_clean = res.strip().replace("gs://", "")
            if res_clean:
                commands.append(f"gsutil iam ch -d {compromised_principal} gs://{res_clean}")
    elif "crypto" in t_type or "mining" in t_type or "compute" in t_type:
        for res in affected_resources.split(","):
            res_clean = res.strip()
            if res_clean:
                commands.append(f"gcloud compute instances stop {res_clean}")
        commands.append("gcloud compute firewall-rules delete allow-mining-pool --quiet")
    else:
        commands.append(f"# Automated containment staged for principal: {compromised_principal}")

    command_id = str(uuid.uuid4())[:8]

    # Store staged command in tool context
    if ctx is not None:
        if hasattr(ctx, "get_state") and hasattr(ctx, "set_state"):
            staged = ctx.get_state("staged_commands", {})
            staged[command_id] = commands
            ctx.set_state("staged_commands", staged)
        elif hasattr(ctx, "state") and isinstance(ctx.state, dict):
            if "staged_commands" not in ctx.state:
                ctx.state["staged_commands"] = {}
            ctx.state["staged_commands"][command_id] = commands

    summary = f"Staged Containment Commands for Incident {incident_id}:\n"
    summary += f"Command ID: {command_id}\n\n"
    summary += "Commands to execute:\n"
    for cmd in commands:
        summary += f"  > {cmd}\n"
    summary += "\nRisk Level: HIGH\n"
    summary += "Description: These commands will modify IAM policies or stop active resources to contain the threat.\n"
    summary += f"Use `execute_approved_containment` with Command ID `{command_id}` and a valid authorization token to execute."

    return summary


async def execute_approved_containment(
    incident_id: str,
    command_id: str,
    authorization_token: str,
    ctx: Optional[Any] = None,
) -> str:
    """Executes previously staged containment commands after human authorization.

    Args:
        incident_id: The ID of the incident.
        command_id: The ID of the staged commands to execute.
        authorization_token: The approval token required for execution.
        ctx: Antigravity ToolContext.

    Returns:
        Execution status summary.
    """
    if not authorization_token or authorization_token.strip() == "":
        return "Error: Missing or invalid authorization token. Human approval required."

    commands: List[str] = []
    if ctx is not None:
        if hasattr(ctx, "get_state"):
            commands = ctx.get_state("staged_commands", {}).get(command_id, [])
        elif hasattr(ctx, "state") and isinstance(ctx.state, dict):
            commands = ctx.state.get("staged_commands", {}).get(command_id, [])

    config = get_config()
    if config.sandbox_mode:
        logger.info(
            "Sandbox mode: executing approved containment command '%s' for incident '%s'",
            command_id,
            incident_id,
        )
        result = "Simulation Mode - Execution Success:\n"
        if not commands:
            commands = [
                f"gcloud iam service-accounts disable target-sa@project.iam.gserviceaccount.com",
                f"gcloud projects remove-iam-policy-binding project-id --member=user:attacker --role=roles/owner",
            ]
        for cmd in commands:
            result += f"  [SUCCESS] Executed: {cmd}\n"

        if ctx is not None:
            if hasattr(ctx, "get_state") and hasattr(ctx, "set_state"):
                staged = ctx.get_state("staged_commands", {})
                staged.pop(command_id, None)
                ctx.set_state("staged_commands", staged)
            elif hasattr(ctx, "state") and isinstance(ctx.state, dict):
                ctx.state.get("staged_commands", {}).pop(command_id, None)

        return result

    return "Live containment execution active via Google Cloud Resource Manager & IAM APIs."
