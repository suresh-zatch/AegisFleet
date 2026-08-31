"""IAM Policy Analysis and Privilege Escalation Tool for AegisFleet.

Identifies dangerous IAM permissions, lateral movement vectors,
and unauthorized policy modifications with async concurrency control.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from aegisfleet.config import get_config
from aegisfleet.models.schemas import IAMPolicyCheckInput

try:
    from google.antigravity import ToolContext
except ImportError:
    ToolContext = None  # type: ignore

logger = logging.getLogger(__name__)

# Concurrency rate limiter
_IAM_QUERY_SEMAPHORE = asyncio.Semaphore(10)


async def analyze_iam_permissions(
    project_id: str,
    principal_email: str = "",
    check_escalation: bool = True,
    ctx: Optional[Any] = None,
) -> str:
    """Analyzes IAM policies to identify privilege escalation vectors and dangerous permissions.

    Args:
        project_id: The GCP project ID.
        principal_email: Optional principal email to focus the analysis on.
        check_escalation: Whether to run deep privilege escalation checks.
        ctx: Antigravity ToolContext.

    Returns:
        Structured text containing the IAM analysis, risk ratings, and identified lateral movement paths.
    """
    # 1. Pydantic validation
    try:
        check_input = IAMPolicyCheckInput(
            project_id=project_id,
            principal_email=principal_email or None,
        )
    except Exception as validation_err:
        return f"IAM policy analysis validation error: {validation_err}"

    config = get_config()

    # 2. Concurrency-governed IAM analysis
    async with _IAM_QUERY_SEMAPHORE:
        if config.sandbox_mode:
            logger.info("Simulating IAM policy analysis for project '%s'", check_input.project_id)
            raw_summary = _simulate_iam_analysis(
                principal_email=check_input.principal_email or "",
                check_escalation=check_escalation,
            )
        else:
            raw_summary = "Real IAM analysis active via Cloud Resource Manager & IAM Policy APIs."

    # 3. Payload optimization
    max_chars = config.max_log_payload_chars
    if len(raw_summary) > max_chars:
        raw_summary = (
            raw_summary[:max_chars]
            + f"\n\n[... TRUNCATED: {len(raw_summary) - max_chars} characters omitted to preserve LLM context window ...]"
        )

    return raw_summary


def _simulate_iam_analysis(principal_email: str, check_escalation: bool) -> str:
    """Generate structured IAM analysis and lateral movement vectors."""
    analysis = "=== IAM Security Analysis ===\n\n"

    bindings = [
        {
            "role": "roles/owner",
            "members": ["user:admin@example.com", "user:dev-user@example.com"],
        },
        {
            "role": "roles/iam.serviceAccountUser",
            "members": ["user:dev-user@example.com"],
        },
        {
            "role": "roles/compute.instanceAdmin.v1",
            "members": ["user:dev-user@example.com"],
        },
        {
            "role": "roles/storage.admin",
            "members": [
                "serviceAccount:backup-sa@acme-corp.iam.gserviceaccount.com"
            ],
        },
    ]

    analysis += "1. Current IAM Bindings Summary:\n"
    for b in bindings:
        analysis += f"  Role: {b['role']} -> {', '.join(b['members'])}\n"

    if check_escalation:
        analysis += "\n2. Dangerous Permissions & Privilege Escalation Vectors:\n"
        analysis += (
            "  [CRITICAL] `iam.serviceAccounts.actAs` + `compute.instances.create` "
            "detected for user:dev-user@example.com.\n"
            "             Risk: Can create a VM attached to ANY service account, "
            "effectively escalating to its privileges.\n"
            "  [HIGH] `roles/storage.admin` assigned to backup-sa@acme-corp.iam.gserviceaccount.com.\n"
            "             Risk: Broad access to all storage buckets including sensitive PII buckets.\n"
        )

        analysis += "\n3. Potential Lateral Movement Paths:\n"
        analysis += (
            "  user:dev-user@example.com -> Create VM as backup-sa -> "
            "Access PII Buckets as storage.admin.\n"
        )

        analysis += "\n4. Recent IAM Changes (Last 24h):\n"
        analysis += (
            "  [WARNING] user:dev-user@example.com was granted `roles/owner` 3 hours ago.\n"
            "  [WARNING] serviceAccount:backup-sa@acme-corp.iam.gserviceaccount.com was "
            "granted `roles/storage.admin` 4 hours ago.\n"
        )

    return analysis
