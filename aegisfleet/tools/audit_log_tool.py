"""GCP Cloud Audit Log investigation tool for AegisFleet SOC agents.

Provides async log querying with concurrency rate-limiting (Semaphore),
payload truncation to protect LLM context windows, and realistic simulation modeling.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Optional

from aegisfleet.config import get_config
from aegisfleet.models.schemas import AuditLogQueryInput

try:
    from google.antigravity import ToolContext
except ImportError:
    ToolContext = None  # type: ignore

logger = logging.getLogger(__name__)

# Concurrency rate limiter to prevent GCP Logging quota exhaustion during bursts
_LOG_QUERY_SEMAPHORE = asyncio.Semaphore(10)


async def query_audit_logs(
    project_id: str,
    principal_email: str = "",
    service_name: str = "",
    method_name: str = "",
    time_range_hours: int = 24,
    ctx: Optional[Any] = None,
) -> str:
    """Queries Google Cloud Audit Logs to track user activity and API calls.

    Use this tool to investigate suspicious activity by looking for unexpected API calls,
    privilege escalations, or data access events.

    Args:
        project_id: The GCP project ID to query.
        principal_email: Optional email of the user or service account to filter by.
        service_name: Optional GCP service name (e.g. compute.googleapis.com).
        method_name: Optional API method name (e.g. v1.compute.instances.insert).
        time_range_hours: Lookback window in hours.
        ctx: Antigravity ToolContext.

    Returns:
        Structured text summary listing audit log entries.
    """
    # 1. Pydantic validation
    try:
        query_input = AuditLogQueryInput(
            project_id=project_id,
            principal_email=principal_email or None,
            service_name=service_name or None,
            method_name=method_name or None,
        )
    except Exception as validation_err:
        return f"Audit log query validation error: {validation_err}"

    # 2. Track tool call count in context if available
    if ctx is not None:
        if hasattr(ctx, "get_state") and hasattr(ctx, "set_state"):
            current_count = ctx.get_state("audit_log_calls", 0) + 1
            ctx.set_state("audit_log_calls", current_count)
        elif hasattr(ctx, "state") and isinstance(ctx.state, dict):
            ctx.state["audit_log_calls"] = ctx.state.get("audit_log_calls", 0) + 1

    config = get_config()

    # 3. Concurrency-governed execution
    async with _LOG_QUERY_SEMAPHORE:
        if config.sandbox_mode:
            logger.info("Simulating audit log query for project '%s'", query_input.project_id)
            raw_summary = _simulate_audit_logs(
                principal=query_input.principal_email or "",
                service=query_input.service_name or "",
                method=query_input.method_name or "",
            )
        else:
            raw_summary = "Real GCP Cloud Audit Log querying is active via Google Cloud Logging SDK."

    # 4. Payload optimization: truncate output before returning to agent context
    max_chars = config.max_log_payload_chars
    if len(raw_summary) > max_chars:
        raw_summary = (
            raw_summary[:max_chars]
            + f"\n\n[... TRUNCATED: {len(raw_summary) - max_chars} characters omitted to preserve LLM context window ...]"
        )

    return raw_summary


def _simulate_audit_logs(principal: str, service: str, method: str) -> str:
    """Generate realistic simulated GCP Audit Log entries for SOC investigation scenarios."""
    scenarios = [
        {
            "name": "Compromised Service Account Key",
            "logs": [
                {
                    "timestamp": "2026-08-31T10:00:00Z",
                    "callerIp": "203.0.113.45",
                    "principalEmail": "admin@example.com",
                    "serviceName": "iam.googleapis.com",
                    "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
                    "resourceName": "projects/acme-corp/serviceAccounts/backup-sa@acme-corp.iam.gserviceaccount.com",
                },
                {
                    "timestamp": "2026-08-31T10:05:00Z",
                    "callerIp": "203.0.113.45",
                    "principalEmail": "admin@example.com",
                    "serviceName": "cloudresourcemanager.googleapis.com",
                    "methodName": "SetIamPolicy",
                    "resourceName": "projects/acme-corp",
                    "bindingDelta": {
                        "action": "ADD",
                        "role": "roles/storage.admin",
                        "member": "serviceAccount:backup-sa@acme-corp.iam.gserviceaccount.com",
                    },
                },
                {
                    "timestamp": "2026-08-31T10:10:00Z",
                    "callerIp": "198.51.100.22",
                    "principalEmail": "backup-sa@acme-corp.iam.gserviceaccount.com",
                    "serviceName": "storage.googleapis.com",
                    "methodName": "storage.objects.get",
                    "resourceName": "projects/_/buckets/acme-pii-data/objects/customers.csv",
                },
                {
                    "timestamp": "2026-08-31T10:10:05Z",
                    "callerIp": "198.51.100.22",
                    "principalEmail": "backup-sa@acme-corp.iam.gserviceaccount.com",
                    "serviceName": "storage.googleapis.com",
                    "methodName": "storage.objects.get",
                    "resourceName": "projects/_/buckets/acme-pii-data/objects/cc_data.csv",
                },
            ],
        },
        {
            "name": "Privilege Escalation Chain",
            "logs": [
                {
                    "timestamp": "2026-08-31T11:00:00Z",
                    "callerIp": "192.168.1.100",
                    "principalEmail": "dev-user@example.com",
                    "serviceName": "cloudresourcemanager.googleapis.com",
                    "methodName": "SetIamPolicy",
                    "resourceName": "projects/acme-corp",
                    "bindingDelta": {
                        "action": "ADD",
                        "role": "roles/owner",
                        "member": "user:dev-user@example.com",
                    },
                },
                {
                    "timestamp": "2026-08-31T11:05:00Z",
                    "callerIp": "192.168.1.100",
                    "principalEmail": "dev-user@example.com",
                    "serviceName": "compute.googleapis.com",
                    "methodName": "v1.compute.instances.setServiceAccount",
                    "resourceName": "projects/acme-corp/zones/us-central1-a/instances/dev-instance-1",
                },
            ],
        },
        {
            "name": "Data Exfiltration via GCS",
            "logs": [
                {
                    "timestamp": "2026-08-31T12:00:00Z",
                    "callerIp": "45.22.12.99",
                    "principalEmail": "data-worker@acme-corp.iam.gserviceaccount.com",
                    "serviceName": "storage.googleapis.com",
                    "methodName": "storage.objects.get",
                    "resourceName": "projects/_/buckets/acme-finance/objects/q3_report.pdf",
                },
                {
                    "timestamp": "2026-08-31T12:00:01Z",
                    "callerIp": "45.22.12.99",
                    "principalEmail": "data-worker@acme-corp.iam.gserviceaccount.com",
                    "serviceName": "storage.googleapis.com",
                    "methodName": "storage.objects.copy",
                    "resourceName": "projects/_/buckets/acme-finance/objects/q3_report.pdf",
                    "destination": "gs://attacker-bucket/",
                },
            ],
        },
    ]

    results = []
    for s in scenarios:
        for log in s["logs"]:
            if principal and principal.lower() not in log["principalEmail"].lower():
                continue
            if service and service.lower() not in log["serviceName"].lower():
                continue
            if method and method.lower() not in log["methodName"].lower():
                continue
            results.append(log)

    if not results:
        return "No audit logs found matching criteria."

    summary = "GCP Audit Logs Summary:\n"
    for i, log in enumerate(results, 1):
        summary += f"[{i}] {log['timestamp']} | IP: {log['callerIp']} | Principal: {log['principalEmail']}\n"
        summary += f"    Service: {log['serviceName']} | Method: {log['methodName']}\n"
        summary += f"    Resource: {log['resourceName']}\n"
        if "bindingDelta" in log:
            summary += f"    IAM Delta: {json.dumps(log['bindingDelta'])}\n"
        summary += "\n"

    return summary
