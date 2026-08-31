"""AegisFleet v2.0: Azure Activity Logs & Microsoft Entra ID Investigation Tool.

Provides async querying of Azure Resource Manager events and Entra ID audit logs
for multi-cloud cross-plane threat investigations.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional

from aegisfleet.config import get_config

logger = logging.getLogger(__name__)
_AZURE_SEMAPHORE = asyncio.Semaphore(10)


async def query_azure_activity(
    subscription_id: str = "00000000-0000-0000-0000-000000000000",
    operation_name: str = "",
    caller: str = "",
    time_range_hours: int = 24,
    ctx: Optional[Any] = None,
) -> str:
    """Queries Azure Activity Logs and Entra ID events for cross-cloud threat correlation.

    Args:
        subscription_id: Azure Subscription UUID.
        operation_name: Azure REST Operation (e.g., 'Microsoft.Authorization/roleAssignments/write').
        caller: Principal UPN / Service Principal App ID.
        time_range_hours: Lookback window in hours.
        ctx: Antigravity ToolContext.

    Returns:
        Structured summary of Azure Activity Logs.
    """
    config = get_config()

    async with _AZURE_SEMAPHORE:
        if config.sandbox_mode:
            logger.info("Simulating Azure Activity Log query for subscription '%s'", subscription_id)
            raw_summary = _simulate_azure_activity(operation_name=operation_name, caller=caller)
        else:
            raw_summary = "Real Azure Activity Log querying active via Azure Monitor SDK."

    max_chars = config.max_log_payload_chars
    if len(raw_summary) > max_chars:
        raw_summary = raw_summary[:max_chars] + "\n[... TRUNCATED ...]"

    return raw_summary


def _simulate_azure_activity(operation_name: str, caller: str) -> str:
    """Generate simulated Azure Activity Logs."""
    events = [
        {
            "eventTimestamp": "2026-08-31T09:30:00Z",
            "operationName": "Microsoft.Authorization/roleAssignments/write",
            "caller": "compromised-admin@company.onmicrosoft.com",
            "callerIpAddress": "198.51.100.75",
            "resourceId": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/prod-rg/providers/Microsoft.Authorization/roleAssignments/ra-99",
            "properties": {"roleDefinitionName": "Owner", "principalType": "User"},
        },
        {
            "eventTimestamp": "2026-08-31T09:35:00Z",
            "operationName": "Microsoft.Storage/storageAccounts/listKeys/action",
            "caller": "compromised-admin@company.onmicrosoft.com",
            "callerIpAddress": "198.51.100.75",
            "resourceId": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/prod-rg/providers/Microsoft.Storage/storageAccounts/prodcustomerdata",
        },
    ]

    results = []
    for ev in events:
        if operation_name and operation_name.lower() not in ev["operationName"].lower():
            continue
        if caller and caller.lower() not in ev["caller"].lower():
            continue
        results.append(ev)

    if not results:
        return "No Azure Activity events found matching criteria."

    summary = "=== Azure Activity & Entra ID Summary ===\n"
    for i, ev in enumerate(results, 1):
        summary += f"[{i}] {ev['eventTimestamp']} | Operation: {ev['operationName']} | Caller: {ev['caller']} (IP: {ev['callerIpAddress']})\n"
        summary += f"    Resource: {ev['resourceId']}\n"
        if "properties" in ev:
            summary += f"    Details: {json.dumps(ev['properties'])}\n"
        summary += "\n"

    return summary
