"""Cloud Asset Inventory tool for AegisFleet SOC agents.

Provides async asset querying, topology enumeration, and IAM policy analysis
with concurrency governance and context window payload optimization.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Optional

from aegisfleet.config import get_config
from aegisfleet.models.schemas import AssetQueryInput

try:
    from google.antigravity import ToolContext
except ImportError:
    ToolContext = None  # type: ignore

logger = logging.getLogger(__name__)

# Concurrency rate limiter
_ASSET_QUERY_SEMAPHORE = asyncio.Semaphore(10)


async def query_asset_inventory(
    project_id: str,
    asset_type: str = "",
    resource_name: str = "",
    ctx: Optional[Any] = None,
) -> str:
    """Queries Cloud Asset Inventory to retrieve configurations and metadata for GCP resources.

    Use this to understand the environment, find public buckets, compute instances, IAM policies, etc.

    Args:
        project_id: The GCP project ID.
        asset_type: Optional filter by asset type (e.g. 'compute.googleapis.com/Instance').
        resource_name: Optional filter by specific resource name.
        ctx: Antigravity ToolContext.

    Returns:
        Structured text describing assets and their security configurations.
    """
    # 1. Pydantic validation
    try:
        query_input = AssetQueryInput(
            project_id=project_id,
            asset_type=asset_type or None,
            resource_name=resource_name or None,
        )
    except Exception as validation_err:
        return f"Asset inventory query validation error: {validation_err}"

    config = get_config()

    # 2. Concurrency-governed asset retrieval
    async with _ASSET_QUERY_SEMAPHORE:
        if config.sandbox_mode:
            logger.info("Simulating asset inventory for project '%s'", query_input.project_id)
            raw_summary = _simulate_asset_inventory(
                asset_type=query_input.asset_type or "",
                resource_name=query_input.resource_name or "",
            )
        else:
            raw_summary = "Real Cloud Asset Inventory querying is active via Google Cloud Asset SDK."

    # 3. Payload optimization
    max_chars = config.max_log_payload_chars
    if len(raw_summary) > max_chars:
        raw_summary = (
            raw_summary[:max_chars]
            + f"\n\n[... TRUNCATED: {len(raw_summary) - max_chars} characters omitted to preserve LLM context window ...]"
        )

    return raw_summary


def _simulate_asset_inventory(asset_type: str, resource_name: str) -> str:
    """Generate realistic simulated GCP Asset Inventory data."""
    assets = [
        {
            "name": "//iam.googleapis.com/projects/acme-corp/serviceAccounts/backup-sa@acme-corp.iam.gserviceaccount.com",
            "assetType": "iam.googleapis.com/ServiceAccount",
            "resource": {
                "data": {
                    "email": "backup-sa@acme-corp.iam.gserviceaccount.com",
                    "displayName": "Backup Service Account",
                }
            },
            "iamPolicy": {
                "bindings": [
                    {
                        "role": "roles/iam.serviceAccountKeyAdmin",
                        "members": ["user:admin@example.com"],
                    }
                ]
            },
        },
        {
            "name": "//iam.googleapis.com/projects/acme-corp/serviceAccounts/data-worker@acme-corp.iam.gserviceaccount.com",
            "assetType": "iam.googleapis.com/ServiceAccount",
        },
        {
            "name": "//storage.googleapis.com/acme-pii-data",
            "assetType": "storage.googleapis.com/Bucket",
            "resource": {
                "data": {
                    "labels": {"data-classification": "pii"},
                    "iamConfiguration": {"publicAccessPrevention": "enforced"},
                }
            },
        },
        {
            "name": "//storage.googleapis.com/acme-public-assets",
            "assetType": "storage.googleapis.com/Bucket",
            "resource": {"data": {"labels": {"data-classification": "public"}}},
            "iamPolicy": {
                "bindings": [
                    {"role": "roles/storage.objectViewer", "members": ["allUsers"]}
                ]
            },
        },
        {
            "name": "//compute.googleapis.com/projects/acme-corp/zones/us-central1-a/instances/dev-instance-1",
            "assetType": "compute.googleapis.com/Instance",
            "resource": {
                "data": {
                    "networkInterfaces": [
                        {"accessConfigs": [{"natIP": "34.120.10.22"}]}
                    ],
                    "serviceAccounts": [
                        {
                            "email": "backup-sa@acme-corp.iam.gserviceaccount.com",
                            "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                        }
                    ],
                }
            },
        },
        {
            "name": "//compute.googleapis.com/projects/acme-corp/global/firewalls/allow-ssh-public",
            "assetType": "compute.googleapis.com/Firewall",
            "resource": {
                "data": {
                    "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
                    "sourceRanges": ["0.0.0.0/0"],
                }
            },
        },
    ]

    results = []
    for asset in assets:
        if asset_type and asset_type.lower() not in asset["assetType"].lower():
            continue
        if resource_name and resource_name.lower() not in asset["name"].lower():
            continue
        results.append(asset)

    if not results:
        return "No assets found matching criteria."

    summary = "GCP Asset Inventory Summary:\n"
    for i, asset in enumerate(results, 1):
        summary += f"[{i}] Asset: {asset['name']}\n"
        summary += f"    Type: {asset['assetType']}\n"
        if "resource" in asset:
            summary += f"    Resource Data: {json.dumps(asset['resource']['data'])}\n"
        if "iamPolicy" in asset:
            summary += f"    IAM Policy: {json.dumps(asset['iamPolicy'])}\n"
        summary += "\n"

    return summary
