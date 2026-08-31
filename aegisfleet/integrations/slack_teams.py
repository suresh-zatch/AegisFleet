"""AegisFleet v1.1: Bidirectional Slack Block Kit & MS Teams ChatOps Integration.

Provides:
- Interactive Slack Block Kit message generation with 1-click HITL approval gates.
- Cryptographic HMAC-SHA256 signature verification for inbound Slack webhooks.
- Microsoft Teams Adaptive Card generator.
- Webhook dispatch handlers.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional
import httpx

from aegisfleet.config import get_config
from aegisfleet.models.schemas import IncidentReport, ThreatSeverity

logger = logging.getLogger(__name__)


def verify_slack_signature(
    signing_secret: str,
    timestamp: str,
    body: str,
    signature: str,
) -> bool:
    """Cryptographically verify inbound Slack webhook signatures using HMAC-SHA256.

    Args:
        signing_secret: Slack app signing secret.
        timestamp: X-Slack-Request-Timestamp header.
        body: Raw request body string.
        signature: X-Slack-Signature header (e.g. 'v0=a2114d57b2...').

    Returns:
        True if valid, False otherwise.
    """
    if not signing_secret or not signature or not timestamp:
        # If in sandbox mode without configured secrets, allow simulation tokens
        config = get_config()
        if config.sandbox_mode:
            return True
        return False

    # Prevent replay attacks older than 5 minutes
    try:
        req_time = int(timestamp)
        if abs(time.time() - req_time) > 300:
            logger.warning("Slack signature verification failed: Timestamp drift > 300s.")
            return False
    except ValueError:
        return False

    sig_basestring = f"v0:{timestamp}:{body}".encode("utf-8")
    computed_hash = (
        "v0="
        + hmac.new(
            signing_secret.encode("utf-8"), sig_basestring, hashlib.sha256
        ).hexdigest()
    )

    return hmac.compare_digest(computed_hash, signature)


def generate_slack_block_kit(report: IncidentReport) -> Dict[str, Any]:
    """Generate rich, interactive Slack Block Kit payload with 1-click HITL containment buttons.

    Args:
        report: The IncidentReport to format.

    Returns:
        Dictionary containing Slack blocks.
    """
    severity_emoji = {
        ThreatSeverity.CRITICAL: "🚨",
        ThreatSeverity.HIGH: "⚠️",
        ThreatSeverity.MEDIUM: "🔶",
        ThreatSeverity.LOW: "🔷",
        ThreatSeverity.INFO: "ℹ️",
    }.get(report.threat_severity, "🚨")

    # Command summary text
    cmd_count = len(report.staged_gcloud_commands)
    cmd_list_text = ""
    for idx, cmd in enumerate(report.staged_gcloud_commands[:4], 1):
        cmd_list_text += f"*[{idx}]* `{cmd.command}`\n"
    if cmd_count > 4:
        cmd_list_text += f"_...and {cmd_count - 4} more staged commands._\n"

    blocks: List[Dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{severity_emoji} AegisFleet SOC: [{report.threat_severity}] {report.incident_id}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Title:* *{report.title}*\n*Cloud Provider:* `{report.provider.value}`\n*Timestamp:* `{report.investigation_timestamp}`\n\n*Summary:* {report.summary}",
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*🛡️ Staged Containment Actions ({cmd_count} Commands Ready):*\n{cmd_list_text or '_No commands staged._'}",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"🤖 *Autonomous Swarm Status:* Investigation Complete • *Blast Radius:* {len(report.blast_radius)} assets • *MITRE Techniques:* {len(report.mitre_techniques)}",
                }
            ],
        },
        {"type": "divider"},
        {
            "type": "actions",
            "block_id": f"hitl_actions_{report.incident_id}",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "⚡ 1-Click Authorize Containment",
                        "emoji": True,
                    },
                    "style": "danger",
                    "value": json.dumps({
                        "incident_id": report.incident_id,
                        "action": "AUTHORIZE_ALL",
                        "command_ids": [c.command_id for c in report.staged_gcloud_commands],
                    }),
                    "action_id": "containment_approve_all",
                    "confirm": {
                        "title": {"type": "plain_text", "text": "Confirm Cloud Containment"},
                        "text": {
                            "type": "mrkdwn",
                            "text": f"Are you sure you want to execute {cmd_count} containment commands for *{report.incident_id}*? This will modify cloud infrastructure.",
                        },
                        "confirm": {"type": "plain_text", "text": "Execute Containment"},
                        "deny": {"type": "plain_text", "text": "Cancel"},
                    },
                },
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "🔄 Rollback Containment",
                        "emoji": True,
                    },
                    "style": "primary",
                    "value": json.dumps({
                        "incident_id": report.incident_id,
                        "action": "ROLLBACK_ALL",
                    }),
                    "action_id": "containment_rollback",
                },
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "📊 Open SOC Dashboard",
                        "emoji": True,
                    },
                    "url": f"http://localhost:8080/#incident-{report.incident_id}",
                    "action_id": "open_dashboard_link",
                },
            ],
        },
    ]

    return {"blocks": blocks, "text": f"AegisFleet SOC Alert: [{report.threat_severity}] {report.title}"}


def generate_teams_adaptive_card(report: IncidentReport) -> Dict[str, Any]:
    """Generate Microsoft Teams Adaptive Card (v1.4) payload with actionable HITL buttons."""
    card = {
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": [
            {
                "type": "TextBlock",
                "size": "Medium",
                "weight": "Bolder",
                "text": f"🚨 AegisFleet SOC: [{report.threat_severity}] {report.incident_id}",
                "color": "Attention" if report.threat_severity in (ThreatSeverity.CRITICAL, ThreatSeverity.HIGH) else "Default",
            },
            {
                "type": "TextBlock",
                "text": f"**Title:** {report.title}\n\n**Summary:** {report.summary}",
                "wrap": True,
            },
            {
                "type": "FactSet",
                "facts": [
                    {"title": "Cloud Provider", "value": report.provider.value},
                    {"title": "Staged Commands", "value": str(len(report.staged_gcloud_commands))},
                    {"title": "Blast Radius", "value": f"{len(report.blast_radius)} Resources"},
                ],
            },
        ],
        "actions": [
            {
                "type": "Action.Submit",
                "title": "⚡ 1-Click Authorize Containment",
                "style": "destructive",
                "data": {
                    "incident_id": report.incident_id,
                    "action": "AUTHORIZE_ALL",
                },
            },
            {
                "type": "Action.Submit",
                "title": "🔄 False-Positive Rollback",
                "data": {
                    "incident_id": report.incident_id,
                    "action": "ROLLBACK_ALL",
                },
            },
            {
                "type": "Action.OpenUrl",
                "title": "📊 Open Dashboard",
                "url": f"http://localhost:8080/#incident-{report.incident_id}",
            },
        ],
    }
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": card,
            }
        ],
    }


async def dispatch_slack_notification(
    report: IncidentReport, webhook_url: Optional[str] = None
) -> bool:
    """Send interactive Slack notification via Incoming Webhook."""
    target_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL")
    if not target_url:
        logger.info(
            "Slack webhook URL not configured. Simulating interactive Block Kit dispatch for incident '%s'",
            report.incident_id,
        )
        return True

    payload = generate_slack_block_kit(report)
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(target_url, json=payload)
            if resp.status_code == 200:
                logger.info("Successfully dispatched Slack Block Kit card for '%s'", report.incident_id)
                return True
            logger.warning("Slack webhook returned status code %d: %s", resp.status_code, resp.text)
    except Exception as exc:
        logger.error("Failed to dispatch Slack webhook: %s", exc)
    return False
