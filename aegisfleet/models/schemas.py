"""AegisFleet Pydantic V2 data models for Enterprise Multi-Cloud SOC operations.

Covers v1.0 (Core GCP), v1.1 (Slack/Teams HITL), v2.0 (Multi-Cloud Fabric: AWS & Azure),
and v2.1 (Automated Post-Containment Rollback Engine).
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import json
import re
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, Field, field_validator


class CloudProvider(str, Enum):
    GCP = "GCP"
    AWS = "AWS"
    AZURE = "AZURE"
    MULTI_CLOUD = "MULTI_CLOUD"


class ThreatSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ContainmentStatus(str, Enum):
    STAGED = "STAGED"
    APPROVED = "APPROVED"
    EXECUTED = "EXECUTED"
    REJECTED = "REJECTED"
    ROLLED_BACK = "ROLLED_BACK"
    FAILED = "FAILED"


class ActionType(str, Enum):
    # GCP actions
    DISABLE_SA_KEY = "DISABLE_SERVICE_ACCOUNT_KEY"
    REVOKE_IAM = "REVOKE_IAM_BINDING"
    LOCK_BUCKET = "LOCK_STORAGE_BUCKET"
    DISABLE_SA = "DISABLE_SERVICE_ACCOUNT"
    BLOCK_IP = "BLOCK_IP_ADDRESS"
    ISOLATE_VM = "ISOLATE_VM_INSTANCE"
    # AWS actions
    AWS_DETACH_POLICY = "AWS_DETACH_USER_POLICY"
    AWS_DEACTIVATE_KEY = "AWS_DEACTIVATE_ACCESS_KEY"
    AWS_ISOLATE_EC2 = "AWS_ISOLATE_EC2_SECURITY_GROUP"
    # Azure actions
    AZURE_REVOKE_SESSIONS = "AZURE_REVOKE_USER_SESSIONS"
    AZURE_LOCK_NSG = "AZURE_LOCK_NETWORK_SECURITY_GROUP"


class SCCFinding(BaseModel):
    """Google Cloud Security Command Center or Multi-Cloud finding payload."""

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    provider: CloudProvider = CloudProvider.GCP
    category: str = Field(
        ..., description="Finding category, e.g. 'Persistence: New Service Account Key'"
    )
    resource_name: str = Field(..., description="Full Cloud resource identifier")
    severity: ThreatSeverity = ThreatSeverity.HIGH
    event_time: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    source_properties: Dict[str, Any] = Field(default_factory=dict)
    description: str = ""
    project_id: str = ""
    principal_email: str = ""

    @field_validator("category", "resource_name", mode="before")
    @classmethod
    def sanitize_strings(cls, v: Any) -> str:
        if isinstance(v, str):
            return v.strip()
        return str(v)


class AuditLogQueryInput(BaseModel):
    """Input parameters for querying Cloud Audit Logs."""

    project_id: str
    principal_email: Optional[str] = None
    service_name: Optional[str] = None
    method_name: Optional[str] = None
    resource_name: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    max_results: int = Field(default=50, ge=1, le=200)


class IAMPolicyCheckInput(BaseModel):
    """Input parameters for checking IAM policies."""

    project_id: str
    principal_email: Optional[str] = None
    role: Optional[str] = None
    resource_name: Optional[str] = None


class AssetQueryInput(BaseModel):
    """Input parameters for querying Cloud Asset Inventory."""

    project_id: str
    asset_type: Optional[str] = None
    resource_name: Optional[str] = None


class StagedContainmentCommand(BaseModel):
    """A staged containment command awaiting HITL authorization."""

    command_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    provider: CloudProvider = CloudProvider.GCP
    command: str = Field(..., description="The CLI command (gcloud, aws, or az)")
    action_type: ActionType
    target_resource: str
    risk_level: ThreatSeverity = ThreatSeverity.HIGH
    status: ContainmentStatus = ContainmentStatus.STAGED
    description: str = ""
    executed_at: Optional[str] = None
    executed_by: Optional[str] = None
    rollback_command: Optional[str] = Field(
        default=None, description="Pre-computed command to reverse this containment action"
    )
    pre_containment_state: Optional[Dict[str, Any]] = Field(
        default_factory=dict, description="State snapshot captured prior to mutation"
    )


class AttackPathNode(BaseModel):
    """A node in the attack path graph."""

    step_number: int
    provider: CloudProvider = CloudProvider.GCP
    action: str
    actor: str
    target: str
    timestamp: str
    technique: str = ""  # MITRE ATT&CK
    evidence: str = ""


# ============================================================================
# v2.1: Post-Containment Rollback Models
# ============================================================================

class RollbackAction(BaseModel):
    """A single rollback execution step."""

    action_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    command_id: str
    rollback_command: str
    target_resource: str
    status: str = "PENDING"  # PENDING, SUCCESS, FAILED
    executed_at: Optional[str] = None
    message: str = ""


class RollbackRequest(BaseModel):
    """Request to rollback containment actions for an incident."""

    incident_id: str
    command_ids: Optional[List[str]] = Field(
        default=None, description="Specific command IDs to revert. If empty, reverts all executed commands."
    )
    reason: str = Field(default="False-positive resolution / analyst rollback request")
    authorization_token: Optional[str] = None


class RollbackResponse(BaseModel):
    """Response returned upon rollback completion."""

    incident_id: str
    status: str  # COMPLETED, PARTIAL, FAILED
    rolled_back_commands: List[str] = Field(default_factory=list)
    results: List[RollbackAction] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ============================================================================
# Incident Report Model (v1.0 - v2.1 Comprehensive)
# ============================================================================

class IncidentReport(BaseModel):
    """Complete structured output for an Enterprise SOC incident investigation."""

    incident_id: str = Field(
        default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}"
    )
    provider: CloudProvider = CloudProvider.GCP
    threat_severity: ThreatSeverity
    title: str
    summary: str
    attack_narrative: str = ""
    attack_path: List[AttackPathNode] = Field(default_factory=list)
    mermaid_diagram: str = ""
    ciso_briefing: str = ""
    blast_radius: List[str] = Field(default_factory=list)
    staged_gcloud_commands: List[StagedContainmentCommand] = Field(
        default_factory=list
    )
    recommended_actions: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    iocs: List[str] = Field(default_factory=list)
    affected_resources: List[str] = Field(default_factory=list)
    investigation_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    swarm_trace: List[str] = Field(default_factory=list)
    # v1.1 Slack/Teams metadata
    slack_channel_id: Optional[str] = None
    slack_ts: Optional[str] = None
    # v2.1 Rollback history
    rollback_history: List[RollbackResponse] = Field(default_factory=list)


class HITLApprovalRequest(BaseModel):
    """Request for human-in-the-loop containment approval."""

    incident_id: str
    command_ids: List[str]
    authorization_token: Optional[str] = None


class HITLApprovalResponse(BaseModel):
    """Response from HITL containment approval."""

    incident_id: str
    approved_commands: List[str] = Field(default_factory=list)
    rejected_commands: List[str] = Field(default_factory=list)
    execution_results: List[Dict[str, Any]] = Field(default_factory=list)
    status: str = "COMPLETED"


# ============================================================================
# LLM JSON Extractor Utility
# ============================================================================

def extract_json_from_llm_output(raw_text: str) -> Dict[str, Any]:
    """Extract and parse a JSON dictionary from LLM text containing markdown fences or commentary."""
    text = raw_text.strip()

    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except Exception:
        pass

    fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
    if fence_match:
        try:
            data = json.loads(fence_match.group(1).strip())
            if isinstance(data, dict):
                return data
        except Exception:
            pass

    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        json_candidate = text[first_brace : last_brace + 1]
        try:
            data = json.loads(json_candidate)
            if isinstance(data, dict):
                return data
        except Exception:
            pass

    raise ValueError(f"Unable to extract valid JSON dictionary from LLM response: {raw_text[:200]}...")
