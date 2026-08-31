"""AegisFleet Pydantic V2 data models for GCP SOC operations.

Provides type-safe models for findings, audit telemetry, asset topology,
containment actions, and structured incident outputs with LLM JSON extraction fallbacks.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import json
import re
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, Field, field_validator


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
    FAILED = "FAILED"


class ActionType(str, Enum):
    DISABLE_SA_KEY = "DISABLE_SERVICE_ACCOUNT_KEY"
    REVOKE_IAM = "REVOKE_IAM_BINDING"
    LOCK_BUCKET = "LOCK_STORAGE_BUCKET"
    DISABLE_SA = "DISABLE_SERVICE_ACCOUNT"
    BLOCK_IP = "BLOCK_IP_ADDRESS"
    ISOLATE_VM = "ISOLATE_VM_INSTANCE"


class SCCFinding(BaseModel):
    """Google Cloud Security Command Center finding payload."""

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    category: str = Field(
        ..., description="Finding category, e.g. 'Persistence: New Service Account Key'"
    )
    resource_name: str = Field(..., description="Full GCP resource path")
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


class AuditLogRecord(BaseModel):
    """A single Cloud Audit Log entry."""

    timestamp: str
    principal_email: str
    service_name: str
    method_name: str
    resource_name: str
    status_code: int = 0
    status_message: str = "OK"
    request_metadata: Dict[str, Any] = Field(default_factory=dict)
    caller_ip: str = ""
    user_agent: str = ""


class IAMPolicyCheckInput(BaseModel):
    """Input parameters for checking IAM policies."""

    project_id: str
    principal_email: Optional[str] = None
    role: Optional[str] = None
    resource_name: Optional[str] = None


class IAMBinding(BaseModel):
    """An IAM policy binding."""

    role: str
    members: List[str] = Field(default_factory=list)
    condition: Optional[str] = None
    is_dangerous: bool = False
    risk_reason: str = ""


class ServiceAccountKey(BaseModel):
    """A service account key record."""

    key_id: str
    service_account_email: str
    created_time: str
    expires_time: Optional[str] = None
    key_type: str = "USER_MANAGED"
    is_compromised: bool = False


class AssetQueryInput(BaseModel):
    """Input parameters for querying Cloud Asset Inventory."""

    project_id: str
    asset_type: Optional[str] = None
    resource_name: Optional[str] = None


class GCPAsset(BaseModel):
    """A GCP Cloud Asset representation."""

    asset_name: str
    asset_type: str
    project_id: str
    location: str = ""
    iam_bindings: List[IAMBinding] = Field(default_factory=list)
    network_config: Dict[str, Any] = Field(default_factory=dict)
    labels: Dict[str, str] = Field(default_factory=dict)
    create_time: str = ""
    update_time: str = ""


class StagedContainmentCommand(BaseModel):
    """A staged gcloud containment command awaiting HITL authorization."""

    command_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    command: str = Field(..., description="The gcloud CLI command")
    action_type: ActionType
    target_resource: str
    risk_level: ThreatSeverity = ThreatSeverity.HIGH
    status: ContainmentStatus = ContainmentStatus.STAGED
    description: str = ""
    executed_at: Optional[str] = None
    executed_by: Optional[str] = None


class AttackPathNode(BaseModel):
    """A node in the attack path graph."""

    step_number: int
    action: str
    actor: str
    target: str
    timestamp: str
    technique: str = ""  # MITRE ATT&CK
    evidence: str = ""


class IncidentReport(BaseModel):
    """Complete structured output for a SOC incident investigation."""

    incident_id: str = Field(
        default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}"
    )
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


class SwarmStatus(BaseModel):
    """Status of the agent swarm execution."""

    incident_id: str
    phase: str
    active_agents: List[str] = Field(default_factory=list)
    completed_agents: List[str] = Field(default_factory=list)
    progress_pct: float = 0.0
    messages: List[str] = Field(default_factory=list)


def extract_json_from_llm_output(raw_text: str) -> Dict[str, Any]:
    """Extract and parse a JSON dictionary from LLM text containing markdown fences or commentary.

    Handles:
    - Clean JSON: '{"key": "value"}'
    - Markdown wrapped: '```json\n{"key": "value"}\n```'
    - Conversational preamble: 'Here is the report:\n{"key": "value"}'
    """
    text = raw_text.strip()

    # 1. Direct parse attempt
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except Exception:
        pass

    # 2. Markdown fence extraction
    fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
    if fence_match:
        try:
            data = json.loads(fence_match.group(1).strip())
            if isinstance(data, dict):
                return data
        except Exception:
            pass

    # 3. Outermost brace search
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
