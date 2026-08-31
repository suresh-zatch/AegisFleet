"""AegisFleet session persistence layer with Firestore Connection Pooling.

Supports Cloud Run stateless container lifecycles with transparent local fallback
and singleton Firestore client management.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import asyncio
import json
import logging
import os
from typing import Any, Dict, List, Optional

from aegisfleet.config import get_config
from aegisfleet.models.schemas import ContainmentStatus, IncidentReport, SCCFinding

try:
    from google.cloud import firestore  # type: ignore

    HAS_FIRESTORE = True
except ImportError:
    firestore = None  # type: ignore
    HAS_FIRESTORE = False

logger = logging.getLogger(__name__)

# Global singleton Firestore client to prevent socket exhaustion across requests
_GLOBAL_FIRESTORE_CLIENT: Optional[Any] = None
_FIRESTORE_LOCK = asyncio.Lock()


async def get_firestore_client() -> Optional[Any]:
    """Retrieve or initialize the singleton AsyncClient for Firestore with connection pooling."""
    global _GLOBAL_FIRESTORE_CLIENT
    if not HAS_FIRESTORE or firestore is None:
        return None

    if _GLOBAL_FIRESTORE_CLIENT is None:
        async with _FIRESTORE_LOCK:
            if _GLOBAL_FIRESTORE_CLIENT is None:
                try:
                    config = get_config()
                    _GLOBAL_FIRESTORE_CLIENT = firestore.AsyncClient(
                        project=config.gcp_project_id
                    )
                    logger.info(
                        "Singleton Firestore AsyncClient initialized for project '%s'",
                        config.gcp_project_id,
                    )
                except Exception as exc:
                    logger.warning(
                        "Could not initialize Firestore AsyncClient: %s. Using local fallback.",
                        exc,
                    )
                    _GLOBAL_FIRESTORE_CLIENT = None
    return _GLOBAL_FIRESTORE_CLIENT


class IncidentStore(ABC):
    """Abstract base class for incident storage."""

    @abstractmethod
    async def save_incident(self, report: IncidentReport) -> str:
        """Save a new incident report."""
        pass

    @abstractmethod
    async def get_incident(self, incident_id: str) -> Optional[IncidentReport]:
        """Retrieve an incident report by ID."""
        pass

    @abstractmethod
    async def list_incidents(self, limit: int = 20) -> List[IncidentReport]:
        """List recent incident reports."""
        pass

    @abstractmethod
    async def update_incident(self, incident_id: str, updates: Dict[str, Any]) -> bool:
        """Update fields of an existing incident report."""
        pass

    @abstractmethod
    async def save_finding(self, finding: SCCFinding) -> str:
        """Save an SCC finding."""
        pass

    @abstractmethod
    async def update_containment_status(
        self, incident_id: str, command_id: str, status: ContainmentStatus
    ) -> bool:
        """Update the containment status of an incident."""
        pass


class LocalIncidentStore(IncidentStore):
    """Thread-safe, file-backed local incident store for development and fallback."""

    def __init__(self, data_file: str = "./data/incidents.json"):
        self.data_file = data_file
        self.lock = asyncio.Lock()
        self._ensure_dir()

    def _ensure_dir(self) -> None:
        """Ensure data directory and baseline JSON file exist."""
        os.makedirs(os.path.dirname(os.path.abspath(self.data_file)), exist_ok=True)
        if not os.path.exists(self.data_file):
            with open(self.data_file, "w", encoding="utf-8") as f:
                json.dump({"incidents": {}, "findings": {}}, f)

    async def _load_data(self) -> Dict[str, Any]:
        """Load data from disk safely."""
        async with self.lock:
            try:
                with open(self.data_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {"incidents": {}, "findings": {}}

    async def _save_data(self, data: Dict[str, Any]) -> None:
        """Persist data to disk safely."""
        async with self.lock:
            with open(self.data_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)

    async def save_incident(self, report: IncidentReport) -> str:
        data = await self._load_data()
        data["incidents"][report.incident_id] = report.model_dump(mode="json")
        await self._save_data(data)
        return report.incident_id

    async def get_incident(self, incident_id: str) -> Optional[IncidentReport]:
        data = await self._load_data()
        incident_data = data["incidents"].get(incident_id)
        if incident_data:
            return IncidentReport.model_validate(incident_data)
        return None

    async def list_incidents(self, limit: int = 20) -> List[IncidentReport]:
        data = await self._load_data()
        incidents = [
            IncidentReport.model_validate(inc_data)
            for inc_data in data["incidents"].values()
        ]
        return list(reversed(incidents))[:limit]

    async def update_incident(self, incident_id: str, updates: Dict[str, Any]) -> bool:
        data = await self._load_data()
        if incident_id in data["incidents"]:
            data["incidents"][incident_id].update(updates)
            await self._save_data(data)
            return True
        return False

    async def save_finding(self, finding: SCCFinding) -> str:
        data = await self._load_data()
        finding_id = finding.finding_id
        data["findings"][finding_id] = finding.model_dump(mode="json")
        await self._save_data(data)
        return finding_id

    async def update_containment_status(
        self, incident_id: str, command_id: str, status: ContainmentStatus
    ) -> bool:
        data = await self._load_data()
        if incident_id in data["incidents"]:
            report_data = data["incidents"][incident_id]
            for cmd in report_data.get("staged_gcloud_commands", []):
                if cmd.get("command_id") == command_id:
                    cmd["status"] = status.value
            await self._save_data(data)
            return True
        return False


class FirestoreIncidentStore(IncidentStore):
    """Google Cloud Firestore persistent storage implementation."""

    def __init__(self, collection_name: Optional[str] = None):
        config = get_config()
        self.collection_name = collection_name or config.firestore_collection
        self.local_fallback = LocalIncidentStore()

    async def save_incident(self, report: IncidentReport) -> str:
        try:
            db = await get_firestore_client()
            if db:
                doc_ref = db.collection(self.collection_name).document(report.incident_id)
                await doc_ref.set(report.model_dump(mode="json"))
                return report.incident_id
        except Exception as exc:
            logger.error("Firestore save error: %s. Using local fallback.", exc)
        return await self.local_fallback.save_incident(report)

    async def get_incident(self, incident_id: str) -> Optional[IncidentReport]:
        try:
            db = await get_firestore_client()
            if db:
                doc_ref = db.collection(self.collection_name).document(incident_id)
                doc = await doc_ref.get()
                if doc.exists:
                    return IncidentReport.model_validate(doc.to_dict())
        except Exception as exc:
            logger.error("Firestore get error: %s. Using local fallback.", exc)
        return await self.local_fallback.get_incident(incident_id)

    async def list_incidents(self, limit: int = 20) -> List[IncidentReport]:
        try:
            db = await get_firestore_client()
            if db:
                query = db.collection(self.collection_name).limit(limit)
                docs = query.stream()
                incidents: List[IncidentReport] = []
                async for doc in docs:
                    incidents.append(IncidentReport.model_validate(doc.to_dict()))
                return incidents
        except Exception as exc:
            logger.error("Firestore list error: %s. Using local fallback.", exc)
        return await self.local_fallback.list_incidents(limit)

    async def update_incident(self, incident_id: str, updates: Dict[str, Any]) -> bool:
        try:
            db = await get_firestore_client()
            if db:
                doc_ref = db.collection(self.collection_name).document(incident_id)
                await doc_ref.update(updates)
                return True
        except Exception as exc:
            logger.error("Firestore update error: %s. Using local fallback.", exc)
        return await self.local_fallback.update_incident(incident_id, updates)

    async def save_finding(self, finding: SCCFinding) -> str:
        try:
            db = await get_firestore_client()
            if db:
                doc_ref = db.collection("scc_findings").document(finding.finding_id)
                await doc_ref.set(finding.model_dump(mode="json"))
                return finding.finding_id
        except Exception as exc:
            logger.error("Firestore save_finding error: %s. Using local fallback.", exc)
        return await self.local_fallback.save_finding(finding)

    async def update_containment_status(
        self, incident_id: str, command_id: str, status: ContainmentStatus
    ) -> bool:
        try:
            db = await get_firestore_client()
            if db:
                inc = await self.get_incident(incident_id)
                if inc:
                    for cmd in inc.staged_gcloud_commands:
                        if cmd.command_id == command_id:
                            cmd.status = status
                    await self.save_incident(inc)
                    return True
        except Exception as exc:
            logger.error("Firestore update_containment error: %s. Using local fallback.", exc)
        return await self.local_fallback.update_containment_status(
            incident_id, command_id, status
        )


_store_instance: Optional[IncidentStore] = None


def get_incident_store() -> IncidentStore:
    """Return the singleton instance of IncidentStore."""
    global _store_instance
    if _store_instance is None:
        if HAS_FIRESTORE:
            _store_instance = FirestoreIncidentStore()
        else:
            _store_instance = LocalIncidentStore()
    return _store_instance
