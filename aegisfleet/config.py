"""Configuration module for AegisFleet SOC Responder.

Provides strictly validated Pydantic BaseSettings for cloud environments,
including GCP parameters, Gemini model selectors, Firestore collections,
concurrency limits, and structured JSON logging.
"""

from __future__ import annotations

from functools import lru_cache
import json
import logging
import os
import sys
from typing import List, Optional

from dotenv import load_dotenv
from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

load_dotenv()


class StructuredJsonFormatter(logging.Formatter):
    """Custom logging formatter that outputs JSON logs compatible with Google Cloud Logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "severity": record.levelname,
            "message": record.getMessage(),
            "timestamp": self.formatTime(record, self.datefmt),
            "logger": record.name,
            "component": "aegisfleet",
            "sourceLocation": {
                "file": record.pathname,
                "line": record.lineno,
                "function": record.funcName,
            },
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


def configure_logging(level: str = "INFO", json_format: bool = True) -> None:
    """Configure root logger with structured JSON formatting for Cloud Run / GCP."""
    root_logger = logging.getLogger()
    root_logger.setLevel(level.upper())
    root_logger.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    if json_format:
        handler.setFormatter(StructuredJsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
    root_logger.addHandler(handler)


class AegisFleetConfig(BaseSettings):
    """Application configuration settings for AegisFleet."""

    model_config = SettingsConfigDict(
        env_prefix="AEGISFLEET_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Cloud & Authentication
    gcp_project_id: str = Field(
        default="aegisfleet-demo",
        validation_alias=AliasChoices("AEGISFLEET_GCP_PROJECT_ID", "GCP_PROJECT_ID"),
        description="Target GCP project ID",
    )
    gcp_region: str = Field(
        default="us-central1",
        validation_alias=AliasChoices("AEGISFLEET_GCP_REGION", "GCP_REGION"),
        description="Default GCP region",
    )
    gemini_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("AEGISFLEET_GEMINI_API_KEY", "GEMINI_API_KEY"),
        description="Google Gemini API key",
    )
    gemini_model: str = Field(
        default="gemini-3.6-flash",
        validation_alias=AliasChoices("AEGISFLEET_GEMINI_MODEL", "GEMINI_MODEL"),
        description="Gemini model identifier for standard agent tasks",
    )
    gemini_thinking_model: str = Field(
        default="gemini-3.6-flash",
        validation_alias=AliasChoices(
            "AEGISFLEET_GEMINI_THINKING_MODEL", "GEMINI_THINKING_MODEL"
        ),
        description="Gemini model identifier for deep reasoning and correlation",
    )
    firestore_collection: str = Field(
        default="aegisfleet_incidents",
        validation_alias=AliasChoices(
            "AEGISFLEET_FIRESTORE_COLLECTION", "FIRESTORE_COLLECTION"
        ),
        description="Firestore collection name for incident records",
    )

    # Runtime behavior & Safety
    sandbox_mode: bool = Field(
        default=True,
        validation_alias=AliasChoices("AEGISFLEET_SANDBOX_MODE", "SANDBOX_MODE"),
        description="When True, containment commands are simulated and not executed against live GCP resources",
    )
    max_tool_retries: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum retry count for tool invocations per session",
    )
    max_concurrent_tool_calls: int = Field(
        default=5,
        ge=1,
        le=50,
        description="Concurrency limit for parallel GCP telemetry fetching tools",
    )
    max_log_payload_chars: int = Field(
        default=4000,
        ge=500,
        le=50000,
        description="Maximum character limit for raw log snippets injected into LLM context",
    )

    # Web & Networking
    log_level: str = Field(default="INFO", description="Logging level")
    json_logs: bool = Field(
        default=True, description="Enable structured JSON logging for Google Cloud Logging"
    )
    cors_origins: List[str] = Field(
        default_factory=lambda: ["*"],
        description="Allowed CORS origins for API requests",
    )
    port: int = Field(default=8080, ge=1024, le=65535, description="Server port")

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Any) -> List[str]:
        if isinstance(v, str):
            if v.strip() == "*":
                return ["*"]
            return [orig.strip() for orig in v.split(",") if orig.strip()]
        return v

    def validate_startup(self) -> None:
        """Validate critical configuration settings at server startup."""
        if not self.sandbox_mode and not self.gemini_api_key:
            raise ValueError(
                "GEMINI_API_KEY is strictly required when running in non-sandbox live mode."
            )


@lru_cache(maxsize=1)
def get_config() -> AegisFleetConfig:
    """Return the cached singleton configuration instance."""
    return AegisFleetConfig()
