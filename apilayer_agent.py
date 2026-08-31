"""
APILayer Unified Suite Integration for Google Antigravity SDK.

Services integrated:
- ipstack: IP Geolocation lookup
- marketstack: Real-time and end-of-day stock market data
- mailboxlayer: Email deliverability & syntax validation
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from typing import Any, Optional

import httpx
from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from google.antigravity import Agent, LocalAgentConfig, types

# Load environment variables from .env
load_dotenv()
logger = logging.getLogger("apilayer_agent")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


# ============================================================================
# 1. Configuration Management
# ============================================================================

class APILayerSettings(BaseSettings):
    """Runtime configuration for APILayer and Gemini."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    apilayer_api_key: str = Field(
        default_factory=lambda: os.getenv("APILAYER_API_KEY", "")
    )
    gemini_api_key: str = Field(
        default_factory=lambda: os.getenv("GEMINI_API_KEY", "")
    )
    gemini_model: str = Field(default="gemini-2.5-flash")
    http_timeout_seconds: float = Field(default=15.0)


settings = APILayerSettings()


# ============================================================================
# 2. Pydantic Input Schemas
# ============================================================================

class IPGeolocationInput(BaseModel):
    """Input parameters for IP geolocation lookup via ipstack."""

    ip_address: str = Field(
        ...,
        description="Valid IPv4 or IPv6 address to geolocate (e.g. '134.201.250.155').",
        examples=["134.201.250.155", "2001:4860:4860::8888"],
    )

    @field_validator("ip_address")
    @classmethod
    def validate_ip_format(cls, v: str) -> str:
        v = v.strip()
        ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        ipv6_pattern = r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$"
        if not (re.match(ipv4_pattern, v) or re.match(ipv6_pattern, v) or ":" in v):
            raise ValueError(f"Invalid IP address format: '{v}'")
        return v


class StockQuoteInput(BaseModel):
    """Input parameters for stock data lookup via marketstack."""

    symbols: str = Field(
        ...,
        description="One or more comma-separated stock ticker symbols (e.g. 'AAPL', 'MSFT,GOOGL').",
        examples=["AAPL", "GOOGL,MSFT"],
    )

    @field_validator("symbols")
    @classmethod
    def clean_symbols(cls, v: str) -> str:
        cleaned = ",".join(s.strip().upper() for s in v.split(",") if s.strip())
        if not cleaned:
            raise ValueError("Stock symbol string cannot be empty.")
        return cleaned


class EmailValidationInput(BaseModel):
    """Input parameters for email validation via mailboxlayer."""

    email: str = Field(
        ...,
        description="The email address to verify for deliverability and syntax (e.g. 'test@example.com').",
        examples=["test@example.com", "support@github.com"],
    )

    @field_validator("email")
    @classmethod
    def validate_email_syntax(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v or "." not in v.split("@")[-1]:
            raise ValueError(f"Invalid email structure: '{v}'")
        return v


# ============================================================================
# 3. Helper for Error Wrapping
# ============================================================================

def _format_error_hint(
    service: str,
    error_type: str,
    message: str,
    recovery_hint: str,
    status_code: Optional[int] = None,
) -> str:
    """Format structured error JSON so the LLM can self-correct instead of crashing."""
    payload = {
        "status": "error",
        "service": service,
        "error_type": error_type,
        "status_code": status_code,
        "message": message,
        "agent_recovery_hint": recovery_hint,
    }
    return json.dumps(payload, indent=2)


# ============================================================================
# 4. Custom Asynchronous APILayer Tools
# ============================================================================

async def get_ip_geolocation(ip_address: str) -> str:
    """Geolocate an IP address (country, city, latitude, longitude, ISP) using the APILayer ipstack service.

    Args:
        ip_address: Valid IPv4 or IPv6 address (e.g. '134.201.250.155').

    Returns:
        JSON string containing geolocation data or structured error recovery hint.
    """
    try:
        validated = IPGeolocationInput(ip_address=ip_address)
    except Exception as validation_err:
        return _format_error_hint(
            service="ipstack",
            error_type="InputValidationError",
            message=str(validation_err),
            recovery_hint="Check the IP address format. It must be a valid IPv4 or IPv6 address.",
        )

    api_key = settings.apilayer_api_key
    if not api_key:
        return _format_error_hint(
            service="ipstack",
            error_type="ConfigurationError",
            message="APILAYER_API_KEY environment variable is not set.",
            recovery_hint="Inform the user that the APILayer API key is missing from environment variables.",
        )

    # Primary APILayer Gateway URL with fallback
    urls_to_try = [
        ("https://api.apilayer.com/ipstack/" + validated.ip_address, {"apikey": api_key}, {}),
        (f"http://api.ipstack.com/{validated.ip_address}", {}, {"access_key": api_key}),
    ]

    try:
        async with httpx.AsyncClient(timeout=settings.http_timeout_seconds) as client:
            last_err = ""
            for url, headers, params in urls_to_try:
                try:
                    response = await client.get(url, headers=headers, params=params)
                    if response.status_code == 200:
                        data = response.json()
                        if "error" in data:
                            last_err = data["error"].get("info", "API error")
                            continue
                        return json.dumps({
                            "status": "success",
                            "ip": data.get("ip", validated.ip_address),
                            "type": data.get("type"),
                            "continent_name": data.get("continent_name"),
                            "country_name": data.get("country_name"),
                            "region_name": data.get("region_name"),
                            "city": data.get("city"),
                            "zip": data.get("zip"),
                            "latitude": data.get("latitude"),
                            "longitude": data.get("longitude"),
                        }, indent=2)
                except Exception as e:
                    last_err = str(e)
                    continue

            return _format_error_hint(
                service="ipstack",
                error_type="APIError",
                message=last_err or "Failed to retrieve IP geolocation from endpoints.",
                recovery_hint="Service was unable to geolocate the IP. Provide best effort explanation to user.",
            )

    except httpx.TimeoutException:
        return _format_error_hint(
            service="ipstack",
            error_type="TimeoutError",
            message=f"Request timed out after {settings.http_timeout_seconds}s.",
            recovery_hint="The geolocation service is slow to respond. Skip or mention the timeout.",
        )
    except Exception as req_err:
        return _format_error_hint(
            service="ipstack",
            error_type="NetworkError",
            message=str(req_err),
            recovery_hint="Network transport error. Verify internet connectivity.",
        )


async def get_stock_quote(symbols: str) -> str:
    """Fetch latest stock market prices, volume, and daily high/low for given ticker symbols via marketstack.

    Args:
        symbols: Comma-separated list of stock tickers (e.g. 'AAPL' or 'MSFT,GOOGL').

    Returns:
        JSON string containing ticker prices or structured error recovery hint.
    """
    try:
        validated = StockQuoteInput(symbols=symbols)
    except Exception as validation_err:
        return _format_error_hint(
            service="marketstack",
            error_type="InputValidationError",
            message=str(validation_err),
            recovery_hint="Ensure ticker symbols are valid uppercase letters separated by commas (e.g. 'AAPL').",
        )

    api_key = settings.apilayer_api_key
    if not api_key:
        return _format_error_hint(
            service="marketstack",
            error_type="ConfigurationError",
            message="APILAYER_API_KEY environment variable is not set.",
            recovery_hint="Inform user that APILayer API key is required.",
        )

    urls_to_try = [
        ("https://api.apilayer.com/marketstack/v1/eod/latest", {"apikey": api_key}, {"symbols": validated.symbols}),
        ("http://api.marketstack.com/v1/eod/latest", {}, {"access_key": api_key, "symbols": validated.symbols}),
    ]

    try:
        async with httpx.AsyncClient(timeout=settings.http_timeout_seconds) as client:
            last_err = ""
            for url, headers, params in urls_to_try:
                try:
                    response = await client.get(url, params=params, headers=headers)
                    if response.status_code == 200:
                        data = response.json()
                        raw_data = data.get("data", [])
                        if raw_data:
                            quotes = []
                            for item in raw_data:
                                quotes.append({
                                    "symbol": item.get("symbol"),
                                    "close": item.get("close"),
                                    "high": item.get("high"),
                                    "low": item.get("low"),
                                    "open": item.get("open"),
                                    "volume": item.get("volume"),
                                    "date": item.get("date"),
                                    "exchange": item.get("exchange"),
                                })
                            return json.dumps({"status": "success", "quotes": quotes}, indent=2)
                        elif "error" in data:
                            last_err = data["error"].get("message", "Marketstack API error")
                except Exception as e:
                    last_err = str(e)
                    continue

            return _format_error_hint(
                service="marketstack",
                error_type="NoDataFound",
                message=last_err or f"No quote data returned for symbols: {validated.symbols}",
                recovery_hint="Verify the ticker symbol spelling or check plan access.",
            )

    except httpx.TimeoutException:
        return _format_error_hint(
            service="marketstack",
            error_type="TimeoutError",
            message="Marketstack request timed out.",
            recovery_hint="Stock market service timed out. You may continue with other queries.",
        )
    except Exception as req_err:
        return _format_error_hint(
            service="marketstack",
            error_type="NetworkError",
            message=str(req_err),
            recovery_hint="Network transport error.",
        )


async def validate_email(email: str) -> str:
    """Validate an email address for MX records, SMTP deliverability, disposable domain, and syntax via mailboxlayer.

    Args:
        email: Email address to verify (e.g. 'test@example.com').

    Returns:
        JSON string containing email deliverability report or structured error hint.
    """
    try:
        validated = EmailValidationInput(email=email)
    except Exception as validation_err:
        return _format_error_hint(
            service="mailboxlayer",
            error_type="InputValidationError",
            message=str(validation_err),
            recovery_hint="Provide a valid email address with an '@' and a domain name.",
        )

    api_key = settings.apilayer_api_key
    if not api_key:
        return _format_error_hint(
            service="mailboxlayer",
            error_type="ConfigurationError",
            message="APILAYER_API_KEY environment variable is not set.",
            recovery_hint="Inform user that APILayer API key is required.",
        )

    urls_to_try = [
        ("https://api.apilayer.com/email_verification/check", {"apikey": api_key}, {"email": validated.email}),
        ("http://apilayer.net/api/check", {}, {"access_key": api_key, "email": validated.email}),
    ]

    try:
        async with httpx.AsyncClient(timeout=settings.http_timeout_seconds) as client:
            last_err = ""
            for url, headers, params in urls_to_try:
                try:
                    response = await client.get(url, params=params, headers=headers)
                    if response.status_code == 200:
                        data = response.json()
                        if "error" in data:
                            last_err = data["error"].get("info", "Mailboxlayer API error")
                            continue
                        return json.dumps({
                            "status": "success",
                            "email": data.get("email", validated.email),
                            "user": data.get("user"),
                            "domain": data.get("domain"),
                            "format_valid": data.get("format_valid"),
                            "mx_found": data.get("mx_found"),
                            "smtp_check": data.get("smtp_check"),
                            "is_disposable": data.get("disposable"),
                            "is_free_provider": data.get("free"),
                            "score": data.get("score"),
                        }, indent=2)
                except Exception as e:
                    last_err = str(e)
                    continue

            return _format_error_hint(
                service="mailboxlayer",
                error_type="APIError",
                message=last_err or "Failed to validate email via endpoints.",
                recovery_hint="Email verification returned an error. Report best effort to user.",
            )

    except httpx.TimeoutException:
        return _format_error_hint(
            service="mailboxlayer",
            error_type="TimeoutError",
            message="Mailboxlayer verification timed out.",
            recovery_hint="Email verification timed out. Skip or retry.",
        )
    except Exception as req_err:
        return _format_error_hint(
            service="mailboxlayer",
            error_type="NetworkError",
            message=str(req_err),
            recovery_hint="Network transport error.",
        )


# ============================================================================
# 5. Antigravity Agent Configuration
# ============================================================================

def create_apilayer_agent_config() -> LocalAgentConfig:
    """Create and configure the Google Antigravity LocalAgentConfig with APILayer tools."""

    system_instructions = (
        "You are an autonomous intelligence agent equipped with the APILayer Unified Suite.\n\n"
        "Available Capabilities:\n"
        "1. `get_ip_geolocation`: Fetch geographic location, coordinates, and region for any IP address.\n"
        "2. `get_stock_quote`: Query latest market prices, open/close, volume, and highs/lows for stock tickers.\n"
        "3. `validate_email`: Check email validity, syntax, MX records, and disposable domain status.\n\n"
        "Operational Guidelines:\n"
        "- Execute multiple tools in parallel or sequence to fulfill composite user requests.\n"
        "- If a tool returns a JSON error hint with `status: 'error'`, interpret the `agent_recovery_hint` "
        "and either self-correct your input parameters or gracefully explain the issue to the user.\n"
        "- Present the consolidated findings in a well-formatted markdown response with tables and key highlights."
    )

    return LocalAgentConfig(
        tools=[get_ip_geolocation, get_stock_quote, validate_email],
        system_instructions=system_instructions,
        capabilities=types.CapabilitiesConfig(
            enable_subagents=False,
        ),
    )


# ============================================================================
# 6. Execution Entry Point
# ============================================================================

async def main() -> None:
    """Run a multi-step test query demonstrating tool coordination and synthesis."""
    print("=" * 70)
    print("🚀 Initializing Google Antigravity Agent with APILayer Suite")
    print("=" * 70)

    config = create_apilayer_agent_config()

    prompt = (
        "Please perform the following three investigative tasks:\n"
        "1. Verify the email address 'test@example.com' for deliverability and MX records.\n"
        "2. Find the geolocation and physical coordinates of IP address '134.201.250.155'.\n"
        "3. Check the current stock price and daily statistics for ticker 'AAPL'.\n\n"
        "Synthesize all findings into a structured summary report."
    )

    print(f"\n[User Query]:\n{prompt}\n")
    print("-" * 70)
    print("[Agent Execution & Tool Invocations]:\n")

    async with Agent(config) as agent:
        response = await agent.chat(prompt)

        async for chunk in response:
            print(chunk, end="", flush=True)

    print("\n\n" + "=" * 70)
    print("✅ Execution Complete")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
