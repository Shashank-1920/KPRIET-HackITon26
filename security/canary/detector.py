"""
S.H.A.D.E. — Canary Honeytoken Generator and Detector
Generates trackable decoy credentials for deterministic leak attribution.
Monitors outbound and inbound traffic for honeytoken presence.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import secrets
from typing import Optional
import uuid


@dataclass(frozen=True)
class CanaryToken:
    """Represents an active decoy canary token registered in the system."""

    token_id: str
    token_type: str  # CANARY_API_KEY, CANARY_EMAIL, CANARY_DB_URI, CANARY_TOKEN
    value: str
    tag: str  # Attribution label: e.g. 'finance_db_dump', 'agent_system_prompt'
    created_at: str
    description: str = ""


@dataclass(frozen=True)
class CanaryAlert:
    """Triggered when a registered canary token is observed in payload."""

    alert_id: str
    token_id: str
    token_type: str
    attribution_tag: str
    observed_value_masked: str
    timestamp: str
    severity: str = "CRITICAL"
    message: str = ""


class CanaryDetector:
    """
    Decoy credential generator and breach attribution detector.
    Injects trackable canary tokens into internal documents/prompts and flags
    any external exfiltration or prompt leakage instantly.
    """

    def __init__(self) -> None:
        # In-memory registry of active canary tokens keyed by value
        self._tokens_by_value: dict[str, CanaryToken] = {}
        self._tokens_by_id: dict[str, CanaryToken] = {}

    def register_token(self, token: CanaryToken) -> None:
        """Register an existing canary token into the active monitoring set."""
        self._tokens_by_value[token.value] = token
        self._tokens_by_id[token.token_id] = token

    def generate_api_key(
        self, tag: str, prefix: str = "shade_cnry_", description: str = ""
    ) -> CanaryToken:
        """
        Generate a decoy API key honeytoken.
        Format: shade_cnry_{tag_slug}_{random_hex}
        """
        slug = "".join(c if c.isalnum() else "_" for c in tag.lower())[:12]
        random_suffix = secrets.token_hex(16)
        value = f"{prefix}{slug}_{random_suffix}"
        token = CanaryToken(
            token_id=str(uuid.uuid4()),
            token_type="CANARY_API_KEY",
            value=value,
            tag=tag,
            created_at=datetime.now(timezone.utc).isoformat(),
            description=description or f"Canary API Key for '{tag}' leak attribution",
        )
        self.register_token(token)
        return token

    def generate_email(
        self, tag: str, domain: str = "canary.shade.local", description: str = ""
    ) -> CanaryToken:
        """Generate a decoy email address honeytoken."""
        slug = "".join(c if c.isalnum() else "_" for c in tag.lower())[:10]
        random_suffix = secrets.token_hex(4)
        value = f"honey_{slug}_{random_suffix}@{domain}"
        token = CanaryToken(
            token_id=str(uuid.uuid4()),
            token_type="CANARY_EMAIL",
            value=value,
            tag=tag,
            created_at=datetime.now(timezone.utc).isoformat(),
            description=description or f"Canary Email for '{tag}'",
        )
        self.register_token(token)
        return token

    def generate_db_uri(
        self, tag: str, host: str = "vault.internal.shade", description: str = ""
    ) -> CanaryToken:
        """Generate a decoy database connection string."""
        user = f"decoy_usr_{secrets.token_hex(3)}"
        password = secrets.token_urlsafe(16)
        value = f"postgresql://{user}:{password}@{host}:5432/production_vault"
        token = CanaryToken(
            token_id=str(uuid.uuid4()),
            token_type="CANARY_DB_URI",
            value=value,
            tag=tag,
            created_at=datetime.now(timezone.utc).isoformat(),
            description=description or f"Canary Database URI for '{tag}'",
        )
        self.register_token(token)
        return token

    def is_canary(self, value: str) -> bool:
        """Check if an exact string matches an active canary."""
        return value.strip() in self._tokens_by_value

    def get_token(self, token_value: str) -> Optional[CanaryToken]:
        """Lookup canary token by value."""
        return self._tokens_by_value.get(token_value.strip())

    def get_token_by_id(self, token_id: str) -> Optional[CanaryToken]:
        """Lookup canary token by ID."""
        return self._tokens_by_id.get(token_id)

    def list_active_tokens(self) -> list[CanaryToken]:
        """Return all actively monitored canary honeytokens."""
        return list(self._tokens_by_value.values())

    def scan_payload(self, payload: str) -> list[CanaryAlert]:
        """
        Scan a payload string for any occurrence of registered canary tokens.
        If a token is detected, emits a CRITICAL severity CanaryAlert.
        """
        alerts: list[CanaryAlert] = []
        if not payload:
            return alerts

        for value, token in self._tokens_by_value.items():
            if value in payload:
                # Mask value: first 4 chars + asterisks
                masked = (
                    f"{value[:4]}...{value[-4:]}"
                    if len(value) > 8
                    else "[CANARY_TRIGGERED]"
                )
                alert = CanaryAlert(
                    alert_id=str(uuid.uuid4()),
                    token_id=token.token_id,
                    token_type=token.token_type,
                    attribution_tag=token.tag,
                    observed_value_masked=masked,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    severity="CRITICAL",
                    message=(
                        f"CRITICAL HONEYTOKEN BREACH DETECTED: Canary '{token.token_type}' "
                        f"assigned to [{token.tag}] was exposed in payload!"
                    ),
                )
                alerts.append(alert)

        return alerts
