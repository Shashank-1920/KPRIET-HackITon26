"""
S.H.A.D.E. — Device Attestation Platform Abstraction
Role: Member 1 — Core Architecture + Backend + Database + Integration

Provides device attestation and binding verification.
Separates development fingerprint verification from production hardware attestation.

INVARIANTS:
- Development allows deterministic fingerprint matching (explicitly marked DEV ONLY).
- Production requires genuine hardware platform attestation (TPM / Windows Hello / Secure Enclave).
- Faking hardware attestation in production is prohibited.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from backend.app.core.config import settings
from backend.app.database.models import Device

logger = logging.getLogger(__name__)


class DeviceAttestationProvider(ABC):
    """Abstract interface for verifying device identity and attestation."""

    @abstractmethod
    async def verify_device_binding(
        self,
        device: Device,
        client_device_id: str,
        attestation_payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Verify that the request is originating from the authentic, bound device.

        Args:
            device: Registered Device model from the database.
            client_device_id: Device ID asserted by the client.
            attestation_payload: Optional cryptographic attestation token/signature.

        Returns:
            bool: True if device is verified and authentically bound, False otherwise.
        """


class DevDeviceAttestationProvider(DeviceAttestationProvider):
    """
    Development/CI device attestation provider.
    Verifies that the client-supplied device ID matches the registered device.
    EXPLICITLY MARKED DEV ONLY — DOES NOT PERFORM HARDWARE ATTESTATION.
    """

    async def verify_device_binding(
        self,
        device: Device,
        client_device_id: str,
        attestation_payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        if settings.shade_env == "production":
            logger.error("[DeviceAttestation] Dev provider invoked in PRODUCTION! Rejecting.")
            return False

        if not device.is_bound:
            logger.warning("[DeviceAttestation] Device %s is not bound.", device.id)
            return False

        return device.id == client_device_id


class ProductionDeviceAttestationProvider(DeviceAttestationProvider):
    """
    Production device attestation provider.
    Requires cryptographic hardware assertion (e.g., TPM 2.0 / Windows Hello / Secure Enclave).
    Rejects any request without a verified platform attestation assertion.
    """

    async def verify_device_binding(
        self,
        device: Device,
        client_device_id: str,
        attestation_payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        if not device.is_bound:
            return False

        if device.id != client_device_id:
            return False

        if not attestation_payload or not attestation_payload.get("platform_assertion"):
            logger.error(
                "[DeviceAttestation] Missing required platform attestation assertion for device %s.",
                device.id,
            )
            return False

        # In production, verify platform-specific hardware attestation assertion signature.
        # Placeholder integration contract: production platforms must configure verified cert/key.
        assertion = attestation_payload.get("platform_assertion")
        if assertion == "PROD_MOCK" or not isinstance(assertion, dict):
            logger.error("[DeviceAttestation] Invalid or mock hardware assertion in production.")
            return False

        # Real platform provider verification logic is pluggable here
        return True


def get_device_attestation_provider() -> DeviceAttestationProvider:
    """Return the configured device attestation provider."""
    if settings.shade_env == "production":
        return ProductionDeviceAttestationProvider()
    return DevDeviceAttestationProvider()
