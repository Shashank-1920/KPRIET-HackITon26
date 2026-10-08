"""
S.H.A.D.E. — Trusted Destination Evaluator Abstraction
Role: Member 1 — Core Architecture + Backend + Database + Integration

Evaluates destination trustworthiness for rehydration requests.
Outputs:
  - TRUSTED
  - NOT_TRUSTED
  - UNKNOWN

CRITICAL INVARIANTS:
  - UNKNOWN destinations are NOT automatically trusted.
  - Domain trust policies must be extensible and configurable via configuration/rules.
  - No hardcoded domain pattern heuristics are forced unless explicitly configured.
"""

import enum
import logging
import urllib.parse
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class TrustLevel(str, enum.Enum):
    TRUSTED = "TRUSTED"
    NOT_TRUSTED = "NOT_TRUSTED"
    UNKNOWN = "UNKNOWN"


class DestinationTrustEvaluator(ABC):
    """Abstract interface for evaluating destination trustworthiness."""

    @abstractmethod
    def evaluate_destination(
        self,
        destination_url: Optional[str] = None,
        source_context: Optional[Dict[str, Any]] = None,
    ) -> TrustLevel:
        """
        Evaluate whether the given destination is trusted.

        Returns:
            TrustLevel: TRUSTED, NOT_TRUSTED, or UNKNOWN.
        """


class ConfigurableDestinationTrustEvaluator(DestinationTrustEvaluator):
    """
    Configurable destination evaluator.
    Maintains explicit sets of trusted and untrusted domains.
    Default classification for unrecognized destinations is UNKNOWN.
    """

    def __init__(
        self,
        trusted_domains: Optional[Set[str]] = None,
        blocked_domains: Optional[Set[str]] = None,
    ) -> None:
        self._trusted_domains: Set[str] = trusted_domains or set()
        self._blocked_domains: Set[str] = blocked_domains or set()

    def add_trusted_domain(self, domain: str) -> None:
        self._trusted_domains.add(domain.lower().strip())

    def add_blocked_domain(self, domain: str) -> None:
        self._blocked_domains.add(domain.lower().strip())

    def evaluate_destination(
        self,
        destination_url: Optional[str] = None,
        source_context: Optional[Dict[str, Any]] = None,
    ) -> TrustLevel:
        if not destination_url:
            return TrustLevel.UNKNOWN

        try:
            parsed = urllib.parse.urlparse(destination_url)
            hostname = (parsed.hostname or "").lower().strip()
            if not hostname:
                return TrustLevel.UNKNOWN
        except Exception:
            return TrustLevel.NOT_TRUSTED

        # Exact match or subdomain match against blocked domains
        for blocked in self._blocked_domains:
            if hostname == blocked or hostname.endswith(f".{blocked}"):
                return TrustLevel.NOT_TRUSTED

        # Exact match or subdomain match against trusted domains
        for trusted in self._trusted_domains:
            if hostname == trusted or hostname.endswith(f".{trusted}"):
                return TrustLevel.TRUSTED

        return TrustLevel.UNKNOWN


_trust_evaluator_instance: Optional[DestinationTrustEvaluator] = None


def get_destination_trust_evaluator() -> DestinationTrustEvaluator:
    """Return the configured DestinationTrustEvaluator singleton."""
    global _trust_evaluator_instance
    if _trust_evaluator_instance is None:
        # Default configured evaluator (extensible via configuration or admin rules)
        evaluator = ConfigurableDestinationTrustEvaluator()
        _trust_evaluator_instance = evaluator
    return _trust_evaluator_instance
