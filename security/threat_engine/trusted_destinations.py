"""
S.H.A.D.E. — Trusted Destination Policy Evaluator
Evaluates destination URLs and hostnames against statutory and institutional trust policies.

Critical Security Invariants:
1. Strict domain boundary parsing (prevents substring spoofing such as evilgov.in or fakeac.in.example.com).
2. Government portals (*.gov.in, *.nic.in) -> GOVERNMENT_PORTAL (Trusted).
3. Educational institutions (*.ac.in, *.edu) -> COLLEGE_UNIVERSITY (Trusted).
4. All other destinations default to UNTRUSTED ("Publicly accessible" does not mean "trusted").
5. Deterministic and 100% offline (no external DNS or network calls).
"""

from dataclasses import dataclass
from typing import Final, Optional
from urllib.parse import urlsplit


@dataclass(frozen=True)
class DestinationTrustResult:
    """Evaluation dossier for a requested network destination."""

    destination: str
    hostname: str
    is_trusted: bool
    category: str  # GOVERNMENT_PORTAL, COLLEGE_UNIVERSITY, UNTRUSTED, MALFORMED
    policy_reason: str


class TrustedDestinationEvaluator:
    """
    Evaluates whether an outbound target domain meets verified trust standards.
    Distinguishes official government and accredited university portals from
    arbitrary public or commercial endpoints.
    """

    # Official government root suffixes
    _GOV_SUFFIXES: Final[tuple[str, ...]] = (
        "gov.in",
        "nic.in",
    )

    # Accredited academic and educational suffixes
    _ACADEMIC_SUFFIXES: Final[tuple[str, ...]] = (
        "ac.in",
        "edu",
    )

    def extract_hostname(self, destination: str) -> Optional[str]:
        """
        Safely parse and normalize the hostname from a URL or raw domain string.
        Handles optional schemes (http/https), port numbers, trailing dots, and case normalization.
        """
        if not destination or not isinstance(destination, str):
            return None

        cleaned = destination.strip()
        if not cleaned:
            return None

        # Prepend scheme if absent so urlsplit parses netloc accurately
        if "://" not in cleaned:
            parse_target = f"https://{cleaned}"
        else:
            parse_target = cleaned

        try:
            parsed = urlsplit(parse_target)
            raw_host = parsed.hostname
            if not raw_host:
                return None
            # Normalize to lowercase and strip trailing root domain dots
            norm_host = raw_host.strip().lower().rstrip(".")
            # Basic sanity check: hostname must contain valid characters
            if " " in norm_host or not norm_host:
                return None
            return norm_host
        except Exception:
            return None

    def _matches_suffix(self, hostname: str, root_suffix: str) -> bool:
        """
        Check if hostname strictly matches root_suffix or is a subdomain of root_suffix.
        Guarantees that 'evilgov.in' does NOT match 'gov.in'.
        """
        if hostname == root_suffix:
            return True
        if hostname.endswith(f".{root_suffix}"):
            return True
        return False

    def is_trusted_destination(self, destination: str) -> DestinationTrustResult:
        """
        Evaluate if a destination URL or domain satisfies trusted domain policies.
        """
        hostname = self.extract_hostname(destination)
        if not hostname:
            return DestinationTrustResult(
                destination=str(destination),
                hostname="",
                is_trusted=False,
                category="MALFORMED",
                policy_reason="Malformed or invalid destination format.",
            )

        # 1. Government portal verification (*.gov.in, *.nic.in)
        for gov_root in self._GOV_SUFFIXES:
            if self._matches_suffix(hostname, gov_root):
                return DestinationTrustResult(
                    destination=destination,
                    hostname=hostname,
                    is_trusted=True,
                    category="GOVERNMENT_PORTAL",
                    policy_reason=f"Matches verified government domain policy (*.{gov_root}).",
                )

        # 2. Academic institution verification (*.ac.in, *.edu)
        for acad_root in self._ACADEMIC_SUFFIXES:
            if self._matches_suffix(hostname, acad_root):
                return DestinationTrustResult(
                    destination=destination,
                    hostname=hostname,
                    is_trusted=True,
                    category="COLLEGE_UNIVERSITY",
                    policy_reason=f"Matches verified academic institution policy (*.{acad_root}).",
                )

        # 3. Default: Untrusted destination
        return DestinationTrustResult(
            destination=destination,
            hostname=hostname,
            is_trusted=False,
            category="UNTRUSTED",
            policy_reason=(
                "Destination is not on the trusted-domain allowlist. "
                "Public accessibility does not grant trusted status."
            ),
        )
