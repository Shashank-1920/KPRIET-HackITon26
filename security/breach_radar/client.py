"""
S.H.A.D.E. — Credential Breach Radar (XposedOrNot Client)
Open-source breach detection utilizing the XposedOrNot library and API.

Strict Security Invariants:
1. Passwords are NEVER transmitted in plaintext.
2. Uses k-anonymity (Keccak-512 / SHA3-512 with 10-char prefix).
3. Local offline fallback ensures zero-latency and air-gapped demo resilience.
"""

from dataclasses import dataclass
import hashlib
from typing import Any, Final, Optional

try:
    from xposedornot import NotFoundError, XposedOrNot
    HAS_XON_LIB = True
except ImportError:  # pragma: no cover
    HAS_XON_LIB = False
    XposedOrNot = None
    NotFoundError = Exception


@dataclass(frozen=True)
class BreachRadarCheckResult:
    """Result of an anonymous password breach verification check."""

    hash_prefix: str
    is_breached: bool
    breach_count: int
    checked_via: str
    characteristics: Optional[dict[str, Any]] = None
    error: Optional[str] = None


@dataclass(frozen=True)
class EmailBreachCheckResult:
    """Result of an email breach verification check."""

    email: str
    is_breached: bool
    breaches_count: int
    breaches: list[str]
    checked_via: str
    error: Optional[str] = None


class XposedOrNotClient:
    """
    Open-source credential breach detection client powered by XposedOrNot.
    Protects user privacy using Keccak-512 10-char k-anonymity queries.
    """

    def __init__(
        self,
        enable_offline_cache: bool = True,
        timeout_seconds: float = 4.0,
    ) -> None:
        self.enable_offline_cache = enable_offline_cache
        self.timeout_seconds = timeout_seconds

        self._xon: Optional[Any] = None
        if HAS_XON_LIB:
            try:
                self._xon = XposedOrNot()
            except Exception:
                self._xon = None

        # Local offline database for air-gapped testing and deterministic demos
        # Stores lowercase 10-char prefix of Keccak/SHA3-512 -> breach count
        self._offline_hashes: dict[str, int] = {
            # "password" -> SHA3-512 prefix "e9a7548673" or Keccak "a6818b8188"
            "a6818b8188": 1590937,
            "e9a7548673": 1590937,
            # "123456" -> Keccak / SHA3-512
            "64d09d9930": 48123985,
            # "admin"
            "3422a57ebc": 3218901,
        }

        # Offline mock emails for local tests
        self._offline_emails: dict[str, list[str]] = {
            "test@example.com": ["Ticketfly", "Twitter-Scraped", "Adobe", "Canva", "Dropbox"],
            "breached@shade.local": ["DemoBreach2026", "CorporateLeakedLogs"],
        }

    def _compute_sha3_512_prefix(self, password: str) -> str:
        """Compute the first 10 characters of SHA3-512 in hex."""
        return hashlib.sha3_512(password.encode("utf-8")).hexdigest()[:10].lower()

    def check_password(self, password: str) -> BreachRadarCheckResult:
        """
        Check password against XposedOrNot using k-anonymity.
        """
        if not password:
            return BreachRadarCheckResult(
                hash_prefix="",
                is_breached=False,
                breach_count=0,
                checked_via="VALIDATION",
                error="Empty password provided",
            )

        local_prefix = self._compute_sha3_512_prefix(password)

        # 1. Check local offline cache if active
        if self.enable_offline_cache and local_prefix in self._offline_hashes:
            return BreachRadarCheckResult(
                hash_prefix=local_prefix,
                is_breached=True,
                breach_count=self._offline_hashes[local_prefix],
                checked_via="OFFLINE_CACHE",
            )

        # 2. Query XposedOrNot library if available
        if self._xon is not None:
            try:
                res = self._xon.check_password(password)
                return BreachRadarCheckResult(
                    hash_prefix=res.anon,
                    is_breached=True,
                    breach_count=res.count,
                    checked_via="XPOSEDORNOT_LIVE",
                    characteristics=res.characteristics,
                )
            except NotFoundError:
                return BreachRadarCheckResult(
                    hash_prefix=local_prefix,
                    is_breached=False,
                    breach_count=0,
                    checked_via="XPOSEDORNOT_LIVE",
                )
            except Exception as exc:
                # Network or rate-limit error, fallback to offline evaluation
                count = self._offline_hashes.get(local_prefix, 0)
                return BreachRadarCheckResult(
                    hash_prefix=local_prefix,
                    is_breached=(count > 0),
                    breach_count=count,
                    checked_via="OFFLINE_FALLBACK",
                    error=f"Live XposedOrNot query failed ({type(exc).__name__}). Offline fallback used.",
                )

        # 3. Offline fallback if library unavailable
        count = self._offline_hashes.get(local_prefix, 0)
        return BreachRadarCheckResult(
            hash_prefix=local_prefix,
            is_breached=(count > 0),
            breach_count=count,
            checked_via="OFFLINE_DICTIONARY",
        )

    def check_email(self, email: str) -> EmailBreachCheckResult:
        """
        Check if an email address has been exposed in known public breaches.
        """
        clean_email = email.strip().lower()
        if not clean_email:
            return EmailBreachCheckResult(
                email=clean_email,
                is_breached=False,
                breaches_count=0,
                breaches=[],
                checked_via="VALIDATION",
                error="Empty email provided",
            )

        # 1. Check offline mock database first if present
        if self.enable_offline_cache and clean_email in self._offline_emails:
            breaches = self._offline_emails[clean_email]
            return EmailBreachCheckResult(
                email=clean_email,
                is_breached=True,
                breaches_count=len(breaches),
                breaches=breaches,
                checked_via="OFFLINE_CACHE",
            )

        # 2. Query live XposedOrNot if library available
        if self._xon is not None:
            try:
                res = self._xon.check_email(clean_email)
                # Res has breaches list, possibly nested list
                raw_breaches = getattr(res, "breaches", [])
                flattened: list[str] = []
                for b in raw_breaches:
                    if isinstance(b, list):
                        flattened.extend(str(item) for item in b)
                    else:
                        flattened.append(str(b))
                return EmailBreachCheckResult(
                    email=clean_email,
                    is_breached=len(flattened) > 0,
                    breaches_count=len(flattened),
                    breaches=flattened,
                    checked_via="XPOSEDORNOT_LIVE",
                )
            except NotFoundError:
                return EmailBreachCheckResult(
                    email=clean_email,
                    is_breached=False,
                    breaches_count=0,
                    breaches=[],
                    checked_via="XPOSEDORNOT_LIVE",
                )
            except Exception as exc:
                return EmailBreachCheckResult(
                    email=clean_email,
                    is_breached=False,
                    breaches_count=0,
                    breaches=[],
                    checked_via="OFFLINE_FALLBACK",
                    error=f"Live XON check failed ({type(exc).__name__})",
                )

        return EmailBreachCheckResult(
            email=clean_email,
            is_breached=False,
            breaches_count=0,
            breaches=[],
            checked_via="OFFLINE_FALLBACK",
        )
