"""
S.H.A.D.E. — Breach Radar (HaveIBeenPwned k-Anonymity Client)
Checks password exposure status using HaveIBeenPwned Passwords API v3.

Strict Security Invariants:
1. ONLY the first 5 characters of the SHA-1 hash (prefix) are ever sent externally.
2. Full passwords, hashes, emails, Aadhaar, or PAN are NEVER dispatched over the network.
3. Suffix evaluation occurs 100% in local memory on the host device.
4. Fails safe: Network timeouts or offline states degrade gracefully without crashing.
"""

from dataclasses import dataclass
import hashlib
from typing import Final, Optional
import urllib.error
import urllib.request

API_BASE_URL: Final[str] = "https://api.pwnedpasswords.com/range/"
USER_AGENT: Final[str] = "SHADE-PersonalSOC-BreachRadar/1.0"


@dataclass(frozen=True)
class HIBPCheckResult:
    """Result of a k-anonymity breach verification check."""

    sha1_prefix: str
    is_breached: bool
    breach_count: int
    checked_via: str
    error: Optional[str] = None


class HIBPClient:
    """
    Privacy-preserving client for HaveIBeenPwned Range API.
    Computes local SHA-1, requests hash buckets, and completes suffix matching locally.
    """

    def __init__(
        self,
        base_url: str = API_BASE_URL,
        timeout_seconds: float = 3.0,
        enable_offline_cache: bool = True,
    ) -> None:
        self.base_url = base_url
        self.timeout_seconds = timeout_seconds
        self.enable_offline_cache = enable_offline_cache
        # Local mock/offline database for air-gapped testing and deterministic demos
        self._offline_hashes: dict[str, int] = {
            # "password" -> SHA1: 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8": 10568432,
            # "123456" -> SHA1: 7C4A8D09CA3762AF61E59520943DC26494F8941B
            "7C4A8D09CA3762AF61E59520943DC26494F8941B": 48123985,
            # "admin" -> SHA1: D033E22AE348AEB5660FC2140AEC35850C4DA997
            "D033E22AE348AEB5660FC2140AEC35850C4DA997": 3218901,
        }

    def check_password(self, password: str) -> HIBPCheckResult:
        """
        Check password against HIBP using strictly k-anonymity protocol.
        """
        if not password:
            return HIBPCheckResult(
                sha1_prefix="",
                is_breached=False,
                breach_count=0,
                checked_via="VALIDATION",
                error="Empty password provided",
            )

        # 1. Compute full SHA-1 hash strictly in RAM
        full_sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = full_sha1[:5]
        suffix = full_sha1[5:]

        # 2. Check offline cache first if available
        if self.enable_offline_cache and full_sha1 in self._offline_hashes:
            return HIBPCheckResult(
                sha1_prefix=prefix,
                is_breached=True,
                breach_count=self._offline_hashes[full_sha1],
                checked_via="OFFLINE_CACHE",
            )

        # 3. Dispatch k-anonymity query with 5-character prefix ONLY
        target_url = f"{self.base_url}{prefix}"
        req = urllib.request.Request(
            target_url,
            headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as response:
                if response.status == 200:
                    body = response.read().decode("utf-8", errors="replace")
                    # 4. Suffix matching in RAM
                    for line in body.splitlines():
                        parts = line.strip().split(":")
                        if len(parts) == 2:
                            resp_suffix, count_str = parts
                            if resp_suffix.strip().upper() == suffix:
                                return HIBPCheckResult(
                                    sha1_prefix=prefix,
                                    is_breached=True,
                                    breach_count=int(count_str.strip()),
                                    checked_via="HIBP_PWNED_PASSWORDS_V3",
                                )
                    return HIBPCheckResult(
                        sha1_prefix=prefix,
                        is_breached=False,
                        breach_count=0,
                        checked_via="HIBP_PWNED_PASSWORDS_V3",
                    )
        except (urllib.error.URLError, TimeoutError, OSError) as err:
            # Graceful offline / fallback handling
            # Fallback to local offline dictionary if available
            count = self._offline_hashes.get(full_sha1, 0)
            return HIBPCheckResult(
                sha1_prefix=prefix,
                is_breached=(count > 0),
                breach_count=count,
                checked_via="OFFLINE_FALLBACK",
                error=f"HIBP network lookup bypassed ({type(err).__name__}). Offline fallback evaluated.",
            )

        return HIBPCheckResult(
            sha1_prefix=prefix,
            is_breached=False,
            breach_count=0,
            checked_via="HIBP_PWNED_PASSWORDS_V3",
        )
