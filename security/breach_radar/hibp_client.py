"""
S.H.A.D.E. — Privacy-Preserving HaveIBeenPwned k-Anonymity Client
Role: Member 2 — Security & Threat Engine

Follows NIST and Cloudflare k-anonymity protocol:
- Local SHA-1 hashing of password.
- Only the first 5 hexadecimal characters are transmitted to the external API.
- Full passwords or emails are NEVER dispatched to external endpoints.
- If internet is unavailable, fails gracefully with offline status.
"""

import hashlib
import logging
from dataclasses import dataclass
from typing import Optional
import urllib.request
import urllib.error

logger = logging.getLogger(__name__)


@dataclass
class HIBPCheckResult:
    is_compromised: bool
    breach_count: int
    hash_prefix: str
    verified: bool
    offline: bool = False


class HIBPClient:
    """Privacy-preserving k-anonymity client for breached credential checks."""

    API_URL = "https://api.pwnedpasswords.com/range/"

    def check_password_pwned(self, password: str, timeout: float = 3.0) -> HIBPCheckResult:
        """
        Check if a password appears in known breach corpuses using SHA-1 k-anonymity.
        """
        if not password:
            return HIBPCheckResult(is_compromised=False, breach_count=0, hash_prefix="", verified=False)

        # 1. Compute SHA-1 locally
        sha1_full = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1_full[:5]
        suffix = sha1_full[5:]

        # 2. Query k-anonymity range API with first 5 chars
        req = urllib.request.Request(
            f"{self.API_URL}{prefix}",
            headers={"User-Agent": "SHADE-Security-Auditor/1.0", "Add-Padding": "true"}
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                body = response.read().decode("utf-8")
                for line in body.splitlines():
                    parts = line.strip().split(":")
                    if len(parts) == 2 and parts[0] == suffix:
                        count = int(parts[1])
                        return HIBPCheckResult(
                            is_compromised=True,
                            breach_count=count,
                            hash_prefix=prefix,
                            verified=True,
                            offline=False,
                        )
                # Suffix not found in hash range
                return HIBPCheckResult(
                    is_compromised=False,
                    breach_count=0,
                    hash_prefix=prefix,
                    verified=True,
                    offline=False,
                )
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            logger.info("[HIBPClient] External endpoint unreachable (offline mode): %s", e)
            return HIBPCheckResult(
                is_compromised=False,
                breach_count=0,
                hash_prefix=prefix,
                verified=False,
                offline=True,
            )
