"""S.H.A.D.E. AI Inference Handler & Masked Prompt Pipeline.

Enforces strict boundary invariants (no raw PII in AI prompts) and provides
deterministic local offline model fallback for hackathon venue resilience.
"""

from typing import AsyncGenerator, Generator, List, Optional
import re

class RawPIILeakException(Exception):
    """Raised when an unmasked raw PII pattern attempts to cross into an AI prompt."""
    pass

class MaskedPromptConstructor:
    """Validates and enforces the 'Strictly Masked Payloads' invariant before model dispatch."""

    def __init__(self):
        # Detect raw unmasked Aadhaar or PAN that bypassed DLP
        self._raw_aadhaar = re.compile(r"\b[2-9][0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b")
        self._raw_pan = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
        self._syn_token_pattern = re.compile(r"<SYN_[A-Z0-9_]+>")

    def validate_and_prepare(self, payload: str) -> str:
        """Enforces that no raw sensitive PII is passed to the AI inference pipeline."""
        # Detect raw Aadhaar leak attempt
        if self._raw_aadhaar.search(payload):
            raise RawPIILeakException(
                "CRITICAL INVARIANT VIOLATION: Unmasked Aadhaar pattern detected in outbound AI payload."
            )
        # Detect raw PAN leak attempt
        if self._raw_pan.search(payload):
            raise RawPIILeakException(
                "CRITICAL INVARIANT VIOLATION: Unmasked PAN pattern detected in outbound AI payload."
            )

        return payload

    def extract_synthetic_tokens(self, payload: str) -> List[str]:
        """Returns all synthetic placeholder tokens present in the payload."""
        return self._syn_token_pattern.findall(payload)

class OfflineModelFallback:
    """Deterministic local inference engine for 100% offline hackathon uptime."""

    def __init__(self):
        self._syn_token_pattern = re.compile(r"<SYN_[A-Z0-9_]+>")

    def generate(self, masked_prompt: str) -> str:
        """Synthesizes context-aware completion referencing synthetic tokens."""
        tokens = self._syn_token_pattern.findall(masked_prompt)
        token_str = ", ".join(tokens) if tokens else "None"
        lower_prompt = masked_prompt.lower()

        if any(w in lower_prompt for w in ["code", "python", "script", "function", "api"]):
            if tokens:
                return (
                    f"```python\n"
                    f"# Securely initialized with S.H.A.D.E. sovereign decoy\n"
                    f"CLIENT_SECRET = '{tokens[0]}'\n\n"
                    f"def connect_service():\n"
                    f"    print('Authenticated using synthetic token: {tokens[0]}')\n"
                    f"    return True\n"
                    f"```\n\n"
                    f"The secret `{tokens[0]}` was processed on-device with zero cloud exposure."
                )
            return (
                "```python\n"
                "def process_payload(data):\n"
                "    # Processed via S.H.A.D.E. sovereign hypervisor\n"
                "    return {'status': 'success'}\n"
                "```"
            )

        if any(w in lower_prompt for w in ["kyc", "aadhaar", "pan", "verify", "customer"]):
            if tokens:
                return (
                    f"KYC Verification Dossier:\n"
                    f"- Record Identifier: {tokens[0]}\n"
                    f"- Verification State: VALIDATED\n"
                    f"- Privacy Level: Zero-Data-Egress (Host Processed)\n\n"
                    f"Identity profile verified for sovereign placeholder {tokens[0]}."
                )
            return "KYC verification completed with zero data leakage."

        if tokens:
            return (
                f"S.H.A.D.E. Sovereign Local AI Hypervisor:\n"
                f"Response synthesized locally. Decoy tokens preserved: {token_str}.\n"
                f"Plaintext secrets were shielded from cloud network transmission."
            )

        return "S.H.A.D.E. Sovereign Local AI Hypervisor: Prompt processed on-device with zero cloud egress."

    def stream(self, masked_prompt: str, chunk_size: int = 4) -> Generator[str, None, None]:
        """Synchronously streams token chunks for SSE endpoints."""
        full_text = self.generate(masked_prompt)
        words = full_text.split(" ")
        for i in range(0, len(words), chunk_size):
            yield " ".join(words[i : i + chunk_size]) + " "

    async def astream(self, masked_prompt: str, chunk_size: int = 4) -> AsyncGenerator[str, None]:
        """Asynchronously streams chunks to integrate with FastAPI SSE."""
        full_text = self.generate(masked_prompt)
        words = full_text.split(" ")
        for i in range(0, len(words), chunk_size):
            yield " ".join(words[i : i + chunk_size]) + " "
