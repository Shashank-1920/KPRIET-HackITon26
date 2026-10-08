"""Heuristic prompt injection and adversarial payload analyzer.

Enforces zero-trust cognitive defense on pre-masked payloads in < 2ms.
"""

from dataclasses import dataclass
from typing import List, Tuple
import base64
import binascii
import re
import unicodedata
import urllib.parse

@dataclass
class HeuristicFinding:
    rule_id: str
    rule_name: str
    category: str
    severity_weight: float
    matched_snippet: str
    description: str

class PromptInjectionFilter:
    """Detects adversarial jailbreaks, system prompt extraction, and delimiter smuggling."""

    def __init__(self):
        self._b64_pattern = re.compile(
            r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])"
        )
        self._rules = [
            (
                "JB_001",
                "Instruction Override",
                "JAILBREAK",
                0.55,
                re.compile(
                    r"(ignore|disregard|forget|override|bypass)\s+(all\s+)?(previous|prior|above|former)\s+(instructions|directives|prompts|rules)",
                    re.IGNORECASE,
                ),
                "Direct attempt to override prior system prompt instructions.",
            ),
            (
                "JB_002",
                "DAN / Persona Bypass",
                "JAILBREAK",
                0.50,
                re.compile(
                    r"\b(do\s+anything\s+now|dan\s+mode|developer\s+mode\s+enabled|unrestricted\s+ai|anti-gpt|stan\s+mode)\b",
                    re.IGNORECASE,
                ),
                "Persona adoption pattern attempting to bypass content filters.",
            ),
            (
                "EX_001",
                "System Prompt Exfiltration",
                "EXFILTRATION",
                0.50,
                re.compile(
                    r"(print|show|repeat|output|reveal|dump|leak)\s+(the\s+)?(exact\s+)?(system\s+prompt|initial\s+prompt|developer\s+instructions|base\s+prompt)",
                    re.IGNORECASE,
                ),
                "Attempt to dump internal system directives.",
            ),
            (
                "EX_002",
                "Credential Exfiltration",
                "EXFILTRATION",
                0.45,
                re.compile(
                    r"(print|dump|show|reveal)\s+(all\s+)?(environment\s+variables|env\s+vars|api[_\s]?keys|auth\s+tokens|secret[_\s]?keys)",
                    re.IGNORECASE,
                ),
                "Attempt to coerce environment credentials out of the prompt runtime.",
            ),
            (
                "DL_001",
                "Framing Token Smuggling",
                "DELIMITER_INJECTION",
                0.45,
                re.compile(
                    r"(<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>|\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>)",
                    re.IGNORECASE,
                ),
                "Special chat framing tokens intended to hijack conversational state.",
            ),
            (
                "DL_002",
                "Pseudo-System Tag Injection",
                "DELIMITER_INJECTION",
                0.35,
                re.compile(
                    r"(<\s*system\s*>|<\s*/\s*system\s*>|<\s*admin\s*>|<\s*/\s*admin\s*>)",
                    re.IGNORECASE,
                ),
                "Faux system XML/HTML boundaries.",
            ),
        ]

    def _unpack_base64(self, text: str) -> List[Tuple[str, str]]:
        """Identifies base64 strings and extracts printable ASCII/UTF-8 payloads."""
        results = []
        for candidate in self._b64_pattern.findall(text):
            if len(candidate) % 4 != 0:
                continue
            try:
                decoded = base64.b64decode(candidate, validate=True).decode("utf-8")
                if len(decoded) >= 8 and any(c.isalpha() for c in decoded):
                    results.append((candidate, decoded))
            except (binascii.Error, UnicodeDecodeError):
                continue
        return results

    def inspect(self, text: str) -> Tuple[List[HeuristicFinding], bool, List[str]]:
        """Scans text and returns findings, obfuscation status, and decoded payloads."""
        findings: List[HeuristicFinding] = []
        decoded_payloads: List[str] = []
        has_obfuscation = False

        # Normalize text
        normalized = unicodedata.normalize("NFKD", urllib.parse.unquote(text))

        # Check for encoded Base64 payloads
        b64_pairs = self._unpack_base64(normalized)
        if b64_pairs:
            has_obfuscation = True
            for raw_token, decoded_text in b64_pairs:
                decoded_payloads.append(decoded_text)
                # Re-scan the unpacked payload
                for rule_id, rule_name, cat, weight, pattern, desc in self._rules:
                    m = pattern.search(decoded_text)
                    if m:
                        findings.append(
                            HeuristicFinding(
                                rule_id=rule_id,
                                rule_name=f"[Encoded Base64] {rule_name}",
                                category=cat,
                                severity_weight=weight,
                                matched_snippet=m.group(0),
                                description=desc,
                            )
                        )

        # Direct scan
        for rule_id, rule_name, cat, weight, pattern, desc in self._rules:
            m = pattern.search(normalized)
            if m:
                findings.append(
                    HeuristicFinding(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        category=cat,
                        severity_weight=weight,
                        matched_snippet=m.group(0),
                        description=desc,
                    )
                )

        return findings, has_obfuscation, decoded_payloads
