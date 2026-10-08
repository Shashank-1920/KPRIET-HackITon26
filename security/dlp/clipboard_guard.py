"""
S.H.A.D.E. — Clipboard Interception & Tokenization Guard
Role: Member 2 — Security & DLP Engine

Implements the Ctrl+C interception workflow:
1. Intercepts clipboard content.
2. Runs DLP inspection via DLPEngine.
3. If normal text: ignores completely (PASSTHROUGH).
4. If sensitive: dispatches to backend to tokenize and encrypt in vault,
   and replaces clipboard with the returned 12-character synthetic token.
Invariants:
- Never writes to the database directly; always dispatches through backend contract.
- Never logs raw sensitive values.
"""

import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from security.dlp.engine import DLPEngine
from security.dlp.clipboard_provider import ClipboardProvider, WindowsClipboardProvider, MemoryClipboardProvider

logger = logging.getLogger(__name__)


@dataclass
class ClipboardProcessingResult:
    is_sensitive: bool
    original_text_length: int
    action: str  # "PASSTHROUGH", "TOKENIZED", "REUSED"
    synthetic_token: Optional[str] = None
    detected_type: Optional[str] = None
    resulting_clipboard_text: str = ""


class ClipboardGuard:
    """
    Local clipboard interception guard.
    Inspects copied text and orchestrates synthetic tokenization through backend services.
    Supports integration with native OS ClipboardProvider (Windows / In-Memory).
    """

    def __init__(
        self,
        dlp_engine: Optional[DLPEngine] = None,
        backend_dispatcher: Optional[Callable[[str, str], Any]] = None,
        clipboard_provider: Optional[ClipboardProvider] = None,
    ):
        self.dlp_engine = dlp_engine or DLPEngine()
        self.backend_dispatcher = backend_dispatcher
        self.clipboard_provider = clipboard_provider

    def process_copied_text(self, text: str) -> ClipboardProcessingResult:
        """
        Process copied text triggered by Ctrl+C.
        If normal text: return PASSTHROUGH and preserve content.
        If sensitive: invoke backend to obtain synthetic token and replace clipboard.
        """
        if not text or not text.strip():
            return ClipboardProcessingResult(
                is_sensitive=False,
                original_text_length=len(text) if text else 0,
                action="PASSTHROUGH",
                resulting_clipboard_text=text,
            )

        detection = self.dlp_engine.inspect(text)
        if detection is None:
            # Normal text: completely ignored
            return ClipboardProcessingResult(
                is_sensitive=False,
                original_text_length=len(text),
                action="PASSTHROUGH",
                resulting_clipboard_text=text,
            )

        # Sensitive text detected!
        data_type = detection.data_type

        # Dispatch to backend if dispatcher provided
        if self.backend_dispatcher:
            resp = self.backend_dispatcher(text, data_type)
            if isinstance(resp, dict):
                token = resp.get("synthetic_token")
                action = resp.get("action", "TOKENIZED")
            else:
                token = getattr(resp, "synthetic_token", None)
                action = getattr(resp, "action", "TOKENIZED")

            return ClipboardProcessingResult(
                is_sensitive=True,
                original_text_length=len(text),
                action=action,
                synthetic_token=token,
                detected_type=data_type,
                resulting_clipboard_text=token or text,
            )

        # Fallback simulation if no backend dispatcher provided in standalone mode
        return ClipboardProcessingResult(
            is_sensitive=True,
            original_text_length=len(text),
            action="DETECTED_PENDING_DISPATCH",
            detected_type=data_type,
            resulting_clipboard_text=text,
        )

    def start_monitoring(self, provider: Optional[ClipboardProvider] = None) -> None:
        """
        Start OS clipboard interception via the configured or provided ClipboardProvider.
        """
        active_provider = provider or self.clipboard_provider
        if active_provider is None:
            active_provider = WindowsClipboardProvider() if WindowsClipboardProvider().is_available() else MemoryClipboardProvider()
            self.clipboard_provider = active_provider

        def _on_copied(text: str) -> Optional[str]:
            result = self.process_copied_text(text)
            if result.is_sensitive and result.synthetic_token:
                logger.info(
                    "[ClipboardGuard] Intercepted sensitive %s, replaced with synthetic token",
                    result.detected_type,
                )
                return result.synthetic_token
            return None

        active_provider.start_listening(_on_copied)
        logger.info("[ClipboardGuard] Active clipboard monitoring enabled via %s", type(active_provider).__name__)

    def stop_monitoring(self) -> None:
        """Stop OS clipboard interception."""
        if self.clipboard_provider:
            self.clipboard_provider.stop_listening()
            logger.info("[ClipboardGuard] Clipboard monitoring stopped.")

