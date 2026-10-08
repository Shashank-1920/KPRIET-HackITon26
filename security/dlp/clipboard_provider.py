"""
S.H.A.D.E. — System Clipboard Provider & Native Interception
Role: Member 2 — Security & DLP Engine / System Integration

Provides the native OS clipboard provider abstraction:
- ClipboardProvider: Abstract base class for clipboard I/O and change monitoring.
- WindowsClipboardProvider: Native Windows implementation using ctypes and Win32 user32/kernel32.
- MemoryClipboardProvider: In-memory provider for cross-platform testing and headless environments.

INVARIANTS:
- Runs locally: clipboard content is NEVER uploaded to external services.
- Never logs sensitive plaintext.
- Never retains clipboard history.
- Loop prevention: writing a synthetic token does not re-trigger a duplicate tokenization event.
"""

import logging
import platform
import threading
import time
from abc import ABC, abstractmethod
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class ClipboardProvider(ABC):
    """Abstract interface for local system clipboard operations."""

    @abstractmethod
    def get_text(self) -> Optional[str]:
        """Read plain text from system clipboard."""

    @abstractmethod
    def set_text(self, text: str) -> bool:
        """Write plain text to system clipboard."""

    @abstractmethod
    def start_listening(self, callback: Callable[[str], Optional[str]]) -> None:
        """
        Start monitoring clipboard changes in background.
        When text is copied, invokes callback(text).
        If callback returns a non-None replacement string, writes it to the clipboard.
        """

    @abstractmethod
    def stop_listening(self) -> None:
        """Stop background clipboard monitoring."""

    @abstractmethod
    def is_available(self) -> bool:
        """Check if native clipboard subsystem is available on current host."""


class WindowsClipboardProvider(ClipboardProvider):
    """
    Native Windows Clipboard provider using ctypes bindings to user32.dll and kernel32.dll.
    Tracks clipboard sequence changes (GetClipboardSequenceNumber) and performs atomic replacement.
    """

    CF_UNICODETEXT = 13
    GMEM_MOVEABLE = 0x0002

    def __init__(self, poll_interval_seconds: float = 0.1) -> None:
        self._poll_interval = poll_interval_seconds
        self._is_windows = platform.system() == "Windows"
        self._last_sequence: int = 0
        self._last_written_text: Optional[str] = None
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._u32 = None
        self._k32 = None

        if self._is_windows:
            self._init_win32_bindings()

    def _init_win32_bindings(self) -> None:
        try:
            import ctypes
            from ctypes import wintypes

            u32 = ctypes.windll.user32
            k32 = ctypes.windll.kernel32

            # Define Win32 64-bit safe signatures
            u32.OpenClipboard.argtypes = [wintypes.HWND]
            u32.OpenClipboard.restype = wintypes.BOOL
            u32.CloseClipboard.argtypes = []
            u32.CloseClipboard.restype = wintypes.BOOL
            u32.EmptyClipboard.argtypes = []
            u32.EmptyClipboard.restype = wintypes.BOOL
            u32.GetClipboardData.argtypes = [wintypes.UINT]
            u32.GetClipboardData.restype = wintypes.HANDLE
            u32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
            u32.SetClipboardData.restype = wintypes.HANDLE
            u32.GetClipboardSequenceNumber.argtypes = []
            u32.GetClipboardSequenceNumber.restype = wintypes.DWORD

            k32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
            k32.GlobalAlloc.restype = wintypes.HGLOBAL
            k32.GlobalLock.argtypes = [wintypes.HGLOBAL]
            k32.GlobalLock.restype = ctypes.c_void_p
            k32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
            k32.GlobalUnlock.restype = wintypes.BOOL

            self._u32 = u32
            self._k32 = k32
            self._last_sequence = u32.GetClipboardSequenceNumber()
        except Exception as exc:
            logger.warning("[WindowsClipboard] Failed to initialize Win32 bindings: %s", exc)
            self._u32 = None
            self._k32 = None

    def is_available(self) -> bool:
        return bool(self._is_windows and self._u32 and self._k32)

    def get_text(self) -> Optional[str]:
        if not self.is_available():
            return None

        import ctypes

        for attempt in range(3):
            if self._u32.OpenClipboard(None):
                try:
                    h_data = self._u32.GetClipboardData(self.CF_UNICODETEXT)
                    if not h_data:
                        return None
                    ptr = self._k32.GlobalLock(h_data)
                    if not ptr:
                        return None
                    try:
                        return ctypes.wstring_at(ptr)
                    finally:
                        self._k32.GlobalUnlock(h_data)
                finally:
                    self._u32.CloseClipboard()
            time.sleep(0.01 * (attempt + 1))
        return None

    def set_text(self, text: str) -> bool:
        if not self.is_available():
            return False

        import ctypes

        for attempt in range(3):
            if self._u32.OpenClipboard(None):
                try:
                    self._u32.EmptyClipboard()
                    encoded = (text + "\0").encode("utf-16le")
                    h_mem = self._k32.GlobalAlloc(self.GMEM_MOVEABLE, len(encoded))
                    if not h_mem:
                        return False
                    ptr = self._k32.GlobalLock(h_mem)
                    if not ptr:
                        return False
                    try:
                        ctypes.memmove(ptr, encoded, len(encoded))
                    finally:
                        self._k32.GlobalUnlock(h_mem)

                    if not self._u32.SetClipboardData(self.CF_UNICODETEXT, h_mem):
                        return False

                    # Record write to prevent loop feedback
                    self._last_written_text = text
                    return True
                finally:
                    self._u32.CloseClipboard()
                    # Capture sequence number immediately after closing
                    if self._u32:
                        self._last_sequence = self._u32.GetClipboardSequenceNumber()
            time.sleep(0.01 * (attempt + 1))
        return False

    def start_listening(self, callback: Callable[[str], Optional[str]]) -> None:
        if not self.is_available():
            logger.warning("[WindowsClipboard] Cannot start listener: Win32 bindings unavailable.")
            return

        if self._monitor_thread and self._monitor_thread.is_alive():
            return

        self._stop_event.clear()
        self._last_sequence = self._u32.GetClipboardSequenceNumber()

        def _monitor_loop():
            logger.info("[WindowsClipboard] Background monitoring started.")
            while not self._stop_event.is_set():
                try:
                    current_seq = self._u32.GetClipboardSequenceNumber()
                    if current_seq != self._last_sequence:
                        self._last_sequence = current_seq
                        text = self.get_text()
                        if text and text != self._last_written_text:
                            # Invoke DLP inspection callback
                            replacement = callback(text)
                            if replacement and replacement != text:
                                self.set_text(replacement)
                except Exception as exc:
                    logger.debug("[WindowsClipboard] Monitor iteration exception: %s", exc)

                self._stop_event.wait(self._poll_interval)
            logger.info("[WindowsClipboard] Background monitoring stopped.")

        self._monitor_thread = threading.Thread(target=_monitor_loop, daemon=True)
        self._monitor_thread.start()

    def stop_listening(self) -> None:
        self._stop_event.set()
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=1.0)
            self._monitor_thread = None


class MemoryClipboardProvider(ClipboardProvider):
    """In-memory clipboard provider for unit testing and headless environments."""

    def __init__(self, initial_text: Optional[str] = None) -> None:
        self._content: Optional[str] = initial_text
        self._callback: Optional[Callable[[str], Optional[str]]] = None
        self._is_listening = False

    def is_available(self) -> bool:
        return True

    def get_text(self) -> Optional[str]:
        return self._content

    def set_text(self, text: str) -> bool:
        self._content = text
        if self._is_listening and self._callback:
            replacement = self._callback(text)
            if replacement and replacement != text:
                self._content = replacement
        return True

    def start_listening(self, callback: Callable[[str], Optional[str]]) -> None:
        self._callback = callback
        self._is_listening = True

    def stop_listening(self) -> None:
        self._is_listening = False
        self._callback = None
