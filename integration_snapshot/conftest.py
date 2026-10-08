"""
Root conftest.py — Ensures the repository root is on sys.path
so that `from backend.xxx import yyy` works from any test location.
"""
import sys
from pathlib import Path

# Add the repo root to sys.path so `backend` package is importable
_repo_root = str(Path(__file__).resolve().parent)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)
