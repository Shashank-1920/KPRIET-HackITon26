"""
Root conftest.py — Ensures the repository root is strictly at index 0 of sys.path
and prevents the tests/ directory from shadowing top-level packages (security, ai, backend).
"""
import sys
from pathlib import Path

_repo_root = str(Path(__file__).resolve().parent)
while _repo_root in sys.path:
    sys.path.remove(_repo_root)
sys.path.insert(0, _repo_root)

_tests_dir = str(Path(__file__).resolve().parent / "tests")
while _tests_dir in sys.path:
    sys.path.remove(_tests_dir)
