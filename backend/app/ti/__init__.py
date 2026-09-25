"""Reuse the existing threat_intel implementation — do not duplicate IOC logic.

This shim puts the repo-root `threat_intel/` directory on sys.path and
re-exports its pure pipeline functions. Original files stay untouched;
PostgreSQL persistence is handled by IOCRepository instead of database.py.
"""
import os
import sys

_TI_DIR_CANDIDATES = [
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "threat_intel"),
    os.path.join(os.getcwd(), "threat_intel"),
    "/code/threat_intel",  # docker image layout
]

for _cand in _TI_DIR_CANDIDATES:
    _abs = os.path.abspath(_cand)
    if os.path.isdir(_abs) and _abs not in sys.path:
        sys.path.insert(0, _abs)
        break

from collectors import collect_all  # noqa: E402,F401
from confidence import calculate_confidence, confidence_label  # noqa: E402,F401
from dedup import deduplicate  # noqa: E402,F401
from enrichment import enrich  # noqa: E402,F401
from lifecycle import compute_status  # noqa: E402,F401
from mitre_mapper import map_to_mitre  # noqa: E402,F401
from normalizer import normalize_all, normalize_record  # noqa: E402,F401
from validator import detect_type, filter_valid, validate_record  # noqa: E402,F401
