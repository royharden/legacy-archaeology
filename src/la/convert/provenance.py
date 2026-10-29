"""Portable fingerprints of the local deterministic producer/verifier source."""
from pathlib import Path
import hashlib

from la.review import digest

LOAD_INSTRUCTIONS = ('Static migration candidate; no database execution is implied.\n'
                     'Use the separately authorized database-check adapter; bind values as parameters, never interpolate data.\n'
                     'A fresh isolated namespace and explicit approval are required. Incomplete mappings cannot load.\n')


def producer_code_pin():
    root = Path(__file__).parent.parent
    paths = sorted(p for tree in ('convert', 'review', 'ingest', 'contracts')
                   for p in (root / tree).rglob('*.py'))
    return digest({p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})


def verifier_code_pin():
    # Target-driver code never participates in offline verification.
    return producer_code_pin()
