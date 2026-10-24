"""Hidden-identifier scan over captured provider requests SOURCE. No import-time I/O.

Pure, bounded, exact/substring matching only (no fuzzy matching). The hidden set
is derived from the T0 commitment and, optionally, heldout cases the evaluator
already holds; nothing else is read. The detailed report is an immutable
`leak_scan` capture. Its `prompt_allowlist` isolation capture carries
observed_value 'visible_only' ONLY when no hit was found, so an isolation-reviewer
receipt citing a dirty scan cannot satisfy EligibilityContext (any hit refuses).
"""
from __future__ import annotations

import functools
import hashlib
from pathlib import Path
import re

from .artifacts import CaptureStore, canonical, digest, is_sha
from .eligibility import closed, text, validate_commitment, validate_freeze

MAX_REQUESTS = 512
MAX_REQUEST_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_FINGERPRINTS = 20000
MAX_HITS = 100
PREFIX = 16  # A truncated fingerprint of >= 16 hex characters still counts as a hit.
REQUEST_KINDS = frozenset({'provider_request'})
CHECK_ID = 'prompt_hidden_identifier_scan'
CLEAN, DIRTY = 'visible_only', 'hidden_identifier_found'
_HEX_RUN = re.compile('[0-9a-f]{%d,}' % PREFIX)
# IDs match case-insensitively unless glued to a letter/digit: 'heldout-00.' and
# 'heldout-00-batch' are hits, 'xheldout-00x' and a distinct 'heldout-001' are not.
_ID_EDGE = 'A-Za-z0-9'
# Hashes of empty/null values are generic, not hidden truth (e.g. an empty layout).
_GENERIC = frozenset(digest(value) for value in (None, [], {}, '', 0))
# OSError covers a referenced capture file that is missing/unreadable.
_MALFORMED = (KeyError, TypeError, AttributeError, IndexError, OSError)


def _typed(function):
    """Crafted shapes refuse as ValueError, never KeyError/TypeError."""
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except _MALFORMED as exc:
            raise ValueError('malformed leak-scan input: ' + type(exc).__name__) from None
    return wrapper


@_typed
def hidden_identifiers(commitment: dict, *, cases=None) -> dict:
    """Hidden identifier set for one edition; values never leave this structure raw.

    From T0: heldout variant IDs and their oracle/canonical/layout SHA256s, plus
    the sealed-assets hash. From optional evaluator-held heldout cases: per-row
    canonical value fingerprints digest(row['fields']) and per-row oracle digests.
    Visible-input hashes (source/samples/brief/visible) are deliberately excluded:
    they legitimately appear in permitted prompts.
    """
    t0 = validate_commitment(commitment)
    heldout = [v for v in t0['variants'] if v['split'] == 'heldout']
    fingerprints = {t0['sealed_assets_sha256']: 'sealed_assets'}
    for variant in heldout:
        for key in ('oracle_sha256', 'canonical_sha256', 'layout_sha256'):
            fingerprints.setdefault(variant[key], key)
    declared = {v['variant_id']: v for v in heldout}
    for case in cases or ():
        variant = declared.get(getattr(case, 'variant_id', None))
        if variant is None or case.split != 'heldout' or case.edition != t0['edition']:
            raise ValueError('leak-scan cases must be declared heldout variants of this edition')
        rows = [row for batch in case.batches for row in batch.oracle]
        if digest(rows) != variant['oracle_sha256']:
            raise ValueError('leak-scan case oracle differs from T0 commitment')
        for row in rows:
            # Empty/quarantined field sets hash to generic values that carry no hidden truth.
            if row.get('expected_outcome') == 'converted' and row.get('fields'):
                fingerprints.setdefault(digest(row['fields']), 'canonical_row')
            fingerprints.setdefault(digest(row), 'oracle_row')
    fingerprints = {sha: label for sha, label in fingerprints.items() if sha not in _GENERIC}
    if len(fingerprints) > MAX_FINGERPRINTS:
        raise ValueError('bounded hidden fingerprint set required')
    # Every 16-hex window of every fingerprint, so a truncated leak from any offset hits.
    fragments = {sha[start:start + PREFIX]: sha for sha in fingerprints for start in range(64 - PREFIX + 1)}
    return {'edition': t0['edition'], 'commitment_sha256': t0['commitment_sha256'],
            'variant_ids': sorted(declared), 'fingerprints': fingerprints, 'fragments': fragments}


@_typed
def attempt_request_refs(store: CaptureStore, registry, edition: str) -> list[dict]:
    """provider_request refs reached from one TERMINAL protected attempt's arm receipts."""
    from .edition_registry import EditionRegistry
    if type(store) is not CaptureStore or type(registry) is not EditionRegistry or registry.store.root != store.root:
        raise ValueError('same evaluator store and edition registry required')
    attempt = registry.state(edition)['attempt']
    if attempt is None or attempt['status'] == 'running':
        raise ValueError('scan one terminal recorded attempt')
    arms = [arm['capture'] for arm in attempt['arms'].values() if 'capture' in arm]
    return requests_from_arm_receipts(store, arms)


@_typed
def requests_from_arm_receipts(store: CaptureStore, arm_refs: list[dict]) -> list[dict]:
    """Gateway request captures: arm_receipt -> arm_raw -> attempts[].request_capture."""
    if not isinstance(arm_refs, list) or len(arm_refs) > MAX_REQUESTS:
        raise ValueError('bounded arm receipt list required')
    found = {}
    for ref in arm_refs:
        receipt = store.get(ref, kind='arm_receipt')
        for raw_ref in receipt.get('captures', []):
            if not isinstance(raw_ref, dict) or raw_ref.get('kind') != 'arm_raw':
                continue
            raw = store.get(raw_ref, kind='arm_raw')
            for item in raw.get('attempts') or []:
                request = item.get('request_capture') if isinstance(item, dict) else None
                if request is not None:
                    found.setdefault(request['sha256'], request)
    return [found[key] for key in sorted(found)]


def _hits(data: str, identifiers: dict, request_sha: str):
    """Yield hits one at a time; the caller deduplicates on the fly (bounded memory)."""
    lowered = data.lower()
    fingerprints, fragments = identifiers['fingerprints'], identifiers['fragments']
    for run in _HEX_RUN.findall(lowered):
        covered = set()  # Positions inside an exact 64-hex match are not re-reported as fragments.
        for start in range(len(run) - 64 + 1):
            if run[start:start + 64] in fingerprints:
                yield {'category': fingerprints[run[start:start + 64]], 'match': 'exact', 'request_sha256': request_sha}
                covered.update(range(start, start + 64 - PREFIX + 1))
        for start in range(len(run) - PREFIX + 1):
            fragment = run[start:start + PREFIX]
            if start not in covered and fragment in fragments:
                yield {'category': fingerprints[fragments[fragment]], 'match': 'substring', 'request_sha256': request_sha}
    ids = identifiers['variant_ids']
    if ids:
        pattern = '(?<![%s])(?:%s)(?![%s])' % (_ID_EDGE, '|'.join(re.escape(i) for i in sorted(ids, key=len, reverse=True)), _ID_EDGE)
        for match in re.finditer(pattern, data, re.IGNORECASE):
            yield {'category': 'heldout_variant_id', 'match': 'exact',
                   'identifier_sha256': digest(match.group(0).lower()), 'request_sha256': request_sha}


@_typed
def scan_requests(store: CaptureStore, request_refs: list[dict], identifiers: dict, *, subject=None) -> dict:
    """Pure bounded scan; returns the closed report (no capture written).

    `subject` names what was scanned (e.g. attempt ID and arm receipt refs) so a
    reviewer can see the scan covers the attempt being certified; bounded, recorded.
    """
    subject = {} if subject is None else subject
    if not isinstance(subject, dict) or len(canonical(subject)) > 4096:
        raise ValueError('bounded scan subject description required')
    if type(store) is not CaptureStore: raise ValueError('existing evaluator capture store required')
    if not isinstance(request_refs, list) or not 1 <= len(request_refs) <= MAX_REQUESTS:
        raise ValueError('one bounded nonempty request capture list required')
    if len({ref.get('sha256') for ref in request_refs if isinstance(ref, dict)}) != len(request_refs):
        raise ValueError('duplicate/malformed request capture reference')
    total, groups, occurrences, scanned = 0, {}, 0, []
    for ref in request_refs:
        closed(ref, {'sha256', 'kind', 'bytes'}, 'request capture reference')
        if (ref['kind'] not in REQUEST_KINDS or not is_sha(ref['sha256'])
                or type(ref['bytes']) is not int or not 0 < ref['bytes'] <= MAX_REQUEST_BYTES):
            raise ValueError('only bounded provider_request captures are scanned')
        total += ref['bytes']
        if total > MAX_TOTAL_BYTES: raise ValueError('leak-scan total byte bound')
        payload = store.get(ref, kind=ref['kind'])
        data = canonical(payload).decode('utf-8')
        if len(data.encode('utf-8')) > MAX_REQUEST_BYTES: raise ValueError('request capture byte bound')
        for hit in _hits(data, identifiers, ref['sha256']):
            groups.setdefault(digest(hit), hit); occurrences += 1
        scanned.append(dict(ref))
    # Deduplicate and bound; hidden values are never copied, only categories/positions.
    unique = sorted(groups.values(), key=lambda h: (h['request_sha256'], h['category'], digest(h)))
    report = {'schema_version': 1, 'kind': 'leak_scan', 'edition': identifiers['edition'],
              'commitment_sha256': identifiers['commitment_sha256'],
              'identifier_set_sha256': digest({'fingerprints': sorted(identifiers['fingerprints']),
                                               'variant_ids': identifiers['variant_ids']}),
              'fingerprint_count': len(identifiers['fingerprints']), 'variant_id_count': len(identifiers['variant_ids']),
              'subject': subject, 'method': {'hex_exact': 64, 'hex_fragment_any_offset': PREFIX, 'variant_id': 'alnum_boundary_case_insensitive',
                         'fuzzy': False},
              'scanner_code_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'requests': scanned, 'scanned_bytes': total, 'hit_count': len(unique), 'occurrence_count': occurrences,
              'hits': unique[:MAX_HITS], 'hits_truncated': len(unique) > MAX_HITS,
              'result': CLEAN if not unique else DIRTY}
    return report


@_typed
def record_leak_scan(store: CaptureStore, *, commitment: dict, freeze: dict, request_refs: list[dict],
                     host: str, identity: str, observed_at: str, cases=None, subject=None) -> dict:
    """Write the immutable leak_scan report and its prompt_allowlist isolation capture.

    The isolation capture is always written (a dirty one is evidence too); only a
    clean one carries 'visible_only'. A reviewer signs a separate receipt citing
    `isolation_capture['sha256']`; this function signs nothing.
    """
    t2 = validate_freeze(freeze, commitment)
    text(host, 'host'); text(identity, 'identity'); text(observed_at, 'observation time')
    report = scan_requests(store, request_refs, hidden_identifiers(commitment, cases=cases), subject=subject)
    leak_ref = store.put('leak_scan', report)
    capture = {'schema_version': 1, 'kind': 'prompt_allowlist', 'edition': t2['edition'],
               'freeze_sha256': t2['freeze_sha256'], 'nonce': t2['nonce'], 'host': host, 'identity': identity,
               'observed_at': observed_at, 'collector_sha256': report['scanner_code_sha256'],
               'source_sha256': t2['pins']['release_sha256'], 'config_sha256': t2['pins']['config_sha256'],
               'observations': [{'check_id': CHECK_ID, 'subject_sha256': leak_ref['sha256'],
                                 'observed_value': report['result']}]}
    isolation_ref = store.put('isolation_capture', capture)
    return {'schema_version': 1, 'clean': report['result'] == CLEAN, 'hit_count': report['hit_count'],
            'leak_scan': leak_ref, 'isolation_capture': isolation_ref}


@_typed
def assert_clean(store: CaptureStore, leak_ref: dict) -> dict:
    """For reporting callers: refuse any result whose leak scan found a hidden identifier."""
    report = store.get(leak_ref, kind='leak_scan')
    if not isinstance(report, dict) or report.get('kind') != 'leak_scan' or report.get('result') != CLEAN or report.get('hit_count') != 0:
        raise ValueError('hidden identifier found in captured provider requests; results ineligible')
    return report
