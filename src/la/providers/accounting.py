"""Durable single-flight accounting. Imports never open a database or read keys."""
from __future__ import annotations

import json
import sqlite3
import stat
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from la.contracts import canonical, digest
from .wire import request_pins,settlement_fields


def amount(value) -> Decimal:
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        raise ValueError('money must be an exact decimal string')
    try:
        result = Decimal(value)
    except Exception as exc:
        raise ValueError('invalid monetary amount') from exc
    if not result.is_finite() or result < 0:
        raise ValueError('invalid monetary amount')
    return result


FENCE_PINS = ('evaluation_phase', 'evaluation_authority_sha256', 'gateway_prompt_sha256',
              'source_sha256', 'evaluator_method')


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class CallLedger:
    """One authority per budget, shared across runs. No automatic recovery/retry.

    Reservations survive process death. Events are append-only; a projection is
    updated in the same transaction. Reconciliation requires a pinned receipt.
    Legacy `calls` rows are refused until explicitly migrated, never discarded.
    """

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_symlink(): raise ValueError('accounting authority symlink refused')
        if self.path.exists():
            info=self.path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_size>32*1024*1024:
                raise ValueError('accounting authority storage limit; preserve liabilities for authorized archival')
        with self.connection() as db:
            legacy = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='calls'").fetchone()
            if legacy and db.execute('SELECT count(*) FROM calls').fetchone()[0]:
                raise ValueError('legacy call ledger requires explicit audited migration')
            db.executescript('''
                CREATE TABLE IF NOT EXISTS provider_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, run TEXT NOT NULL,
                    method TEXT NOT NULL, liability TEXT NOT NULL,
                    status TEXT NOT NULL, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS provider_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    attempt INTEGER, payload TEXT NOT NULL);
            ''')

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def event(db, attempt, value):
        event = dict(value, timestamp=now(), attempt_id=attempt)
        event['event_sha256'] = digest(event)
        db.execute('INSERT INTO provider_events(attempt,payload) VALUES(?,?)',
                   (attempt, canonical(event).decode()))

    def reserve(self, *, run, method, reserve, cap, pins) -> dict:
        request_pins(pins,accounting=True)
        if method not in ('B1', 'rank') or type(run) is not str or not run or len(run)>1024:
            raise ValueError('run and known provider method required')
        reserve, cap = amount(reserve), amount(cap)
        if cap == 0 or reserve > cap:
            raise ValueError('conservative request reserve exceeds cap')
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            prior = db.execute('SELECT liability,status FROM provider_attempts').fetchall()
            if any(status in ('reserved', 'unknown_liability') for _, status in prior):
                raise ValueError('in-flight or unknown liability blocks every additional call')
            # A1.1: a fenced (voidable, never-sent) evaluator call can never reach transport.
            if 'evaluation_phase' in pins:
                for (payload,) in db.execute("SELECT payload FROM provider_attempts WHERE status='fenced'"):
                    fence = json.loads(payload)
                    if all(fence.get(key) == pins.get(key) for key in FENCE_PINS):
                        raise ValueError('evaluator call is fenced as unsent; it can never be reserved')
            if sum((amount(value) for value, _ in prior), Decimal(0)) + reserve > cap:
                raise ValueError('conservative total budget exhausted')
            # Layout run identity must be shared across repairs and regeneration.
            used = db.execute('SELECT count(*) FROM provider_attempts WHERE run=? AND method=?',
                              (run, method)).fetchone()[0]
            if used >= (1 if method == 'B1' else 3):
                raise ValueError('attempt budget exhausted; failures and repairs count')
            receipt = dict(pins, schema_version=1, run=run, method=method, mode='live',
                           attempt=used + 1, reserved_usd=str(reserve), status='reserved',
                           cost_known=False, cost_usd=None, raw_usage=None, timestamp=now())
            cursor = db.execute('INSERT INTO provider_attempts(run,method,liability,status,payload) VALUES(?,?,?,?,?)',
                                (run, method, str(reserve), 'reserved', canonical(receipt).decode()))
            receipt['attempt_id'] = cursor.lastrowid
            db.execute('UPDATE provider_attempts SET payload=? WHERE id=?',
                       (canonical(receipt).decode(), cursor.lastrowid))
            self.event(db, cursor.lastrowid, dict(kind='reservation', receipt=receipt))
        return receipt

    def finish(self, reservation, *, status, cost=None, **fields) -> dict:
        settlement_fields(fields)
        if status not in ('completed', 'not_sent', 'unknown_liability'):
            raise ValueError('invalid settlement status')
        known = cost is not None
        cost = amount(cost) if known else None
        if status == 'unknown_liability' and known or status != 'unknown_liability' and not known:
            raise ValueError('inconsistent settlement cost state')
        if status == 'not_sent' and cost != 0:
            raise ValueError('a never-sent request must have known zero cost')
        receipt = dict(reservation, **fields, status=status, cost_known=known,
                       cost_usd=str(cost) if known else None, completed_at=now())
        receipt['receipt_sha256'] = digest(receipt)
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT status,payload FROM provider_attempts WHERE id=?',
                             (reservation['attempt_id'],)).fetchone()
            if not row or row[0] != 'reserved' or json.loads(row[1]) != reservation:
                raise ValueError('reservation changed or already settled')
            liability = str(cost) if known else reservation['reserved_usd']
            db.execute('UPDATE provider_attempts SET liability=?,status=?,payload=? WHERE id=?',
                       (liability, status, canonical(receipt).decode(), reservation['attempt_id']))
            self.event(db, reservation['attempt_id'], dict(kind='settlement', receipt=receipt))
        return receipt

    def fence_unsent(self, *, evaluation_phase, evaluation_authority_sha256, gateway_prompt_sha256,
                     source_sha256, evaluator_method, fence_id) -> dict:
        """Atomically prove-and-fence one evaluator call as never sent (T3-LIVE-API A1.1).

        generate_once reserves here before any transport. In one BEGIN IMMEDIATE:
        if no possibly-sent provider attempt carries these five pins, write a
        zero-cost 'fenced' tombstone that reserve() then refuses forever. Settled
        never-sent attempts remain in accounting history and request counts but
        do not prevent the fence; unresolved or possibly-billed attempts do.
        Exact retry with the same fence_id returns the existing fence. The result
        pins this ledger's path so another (e.g. fresh, empty) ledger cannot stand in.
        """
        from la.contracts.protocol import identity
        if evaluation_phase not in ('T1', 'T3') or evaluator_method not in ('B1', 'C0', 'R0', 'R1'):
            raise ValueError('explicit T1/T3 phase and evaluator method required')
        query = dict(evaluation_phase=evaluation_phase, evaluation_authority_sha256=evaluation_authority_sha256,
                     gateway_prompt_sha256=gateway_prompt_sha256, source_sha256=source_sha256,
                     evaluator_method=evaluator_method)
        for key in ('evaluation_authority_sha256', 'gateway_prompt_sha256', 'source_sha256'):
            identity(query[key])
        identity(fence_id)
        attempts, existing = [], None
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            for status, payload in db.execute('SELECT status,payload FROM provider_attempts ORDER BY id'):
                value = json.loads(payload)
                if not all(value.get(key) == item for key, item in query.items()):
                    continue
                if status == 'fenced' and value.get('fence_id') == fence_id:
                    existing = value
                    continue
                if (status == 'not_sent' and value.get('status') == 'not_sent'
                        and value.get('cost_known') is True
                        and amount(value.get('cost_usd')) == 0):
                    continue
                attempts.append(value)
                if len(attempts) > 1000: raise ValueError('attestation match bound exceeded')
            fence = None
            if not attempts:
                fence = existing
                if fence is None:
                    fence = dict(query, schema_version=1, kind='unsent_fence', fence_id=fence_id,
                                 cost_known=True, cost_usd='0', fenced_at=now())
                    cursor = db.execute('INSERT INTO provider_attempts(run,method,liability,status,payload) VALUES(?,?,?,?,?)',
                                        ('fence:' + fence_id, 'fence', '0', 'fenced', canonical(fence).decode()))
                    self.event(db, cursor.lastrowid, dict(kind='fence', fence=fence))
        result = {'schema_version': 1, 'kind': 'call_ledger_attestation',
                  'ledger_path_sha256': digest(str(self.path.resolve())), 'query': query,
                  'attempts': attempts, 'fenced': fence is not None, 'fence': fence, 'observed_at': now()}
        result['attestation_sha256'] = digest(result)
        return result

    def reconcile(self, attempt_id, *, actual_cost_usd, authority, evidence_sha256, expected_receipt_sha256):
        """Explicit operator billing reconciliation; never resets request counts."""
        from la.contracts.protocol import integer,text,identity
        integer(attempt_id,1,2**63-1); text(authority,256); identity(expected_receipt_sha256)
        cost = amount(actual_cost_usd)
        if not authority or not isinstance(evidence_sha256, str) or len(evidence_sha256) != 64 or any(c not in '0123456789abcdef' for c in evidence_sha256):
            raise ValueError('reconciliation authority and billing evidence hash required')
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT status,payload FROM provider_attempts WHERE id=?', (attempt_id,)).fetchone()
            if not row or row[0] not in ('reserved', 'unknown_liability'):
                raise ValueError('only unresolved liability can be reconciled')
            prior = json.loads(row[1])
            if digest(prior) != expected_receipt_sha256:
                raise ValueError('reconciliation CAS failed')
            receipt = dict(prior, status='reconciled', cost_known=True, cost_usd=str(cost),
                           reconciliation_authority=authority, billing_evidence_sha256=evidence_sha256,
                           prior_receipt_sha256=expected_receipt_sha256, reconciled_at=now())
            receipt.pop('receipt_sha256', None)
            receipt['receipt_sha256'] = digest(receipt)
            db.execute('UPDATE provider_attempts SET liability=?,status=?,payload=? WHERE id=?',
                       (str(cost), 'reconciled', canonical(receipt).decode(), attempt_id))
            self.event(db, attempt_id, dict(kind='reconciliation', receipt=receipt))
        return receipt

    def record_non_model_span(self, *, run, name, elapsed_seconds):
        elapsed = amount(elapsed_seconds)
        with self.connection() as db:
            self.event(db, None, dict(kind='non_model_span', run=run, name=name,
                                      elapsed_seconds=str(elapsed), model_cost_applicable=False))

    def snapshot(self) -> dict:
        with self.connection() as db:
            db.execute('BEGIN')
            rows = [(row[0], json.loads(row[1])) for row in db.execute('SELECT status,payload FROM provider_attempts ORDER BY id')]
            events = [json.loads(row[0]) for row in db.execute('SELECT payload FROM provider_events ORDER BY sequence')]
        # Fences are zero-cost never-sent tombstones, not provider request attempts.
        calls = [value for status, value in rows if status != 'fenced']
        fences = [value for status, value in rows if status == 'fenced']
        result = dict(schema_version=1, calls=calls, events=events,
                      known_cost_usd=str(sum((amount(c['cost_usd']) for c in calls if c['cost_known']), Decimal(0))),
                      unknown_attempt_ids=[c['attempt_id'] for c in calls if not c['cost_known']],
                      request_attempts=len(calls))
        if fences: result['fences'] = fences  # absent when none, so prior export shapes are unchanged
        return dict(result, export_sha256=digest(result))

    def export(self, destination) -> dict:
        """Content addressed immutable export of the committed SQLite authority."""
        snapshot = self.snapshot()
        root = Path(destination)
        root.mkdir(parents=True, exist_ok=True)
        path = root / (snapshot['export_sha256'] + '.json')
        if path.is_symlink() or path.resolve().parent != root.resolve():
            raise ValueError('accounting export path escape')
        payload = canonical(snapshot) + b'\n'
        from la.app.storage import publish_bytes, JSON_BYTES
        publish_bytes(path,payload,limit=JSON_BYTES)
        return {'path': str(path), 'export_sha256': snapshot['export_sha256']}
