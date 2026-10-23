"""Durable single-flight accounting. Imports never open a database or read keys."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from la.contracts import canonical, digest


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
        if method not in ('B1', 'rank') or not isinstance(run, str) or not run:
            raise ValueError('run and known provider method required')
        reserve, cap = amount(reserve), amount(cap)
        if cap == 0 or reserve > cap:
            raise ValueError('conservative request reserve exceeds cap')
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            prior = db.execute('SELECT liability,status FROM provider_attempts').fetchall()
            if any(status in ('reserved', 'unknown_liability') for _, status in prior):
                raise ValueError('in-flight or unknown liability blocks every additional call')
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
        if status not in ('completed', 'not_sent', 'unknown_liability'):
            raise ValueError('invalid settlement status')
        known = cost is not None
        cost = amount(cost) if known else None
        if status == 'unknown_liability' and known or status != 'unknown_liability' and not known:
            raise ValueError('inconsistent settlement cost state')
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

    def reconcile(self, attempt_id, *, actual_cost_usd, authority, evidence_sha256, expected_receipt_sha256):
        """Explicit operator billing reconciliation; never resets request counts."""
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
            calls = [json.loads(row[0]) for row in db.execute('SELECT payload FROM provider_attempts ORDER BY id')]
            events = [json.loads(row[0]) for row in db.execute('SELECT payload FROM provider_events ORDER BY sequence')]
        result = dict(schema_version=1, calls=calls, events=events,
                      known_cost_usd=str(sum((amount(c['cost_usd']) for c in calls if c['cost_known']), Decimal(0))),
                      unknown_attempt_ids=[c['attempt_id'] for c in calls if not c['cost_known']],
                      request_attempts=len(calls))
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
