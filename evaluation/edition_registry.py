"""Evaluator-owned append-only edition/attempt journal SOURCE.

SQLite is the committed authority; immutable JSON captures are rebuildable
exports of committed events. No registry/database is created on module import.
The operator must place both registry and captures outside inference-readable
storage and establish that custody separately before any hidden attempt.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3

from .artifacts import CaptureStore, canonical, digest, is_sha
from .eligibility import (ReceiptVerifier, closed, text, validate_commitment,
                          validate_custody, validate_freeze, validate_suite, variant_identity)

TERMINAL = {'completed', 'partial', 'failed', 'cancelled', 'no_output'}


@dataclass(frozen=True)
class JournalReceipt:
    event: dict
    newly_created: bool
    capture: dict


class EditionRegistry:
    def __init__(self, path: str | Path, store: CaptureStore):
        supplied = Path(path)
        if supplied.is_symlink() or not supplied.parent.is_dir():
            raise ValueError('existing evaluator-owned registry parent required')
        self.path, self.store = supplied.resolve(), store
        with self._connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS edition_events (sequence INTEGER PRIMARY KEY, '
                       'event_sha256 TEXT UNIQUE NOT NULL, request_id TEXT UNIQUE NOT NULL, event_json TEXT NOT NULL)')

    def _connect(self):
        if self.path.is_symlink():
            raise ValueError('registry symlink rejected')
        db = sqlite3.connect(self.path, timeout=5)
        db.execute('PRAGMA synchronous=FULL')
        return db

    def _events(self, db) -> list[dict]:
        events, previous = [], None
        for sequence, event_sha, request_id, raw in db.execute(
                'SELECT sequence,event_sha256,request_id,event_json FROM edition_events ORDER BY sequence'):
            item = json.loads(raw)
            closed(item, {'schema_version', 'sequence', 'previous_sha256', 'edition', 'event_type',
                          'request_id', 'request_sha256', 'payload', 'event_sha256'}, 'registry event')
            if (type(item['sequence']) is not int or item['sequence'] != len(events) + 1 or sequence != item['sequence']
                    or item['previous_sha256'] != previous or request_id != item['request_id']
                    or event_sha != item['event_sha256'] or canonical(item).decode() != raw
                    or item['event_sha256'] != digest({key: val for key, val in item.items() if key != 'event_sha256'})):
                raise ValueError('registry immutable chain mismatch')
            if item['request_sha256'] != digest({'edition': item['edition'], 'event_type': item['event_type'], 'payload': item['payload']}):
                raise ValueError('registry request binding mismatch')
            text(item['request_id'], 'request_id')
            events.append(item); previous = event_sha
        return events

    def events(self) -> list[dict]:
        with self._connect() as db:
            return self._events(db)

    @property
    def head(self) -> str | None:
        events = self.events()
        return events[-1]['event_sha256'] if events else None

    def _state(self, events: list[dict], edition: str) -> dict:
        state = {'commitment': None, 'freeze': None, 'exposed': False, 'retired': False, 'attempt': None}
        for event in events:
            if event['edition'] != edition:
                continue
            kind, payload = event['event_type'], event['payload']
            if kind == 'registered':
                if state['commitment'] is not None:
                    raise ValueError('edition registered twice')
                state['commitment'] = validate_commitment(payload)
            elif state['commitment'] is None:
                raise ValueError('event precedes edition registration')
            elif kind == 'frozen':
                if state['attempt'] is not None or state['retired'] or state['exposed']:
                    raise ValueError('frozen configuration changed after consumption/exposure')
                state['freeze'] = validate_freeze(payload, state['commitment'])
            elif kind == 'attempt_started':
                closed(payload, {'suite', 'authority_sha256', 'custody_sha256'}, 'attempt start')
                if state['attempt'] is not None or state['retired'] or state['exposed'] or state['freeze'] is None:
                    raise ValueError('edition already consumed/exposed/retired or not frozen')
                validate_suite(payload['suite'], state['commitment'], state['freeze'])
                if not is_sha(payload['authority_sha256']) or not is_sha(payload['custody_sha256']):
                    raise ValueError('attempt missing authority/custody pins')
                state['attempt'] = {'suite': payload['suite'], 'status': 'running', 'event_sha256': event['event_sha256']}
            elif kind == 'attempt_finished':
                closed(payload, {'attempt_id', 'status', 'result_capture'}, 'attempt finish')
                if (state['attempt'] is None or state['attempt']['status'] != 'running'
                        or payload['attempt_id'] != state['attempt']['suite']['attempt_id'] or payload['status'] not in TERMINAL):
                    raise ValueError('invalid terminal attempt transition')
                closed(payload['result_capture'], {'sha256', 'kind', 'bytes'}, 'terminal capture')
                state['attempt']['status'] = payload['status']
                state['attempt']['result_capture'] = payload['result_capture']
            elif kind in ('exposed', 'retired'):
                closed(payload, {'reason', 'authority_sha256'}, 'edition disposition')
                text(payload['reason'], 'disposition reason', 1000)
                if not is_sha(payload['authority_sha256']):
                    raise ValueError('edition disposition authority pin required')
                if kind == 'retired' and state['attempt'] is not None and state['attempt']['status'] == 'running':
                    raise ValueError('finish/cancel the running attempt before retirement')
                state['exposed' if kind == 'exposed' else 'retired'] = True
            else:
                raise ValueError('unknown registry event type')
        return state

    def state(self, edition: str) -> dict:
        return self._state(self.events(), edition)

    def _append(self, edition: str, kind: str, payload: dict, *, request_id: str,
                expected_head: str | None) -> JournalReceipt:
        text(edition, 'edition'); text(request_id, 'request_id')
        request_sha = digest({'edition': edition, 'event_type': kind, 'payload': payload})
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            events = self._events(db)
            previous_request = next((event for event in events if event['request_id'] == request_id), None)
            if previous_request is not None:
                if previous_request['request_sha256'] != request_sha:
                    raise ValueError('request ID reused with different content')
                event, created = previous_request, False
            else:
                current_head = events[-1]['event_sha256'] if events else None
                if expected_head != current_head:
                    raise ValueError('registry compare-and-swap conflict')
                event = {'schema_version': 1, 'sequence': len(events) + 1, 'previous_sha256': current_head,
                         'edition': edition, 'event_type': kind, 'request_id': request_id,
                         'request_sha256': request_sha, 'payload': payload}
                event['event_sha256'] = digest(event)
                self._state(events + [event], edition)  # Reject illegal state before durable mutation.
                if kind == 'registered':
                    new = validate_commitment(payload)
                    heldout_gold = {v['canonical_sha256'] for v in new['variants'] if v['split'] == 'heldout'}
                    for old in events:
                        if old['event_type'] != 'registered':
                            continue
                        prior = self._state(events, old['edition'])
                        if prior['exposed'] or prior['retired'] or prior['attempt'] is not None:
                            exposed_gold = {v['canonical_sha256'] for v in prior['commitment']['variants']}
                        else:
                            exposed_gold = {v['canonical_sha256'] for v in prior['commitment']['variants'] if v['split'] != 'heldout'}
                        if heldout_gold & exposed_gold or new['sealed_assets_sha256'] == prior['commitment']['sealed_assets_sha256']:
                            raise ValueError('reused/exposed gold cannot become a new unseen edition')
                db.execute('INSERT INTO edition_events VALUES (?,?,?,?)',
                           (event['sequence'], event['event_sha256'], request_id, canonical(event).decode()))
                created = True
            db.commit()
        # A crash here leaves the event committed; exact retry/export rebuilds it.
        return JournalReceipt(event, created, self.store.put('edition_event', event))

    def register(self, commitment: dict, *, request_id: str, expected_head: str | None) -> JournalReceipt:
        item = validate_commitment(commitment)
        return self._append(item['edition'], 'registered', item, request_id=request_id, expected_head=expected_head)

    def freeze(self, freeze: dict, *, request_id: str, expected_head: str | None) -> JournalReceipt:
        state = self.state(freeze['edition'])
        item = validate_freeze(freeze, state['commitment'])
        return self._append(item['edition'], 'frozen', item, request_id=request_id, expected_head=expected_head)

    def finish(self, edition: str, attempt_id: str, status: str, result_capture: dict, *,
               request_id: str, expected_head: str | None) -> JournalReceipt:
        self.store.get(result_capture)
        return self._append(edition, 'attempt_finished', {'attempt_id': attempt_id, 'status': status,
                            'result_capture': result_capture}, request_id=request_id, expected_head=expected_head)

    def disposition(self, edition: str, kind: str, signed_authority: dict, *, verifier: ReceiptVerifier,
                    request_id: str, expected_head: str | None) -> JournalReceipt:
        authority = closed(verifier.verify(signed_authority, 'run_owner'),
                           {'schema_version', 'action', 'edition', 'reason', 'registry_head'}, 'disposition authority')
        if kind not in ('exposed', 'retired') or authority['action'] != kind or authority['edition'] != edition:
            raise ValueError('wrong disposition authority')
        if authority['registry_head'] != expected_head:
            raise ValueError('stale disposition authority')
        return self._append(edition, kind, {'reason': authority['reason'], 'authority_sha256': digest(signed_authority)},
                            request_id=request_id, expected_head=expected_head)

    def export(self) -> list[dict]:
        return [self.store.put('edition_event', event) for event in self.events()]


@dataclass(frozen=True)
class EligibilityContext:
    registry: EditionRegistry
    commitment: dict
    freeze: dict
    suite: dict
    probe_receipt: dict
    review_receipts: list[dict]
    authority_receipt: dict
    verifier: ReceiptVerifier

    def validate(self) -> dict:
        t0 = validate_commitment(self.commitment)
        t2 = validate_freeze(self.freeze, t0)
        suite = validate_suite(self.suite, t0, t2)
        state = self.registry.state(t0['edition'])
        if state['commitment'] != t0 or state['freeze'] != t2 or state['exposed'] or state['retired']:
            raise ValueError('registry edition exposed/retired or pins differ')
        authority = closed(self.verifier.verify(self.authority_receipt, 'run_owner'),
                           {'schema_version', 'action', 'edition', 'suite_sha256', 'freeze_sha256',
                            'nonce', 'mode', 'capture_root_sha256', 'identity', 'host', 'collector_sha256',
                            'spend_authority_sha256'},
                           'suite authority')
        if authority['action'] != 'execute_suite':
            raise ValueError('explicit suite action required')
        for key in ('edition', 'suite_sha256', 'freeze_sha256', 'nonce', 'mode', 'capture_root_sha256'):
            if authority[key] != suite[key]:
                raise ValueError('authority/suite identity mismatch')
        if suite['capture_root_sha256'] != digest(str(self.registry.store.root)):
            raise ValueError('custody capture-root mismatch')
        if suite['mode'] == 'live' and not is_sha(authority['spend_authority_sha256']):
            raise ValueError('live suite requires signed spend authority pin')
        # All signed receipts and distinct underlying observation captures must
        # actually exist in evaluator-owned storage, not merely name hashes.
        for signed in (self.authority_receipt, self.probe_receipt, *self.review_receipts):
            envelope = {'schema_version': 1, 'kind': 'signed_evidence', 'payload': signed}
            self.registry.store.get({'sha256': digest(envelope), 'kind': 'signed_evidence'})
        capture_contents = set()
        expected_values = {'inherited_handles': 'no_oracle_handle', 'oracle_broker': 'no_oracle_endpoint',
                           'network_route': 'no_oracle_route', 'inference_distribution': 'evaluator_and_hidden_absent',
                           'prompt_allowlist': 'visible_only', 'independent_custody_review': 'candidate_bound_review_complete'}
        for signed in self.review_receipts:
            review = self.verifier.verify(signed, 'isolation_reviewer')
            captured = closed(self.registry.store.get({'sha256': review['capture_sha256'], 'kind': 'isolation_capture'}),
                {'schema_version', 'kind', 'edition', 'freeze_sha256', 'nonce', 'host', 'identity',
                 'observed_at', 'collector_sha256', 'source_sha256', 'config_sha256', 'observations'}, 'isolation capture')
            for key in ('kind', 'edition', 'freeze_sha256', 'nonce', 'host', 'identity'):
                if captured[key] != review[key]:
                    raise ValueError('underlying capture differs from signed isolation review')
            if (captured['source_sha256'] != t2['pins']['release_sha256']
                    or captured['config_sha256'] != t2['pins']['config_sha256']
                    or not is_sha(captured['collector_sha256'])):
                raise ValueError('underlying isolation capture candidate pins mismatch')
            text(captured['observed_at'], 'isolation observation time')
            observations = captured['observations']
            if not isinstance(observations, list) or not observations:
                raise ValueError('actual isolation observations missing')
            for observation in observations:
                closed(observation, {'check_id', 'subject_sha256', 'observed_value'}, 'isolation effect')
                text(observation['check_id'], 'check_id')
                if (not is_sha(observation['subject_sha256']) or
                        observation['observed_value'] != expected_values.get(captured['kind'])):
                    raise ValueError('isolation effect remains unverified')
            content_pin = digest(observations)
            if content_pin in capture_contents:
                raise ValueError('copied isolation effects cannot prove distinct requirements')
            capture_contents.add(content_pin)
        custody = validate_custody(self.probe_receipt, self.review_receipts, commitment=t0, freeze=t2,
            verifier=self.verifier, expected_identity=authority['identity'], expected_host=authority['host'],
            collector_sha256=authority['collector_sha256'])
        return custody

    def request_authority(self) -> dict:
        self.validate()
        return self.verifier.verify(self.authority_receipt, 'run_owner')

    def begin(self, *, request_id: str, expected_head: str | None) -> JournalReceipt:
        custody = self.validate()
        return self.registry._append(self.commitment['edition'], 'attempt_started',
            {'suite': validate_suite(self.suite, self.commitment, self.freeze),
             'authority_sha256': digest(self.authority_receipt), 'custody_sha256': custody['custody_sha256']},
            request_id=request_id, expected_head=expected_head)

    def authorize_case(self, case, pins: dict, store: CaptureStore, mode: str) -> None:
        self.validate()
        state = self.registry.state(case.edition)
        attempt = state['attempt']
        if attempt is None or attempt['status'] != 'running' or attempt['suite'] != self.suite:
            raise ValueError('no active exact predeclared attempt; retry cannot rerun a consumed edition')
        if mode != self.suite['mode'] or pins != self.freeze['pins'] or store.root != self.registry.store.root:
            raise ValueError('mixed runtime frozen configurations')
        actual = variant_identity(case)
        declared = next((variant for variant in self.commitment['variants'] if variant['variant_id'] == case.variant_id), None)
        if actual != declared or case.variant_id not in self.suite['variant_ids']:
            raise ValueError('actual source/sample/brief/oracle/layout differs from T0')
