"""Evaluator-owned append-only edition/attempt journal SOURCE.

SQLite is the committed authority; immutable JSON captures are rebuildable
exports of committed events. No registry/database is created on module import.
The operator must place both registry and captures outside inference-readable
storage and establish that custody separately before any hidden attempt.
"""
from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
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

    @contextmanager
    def _connect(self):
        if self.path.is_symlink():
            raise ValueError('registry symlink rejected')
        db = sqlite3.connect(self.path, timeout=5)
        try:
            db.execute('PRAGMA synchronous=FULL')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

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
        state = {'commitment': None, 'freeze': None, 'exposed': False, 'retired': False, 'attempt': None, 't1': None}
        for event in events:
            if event['edition'] != edition:
                continue
            kind, payload = event['event_type'], event['payload']
            if kind.startswith('t1_') or state['t1'] is not None:
                from .public_live import fold_public_event
                if fold_public_event(state, event):
                    continue
            if kind == 'registered':
                if state['commitment'] is not None or state['t1'] is not None:
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
                state['attempt'] = {'suite': payload['suite'], 'status': 'running',
                                    'event_sha256': event['event_sha256'], 'arms': {}}
            elif kind in ('arm_started', 'arm_finished'):
                expected = {'attempt_id', 'variant_id', 'method'}
                if kind == 'arm_finished':
                    expected |= {'status', 'capture'}
                closed(payload, expected, 'arm transition')
                attempt = state['attempt']
                if (attempt is None or attempt['status'] != 'running'
                        or payload['attempt_id'] != attempt['suite']['attempt_id']
                        or payload['variant_id'] not in attempt['suite']['variant_ids']
                        or payload['method'] not in attempt['suite']['methods']):
                    raise ValueError('arm outside the active exact predeclared suite')
                key = digest({'variant_id': payload['variant_id'], 'method': payload['method']})
                if kind == 'arm_started':
                    if state['exposed'] or state['retired']:
                        raise ValueError('exposed/retired edition cannot start another arm')
                    if key in attempt['arms']:
                        raise ValueError('duplicate arm execution forbidden')
                    attempt['arms'][key] = {'status': 'running'}
                else:
                    if key not in attempt['arms'] or attempt['arms'][key]['status'] != 'running':
                        raise ValueError('arm finish lacks its unique start')
                    if payload['status'] not in ('completed', 'partial', 'failed', 'abstained'):
                        raise ValueError('unknown arm terminal state')
                    closed(payload['capture'], {'sha256', 'kind', 'bytes'}, 'arm result capture')
                    attempt['arms'][key] = {'status': payload['status'], 'capture': payload['capture']}
            elif kind == 'attempt_finished':
                closed(payload, {'attempt_id', 'status', 'result_capture'}, 'attempt finish')
                if (state['attempt'] is None or state['attempt']['status'] != 'running'
                        or payload['attempt_id'] != state['attempt']['suite']['attempt_id'] or payload['status'] not in TERMINAL):
                    raise ValueError('invalid terminal attempt transition')
                closed(payload['result_capture'], {'sha256', 'kind', 'bytes'}, 'terminal capture')
                if payload['status'] == 'completed':
                    if state['exposed'] or state['retired']:
                        raise ValueError('exposed/retired suite cannot claim completed custody')
                    required = len(state['attempt']['suite']['methods']) * len(state['attempt']['suite']['variant_ids'])
                    if (len(state['attempt']['arms']) != required or
                            any(arm['status'] != 'completed' for arm in state['attempt']['arms'].values())):
                        raise ValueError('completed suite requires every unique predeclared arm result')
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
                if kind in ('t1_attempt_started', 't1_arm_started', 't1_request_reserved', 't1_selected'):
                    public = self._state(events, edition)['t1']
                    if public is None: raise ValueError('public phase registration missing')
                    self.check_t1_chronology(public['catalog'], events=events)
                if kind in ('t1_attempt_started', 't1_request_reserved'):
                    self.assert_no_unknown_public_liability(events=events)
                if kind == 'frozen':
                    self.check_freeze_chronology(payload, events)
                self._state(events + [event], edition)  # Reject illegal state before durable mutation.
                if kind == 'registered':
                    new = validate_commitment(payload)
                    heldout_gold = {v['canonical_sha256'] for v in new['variants'] if v['split'] == 'heldout'}
                    public_gold = {v['canonical_sha256'] for v in new['variants'] if v['split'] != 'heldout'}
                    if heldout_gold & public_gold:
                        raise ValueError('heldout gold already appears in this family public splits')
                    for old in events:
                        if old['event_type'] == 't1_registered':
                            if heldout_gold & {variant['canonical_sha256'] for variant in old['payload']['variants']}:
                                raise ValueError('public/retired T1 gold cannot become hidden')
                        if old['event_type'] != 'registered':
                            continue
                        prior = self._state(events, old['edition'])
                        if new['nonce'] == prior['commitment']['nonce']:
                            raise ValueError('edition nonce already used')
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
        self.check_freeze_chronology(item, self.events())
        return self._append(item['edition'], 'frozen', item, request_id=request_id, expected_head=expected_head)

    def check_freeze_chronology(self, item, events):
        for event in events:
            if event['event_type'] == 't1_registered' and event['payload']['corpus_commitment_sha256'] == item['commitment_sha256']:
                public = self._state(events, event['edition'])['t1']
                if any(a['status'] == 'running' for a in public['attempts'].values()):
                    raise ValueError('finish linked public T1 attempts before T2 freeze')
        if 'selection_sha256' in item:
            selections = [event for event in events if event['event_type'] == 't1_selected'
                          and event['payload']['selection_sha256'] == item['selection_sha256']]
            if len(selections) != 1 or selections[0]['payload']['pins'] != item['pins']:
                raise ValueError('T2 does not match actual committed T1 selection')
            public = self._state(events, selections[0]['edition'])['t1']
            if public['catalog']['corpus_commitment_sha256'] != item['commitment_sha256']:
                raise ValueError('T1 selection was not linked to pre-tuning T0')
    def register_public(self, catalog, *, request_id, expected_head):
        from .public_live import validate_catalog
        item = validate_catalog(catalog)
        self.check_t1_chronology(item)
        return self._append(item['edition'], 't1_registered', item, request_id=request_id, expected_head=expected_head)

    def check_t1_chronology(self, catalog, *, events=None):
        pin = catalog['corpus_commitment_sha256']
        if pin is None:
            return  # Explicit public exploratory trial, not eligible for hidden promotion.
        events = self.events() if events is None else events
        sealed = next((event for event in events if event['event_type'] == 'registered'
                       and event['payload']['commitment_sha256'] == pin), None)
        if sealed is None:
            raise ValueError('linked T0 must be sealed before public tuning')
        state = self._state(events, sealed['edition'])
        if state['freeze'] is not None or state['attempt'] is not None or state['exposed'] or state['retired']:
            raise ValueError('T1 tuning cannot occur after final T2/T3/exposure')
        original = {variant['variant_id']: variant for variant in state['commitment']['variants']}
        if any(variant != original.get(variant['variant_id']) for variant in catalog['variants']):
            raise ValueError('public inputs differ from pre-tuning T0 split')

    def assert_no_unknown_public_liability(self, *, events=None):
        events = self.events() if events is None else events
        for registration in events:
            if registration['event_type'] != 't1_registered': continue
            public = self._state(events, registration['edition'])['t1']
            if any(call['status'] != 'known' for attempt in public['attempts'].values() for call in attempt['calls'].values()):
                raise ValueError('unresolved public liability/single-flight reserve blocks additional live calls across editions')

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

    def __post_init__(self):
        if type(self.registry) is not EditionRegistry or type(self.verifier) is not ReceiptVerifier:
            raise ValueError('concrete evaluator registry and Ed25519 verifier required, not mocked capability objects')

    def validate(self) -> dict:
        t0 = validate_commitment(self.commitment)
        t2 = validate_freeze(self.freeze, t0)
        suite = validate_suite(self.suite, t0, t2)
        if suite['mode'] == 'live': self.registry.assert_no_unknown_public_liability()
        state = self.registry.state(t0['edition'])
        if state['commitment'] != t0 or state['freeze'] != t2 or state['exposed'] or state['retired']:
            raise ValueError('registry edition exposed/retired or pins differ')
        authority = closed(self.verifier.verify(self.authority_receipt, 'run_owner'),
                           {'schema_version', 'action', 'edition', 'suite_sha256', 'freeze_sha256',
                            'nonce', 'mode', 'capture_root_sha256', 'identity', 'host', 'collector_sha256',
                            'spend_authority_sha256', 'registry_sha256'},
                           'suite authority')
        if authority['action'] != 'execute_suite':
            raise ValueError('explicit suite action required')
        for key in ('edition', 'suite_sha256', 'freeze_sha256', 'nonce', 'mode', 'capture_root_sha256'):
            if authority[key] != suite[key]:
                raise ValueError('authority/suite identity mismatch')
        if suite['capture_root_sha256'] != digest(str(self.registry.store.root)):
            raise ValueError('custody capture-root mismatch')
        if authority['registry_sha256'] != digest(str(self.registry.path)):
            raise ValueError('signed authority names a different edition registry')
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

    def claim_arm(self, variant_id: str, method: str) -> JournalReceipt:
        payload = {'attempt_id': self.suite['attempt_id'], 'variant_id': variant_id, 'method': method}
        receipt = self.registry._append(self.commitment['edition'], 'arm_started', payload,
            request_id='arm-start:' + digest(payload), expected_head=self.registry.head)
        if not receipt.newly_created:
            raise ValueError('historical arm start cannot authorize re-execution')
        return receipt

    def finish_arm(self, variant_id: str, method: str, status: str, capture: dict) -> JournalReceipt:
        self.registry.store.get(capture)
        payload = {'attempt_id': self.suite['attempt_id'], 'variant_id': variant_id,
                   'method': method, 'status': status, 'capture': capture}
        return self.registry._append(self.commitment['edition'], 'arm_finished', payload,
            request_id='arm-finish:' + digest({'attempt_id': self.suite['attempt_id'],
                        'variant_id': variant_id, 'method': method}), expected_head=self.registry.head)

    def finish_suite(self, status, capture, *, request_id):
        return self.registry.finish(self.commitment['edition'], self.suite['attempt_id'], status, capture,
                                    request_id=request_id, expected_head=self.registry.head)
