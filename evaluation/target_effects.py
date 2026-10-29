"""Independent D5 v2/v3 target/effect grading. No product/driver imports.

Externally pinned observer/candidate/authority identity is required. A hash is an
identity check, not proof that a collector ran; authentic capture remains the
operator/custody boundary. Producer success booleans are not part of this wire.
"""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from copy import deepcopy
import re

from .artifacts import canonical, digest, is_sha
from .eligibility import closed, hashes, text
from .scorer import FIELDS, identity, score

OBS_KEYS = {'schema_version', 'kind', 'candidate', 'authority_sha256', 'target_config_sha256',
            'observer_code_sha256', 'attempt', 'target', 'commit_state', 'readback',
            'negative_effects', 'recovery', 'issues', 'observation_sha256'}
EFFECT_KEYS = {'schema_version', 'kind', 'probe_kind', 'candidate_sha256', 'source_sha256',
               'authority_sha256', 'target_config_sha256', 'observer_code_sha256', 'execution_id',
               'attempt_id', 'namespace', 'target', 'before', 'transaction', 'after',
               'transaction_state', 'issues', 'effect_sha256'}
PRODUCT_KEYS = {'schema_version', 'kind', 'candidate_sha256', 'source_sha256', 'framing_sha256',
                'mapping_sha256', 'config_sha256', 'producer_code_sha256', 'counts', 'record_count',
                'method', 'edition', 'freeze_sha256'}
EVAL_KEYS = PRODUCT_KEYS | {'sample_artifact_sha256', 'schema_sha256', 'load_sha256',
                          'outcomes_sha256', 'rows_sha256', 'product_loadable', 'product_approval'}
PHASE_KEYS = {'evaluation_phase', 'split', 'evaluation_plan_sha256'}
STATES = {'rollback': {'22012'}, 'nonnull': {'23502'}, 'check': {'23514'},
          'numeric_overflow': {'22003'}, 'duplicate_identity': {'23505'},
          'invalid_date': {'22007', '22008'}}
OBSERVATION_VERSIONS = (2, 3)


def _closed_version(value, keys, version, label):
    if not isinstance(value, dict) or set(value) != keys or type(value['schema_version']) is not int or value['schema_version'] != version:
        raise ValueError('closed ' + label + ' required')
    return deepcopy(value)


def _sealed(value, key):
    if not is_sha(value.get(key)) or value[key] != digest({name: item for name, item in value.items() if name != key}):
        raise ValueError(key + ' mismatch')


def _uuid(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{32}', value) is None:
        raise ValueError('exact execution/attempt identity required')


def _namespace(value):
    if not isinstance(value, str) or re.fullmatch('la_[0-9a-f]{32}', value) is None:
        raise ValueError('owned disposable namespace required')


def _issues(value):
    if not isinstance(value, list) or len(value) > 32:
        raise ValueError('bounded observation issues required')
    for issue in value:
        if (not isinstance(issue, dict) or 'code' not in issue or set(issue) - {'code', 'error_type'}
                or any(not isinstance(item, str) or not item or len(item) > 100 for item in issue.values())):
            raise ValueError('unknown observation issue fields')


def _provenance_rows(rows):
    if not isinstance(rows, list) or len(rows) > 10000:
        raise ValueError('bounded actual provenance rows required')
    for row in rows:
        closed(row, {'source_sha256', 'ordinal', 'raw_sha256'}, 'actual provenance row')
        if (not is_sha(row['source_sha256']) or not is_sha(row['raw_sha256'])
                or type(row['ordinal']) is not int or row['ordinal'] < 0):
            raise ValueError('invalid actual provenance identity')


@dataclass(frozen=True)
class TargetExpectation:
    candidate: dict
    authority_sha256: str
    target_config_sha256: str
    observer_code_sha256: str
    target: dict
    columns: list[list]
    required_negatives: tuple[str, ...] = tuple(STATES)

    def validate(self):
        descriptor = self.candidate
        kind = descriptor.get('kind') if isinstance(descriptor, dict) else None
        version = descriptor.get('schema_version') if isinstance(descriptor, dict) else None
        if version not in (1, 2) or (version == 2 and kind != 'disposable_evaluation_candidate'):
            raise ValueError('unknown target candidate version')
        keys = PRODUCT_KEYS if kind == 'product_bundle' else EVAL_KEYS | (PHASE_KEYS if version == 2 else set())
        _closed_version(descriptor, keys, version, 'target candidate')
        if kind not in ('product_bundle', 'disposable_evaluation_candidate'):
            raise ValueError('unknown candidate kind')
        hashes(descriptor, PRODUCT_KEYS - {'schema_version', 'kind', 'counts', 'record_count', 'method', 'edition', 'freeze_sha256'})
        counts = closed(descriptor['counts'], {'converted', 'unresolved', 'quarantined'}, 'candidate counts')
        if (any(type(value) is not int or value < 0 for value in counts.values()) or
                type(descriptor['record_count']) is not int or sum(counts.values()) != descriptor['record_count']):
            raise ValueError('candidate record accounting mismatch')
        if kind == 'disposable_evaluation_candidate':
            hashes(descriptor, EVAL_KEYS - PRODUCT_KEYS - {'product_loadable', 'product_approval'})
            if (descriptor['method'] not in ('B0', 'B1', 'C0', 'R0', 'R1') or
                    descriptor['product_loadable'] is not False or descriptor['product_approval'] != 'absent'):
                raise ValueError('evaluator candidate cannot be product approval')
            text(descriptor['edition'], 'edition')
            if version == 1: hashes(descriptor, ('freeze_sha256',))
            elif descriptor['evaluation_phase'] == 'T1':
                if descriptor['split'] not in ('development', 'validation') or descriptor['freeze_sha256'] is not None or not is_sha(descriptor['evaluation_plan_sha256']):
                    raise ValueError('T1 target requires a public plan, never a substituted T2 freeze')
            elif descriptor['evaluation_phase'] == 'T3':
                if descriptor['split'] not in ('development', 'validation', 'heldout') or descriptor['evaluation_plan_sha256'] is not None or not is_sha(descriptor['freeze_sha256']):
                    raise ValueError('T3 target requires actual T2 freeze')
            else: raise ValueError('unknown evaluation phase')
            _sealed(descriptor, 'candidate_sha256')
        elif any(descriptor[key] is not None for key in ('method', 'edition', 'freeze_sha256')):
            raise ValueError('product target cannot impersonate an evaluator arm')
        if any(not is_sha(pin) for pin in (self.authority_sha256, self.target_config_sha256, self.observer_code_sha256)):
            raise ValueError('separately approved target/authority/observer pins required')
        target_keys = {'database', 'role', 'host', 'port', 'server_version_num',
                       'authority_reference', 'scope', 'driver_version'}
        forwarded = isinstance(self.target, dict) and set(self.target) == target_keys | {'connection_host', 'connection_port'}
        target = closed(self.target, target_keys | ({'connection_host', 'connection_port'} if forwarded else set()), 'actual target')
        connect_host = target['connection_host'] if forwarded else target['host']
        connect_port = target['connection_port'] if forwarded else target['port']
        if forwarded:
            if not isinstance(target['host'], str) or '%' in target['host']:
                raise ValueError('literal observed server IP required')
            try:
                address = ip_address(target['host'])
            except (ValueError, TypeError) as exc:
                raise ValueError('literal observed server IP required') from exc
            if (not (address.is_private or address.is_loopback) or address.is_unspecified
                    or address.is_multicast or address.is_link_local or str(address) != target['host']):
                raise ValueError('canonical private or loopback observed server IP required')
        if (target['authority_reference'] != self.authority_sha256 or target['scope'] != 'disposable_local_test'
                or connect_host not in ('127.0.0.1', '::1') or type(connect_port) is not int
                or not 1 <= connect_port <= 65535 or connect_port in (20178, 20179, 55490)
                or type(target['port']) is not int
                or not 1 <= target['port'] <= 65535 or target['port'] in (20178, 20179, 55490)
                or type(target['server_version_num']) is not int):
            raise ValueError('unapproved target scope')
        for name in ('database', 'role', 'driver_version'):
            text(target[name], name, 200)
        if (not isinstance(self.columns, list) or len(self.columns) != 8 or
                any(not isinstance(column, list) or len(column) != 5 for column in self.columns)):
            raise ValueError('exact eight-column catalog contract required')
        names = [column[0] for column in self.columns]
        if names != ['source_sha256', 'ordinal', 'raw_sha256', *FIELDS]:
            raise ValueError('catalog names/order cannot repair wrong semantic targets')
        for name, kind, nullable, precision, scale in self.columns:
            expected = 'bigint' if name == 'ordinal' else 'numeric' if name == 'balance' else 'date' if name == 'effective_date' else 'text'
            if kind != expected or nullable not in ('YES', 'NO'):
                raise ValueError('target catalog semantic type/null contract mismatch')
            if name == 'balance' and (type(precision) is not int or type(scale) is not int or
                                      scale not in (0, 2, 3) or not max(1, scale) <= precision <= 1000):
                raise ValueError('exact declared numeric precision/scale required')
        if len(self.required_negatives) != len(STATES) or set(self.required_negatives) != set(STATES):
            raise ValueError('closed finite negative suite required')
        return self


def validate_target_observation(value, *, expectation):
    """Closed wire validation only; no effect acceptance, transport or repair."""
    expectation.validate()
    return _observation(value, expectation)


def _observation(value, expected):
    version = value.get('schema_version') if isinstance(value, dict) else None
    if type(version) is not int or version not in OBSERVATION_VERSIONS:
        raise ValueError('unknown target observation version')
    item = _closed_version(value, OBS_KEYS | ({'controlled_fault'} if version == 3 else set()), version, 'target observation')
    _sealed(item, 'observation_sha256')
    if item['kind'] != 'target_observation' or item['candidate'] != expected.candidate:
        raise ValueError('observation candidate differs from externally pinned target')
    for key in ('authority_sha256', 'target_config_sha256', 'observer_code_sha256'):
        if item[key] != getattr(expected, key):
            raise ValueError('wrong observation ' + key)
    if item['target'] is not None and item['target'] != expected.target:
        raise ValueError('wrong actual target/version/role')
    attempt = closed(item['attempt'], {'execution_id', 'attempt_id', 'namespace', 'write_connection_id',
        'read_connection_id', 'prior_observation_sha256'}, 'target attempt')
    _uuid(attempt['execution_id']); _uuid(attempt['attempt_id']); _namespace(attempt['namespace'])
    if any(attempt[key] is not None and not is_sha(attempt[key]) for key in
           ('write_connection_id', 'read_connection_id', 'prior_observation_sha256')):
        raise ValueError('unbound connection/recovery identity')
    if item['commit_state'] not in ('not_run', 'failed', 'indeterminate', 'committed'):
        raise ValueError('unknown commit state')
    if not isinstance(item['issues'], list) or len(item['issues']) > 32 or not isinstance(item['negative_effects'], list) or len(item['negative_effects']) > 7:
        raise ValueError('bounded issues/effects required')
    _issues(item['issues'])
    if item['readback'] is not None:
        rb = closed(item['readback'], {'capture', 'query_sha256', 'columns', 'rows', 'rows_sha256'}, 'readback wire')
        if not isinstance(rb['rows'], list) or len(rb['rows']) > 10000:
            raise ValueError('bounded concrete readback rows required')
        for row in rb['rows']:
            closed(row, {'record_ref', 'mapping_sha256', 'outcome', 'values'}, 'observed row wire')
            identity(row['record_ref'])
            if not is_sha(row['mapping_sha256']) or row['outcome'] != 'converted':
                raise ValueError('invalid observed mapping/outcome')
            closed(row['values'], set(FIELDS), 'observed semantic values')
            if any(value is not None and (not isinstance(value, str) or len(value) > 16384) for value in row['values'].values()):
                raise ValueError('bounded textual target values required')
    for effect in item['negative_effects']:
        _closed_version(effect, EFFECT_KEYS, 1, 'negative effect wire')
        _sealed(effect, 'effect_sha256')
        _issues(effect['issues'])
        for key in ('before', 'after'):
            if effect[key] is not None:
                _snapshot(effect[key])
        if effect['transaction'] is not None:
            tx = closed(effect['transaction'], {'connection_id', 'statement_sha256', 'sqlstate', 'error_class'}, 'transaction wire')
            if any(tx[key] is not None and not is_sha(tx[key]) for key in ('connection_id', 'statement_sha256')):
                raise ValueError('invalid actual transaction hash')
            if tx['sqlstate'] is not None and (not isinstance(tx['sqlstate'], str) or re.fullmatch('[0-9A-Z]{5}', tx['sqlstate']) is None):
                raise ValueError('invalid observed SQLSTATE')
            if tx['error_class'] is not None: text(tx['error_class'], 'server error class', 100)
    if item['recovery'] is not None:
        closed(item['recovery'], {'prior_observation_sha256', 'marker_query_sha256', 'marker_rows',
            'marker_rows_sha256', 'read_connection_id'}, 'recovery wire')
    if version == 3: _controlled_fault(item)
    return item


def _controlled_fault(observation):
    value = closed(observation['controlled_fault'], {'operation', 'boundary', 'state', 'network_loss_claimed',
        'driver_commit_returned', 'application_ack_delivered', 'trigger_statement_sha256', 'boundary_sha256',
        'injected_error_class', 'partial_write'}, 'controlled fault')
    boundaries = {'controlled_failed_load': 'after_first_insert_before_commit',
                  'controlled_commit_ack': 'after_driver_commit_before_application_ack'}
    if value['operation'] not in boundaries or value['boundary'] != boundaries[value['operation']] or value['state'] not in ('not_reached', 'injected', 'unsupported'):
        raise ValueError('unknown controlled observation boundary/state')
    if value['network_loss_claimed'] is not False or type(value['driver_commit_returned']) is not bool or value['application_ack_delivered'] is not False:
        raise ValueError('application suppression cannot claim a network failure/delivered ACK')
    if value['boundary_sha256'] != digest({'operation': value['operation'], 'boundary': value['boundary'],
                                         'observer_code_sha256': observation['observer_code_sha256']}):
        raise ValueError('controlled fault definition differs from pinned observer')
    if value['trigger_statement_sha256'] is not None and not is_sha(value['trigger_statement_sha256']):
        raise ValueError('invalid controlled statement hash')
    if value['injected_error_class'] is not None:
        text(value['injected_error_class'], 'controlled error class', 100)
    if value['partial_write'] is not None:
        partial = closed(value['partial_write'], {'connection_id', 'query_sha256', 'rows', 'rows_sha256'}, 'partial write')
        _provenance_rows(partial['rows'])
        hashes(partial, ('connection_id', 'query_sha256', 'rows_sha256'))
        if partial['connection_id'] != observation['attempt']['write_connection_id'] or not isinstance(partial['rows'], list) or len(partial['rows']) > 10000 or partial['rows_sha256'] != digest(partial['rows']):
            raise ValueError('partial insert lacks actual connection/query/row lineage')
        for row in partial['rows']:
            closed(row, {'source_sha256', 'ordinal', 'raw_sha256'}, 'partial row provenance')
            if (row['source_sha256'] != observation['candidate']['source_sha256'] or not is_sha(row['raw_sha256'])
                    or type(row['ordinal']) is not int or row['ordinal'] < 0):
                raise ValueError('partial row has invalid source/ordinal/raw identity')
    if value['state'] == 'injected':
        if observation['target'] is None or not is_sha(observation['attempt']['write_connection_id']):
            raise ValueError('injected boundary requires actual target/write connection')
        text(value['injected_error_class'], 'controlled error class')
        if value['operation'] == 'controlled_failed_load':
            if (value['driver_commit_returned'] or value['partial_write'] is None or len(value['partial_write']['rows']) != 1
                    or not is_sha(value['trigger_statement_sha256']) or observation['commit_state'] not in ('failed', 'indeterminate')):
                raise ValueError('failed-load probe requires actual first insert/error before commit')
        elif (not value['driver_commit_returned'] or value['partial_write'] is not None
                or value['trigger_statement_sha256'] is not None or value['injected_error_class'] != 'ControlledAcknowledgementSuppressed'
                or observation['commit_state'] not in ('indeterminate', 'committed')
                or (observation['commit_state'] == 'committed' and observation['recovery'] is None)):
            raise ValueError('controlled ACK lacks actual driver return and deliberate suppression')
    return value


def _snapshot(value):
    snap = closed(value, {'connection_id', 'query_sha256', 'namespace_exists', 'table_exists',
        'rows', 'rows_sha256', 'rows_capture'}, 'durable namespace snapshot')
    hashes(snap, ('connection_id', 'query_sha256', 'rows_sha256'))
    _provenance_rows(snap['rows'])
    if (type(snap['namespace_exists']) is not bool or type(snap['table_exists']) is not bool
            or not isinstance(snap['rows'], list) or snap['rows_sha256'] != digest(snap['rows'])
            or snap['rows_capture'] not in ('relation_absent', 'all_persisted_provenance_rows')):
        raise ValueError('invalid durable-effect capture')
    return snap


def _effect(value, observation, expected, *, failed_load=False):
    item = _closed_version(value, EFFECT_KEYS, 1, 'negative effect')
    _sealed(item, 'effect_sha256')
    if item['kind'] != 'negative_effect' or item['probe_kind'] not in (*STATES, 'failed_load'):
        raise ValueError('unknown negative effect')
    for key in ('authority_sha256', 'target_config_sha256', 'observer_code_sha256'):
        if item[key] != getattr(expected, key):
            raise ValueError('negative effect lineage mismatch')
    if (item['candidate_sha256'] != expected.candidate['candidate_sha256'] or
            item['source_sha256'] != expected.candidate['source_sha256'] or item['target'] != expected.target
            or item['execution_id'] != observation['attempt']['execution_id']):
        raise ValueError('negative effect belongs to another execution/candidate/target')
    _namespace(item['namespace']); _uuid(item['attempt_id'])
    if not failed_load and item['namespace'] == observation['attempt']['namespace']:
        raise ValueError('negative probes must use their own fresh namespace')
    if failed_load and item['namespace'] != observation['attempt']['namespace']:
        raise ValueError('failed-load absence must observe the actual failed namespace')
    if not failed_load and item['probe_kind'] not in STATES:
        raise ValueError('failed-load evidence must be a separate failed attempt')
    if item['transaction_state'] in ('not_run', 'not_applicable', 'indeterminate'):
        return {'kind': item['probe_kind'], 'status': 'missing', 'effect_sha256': item['effect_sha256']}
    if item['transaction_state'] != 'rolled_back' or item['issues']:
        raise ValueError('failed/incomplete negative probe')
    if any(item[key] is None for key in ('before', 'transaction', 'after')):
        return {'kind': item['probe_kind'], 'status': 'missing', 'effect_sha256': item['effect_sha256']}
    before, after = _snapshot(item['before']), _snapshot(item['after'])
    tx = closed(item['transaction'], {'connection_id', 'statement_sha256', 'sqlstate', 'error_class'}, 'server failure')
    hashes(tx, ('connection_id', 'statement_sha256'))
    if failed_load and tx['connection_id'] != observation['attempt']['write_connection_id']:
        raise ValueError('failed-load transaction is not the observed write connection')
    if len({before['connection_id'], tx['connection_id'], after['connection_id']}) != 3:
        raise ValueError('negative observation did not use distinct actual connections')
    if any(snap['namespace_exists'] or snap['table_exists'] or snap['rows'] or
           snap['rows_capture'] != 'relation_absent' for snap in (before, after)):
        raise ValueError('failed load left durable namespace/table/rows or was not fresh')
    text(tx['error_class'], 'server error class')
    allowed = {'failed_load': None, **STATES}[item['probe_kind']]
    if (not isinstance(tx['sqlstate'], str) or re.fullmatch('[0-9A-Z]{5}', tx['sqlstate']) is None
            or (allowed is not None and tx['sqlstate'] not in allowed)):
        raise ValueError('required actual PostgreSQL failure not observed')
    return {'kind': item['probe_kind'], 'status': 'observed', 'effect_sha256': item['effect_sha256']}


def _recovery(observation, prior, expected, valid_count):
    old = _observation(prior, expected) if prior is not None else None
    if observation['recovery'] is None or prior is None:
        return False
    if old['commit_state'] != 'indeterminate':
        raise ValueError('lost-ACK evidence requires the actual unknown-commit predecessor')
    old_codes = {issue['code'] for issue in old['issues']}
    new_codes = {issue['code'] for issue in observation['issues']}
    recovery_kind = None
    if old['schema_version'] != observation['schema_version']:
        raise ValueError('recovery cannot change observation schema/boundary kind')
    if old['target'] != expected.target or not is_sha(old['attempt']['write_connection_id']):
        raise ValueError('recovery predecessor lacks actual target/write identity')
    if old['schema_version'] == 2 and old_codes == {'commit_acknowledgement_unknown'} and new_codes == {'reconciled_lost_commit_acknowledgement'}:
        recovery_kind = 'observed_lost_commit_ack'
    elif old.get('schema_version') == 3 and observation.get('schema_version') == 3:
        fault = _controlled_fault(old)
        if (fault['operation'] == 'controlled_commit_ack' and fault['state'] == 'injected'
                and observation['controlled_fault'] == old['controlled_fault']
                and old_codes == {'controlled_application_ack_suppressed'} and new_codes == {'reconciled_controlled_application_ack'}):
            recovery_kind = 'controlled_application_ack'
    if recovery_kind is None: return False
    a, b = observation['attempt'], old['attempt']
    if any(a[key] != b[key] for key in ('execution_id', 'namespace', 'write_connection_id')) or a['attempt_id'] == b['attempt_id']:
        raise ValueError('lost-ACK recovery changed original run identity')
    value = closed(observation['recovery'], {'prior_observation_sha256', 'marker_query_sha256', 'marker_rows',
        'marker_rows_sha256', 'read_connection_id'}, 'durable recovery marker')
    hashes(value, ('prior_observation_sha256', 'marker_query_sha256', 'marker_rows_sha256', 'read_connection_id'))
    if (value['prior_observation_sha256'] != old['observation_sha256'] or
            a['prior_observation_sha256'] != old['observation_sha256'] or value['read_connection_id'] != a['read_connection_id']
            or value['marker_rows_sha256'] != digest(value['marker_rows'])):
        raise ValueError('recovery marker lineage/hash mismatch')
    marker = {'execution_id': a['execution_id'], 'candidate': expected.candidate,
              'authority_sha256': expected.authority_sha256, 'target_config_sha256': expected.target_config_sha256,
              'row_count': valid_count}
    rows = [[a['execution_id'], expected.candidate['candidate_sha256'], expected.authority_sha256,
             canonical(marker).decode('utf-8')]]
    if value['marker_rows'] != rows:
        raise ValueError('missing/extra/duplicate/wrong durable execution marker')
    return recovery_kind if observation['readback']['capture'] == 'fresh_connection_reconciliation' else False


def _readback_report(valid, item, expected, edition):
    rb = closed(item['readback'], {'capture', 'query_sha256', 'columns', 'rows', 'rows_sha256'}, 'readback')
    hashes(rb, ('query_sha256', 'rows_sha256'))
    if rb['rows_sha256'] != digest(rb['rows']) or rb['columns'] != expected.columns:
        raise ValueError('actual row hash/type/null/precision/scale catalog mismatch')
    a = item['attempt']
    if (item['commit_state'] != 'committed' or not is_sha(a['write_connection_id']) or not is_sha(a['read_connection_id']) or
            a['write_connection_id'] == a['read_connection_id'] or item['target'] != expected.target or
            rb['capture'] not in ('fresh_connection_after_commit', 'fresh_connection_reconciliation')):
        raise ValueError('readback lacks committed fresh target connection')
    kinds = {column[0]: 'decimal' if column[1] == 'numeric' else column[1] for column in rb['columns']}
    if not isinstance(rb['rows'], list):
        raise ValueError('readback rows must be concrete list')
    outcomes = []
    for row in rb['rows']:
        closed(row, {'record_ref', 'mapping_sha256', 'outcome', 'values'}, 'target row')
        identity(row['record_ref'])
        if row['mapping_sha256'] != expected.candidate['mapping_sha256'] or row['outcome'] != 'converted':
            raise ValueError('wrong target row mapping/outcome')
        if not isinstance(row['values'], dict):
            raise ValueError('typed semantic values required')
        outcomes.append({'record_ref': row['record_ref'], 'outcome': 'converted',
            'fields': {name: {'data_type': kinds.get(name), 'value': value} for name, value in row['values'].items()}})
    return score(valid, outcomes, edition=edition)


def grade_target(oracle: list[dict], observation: dict | None, *, expectation: TargetExpectation,
                 prior: dict | None = None, failed_load: dict | None = None,
                 recovery_observation: dict | None = None, edition='development') -> dict:
    """Only actual exact readback + required durable effects can yield passed."""
    expectation.validate()
    valid = [row for row in oracle if row['expected_outcome'] == 'converted']
    empty = score(valid, [], edition=edition)
    base = {'schema_version': 1, 'candidate_sha256': expectation.candidate['candidate_sha256'],
            'edition': edition, 'score': empty, 'target_validation': 'not_run',
            'product_acceptance': 'pending', 'negative_effects': [], 'missing': []}
    if observation is None:
        return {**base, 'reason': 'no observation'}
    try:
        descriptor = expectation.candidate
        if (descriptor['record_count'] != len(oracle) or descriptor['counts']['converted'] != len(valid)
                or descriptor['counts']['unresolved'] or any(row['record_ref']['source_sha256'] != descriptor['source_sha256']
                or row['record_ref']['framing_sha256'] != descriptor['framing_sha256'] for row in oracle)):
            raise ValueError('candidate/input/oracle accounting or source identity mismatch')
        item = _observation(observation, expectation)
        if item['commit_state'] != 'committed':
            return {**base, 'target_validation': {'failed': 'failed', 'indeterminate': 'indeterminate',
                    'not_run': 'not_run'}[item['commit_state']], 'reason': 'no committed readback',
                    'observation_sha256': item['observation_sha256']}
        a = item['attempt']
        report = _readback_report(valid, item, expectation, edition)
        base.update(score=report, observation_sha256=item['observation_sha256'])
        if report['row_parity'] != 'exact':
            return {**base, 'target_validation': 'failed', 'reason': 'independent semantic/identity mismatch'}
        seen, attempts, namespaces = set(), set(), set()
        for effect in item['negative_effects']:
            result = _effect(effect, item, expectation)
            if effect['probe_kind'] in seen or effect['attempt_id'] in attempts or effect['namespace'] in namespaces:
                raise ValueError('duplicated probe/attempt/namespace cannot satisfy distinct effects')
            seen.add(effect['probe_kind']); attempts.add(effect['attempt_id']); namespaces.add(effect['namespace'])
            base['negative_effects'].append(result)
        observed = {entry['kind'] for entry in base['negative_effects'] if entry['status'] == 'observed'}
        base['missing'] = sorted(set(expectation.required_negatives) - observed)
        recovered = _observation(recovery_observation, expectation) if recovery_observation is not None else item
        recovery_kind = False
        if recovered['commit_state'] == 'committed' and recovered['readback'] is not None:
            if recovery_observation is not None and _readback_report(valid, recovered, expectation, edition)['row_parity'] != 'exact':
                raise ValueError('recovery readback disagrees with independent oracle')
            recovery_kind = _recovery(recovered, prior, expectation, len(valid))
        elif recovery_observation is not None:
            base['missing'].append('committed_recovery_readback')
            if prior is not None: _observation(prior, expectation)
        base['recovery_kind'] = recovery_kind or None
        base['recovery_scope'] = ({'controlled_application_ack': 'driver_returned_application_ack_suppressed',
                                  'observed_lost_commit_ack': 'observed_unknown_driver_ack'}.get(recovery_kind))
        base['network_loss_proven'] = False
        if not recovery_kind:
            base['missing'].append('lost_ack_reconciliation')
        if failed_load is None:
            base['missing'].append('failed_load_durable_absence')
        else:
            failed = _observation(failed_load, expectation)
            if failed['commit_state'] in ('not_run', 'indeterminate'):
                base['missing'].append('failed_load_durable_absence')
            elif failed['commit_state'] != 'failed' or failed['attempt']['execution_id'] == a['execution_id']:
                raise ValueError('separate actual failed-load observation required')
            else:
                entries = [effect for effect in failed['negative_effects'] if effect['probe_kind'] == 'failed_load']
                controlled = _controlled_fault(failed) if failed['schema_version'] == 3 else None
                if controlled is None or controlled['operation'] != 'controlled_failed_load' or controlled['state'] != 'injected':
                    base['missing'].append('actual_partial_write_before_failure')
                else:
                    partial = controlled['partial_write']['rows'][0]
                    known_refs = [{key: row['record_ref'][key] for key in ('source_sha256', 'ordinal', 'raw_sha256')} for row in valid]
                    if partial not in known_refs: raise ValueError('controlled partial row not present in canonical input identities')
                    if len(entries) == 1 and entries[0]['transaction'] is not None:
                        tx = entries[0]['transaction']
                        if (tx['sqlstate'] != '22012' or tx['statement_sha256'] != controlled['trigger_statement_sha256']
                                or tx['error_class'] != controlled['injected_error_class']):
                            raise ValueError('failed-load error does not match actual controlled SELECT 1/0 boundary')
                if len(entries) != 1 or _effect(entries[0], failed, expectation, failed_load=True)['status'] != 'observed':
                    base['missing'].append('failed_load_durable_absence')
        if item['issues']:
            base['missing'].append('unresolved_observation_issues')
        return {**base, 'target_validation': 'indeterminate' if base['missing'] else 'passed',
                'reason': 'missing actual effects' if base['missing'] else 'exact readback and required effects observed'}
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        return {**base, 'target_validation': 'failed', 'reason': str(exc)}
