"""Hand-authored v2 target wires for future tests; no target/collector execution."""
from copy import deepcopy
from dataclasses import replace
from evaluator_support import refs, product_rows
from evaluation.artifacts import canonical, digest
from evaluation.target_effects import STATES, TargetExpectation


def seal(value, key):
    value[key] = digest({name: item for name, item in value.items() if name != key})
    return value


def expectation(method=None):
    descriptor = {'schema_version': 1, 'kind': 'product_bundle' if method is None else 'disposable_evaluation_candidate',
        'candidate_sha256': 'b' * 64, 'source_sha256': refs()[0]['source_sha256'], 'framing_sha256': 'f' * 64,
        'mapping_sha256': 'a' * 64, 'config_sha256': digest('config'), 'producer_code_sha256': digest('producer'),
        'counts': {'converted': 3, 'unresolved': 0, 'quarantined': 1}, 'record_count': 4,
        'method': method, 'edition': None if method is None else 'public-test-v1',
        'freeze_sha256': None if method is None else digest('frozen public fixture')}
    if method is not None:
        descriptor.update({key: digest(key) for key in ('sample_artifact_sha256', 'schema_sha256',
            'load_sha256', 'outcomes_sha256', 'rows_sha256')})
        descriptor.update(product_loadable=False, product_approval='absent')
        seal(descriptor, 'candidate_sha256')
    target = {'database': 'synthetic', 'role': 'synthetic', 'host': '127.0.0.1', 'port': 22990,
        'server_version_num': 170000, 'authority_reference': digest('authority'),
        'scope': 'disposable_local_test', 'driver_version': 'synthetic-version'}
    columns = [['source_sha256', 'text', 'NO', None, None], ['ordinal', 'bigint', 'NO', 64, 0],
        ['raw_sha256', 'text', 'NO', None, None], ['account_ref', 'text', 'NO', None, None],
        ['description', 'text', 'NO', None, None], ['balance', 'numeric', 'NO', 8, 2],
        ['effective_date', 'date', 'YES', None, None], ['status', 'text', 'NO', None, None]]
    return TargetExpectation(descriptor, digest('authority'), digest('target-config'), digest('observer'), target, columns)


def effect(expected, kind, execution='1' * 32, namespace=None):
    snap = lambda suffix: {'connection_id': digest([kind, suffix]), 'query_sha256': digest(['query', kind]),
        'namespace_exists': False, 'table_exists': False, 'rows': [], 'rows_sha256': digest([]), 'rows_capture': 'relation_absent'}
    value = {'schema_version': 1, 'kind': 'negative_effect', 'probe_kind': kind,
        'candidate_sha256': expected.candidate['candidate_sha256'], 'source_sha256': expected.candidate['source_sha256'],
        'authority_sha256': expected.authority_sha256, 'target_config_sha256': expected.target_config_sha256,
        'observer_code_sha256': expected.observer_code_sha256, 'execution_id': execution,
        'attempt_id': digest(['attempt', kind])[:32], 'namespace': namespace or 'la_' + digest(['namespace', kind])[:32],
        'target': deepcopy(expected.target), 'before': snap('before'), 'after': snap('after'),
        'transaction': {'connection_id': digest([kind, 'write']), 'statement_sha256': digest(['statement', kind]),
                        'sqlstate': '23514' if kind == 'failed_load' else sorted(STATES[kind])[0],
                        'error_class': 'SyntheticServerError'}, 'transaction_state': 'rolled_back', 'issues': []}
    return seal(value, 'effect_sha256')


def observations(expected):
    rows = product_rows()[:3]
    for row in rows:
        row.pop('reasons'); row['mapping_sha256'] = expected.candidate['mapping_sha256']
    positive = {'schema_version': 2, 'kind': 'target_observation', 'candidate': deepcopy(expected.candidate),
        'authority_sha256': expected.authority_sha256, 'target_config_sha256': expected.target_config_sha256,
        'observer_code_sha256': expected.observer_code_sha256,
        'attempt': {'execution_id': '1' * 32, 'attempt_id': '2' * 32, 'namespace': 'la_' + '3' * 32,
            'write_connection_id': digest('write'), 'read_connection_id': digest('read'), 'prior_observation_sha256': None},
        'target': deepcopy(expected.target), 'commit_state': 'committed',
        'readback': {'capture': 'fresh_connection_after_commit', 'query_sha256': digest('read-query'),
            'columns': deepcopy(expected.columns), 'rows': rows, 'rows_sha256': digest(rows)},
        'negative_effects': [effect(expected, kind) for kind in STATES], 'recovery': None, 'issues': []}
    seal(positive, 'observation_sha256')
    failed = deepcopy(positive)
    failed.update(commit_state='failed', readback=None)
    failed['attempt'].update(execution_id='4' * 32, attempt_id='5' * 32,
                             namespace='la_' + '6' * 32, read_connection_id=None)
    failed['negative_effects'] = [effect(expected, 'failed_load', execution='4' * 32, namespace='la_' + '6' * 32)]
    failed['attempt']['write_connection_id'] = failed['negative_effects'][0]['transaction']['connection_id']
    failed['schema_version'] = 3
    partial = {key: refs()[0][key] for key in ('source_sha256', 'ordinal', 'raw_sha256')}
    failed['controlled_fault'] = {'operation': 'controlled_failed_load', 'boundary': 'after_first_insert_before_commit',
        'state': 'injected', 'network_loss_claimed': False, 'driver_commit_returned': False,
        'application_ack_delivered': False, 'trigger_statement_sha256': digest('synthetic failing statement'),
        'boundary_sha256': digest({'operation': 'controlled_failed_load', 'boundary': 'after_first_insert_before_commit',
                                  'observer_code_sha256': expected.observer_code_sha256}),
        'injected_error_class': 'SyntheticControlledFailure', 'partial_write': {
            'connection_id': failed['attempt']['write_connection_id'], 'query_sha256': digest('partial-row-query'),
            'rows': [partial], 'rows_sha256': digest([partial])}}
    failed['negative_effects'][0]['transaction'].update(sqlstate='22012',
        statement_sha256=failed['controlled_fault']['trigger_statement_sha256'],
        error_class=failed['controlled_fault']['injected_error_class'])
    seal(failed['negative_effects'][0], 'effect_sha256')
    seal(failed, 'observation_sha256')
    prior = deepcopy(positive)
    prior.update(commit_state='indeterminate', readback=None, negative_effects=[])
    prior['issues'] = [{'code': 'commit_acknowledgement_unknown'}]
    prior['attempt'].update(execution_id='7' * 32, attempt_id='8' * 32,
                            namespace='la_' + '9' * 32, read_connection_id=None)
    seal(prior, 'observation_sha256')
    recovered = deepcopy(positive)
    recovered['attempt'] = {**prior['attempt'], 'attempt_id': 'a' * 32, 'read_connection_id': digest('recovery-read'),
                            'prior_observation_sha256': prior['observation_sha256']}
    recovered['negative_effects'] = []
    recovered['issues'] = [{'code': 'reconciled_lost_commit_acknowledgement'}]
    recovered['readback']['capture'] = 'fresh_connection_reconciliation'
    marker = {'execution_id': '7' * 32, 'candidate': expected.candidate, 'authority_sha256': expected.authority_sha256,
              'target_config_sha256': expected.target_config_sha256, 'row_count': 3}
    marker_rows = [['7' * 32, expected.candidate['candidate_sha256'], expected.authority_sha256, canonical(marker).decode()]]
    recovered['recovery'] = {'prior_observation_sha256': prior['observation_sha256'],
        'marker_query_sha256': digest('marker-query'), 'marker_rows': marker_rows, 'marker_rows_sha256': digest(marker_rows),
        'read_connection_id': recovered['attempt']['read_connection_id']}
    seal(recovered, 'observation_sha256')
    return positive, prior, failed, recovered
