"""Score committed database observations against independent canonical records.

No database driver, product converter or producer success boolean is consulted.
Observation production/authorization belongs to the external target adapter.
"""
from __future__ import annotations

from .artifacts import digest, is_sha
from .scorer import FIELDS, score, score_product


def score_target(oracle: list[dict], observation: dict | None, *,
                 bundle_sha256: str, mapping_sha256: str, edition: str) -> dict:
    if observation is None:
        return {'schema_version': 1, 'target_validation': 'not_run', 'reason': 'no target observation',
                'row_parity': 'not_run', 'product_acceptance': 'pending'}
    allowed = {'schema_version', 'bundle_sha256', 'mapping_sha256', 'kind', 'commit_state',
               'execution_id', 'server_version', 'namespace', 'role', 'write_connection_id',
               'read_connection_id', 'observer_code_sha256', 'edition', 'column_types',
               'rows', 'rows_sha256', 'negative_observations'}
    if not isinstance(observation, dict) or set(observation) - allowed:
        raise ValueError('unknown target observation fields; credentials/DSNs are not accepted')
    if not is_sha(bundle_sha256) or not is_sha(mapping_sha256):
        raise ValueError('expected bundle/mapping pins required')
    missing = []
    for key, expected in (('bundle_sha256', bundle_sha256), ('mapping_sha256', mapping_sha256),
                          ('kind', 'committed_fresh_readback'), ('commit_state', 'committed')):
        if observation.get(key) != expected:
            missing.append(key)
    for key in ('execution_id', 'server_version', 'namespace', 'role', 'write_connection_id', 'read_connection_id'):
        if not isinstance(observation.get(key), str) or not observation[key]:
            missing.append(key)
    if observation.get('write_connection_id') == observation.get('read_connection_id'):
        missing.append('fresh_connection')
    if not is_sha(observation.get('observer_code_sha256')):
        missing.append('observer_code_pin')
    if observation.get('edition') != edition:
        missing.append('edition')
    if missing:
        return {'schema_version': 1, 'target_validation': 'indeterminate',
                'reason': 'unbound or uncommitted target observation', 'missing': missing,
                'observation_sha256': digest(observation), 'product_acceptance': 'pending'}
    columns = observation.get('column_types', {})
    expected_types = {name: 'decimal' if name == 'balance' else 'date' if name == 'effective_date' else 'text'
                      for name in FIELDS}
    if columns != expected_types:
        return {'schema_version': 1, 'target_validation': 'failed', 'reason': 'target column type mismatch',
                'observation_sha256': digest(observation), 'product_acceptance': 'pending'}
    outcomes = []
    for row in observation.get('rows', []):
        # Column type is observed target catalog/driver metadata, never gold.
        outcomes.append({'record_ref': row.get('record_ref', {}), 'outcome': 'converted',
                         'fields': {name: {'data_type': columns.get(name), 'value': value}
                                    for name, value in row.get('values', {}).items()}})
    # Malformed source records are not load rows; verify they did not appear as
    # extras while valid record denominators remain complete.
    load_oracle = [row for row in oracle if row['expected_outcome'] == 'converted']
    report = score(load_oracle, outcomes, edition=edition)
    negatives = observation.get('negative_observations', {})
    rollback = negatives.get('rollback', {})
    recovery = negatives.get('lost_ack', {})
    constraints = negatives.get('constraints', [])
    required = []
    if (rollback.get('bundle_sha256') != bundle_sha256 or not rollback.get('failure_injected_before_commit')
            or not isinstance(rollback.get('rows_before'), list)
            or rollback.get('rows_before') != rollback.get('rows_after_fresh_read')
            or not rollback.get('fresh_read_connection_id')):
        required.append('rollback_effect_observation')
    if (recovery.get('bundle_sha256') != bundle_sha256 or recovery.get('durable_bundle_sha256') != bundle_sha256
            or recovery.get('execution_id') != observation['execution_id']
            or not recovery.get('fresh_read_connection_id') or recovery.get('duplicate_execution_rows') != 0):
        required.append('lost_ack_durable_reconciliation')
    kinds = set()
    states = {'not_null': '23502', 'check': '23514', 'numeric_overflow': '22003'}
    for item in constraints:
        if (item.get('bundle_sha256') == bundle_sha256 and item.get('sqlstate') == states.get(item.get('kind'))
                and item.get('kind') in states and is_sha(item.get('probe_statement_sha256'))
                and item.get('rows_before') == item.get('rows_after_fresh_read')
                and isinstance(item.get('rows_before'), list) and item.get('fresh_read_connection_id')):
            kinds.add(item.get('kind'))
    if not {'not_null', 'check', 'numeric_overflow'} <= kinds:
        required.append('constraint_failure_observations')
    actual_pin = observation.get('rows_sha256')
    if actual_pin != digest(observation.get('rows', [])):
        required.append('target_rows_pin')
    required.append('v2_independent_target_effect_grading_required')
    state = 'failed' if report['row_parity'] != 'exact' else 'indeterminate'
    return {'schema_version': 1, 'bundle_sha256': bundle_sha256, 'mapping_sha256': mapping_sha256,
            'observation_sha256': digest(observation), 'score': report,
            'row_parity': report['row_parity'], 'target_validation': state,
            'missing_negative_evidence': required, 'product_acceptance': 'pending'}


def observe_and_score(oracle: list[dict], artifacts: dict, target_port, *, authority: dict,
                       edition: str, store) -> dict:
    """Explicit separate target action; no oracle reaches the injected port."""
    if authority.get('authorized') is not True or not is_sha(authority.get('authority_sha256')):
        raise ValueError('separate target authority required')
    if authority.get('bundle_sha256') != artifacts.get('bundle_sha256'):
        raise ValueError('target authority bundle mismatch')
    observation = target_port(artifacts, authority)
    # Validate the allowed envelope before any raw capture can persist a DSN.
    report = score_target(oracle, observation, bundle_sha256=artifacts['bundle_sha256'],
                          mapping_sha256=artifacts['mapping_sha256'], edition=edition)
    raw = store.put('target_observation', observation)
    receipt = {'schema_version': 1, 'observation': raw, 'report': report}
    return {**receipt, 'receipt_capture': store.put('target_score', receipt)}


def score_execution_receipt(oracle: list[dict], execution_receipt: dict, mapping: dict, *,
                            bundle_sha256: str, edition: str) -> dict:
    """Consume D5's actual sealed database_check/reconcile_commit wire artifact.

    Structural/negative flags are not oracle acceptance. This compatibility path
    reports independent parity but leaves full target validation indeterminate
    until concrete negative-effect observations are supplied to score_target.
    """
    receipt = execution_receipt
    if receipt.get('receipt_sha256') != digest({key: value for key, value in receipt.items() if key != 'receipt_sha256'}):
        raise ValueError('execution receipt hash mismatch')
    artifact = receipt.get('observation_artifact')
    if artifact is None:
        return {'schema_version': 1, 'target_validation': 'indeterminate' if
                receipt.get('execution_status') == 'commit_outcome_unknown' else 'not_run',
                'row_parity': 'not_run', 'reason': receipt.get('reason', 'no actual readback'),
                'product_acceptance': 'pending'}
    if artifact.get('observations_sha256') != digest({key: value for key, value in artifact.items()
                                                      if key != 'observations_sha256'}):
        raise ValueError('target observation artifact hash mismatch')
    if (artifact.get('bundle_sha256') != bundle_sha256 or receipt.get('bundle_sha256') != bundle_sha256
            or receipt.get('committed') is not True
            or artifact.get('capture') not in ('fresh_connection_after_commit', 'fresh_connection_reconciliation')
            or receipt.get('execution_status') not in ('committed_readback', 'commit_identity_reconciled')):
        raise ValueError('uncommitted or wrong-bundle target observation')
    for key in ('run_id', 'namespace', 'target'):
        if artifact.get(key) != receipt.get(key) or not artifact.get(key):
            raise ValueError('target observation/receipt lineage mismatch')
    identity = receipt.get('identity', {})
    if (identity.get('mapping_sha256') != mapping.get('mapping_sha256')
            or identity.get('bundle_sha256') != bundle_sha256
            or identity.get('source_sha256') != mapping.get('source_sha256')):
        raise ValueError('target mapping/source identity mismatch')
    rows = artifact.get('rows', [])
    if rows != receipt.get('observations') or any(row.get('mapping_sha256') != mapping.get('mapping_sha256') for row in rows):
        raise ValueError('target row/mapping lineage mismatch')
    report = score_product([row for row in oracle if row['expected_outcome'] == 'converted'],
                           rows, mapping, edition=edition)
    return {'schema_version': 1, 'edition': edition, 'bundle_sha256': bundle_sha256,
            'execution_receipt_sha256': receipt['receipt_sha256'],
            'observation_sha256': artifact['observations_sha256'], 'score': report,
            'row_parity': report['row_parity'],
            'target_validation': 'failed' if report['row_parity'] != 'exact' else 'indeterminate',
            'reason': 'concrete_negative_effect_observations_pending', 'product_acceptance': 'pending'}
