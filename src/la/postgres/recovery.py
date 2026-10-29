"""Explicit pinned archival recovery selection; no connection, load or grading."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib

from la.review import digest
from .authority import verified_target_authority
from .candidate import PHASE_KEYS, is_sha
from .effects import _issues, validate_target_observation
from .experiment import (MAX_MANIFEST_BYTES, MAX_OBSERVATION_BYTES, MAX_TOTAL_BYTES,
                         TargetExperimentCallbacks, _bounded, _child, open_target_experiment)
from .target import TargetConfig
from la.convert.bundle import _json as strict_json

MAX_RECOVERY_RECORDS = 16
RECORD_KEYS = {'schema_version', 'kind', 'parent_experiment_sha256', 'candidate_sha256',
               'authority_sha256', 'target_config_sha256', 'observer_code_sha256',
               'prior_observation_sha256', 'capture', 'capture_status', 'issues',
               'target_validation', 'row_parity', 'product_acceptance', 'reconciliation_sha256'}
CAPTURE_KEYS = {'file', 'sha256', 'observation_sha256', 'execution_id', 'attempt_id', 'namespace'}


def _archive_scope(snapshot, artifacts, authority, config, verifier):
    """Verify captured authority, never authorize new execution under old code."""
    manifest = snapshot.manifest
    if type(config) is not TargetConfig: raise ValueError('concrete pinned target config required')
    config.validate()
    body = verified_target_authority(authority, verifier)
    candidate = manifest['candidate']
    if candidate is None: raise ValueError('verified original candidate required')
    keys = {'schema_version', 'kind', 'authority_id', 'scope', 'candidate_sha256', 'source_sha256',
            'method', 'edition', 'freeze_sha256', 'observer_code_sha256', 'operations', 'authority_sha256'}
    if candidate['schema_version'] == 2: keys |= PHASE_KEYS
    if (not isinstance(body, dict) or set(body) != keys or type(body['schema_version']) is not int or
            body['schema_version'] != candidate['schema_version'] or body['kind'] != 'disposable_target_authority' or
            not isinstance(body['authority_id'], str) or not body['authority_id'].strip() or len(body['authority_id']) > 200):
        raise ValueError('closed captured authority scope required')
    if (digest(artifacts) != manifest['artifact_sha256'] or digest(authority) != manifest['authority_envelope_sha256'] or
            digest(config.public()) != manifest['target_config_sha256'] or
            body['authority_sha256'] != digest({k: v for k, v in body.items() if k != 'authority_sha256'}) or
            body['authority_sha256'] != manifest['authority_sha256'] or config.authority_reference != manifest['authority_sha256'] or
            body['observer_code_sha256'] != manifest['observer_code_sha256']):
        raise ValueError('original artifact/signed authority/config/code pin mismatch')
    scope = 'product_bundle' if candidate['kind'] == 'product_bundle' else 'disposable_evaluation'
    fields = {'candidate_sha256', 'source_sha256', 'method', 'edition', 'freeze_sha256'}
    if candidate['schema_version'] == 2: fields |= PHASE_KEYS
    if body['scope'] != scope or any(body[key] != candidate[key] for key in fields):
        raise ValueError('captured candidate/source/phase authority mismatch')
    operations = body['operations']
    allowed = {'load', 'negative_probes', 'reconcile', 'controlled_failed_load', 'controlled_commit_ack'}
    if (not isinstance(operations, list) or any(not isinstance(op, str) or op not in allowed for op in operations) or
            len(set(operations)) != len(operations) or 'reconcile' not in operations):
        raise ValueError('captured authority does not grant reconciliation')


def _source_label(prior):
    if prior is None: return 'no_original_predecessor'
    codes = {issue['code'] for issue in prior['issues']}
    unknown, known = 'commit_acknowledgement_unknown' in codes, 'committed_readback_unavailable' in codes
    fault = prior.get('controlled_fault')
    if fault is not None:
        if unknown or known or fault['operation'] != 'controlled_commit_ack':
            raise ValueError('controlled boundary cannot be relabelled as driver ACK/readback failure')
        return ('controlled_application_ack_suppression' if fault['state'] == 'injected'
                else 'controlled_application_ack_boundary_unreached')
    if unknown and known: raise ValueError('conflicting driver ACK source labels')
    if unknown: return 'unknown_driver_commit_acknowledgement'
    if known: return 'known_commit_readback_failure'
    return 'unclassified_original_attempt'


def _capture(snapshot, record, prior):
    ref = record['capture']
    if ref is None:
        if record['capture_status'] == 'captured': raise ValueError('captured record omitted observation')
        return None, 0
    if record['capture_status'] != 'captured' or not isinstance(ref, dict) or set(ref) != CAPTURE_KEYS:
        raise ValueError('closed explicitly captured recovery reference required')
    if any(not is_sha(ref[key]) for key in ('sha256', 'observation_sha256')):
        raise ValueError('invalid recovery member pins')
    relative = 'reconciliations/observation-' + ref['observation_sha256'] + '.json'
    if ref['file'] != relative: raise ValueError('recovery member path is not canonical identity path')
    raw = _bounded(_child(snapshot.root, relative, exists=True), MAX_OBSERVATION_BYTES)
    if hashlib.sha256(raw).hexdigest() != ref['sha256']: raise ValueError('recovery member byte pin mismatch')
    observation = validate_target_observation(strict_json(raw, relative))
    manifest = snapshot.manifest
    if (observation['observation_sha256'] != ref['observation_sha256'] or
            observation['candidate'] != manifest['candidate'] or
            any(observation[key] != manifest[key] for key in ('authority_sha256', 'target_config_sha256', 'observer_code_sha256'))):
        raise ValueError('recovery observation candidate/source/phase/scope mismatch')
    if prior is None or prior['commit_state'] != 'indeterminate' or prior['attempt']['write_connection_id'] is None:
        raise ValueError('later observation requires actual original indeterminate write')
    attempt, original = observation['attempt'], prior['attempt']
    if (any(ref[key] != attempt[key] for key in ('execution_id', 'attempt_id', 'namespace')) or
            any(attempt[key] != original[key] for key in ('execution_id', 'namespace', 'write_connection_id')) or
            attempt['attempt_id'] == original['attempt_id'] or attempt['prior_observation_sha256'] != prior['observation_sha256']):
        raise ValueError('later attempt is not linked to exact original write')
    if (observation['schema_version'] != prior['schema_version'] or
            observation.get('controlled_fault') != prior.get('controlled_fault') or
            observation['commit_state'] not in ('committed', 'indeterminate') or
            (observation['target'] is not None and observation['target'] != prior['target']) or
            (observation['readback'] is not None and observation['readback']['capture'] != 'fresh_connection_reconciliation')):
        raise ValueError('later recovery changed original boundary or readback source')
    if observation['negative_effects']:
        raise ValueError('read-only reconciliation cannot introduce new probes')
    codes = {issue['code'] for issue in observation['issues']}
    allowed_recovery = {'controlled_application_ack_suppression': 'reconciled_controlled_application_ack',
                        'unknown_driver_commit_acknowledgement': 'reconciled_lost_commit_acknowledgement',
                        'known_commit_readback_failure': 'reconciled_known_commit_readback'}
    label = _source_label(prior)
    recovered_codes = codes & set(allowed_recovery.values())
    if recovered_codes and (label not in allowed_recovery or recovered_codes != {allowed_recovery[label]}):
        raise ValueError('recovery conflates controlled/driver ACK/known readback source')
    if observation['commit_state'] == 'committed' and (observation['recovery'] is None or label not in allowed_recovery or allowed_recovery[label] not in codes):
        raise ValueError('committed later recovery requires matching actual marker/source lineage')
    return deepcopy(observation), len(raw)


@dataclass(frozen=True)
class TargetReconciliationSnapshot:
    experiment: object
    records: tuple
    observations: dict
    source_label: str

    @property
    def selected(self): return deepcopy(self.records[-1])

    @property
    def observation(self):
        return deepcopy(self.observations.get(self.records[-1]['reconciliation_sha256']))


def open_target_reconciliation(experiment_path, artifacts, authority, *, expected_experiment_sha256,
                               expected_reconciliation_sha256, expected_prior_observation_sha256,
                               target_config, authority_verifier):
    """Read only an explicit selection and its bounded oldest-to-newest pinned chain."""
    if not is_sha(expected_reconciliation_sha256): raise ValueError('explicit later reconciliation pin required')
    snapshot = open_target_experiment(experiment_path, expected_experiment_sha256=expected_experiment_sha256)
    _archive_scope(snapshot, artifacts, authority, target_config, authority_verifier)
    prior = snapshot.observations.get('ack_prior')
    prior_pin = prior['observation_sha256'] if prior is not None else None
    if expected_prior_observation_sha256 != prior_pin or (prior_pin is not None and not is_sha(expected_prior_observation_sha256)):
        raise ValueError('explicit original prior pin mismatch')
    source = _source_label(prior)
    records, observations, seen, members, attempts, total = [], {}, set(), set(), set(), 0
    selected = expected_reconciliation_sha256
    while selected is not None:
        if not is_sha(selected) or selected in seen or len(records) >= MAX_RECOVERY_RECORDS:
            raise ValueError('recovery chain invalid/duplicate/cyclic/too long')
        seen.add(selected)
        relative = 'reconciliations/record-' + selected + '.json'
        raw = _bounded(_child(snapshot.root, relative, exists=True), MAX_MANIFEST_BYTES)
        total += len(raw)
        record = strict_json(raw, relative)
        version = record.get('schema_version') if isinstance(record, dict) else None
        keys = RECORD_KEYS | {'previous_reconciliation_sha256'} if version == 2 else RECORD_KEYS
        if (not isinstance(record, dict) or set(record) != keys or type(version) is not int or version not in (1, 2) or
                record['kind'] != 'target_experiment_reconciliation' or record['reconciliation_sha256'] != selected or
                digest({k: v for k, v in record.items() if k != 'reconciliation_sha256'}) != selected):
            raise ValueError('closed pinned reconciliation record required')
        manifest = snapshot.manifest
        if (record['parent_experiment_sha256'] != expected_experiment_sha256 or
                record['prior_observation_sha256'] != prior_pin or record['candidate_sha256'] != manifest['candidate']['candidate_sha256'] or
                any(record[key] != manifest[key] for key in ('authority_sha256', 'target_config_sha256', 'observer_code_sha256'))):
            raise ValueError('later record parent/prior/candidate/authority/config/code mismatch')
        if (record['capture_status'] not in ('not_run', 'indeterminate', 'captured') or
                record['target_validation'] != 'not_run' or record['row_parity'] != 'not_run' or record['product_acceptance'] != 'pending'):
            raise ValueError('recovery record cannot grant target/parity/product acceptance')
        _issues(record['issues'])
        observation, size = _capture(snapshot, record, prior)
        total += size
        if total > MAX_TOTAL_BYTES: raise ValueError('later recovery chain byte limit')
        if observation is not None:
            identity, attempt = observation['observation_sha256'], observation['attempt']['attempt_id']
            if identity in members or attempt in attempts: raise ValueError('duplicate recovery observation/attempt in chain')
            members.add(identity); attempts.add(attempt)
        observations[selected] = observation
        records.append(deepcopy(record))
        selected = record.get('previous_reconciliation_sha256')
    return TargetReconciliationSnapshot(snapshot, tuple(reversed(records)), observations, source)


@dataclass(frozen=True)
class TargetReconciliationCallbacks:
    snapshot: TargetReconciliationSnapshot

    def _original(self, artifact, authority):
        original = TargetExperimentCallbacks(self.snapshot.experiment)
        original._scope(artifact, authority)
        return original

    def observe(self, artifact, authority): return self._original(artifact, authority).observe(artifact, authority)

    def failed_load(self, artifact, authority): return self._original(artifact, authority).failed_load(artifact, authority)

    def recovery(self, artifact, authority):
        self._original(artifact, authority)
        prior = self.snapshot.experiment.observations.get('ack_prior')
        if prior is None and self.snapshot.observation is None: return None
        return {'prior': deepcopy(prior), 'reconciled': self.snapshot.observation}

    def projection(self):
        manifest = self.snapshot.experiment.manifest
        return {'schema_version': 1, 'kind': 'explicit_recovery_selection',
                'experiment_sha256': manifest['experiment_sha256'],
                'reconciliation_sha256': self.snapshot.selected['reconciliation_sha256'],
                'prior_observation_sha256': self.snapshot.selected['prior_observation_sha256'],
                'source_label': self.snapshot.source_label, 'normal_source': 'original_experiment',
                'failed_load_source': 'original_experiment', 'recovery_source': 'explicit_later_record',
                'history': [{'reconciliation_sha256': r['reconciliation_sha256'],
                             'previous_reconciliation_sha256': r.get('previous_reconciliation_sha256'),
                             'capture_status': r['capture_status'], 'issues': deepcopy(r['issues']),
                             'observation_sha256': r['capture']['observation_sha256'] if r['capture'] else None,
                             'commit_state': (self.snapshot.observations[r['reconciliation_sha256']]['commit_state']
                                              if self.snapshot.observations[r['reconciliation_sha256']] else None),
                             'observation_issues': (deepcopy(self.snapshot.observations[r['reconciliation_sha256']]['issues'])
                                                    if self.snapshot.observations[r['reconciliation_sha256']] else []),
                             'attempt_id': r['capture']['attempt_id'] if r['capture'] else None,
                             'namespace': r['capture']['namespace'] if r['capture'] else None}
                            for r in self.snapshot.records],
                'target_validation': 'not_run', 'row_parity': 'not_run', 'product_acceptance': 'pending'}


def target_reconciliation_callbacks(experiment_path, artifacts, authority, *, expected_experiment_sha256,
                                    expected_reconciliation_sha256, expected_prior_observation_sha256,
                                    target_config, authority_verifier):
    return TargetReconciliationCallbacks(open_target_reconciliation(experiment_path, artifacts, authority,
        expected_experiment_sha256=expected_experiment_sha256,
        expected_reconciliation_sha256=expected_reconciliation_sha256,
        expected_prior_observation_sha256=expected_prior_observation_sha256,
        target_config=target_config, authority_verifier=authority_verifier))
