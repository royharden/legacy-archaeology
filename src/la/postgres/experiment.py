"""Bounded immutable target-experiment capture; no evaluator/gold imports or grading."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath
import re
import uuid

from la.review import canonical, digest
from la.convert.bundle import _json as strict_json
from .authority import verified_target_authority
from .candidate import is_sha, observer_code_pin, resolve_candidate, verify_authority
from .effects import (NEGATIVE_KINDS, _write_immutable_capture, collect_negative_effect,
                      seal_observation, validate_negative_effect, validate_target_observation,
                      write_negative_effect, write_target_observation)
from .runner import (collect_controlled_ack_predecessor, collect_controlled_failed_load,
                     reconcile_target_candidate, target_observer_v2)
from .target import TargetConfig

REQUIRED_OPERATIONS = ('load', 'negative_probes', 'controlled_failed_load', 'controlled_commit_ack', 'reconcile')
MAX_OBSERVATION_BYTES = 32 * 1024 * 1024
MAX_EFFECT_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_CAPTURES = 32
MANIFEST_KEYS = {'schema_version', 'kind', 'experiment_id', 'candidate', 'artifact_sha256', 'authority_sha256',
                 'authority_envelope_sha256', 'target_config_sha256', 'observer_code_sha256',
                 'requested_operations', 'capture_status', 'captures', 'operations', 'omissions',
                 'target_validation', 'row_parity', 'product_acceptance', 'experiment_sha256'}
RECORD_KEYS = {'role', 'operation', 'kind', 'file', 'sha256', 'identity_sha256', 'execution_id',
               'attempt_id', 'namespace', 'state', 'derived_from'}


def _root(path):
    given = Path(path).absolute()
    for item in (given, *given.parents):
        if item.is_symlink() or (hasattr(item, 'is_junction') and item.is_junction()):
            raise ValueError('capture root cannot traverse links/junctions')
    root = given.resolve(strict=True)
    if not root.is_dir() or any((parent / 'manifest.json').is_file() for parent in (root, *root.parents)):
        raise ValueError('owned capture directory required outside frozen bundles')
    return root


def _child(root, relative, *, exists=False):
    if not isinstance(relative, str) or '\\' in relative:
        raise ValueError('POSIX relative capture path required')
    parts = PurePosixPath(relative)
    if (parts.is_absolute() or not parts.parts or parts.as_posix() != relative or
            any(part in ('..', '.') or re.fullmatch('[A-Za-z0-9_.-]+', part) is None for part in parts.parts)):
        raise ValueError('capture path escape')
    path = root.joinpath(*parts.parts)
    for item in (path, *path.parents):
        if item == root: break
        if item.is_symlink() or (hasattr(item, 'is_junction') and item.is_junction()):
            raise ValueError('capture member link escape')
    resolved = path.resolve(strict=exists)
    if not resolved.is_relative_to(root): raise ValueError('capture path escapes declared experiment')
    return resolved


def _bounded(path, limit):
    if not path.is_file() or path.stat().st_size > limit:
        raise ValueError('capture file missing or too large')
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit: raise ValueError('capture grew beyond limit')
    return data


def _seal(value):
    result = deepcopy(value)
    result['experiment_sha256'] = digest(result)
    return result


class _CaptureWriter:
    def __init__(self, root, manifest):
        self.root, self.manifest, self.total = root, manifest, 0
        self.values = {}

    def omit(self, role, reason, exc=None):
        value = {'role': role, 'reason': reason}
        if exc is not None: value['error_type'] = type(exc).__name__
        self.manifest['omissions'].append(value)

    def operation(self, name, status, exc=None):
        value = {'operation': name, 'status': status}
        if exc is not None: value['error_type'] = type(exc).__name__
        self.manifest['operations'].append(value)

    def capture(self, role, operation, payload, *, effect=False, derived_from=()):
        if role in self.values or not re.fullmatch('[a-z0-9_]{1,100}', role):
            raise ValueError('unique bounded capture role required')
        if len(self.manifest['captures']) >= MAX_CAPTURES: raise ValueError('capture member limit')
        if effect:
            payload = validate_negative_effect(payload)
            kind, identity_key, limit = 'negative_effect', 'effect_sha256', MAX_EFFECT_BYTES
        else:
            payload = validate_target_observation(payload)
            kind, identity_key, limit = 'target_observation', 'observation_sha256', MAX_OBSERVATION_BYTES
        candidate = self.manifest['candidate']
        actual_candidate = payload['candidate_sha256'] if effect else payload['candidate']['candidate_sha256']
        if (actual_candidate != candidate['candidate_sha256'] or
                (effect and payload['source_sha256'] != candidate['source_sha256']) or
                (not effect and payload['candidate'] != candidate) or
                any(payload[key] != self.manifest[key] for key in ('authority_sha256', 'target_config_sha256', 'observer_code_sha256'))):
            raise ValueError('capture scope differs from verified experiment')
        data = (canonical(payload) + '\n').encode()
        if len(data) > limit or self.total + len(data) > MAX_TOTAL_BYTES:
            raise ValueError('encoded capture byte limit')
        identity = payload[identity_key]
        relative = ('effects/' if effect else 'captures/') + role + '-' + identity + '.json'
        path = _child(self.root, relative)
        receipt = write_negative_effect(path, payload) if effect else write_target_observation(path, payload)
        attempt = payload if effect else payload['attempt']
        record = {'role': role, 'operation': operation, 'kind': kind, 'file': relative,
                  'sha256': receipt['sha256'], 'identity_sha256': identity,
                  'execution_id': attempt['execution_id'], 'attempt_id': attempt['attempt_id'],
                  'namespace': attempt['namespace'],
                  'state': payload['transaction_state'] if effect else payload['commit_state'],
                  'derived_from': list(derived_from)}
        self.total += len(data)
        self.manifest['captures'].append(record)
        self.values[role] = deepcopy(payload)
        return payload

    def observation(self, role, operation, collector):
        try:
            payload = collector()
            captured = self.capture(role, operation, payload)
            self.operation(operation, 'captured')
            # Preserve embedded actual effects separately as soon as this stage returns.
            for index, effect in enumerate(payload['negative_effects']):
                name = 'effect_' + role + '_' + effect['probe_kind'] + '_' + str(index)
                try: self.capture(name, operation, effect, effect=True)
                except Exception as exc: self.omit(name, 'effect_publication_error', exc)
            return captured
        except Exception as exc:
            self.operation(operation, 'error', exc)
            self.omit(role, 'collection_or_publication_error', exc)
            return None


def _manifest(experiment_id):
    return {'schema_version': 1, 'kind': 'target_experiment', 'experiment_id': experiment_id,
            'candidate': None, 'artifact_sha256': None, 'authority_sha256': None, 'authority_envelope_sha256': None,
            'target_config_sha256': None, 'observer_code_sha256': observer_code_pin(),
            'requested_operations': list(REQUIRED_OPERATIONS), 'capture_status': 'not_run',
            'captures': [], 'operations': [], 'omissions': [], 'target_validation': 'not_run',
            'row_parity': 'not_run', 'product_acceptance': 'pending'}


def _publish(root, manifest):
    result = _seal(manifest)
    if len((canonical(result) + '\n').encode()) > MAX_MANIFEST_BYTES:
        raise ValueError('experiment manifest size limit')
    _write_immutable_capture(_child(root, 'experiment.json'), result, 'experiment_sha256')
    return result


def collect_target_experiment(artifacts, authority, *, capture_root, experiment_id=None,
                               dsn=None, target_config=None, authority_verifier=None):
    """Collect once, persist each stage, and publish a neutral pinned capture manifest.

    No environment lookup, signer, retry, evaluator import or target-pass decision.
    Existing experiment IDs refuse before any collection or connection.
    """
    root = _root(capture_root)
    experiment_id = 'tx_' + uuid.uuid4().hex if experiment_id is None else experiment_id
    if not isinstance(experiment_id, str) or re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,63}', experiment_id) is None:
        raise ValueError('bounded experiment child identity required')
    root = _child(root, experiment_id)
    root.mkdir(exist_ok=False)
    manifest = _manifest(experiment_id)
    writer = _CaptureWriter(root, manifest)
    try:
        if type(target_config) is not TargetConfig: raise ValueError('concrete operator target config required')
        body = verified_target_authority(authority, authority_verifier)
        candidate = resolve_candidate(artifacts, target_config)
        for operation in REQUIRED_OPERATIONS:
            verify_authority(body, candidate, target_config, operation)
        manifest.update(candidate=deepcopy(candidate.descriptor), artifact_sha256=digest(artifacts), authority_sha256=body['authority_sha256'],
                        authority_envelope_sha256=digest(authority), target_config_sha256=digest(target_config.public()))
    except Exception as exc:
        writer.operation('preflight', 'refused', exc)
        writer.omit('experiment', 'authority_candidate_or_dependency_refused', exc)
        manifest['capture_status'] = 'refused'
        return _publish(root, manifest)
    if not dsn:
        writer.operation('preflight', 'not_run')
        for operation in REQUIRED_OPERATIONS:
            writer.operation(operation, 'not_run')
        for role in ('normal_readback', 'normal', 'failed_load', 'ack_prior', 'ack_reconciled',
                     *('negative_' + kind for kind in NEGATIVE_KINDS)):
            writer.omit(role, 'dsn_not_supplied')
        return _publish(root, manifest)

    normal = writer.observation('normal_readback', 'load', lambda: target_observer_v2(
        artifacts, authority, dsn=dsn, target_config=target_config, authority_verifier=authority_verifier))
    effects, parents = [], []
    if normal is not None:
        parents.append(normal['observation_sha256'])
    for kind in NEGATIVE_KINDS:
        role = 'negative_' + kind
        if normal is None or normal['commit_state'] != 'committed':
            writer.operation(role, 'not_run'); writer.omit(role, 'no_committed_normal_anchor'); continue
        try:
            effect = collect_negative_effect(candidate, body, target_config, dsn=dsn,
                                              probe_kind=kind, execution_id=normal['attempt']['execution_id'])
            writer.capture(role, 'negative_probes', effect, effect=True)
            writer.operation(role, 'captured')
            effects.append(effect); parents.append(effect['effect_sha256'])
        except Exception as exc:
            writer.operation(role, 'error', exc); writer.omit(role, 'negative_collection_or_publication_error', exc)
    if normal is not None:
        combined = {key: deepcopy(value) for key, value in normal.items() if key != 'observation_sha256'}
        # Same actual committed readback; attach only actual separately captured effects.
        combined['negative_effects'] = effects if normal['commit_state'] == 'committed' else normal['negative_effects']
        try:
            writer.capture('normal', 'normal_with_effects', seal_observation(combined), derived_from=parents)
        except Exception as exc: writer.omit('normal', 'combined_observation_publication_error', exc)

    writer.observation('failed_load', 'controlled_failed_load', lambda: collect_controlled_failed_load(
        artifacts, authority, dsn=dsn, target_config=target_config, authority_verifier=authority_verifier))
    prior = writer.observation('ack_prior', 'controlled_commit_ack', lambda: collect_controlled_ack_predecessor(
        artifacts, authority, dsn=dsn, target_config=target_config, authority_verifier=authority_verifier))
    if prior is not None and prior['commit_state'] == 'indeterminate' and prior['attempt']['write_connection_id'] is not None:
        writer.observation('ack_reconciled', 'reconcile', lambda: reconcile_target_candidate(
            artifacts, authority, prior, dsn=dsn, target_config=target_config, authority_verifier=authority_verifier))
    else:
        writer.operation('reconcile', 'not_run'); writer.omit('ack_reconciled', 'no_actual_indeterminate_predecessor')
    required_roles = {'normal_readback', 'normal', 'failed_load', 'ack_prior', 'ack_reconciled'} | {'negative_' + kind for kind in NEGATIVE_KINDS}
    manifest['capture_status'] = 'collected' if required_roles <= set(writer.values) and not manifest['omissions'] else 'partial'
    return _publish(root, manifest)


@dataclass(frozen=True)
class TargetExperimentSnapshot:
    root: Path
    manifest: dict
    observations: dict


def open_target_experiment(experiment_path, *, expected_experiment_sha256,
                            expected_candidate_sha256=None, expected_authority_sha256=None):
    """Read exact immutable captures; explicit external manifest pin is mandatory."""
    if not is_sha(expected_experiment_sha256): raise ValueError('external experiment pin required')
    root = _root(experiment_path)
    raw = _bounded(_child(root, 'experiment.json', exists=True), MAX_MANIFEST_BYTES)
    manifest = strict_json(raw, 'experiment.json')
    if not isinstance(manifest, dict) or set(manifest) != MANIFEST_KEYS or type(manifest['schema_version']) is not int or manifest['schema_version'] != 1 or manifest['kind'] != 'target_experiment':
        raise ValueError('closed experiment manifest required')
    if manifest['experiment_sha256'] != expected_experiment_sha256 or digest({k: v for k, v in manifest.items() if k != 'experiment_sha256'}) != expected_experiment_sha256:
        raise ValueError('experiment external/content pin mismatch')
    if manifest['target_validation'] != 'not_run' or manifest['row_parity'] != 'not_run' or manifest['product_acceptance'] != 'pending':
        raise ValueError('experiment cannot grant target/parity/product acceptance')
    if manifest['capture_status'] not in ('not_run', 'refused', 'partial', 'collected') or manifest['requested_operations'] != list(REQUIRED_OPERATIONS):
        raise ValueError('unknown capture status/operation scope')
    candidate = manifest['candidate']
    if not isinstance(manifest['experiment_id'], str) or re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,63}', manifest['experiment_id']) is None:
        raise ValueError('invalid experiment identity')
    if candidate is not None:
        from .candidate import validate_descriptor
        validate_descriptor(candidate)
        if any(not is_sha(manifest[key]) for key in ('artifact_sha256', 'authority_sha256', 'authority_envelope_sha256', 'target_config_sha256', 'observer_code_sha256')):
            raise ValueError('missing verified experiment scope')
    elif manifest['capture_status'] != 'refused' or manifest['captures'] or any(manifest[key] is not None for key in ('artifact_sha256', 'authority_sha256', 'authority_envelope_sha256', 'target_config_sha256')):
        raise ValueError('unverified experiment cannot contain captures or authority')
    if expected_candidate_sha256 is not None and (not is_sha(expected_candidate_sha256) or candidate is None or candidate['candidate_sha256'] != expected_candidate_sha256):
        raise ValueError('wrong external candidate pin')
    if expected_authority_sha256 is not None and (not is_sha(expected_authority_sha256) or manifest['authority_sha256'] != expected_authority_sha256):
        raise ValueError('wrong external authority pin')
    records = manifest['captures']
    if not isinstance(records, list) or len(records) > MAX_CAPTURES or not isinstance(manifest['operations'], list) or len(manifest['operations']) > 16 or not isinstance(manifest['omissions'], list) or len(manifest['omissions']) > 64:
        raise ValueError('experiment record count limit')
    for entry in manifest['operations']:
        if (not isinstance(entry, dict) or set(entry) not in ({'operation', 'status'}, {'operation', 'status', 'error_type'}) or
                not isinstance(entry['operation'], str) or len(entry['operation']) > 100 or
                entry['status'] not in ('captured', 'error', 'refused', 'not_run')):
            raise ValueError('closed operation record required')
    for entry in manifest['omissions']:
        if (not isinstance(entry, dict) or set(entry) not in ({'role', 'reason'}, {'role', 'reason', 'error_type'}) or
                any(not isinstance(entry[key], str) or len(entry[key]) > 100 for key in entry)):
            raise ValueError('closed omission record required')
    values, identities, paths, total = {}, set(), set(), 0
    role_operations = {'normal_readback': 'load', 'normal': 'normal_with_effects',
                       'failed_load': 'controlled_failed_load', 'ack_prior': 'controlled_commit_ack',
                       'ack_reconciled': 'reconcile'}
    for record in records:
        if not isinstance(record, dict) or set(record) != RECORD_KEYS or not isinstance(record['role'], str) or re.fullmatch('[a-z0-9_]{1,100}', record['role']) is None or record['role'] in values or not isinstance(record['file'], str) or record['file'] in paths or record['kind'] not in ('target_observation', 'negative_effect'):
            raise ValueError('duplicate/unknown experiment capture')
        effect = record['kind'] == 'negative_effect'
        data = _bounded(_child(root, record['file'], exists=True), MAX_EFFECT_BYTES if effect else MAX_OBSERVATION_BYTES)
        total += len(data)
        if total > MAX_TOTAL_BYTES or hashlib.sha256(data).hexdigest() != record['sha256']:
            raise ValueError('experiment member byte/hash mismatch')
        payload = strict_json(data, record['file'])
        payload = validate_negative_effect(payload) if effect else validate_target_observation(payload)
        role = record['role']
        if not effect and (role not in role_operations or record['operation'] != role_operations[role]):
            raise ValueError('unknown observation role/operation')
        if effect and role.startswith('negative_') and (role != 'negative_' + payload['probe_kind'] or payload['probe_kind'] not in NEGATIVE_KINDS or record['operation'] != 'negative_probes'):
            raise ValueError('wrong standalone negative role/operation')
        if effect and not role.startswith('negative_'):
            parents = [value for parent_role, value in values.items() if parent_role in role_operations and record['operation'] == role_operations[parent_role] and payload in value.get('negative_effects', [])]
            if not parents: raise ValueError('standalone embedded effect has no earlier observation')
        key = 'effect_sha256' if effect else 'observation_sha256'
        if payload[key] != record['identity_sha256'] or any(payload[name] != manifest[name] for name in ('authority_sha256', 'target_config_sha256', 'observer_code_sha256')):
            raise ValueError('capture identity/authority/config/observer mismatch')
        if candidate is None or (payload['candidate_sha256'] if effect else payload['candidate']['candidate_sha256']) != candidate['candidate_sha256']:
            raise ValueError('capture candidate mismatch')
        if (effect and payload['source_sha256'] != candidate['source_sha256']) or (not effect and payload['candidate'] != candidate):
            raise ValueError('capture source/descriptor mismatch')
        attempt = payload if effect else payload['attempt']
        if any(record[name] != attempt[name] for name in ('execution_id', 'attempt_id', 'namespace')) or record['state'] != (payload['transaction_state'] if effect else payload['commit_state']):
            raise ValueError('capture attempt/state mismatch')
        if not isinstance(record['derived_from'], list) or any(parent not in identities for parent in record['derived_from']):
            raise ValueError('derived capture has missing/unpinned parents')
        values[record['role']] = payload; paths.add(record['file']); identities.add(payload[key])
    # The combined observation cannot change the actual raw readback or invent effects.
    if 'normal' in values and 'normal_readback' in values:
        normal, raw_normal = values['normal'], values['normal_readback']
        fields = set(normal) - {'observation_sha256', 'negative_effects'}
        if any(normal[key] != raw_normal[key] for key in fields): raise ValueError('combined normal changed raw observation')
        if raw_normal['commit_state'] == 'committed':
            expected = [values['negative_' + kind] for kind in NEGATIVE_KINDS if 'negative_' + kind in values]
            if normal['negative_effects'] != expected: raise ValueError('combined normal invented/dropped effects')
        normal_record = next(record for record in records if record['role'] == 'normal')
        parents = [raw_normal['observation_sha256']] + [values['negative_' + kind]['effect_sha256'] for kind in NEGATIVE_KINDS if 'negative_' + kind in values]
        if normal_record['derived_from'] != parents: raise ValueError('combined normal must identify every exact input')
    required_roles = {'normal_readback', 'normal', 'failed_load', 'ack_prior', 'ack_reconciled'} | {'negative_' + kind for kind in NEGATIVE_KINDS}
    if manifest['capture_status'] == 'collected' and (not required_roles <= set(values) or manifest['omissions']):
        raise ValueError('collected status cannot hide missing captures')
    return TargetExperimentSnapshot(root, deepcopy(manifest), deepcopy(values))


@dataclass(frozen=True)
class TargetExperimentCallbacks:
    snapshot: TargetExperimentSnapshot

    def _scope(self, artifact, authority):
        manifest = self.snapshot.manifest
        if not isinstance(artifact, dict) or artifact.get('kind') != 'disposable_evaluation_candidate' or artifact.get('descriptor') != manifest['candidate'] or digest(artifact) != manifest['artifact_sha256']:
            raise ValueError('callback artifact differs from pinned evaluation candidate')
        if not isinstance(authority, dict) or digest(authority) != manifest['authority_envelope_sha256']:
            raise ValueError('callback signed authority differs from captured grant')

    def observe(self, artifact, authority):
        self._scope(artifact, authority)
        return deepcopy(self.snapshot.observations.get('normal') or self.snapshot.observations.get('normal_readback'))

    def failed_load(self, artifact, authority):
        self._scope(artifact, authority)
        return deepcopy(self.snapshot.observations.get('failed_load'))

    def recovery(self, artifact, authority):
        self._scope(artifact, authority)
        prior, reconciled = self.snapshot.observations.get('ack_prior'), self.snapshot.observations.get('ack_reconciled')
        if prior is None and reconciled is None: return None
        return {'prior': deepcopy(prior), 'reconciled': deepcopy(reconciled)}


def target_experiment_callbacks(experiment_path, *, expected_experiment_sha256,
                                expected_candidate_sha256=None, expected_authority_sha256=None):
    return TargetExperimentCallbacks(open_target_experiment(experiment_path,
        expected_experiment_sha256=expected_experiment_sha256,
        expected_candidate_sha256=expected_candidate_sha256, expected_authority_sha256=expected_authority_sha256))


def reconcile_target_experiment(experiment_path, artifacts, authority, *, expected_experiment_sha256,
                                 dsn=None, target_config=None, authority_verifier=None,
                                 previous_reconciliation_sha256=None):
    """Append one immutable read-only reconciliation record; never call any load collector."""
    snapshot = open_target_experiment(experiment_path, expected_experiment_sha256=expected_experiment_sha256)
    if type(target_config) is not TargetConfig: raise ValueError('concrete target config required')
    body = verified_target_authority(authority, authority_verifier)
    candidate = resolve_candidate(artifacts, target_config)
    verify_authority(body, candidate, target_config, 'reconcile')
    manifest = snapshot.manifest
    if candidate.descriptor != manifest['candidate'] or digest(artifacts) != manifest['artifact_sha256'] or body['authority_sha256'] != manifest['authority_sha256'] or digest(authority) != manifest['authority_envelope_sha256'] or digest(target_config.public()) != manifest['target_config_sha256']:
        raise ValueError('reconciliation scope differs from captured experiment')
    prior = snapshot.observations.get('ack_prior')
    if previous_reconciliation_sha256 is not None:
        from .recovery import MAX_RECOVERY_RECORDS, open_target_reconciliation
        previous = open_target_reconciliation(experiment_path, artifacts, authority,
            expected_experiment_sha256=expected_experiment_sha256,
            expected_reconciliation_sha256=previous_reconciliation_sha256,
            expected_prior_observation_sha256=prior['observation_sha256'] if prior else None,
            target_config=target_config, authority_verifier=authority_verifier)
        if len(previous.records) >= MAX_RECOVERY_RECORDS: raise ValueError('recovery chain record limit')
    record = {'schema_version': 2, 'kind': 'target_experiment_reconciliation',
              'previous_reconciliation_sha256': previous_reconciliation_sha256,
              'parent_experiment_sha256': expected_experiment_sha256,
              'candidate_sha256': candidate.descriptor['candidate_sha256'],
              'authority_sha256': body['authority_sha256'], 'target_config_sha256': digest(target_config.public()),
              'observer_code_sha256': observer_code_pin(), 'prior_observation_sha256': prior['observation_sha256'] if prior else None,
              'capture': None, 'capture_status': 'not_run', 'issues': [], 'target_validation': 'not_run',
              'row_parity': 'not_run', 'product_acceptance': 'pending'}
    if prior is None or prior['commit_state'] != 'indeterminate' or prior['attempt']['write_connection_id'] is None:
        record['issues'].append({'code': 'no_actual_indeterminate_predecessor'})
    elif not dsn:
        record['issues'].append({'code': 'dsn_not_supplied'})
    else:
        try:
            observation = reconcile_target_candidate(artifacts, authority, prior, dsn=dsn,
                                                      target_config=target_config, authority_verifier=authority_verifier)
            identity = observation['observation_sha256']
            relative = 'reconciliations/observation-' + identity + '.json'
            data = (canonical(observation) + '\n').encode()
            if len(data) > MAX_OBSERVATION_BYTES: raise ValueError('reconciliation observation size limit')
            receipt = write_target_observation(_child(snapshot.root, relative), observation)
            record.update(capture={'file': relative, 'sha256': receipt['sha256'],
                                   'observation_sha256': identity, 'execution_id': observation['attempt']['execution_id'],
                                   'attempt_id': observation['attempt']['attempt_id'], 'namespace': observation['attempt']['namespace']},
                          capture_status='captured')
        except Exception as exc:
            record['capture_status'] = 'indeterminate'
            record['issues'].append({'code': 'reconciliation_or_publication_error', 'error_type': type(exc).__name__})
    record['reconciliation_sha256'] = digest(record)
    relative = 'reconciliations/record-' + record['reconciliation_sha256'] + '.json'
    path = _child(snapshot.root, relative)
    if path.exists():
        existing = strict_json(_bounded(path, MAX_MANIFEST_BYTES), relative)
        if existing != record: raise ValueError('immutable reconciliation identity collision')
    else:
        _write_immutable_capture(path, record, 'reconciliation_sha256')
    return record
