"""Common explicitly configured target ports for B0/B1/C0/R0/R1 SOURCE.

No oracle is passed to any producer. This module never imports product SQL or
normalization code. Adapters wrap D5's actual prepare_evaluation_candidate and
target_observer_v2/reconcile_target_candidate APIs in evaluator-only commands.
"""
from __future__ import annotations

from dataclasses import dataclass
from copy import deepcopy
from typing import Callable

from .artifacts import digest, is_sha
from .eligibility import ReceiptVerifier, closed
from .target_effects import PHASE_KEYS, TargetExpectation, grade_target, validate_target_observation


@dataclass(frozen=True)
class TargetGrant:
    authority: dict
    expectation: TargetExpectation
    verifier: ReceiptVerifier | None = None

    def validate(self):
        self.expectation.validate()
        if type(self.verifier) is not ReceiptVerifier:
            raise ValueError('concrete Ed25519 target_authority verifier required')
        payload = self.verifier.verify(self.authority, 'target_authority')
        keys = {'schema_version', 'kind', 'authority_id', 'scope', 'candidate_sha256',
            'source_sha256', 'method', 'edition', 'freeze_sha256', 'observer_code_sha256',
            'operations', 'authority_sha256'}
        version = payload.get('schema_version') if isinstance(payload, dict) else None
        if version == 2: keys |= PHASE_KEYS
        # Body v2 is the additive phase schema; the signed envelope stays v1.
        if not isinstance(payload, dict) or set(payload) != keys or type(version) is not int or version not in (1, 2):
            raise ValueError('closed versioned target authority required')
        document = payload
        if document['schema_version'] != self.expectation.candidate['schema_version']:
            raise ValueError('authority and candidate phase versions differ')
        if (document['kind'] != 'disposable_target_authority' or document['scope'] != 'disposable_evaluation'
                or document['authority_sha256'] != self.expectation.authority_sha256
                or document['authority_sha256'] != digest({k: v for k, v in document.items() if k != 'authority_sha256'})):
            raise ValueError('target intent differs from separately configured authority pin')
        for key in ('candidate_sha256', 'source_sha256', 'method', 'edition', 'freeze_sha256'):
            if document[key] != self.expectation.candidate[key]:
                raise ValueError('wrong target method/edition/candidate intent')
        if version == 2 and any(document[key] != self.expectation.candidate[key] for key in PHASE_KEYS):
            raise ValueError('wrong T1 plan or T3 freeze authority')
        if document['observer_code_sha256'] != self.expectation.observer_code_sha256:
            raise ValueError('stale observer authority')
        operations = document['operations']
        required = {'load', 'negative_probes', 'reconcile'}
        allowed = required | {'controlled_failed_load', 'controlled_commit_ack'}
        if not isinstance(operations, list) or len(set(operations)) != len(operations) or not required <= set(operations) or not set(operations) <= allowed:
            raise ValueError('all target actions need explicit separately pinned intent')
        return self


@dataclass(frozen=True)
class TargetPorts:
    # prepare(visible, submitted_mapping, method, edition, frozen_candidate_pin)
    prepare: Callable[[dict, dict, str, str, str], dict]
    grant: Callable[[dict, dict], TargetGrant]
    observe: Callable[[dict, dict], dict]
    failed_load: Callable[[dict, dict], dict | None] | None = None
    recovery: Callable[[dict, dict], dict | None] | None = None  # {prior,reconciled}, actual receipts only
    prepare_v2: Callable[[dict, dict, str, str, dict], dict] | None = None


def run_target_arm(case, submitted_mapping: dict, method: str, store, ports: TargetPorts, *,
                    freeze_sha256: str | None, mode: str, preflight=None, phase_scope=None) -> dict:
    """Separate opt-in action; default runner has no target port/connection."""
    if phase_scope is not None:
        closed(phase_scope, {'evaluation_phase', 'split', 'evaluation_plan_sha256', 'freeze_sha256'}, 'target phase')
        if phase_scope['evaluation_phase'] == 'T1':
            if phase_scope['split'] not in ('development', 'validation') or phase_scope['freeze_sha256'] is not None or not is_sha(phase_scope['evaluation_plan_sha256']):
                raise ValueError('T1 target requires named public plan and no T2 freeze')
        elif phase_scope['evaluation_phase'] == 'T3':
            if phase_scope['split'] not in ('development', 'validation', 'heldout') or not is_sha(phase_scope['freeze_sha256']) or phase_scope['evaluation_plan_sha256'] is not None:
                raise ValueError('T3 target requires final freeze, not public plan')
        else: raise ValueError('unknown target phase')
        if phase_scope['split'] != case.split or phase_scope['freeze_sha256'] != freeze_sha256:
            raise ValueError('target phase differs from actual case split/freeze')
        if ports.prepare_v2 is None:
            return {'target_validation': 'not_run', 'reason': 'phase-aware target preparation not configured', 'batches': []}
    elif not is_sha(freeze_sha256):
        return {'target_validation': 'not_run', 'reason': 'no pinned target candidate scope', 'batches': []}
    results = []
    for batch in case.batches:
        raw, extra, stage_errors = None, [], []
        stages = {'observe': 'not_run', 'failed_load': 'not_run', 'recovery': 'not_run'}
        try:
            if preflight is not None:
                preflight()
            artifact = (ports.prepare_v2(deepcopy(batch.visible), deepcopy(submitted_mapping), method, case.edition, deepcopy(phase_scope))
                        if phase_scope is not None else ports.prepare(deepcopy(batch.visible), deepcopy(submitted_mapping), method, case.edition, freeze_sha256))
            scope = {'edition': case.edition, 'method': method,
                'freeze_sha256': freeze_sha256, 'mode': mode, 'batch_id': batch.batch_id}
            if phase_scope is not None: scope.update(phase_scope)
            grant = ports.grant(deepcopy(artifact), scope)
            if type(grant) is not TargetGrant:
                raise ValueError('concrete externally configured TargetGrant required')
            grant.validate()
            descriptor = artifact['descriptor']
            if (descriptor != grant.expectation.candidate or descriptor['kind'] != 'disposable_evaluation_candidate'
                    or descriptor['product_loadable'] is not False or descriptor['product_approval'] != 'absent'
                    or descriptor['method'] != method or descriptor['edition'] != case.edition
                    or descriptor['freeze_sha256'] != freeze_sha256):
                raise ValueError('evaluation target cannot fabricate product authority or change method')
            if phase_scope is not None and any(descriptor.get(key) != value for key, value in phase_scope.items()):
                raise ValueError('actual target candidate changed T1/T3 scope')

            def invoke(name, callback, required):
                # Even offline capture readers cannot imply an ungranted experiment.
                if callback is None:
                    stages[name] = 'not_configured'
                    return None
                if not set(required) <= set(grant.authority['payload']['operations']):
                    stages[name] = 'not_authorized'
                    return None
                if preflight is not None: preflight()
                try:
                    result = callback(deepcopy(artifact), deepcopy(grant.authority))
                except Exception as exc:
                    stages[name] = 'unavailable'
                    stage_errors.append({'stage': name, 'error_type': type(exc).__name__})
                    return None
                stages[name] = 'missing' if result is None else 'returned'
                return result

            observation = invoke('observe', ports.observe, ('load', 'negative_probes'))
            if observation is not None:
                # Validate exact closed wire before persistence; no version coercion.
                observation = validate_target_observation(observation, expectation=grant.expectation)
                raw = store.put('target_observation_v' + str(observation['schema_version']), observation)
                stages['observe'] = 'captured'
            failed = invoke('failed_load', ports.failed_load, ('load', 'controlled_failed_load')) if observation is not None else None
            if failed is not None:
                failed = validate_target_observation(failed, expectation=grant.expectation)
                extra.append(store.put('failed_load_observation', failed))
                stages['failed_load'] = 'captured'
            recovery = invoke('recovery', ports.recovery, ('load', 'controlled_commit_ack', 'reconcile')) if observation is not None else None
            prior = reconciled = None
            if recovery is not None:
                closed(recovery, {'prior', 'reconciled'}, 'actual recovery pair')
                prior, reconciled = recovery['prior'], recovery['reconciled']
                if prior is not None:
                    prior = validate_target_observation(prior, expectation=grant.expectation)
                    extra.append(store.put('unknown_commit_observation', prior))
                if reconciled is not None:
                    reconciled = validate_target_observation(reconciled, expectation=grant.expectation)
                    extra.append(store.put('recovery_observation', reconciled))
                stages['recovery'] = 'captured' if prior is not None and reconciled is not None else 'partial'
            grade = grade_target(batch.oracle, observation, expectation=grant.expectation,
                prior=prior, failed_load=failed, recovery_observation=reconciled, edition=case.edition)
            if stage_errors and grade['target_validation'] == 'not_run':
                grade['target_validation'] = 'indeterminate'
            receipt = {'schema_version': 2, 'edition': case.edition, 'method': method, 'mode': mode,
                'batch_id': batch.batch_id, 'candidate_sha256': descriptor['candidate_sha256'],
                'authority_sha256': grant.expectation.authority_sha256, 'observation': raw,
                'candidate_schema_version': descriptor['schema_version'],
                'observation_schema_version': None if observation is None else observation['schema_version'],
                'phase_scope': deepcopy(phase_scope), 'stages': stages, 'stage_errors': stage_errors,
                'effect_captures': extra, 'grade': grade, 'product_acceptance': 'pending'}
            results.append({**receipt, 'receipt_capture': store.put('target_arm_receipt', receipt)})
        except Exception as exc:
            # Keep every batch in denominators without logging adapter secrets.
            from .scorer import score
            valid = [row for row in batch.oracle if row['expected_outcome'] == 'converted']
            failure = {'schema_version': 2, 'batch_id': batch.batch_id, 'method': method,
                       'mode': mode, 'phase_scope': deepcopy(phase_scope), 'observation': raw,
                       'effect_captures': extra, 'stages': stages, 'stage_errors': stage_errors,
                       'grade': {'target_validation': 'failed',
                       'score': score(valid, [], edition=case.edition), 'error_type': type(exc).__name__}}
            results.append({**failure, 'receipt_capture': store.put('target_arm_failure', failure)})
    states = [item['grade']['target_validation'] for item in results]
    status = ('failed' if 'failed' in states else 'passed' if states and all(s == 'passed' for s in states)
              else 'not_run' if not states or all(s == 'not_run' for s in states) else 'indeterminate')
    return {'target_validation': status, 'batches': results, 'product_acceptance': 'pending'}
