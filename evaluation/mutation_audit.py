"""Finite scorer/control mutation source. No checks execute on import."""
from __future__ import annotations

from copy import deepcopy
from datetime import date, timedelta
from decimal import Decimal
from typing import Callable

from .artifacts import CaptureStore, digest, is_sha
from .scorer import score

VALUE_MUTATIONS = ('wrong_amount', 'wrong_target_name', 'scale_error', 'declared_scale_error',
                   'sign_error', 'null_error', 'date_error', 'drop', 'duplicate',
                   'compensating_errors', 'drop_duplicate')
CONTROL_MUTATIONS = ('changed_evidence', 'stale_approval', 'incomplete_load')


class InapplicableMutation(ValueError):
    pass


def apply_outcome_mutation(outcomes: list[dict], mutation: str) -> list[dict]:
    """Mutate normalized typed observations, without consulting an oracle decoder."""
    if mutation not in VALUE_MUTATIONS:
        raise ValueError('unknown finite outcome mutation')
    rows = deepcopy(outcomes)
    valid = [index for index, row in enumerate(rows) if row.get('outcome') == 'converted']
    if not valid:
        raise InapplicableMutation('no converted row')
    index = valid[0]
    fields = rows[index]['fields']
    if mutation == 'wrong_target_name':
        fields['wrong_account_target'] = fields.pop('account_ref')
    elif mutation == 'drop':
        rows.pop(index)
    elif mutation == 'duplicate':
        rows.append(deepcopy(rows[index]))
    elif mutation == 'null_error':
        nulls = [(i, name) for i in valid for name, field in rows[i]['fields'].items() if field['value'] is None]
        if not nulls:
            raise InapplicableMutation('no typed null to replace with empty')
        i, name = nulls[0]
        rows[i]['fields'][name]['value'] = ''
    elif mutation == 'date_error':
        dated = [i for i in valid if rows[i]['fields']['effective_date']['value'] is not None]
        if not dated:
            raise InapplicableMutation('no nonnull date')
        field = rows[dated[0]]['fields']['effective_date']
        field['value'] = (date.fromisoformat(field['value']) + timedelta(days=1)).isoformat()
    elif mutation == 'drop_duplicate':
        pair = next(((a, b) for a in valid for b in valid if a < b and rows[a]['fields'] == rows[b]['fields']), None)
        if pair is None:
            raise InapplicableMutation('equal business records required')
        a, b = pair
        replacement = deepcopy(rows[a])
        rows.pop(b)
        rows.append(replacement)
    elif mutation == 'compensating_errors':
        if len(valid) < 2:
            raise InapplicableMutation('two rows required')
        for i, direction in zip(valid[:2], (1, -1), strict=True):
            field = rows[i]['fields']['balance']
            amount = Decimal(field['value'])
            field['value'] = str(amount + direction)
    else:
        nonzero = [i for i in valid if Decimal(rows[i]['fields']['balance']['value']) != 0]
        if mutation in ('sign_error', 'scale_error'):
            if not nonzero:
                raise InapplicableMutation('nonzero amount required')
            index = nonzero[0]
        field = rows[index]['fields']['balance']
        amount = Decimal(field['value'])
        if mutation == 'wrong_amount':
            field['value'] = str(amount + Decimal(1).scaleb(amount.as_tuple().exponent))
        elif mutation == 'scale_error':
            field['value'] = str(amount * 100)
        elif mutation == 'declared_scale_error':
            field['value'] = format(amount, '.' + str(max(0, -amount.as_tuple().exponent) + 1) + 'f')
        elif mutation == 'sign_error':
            field['value'] = str(-amount)
    return rows


def audit_scorer_mutations(oracle: list[dict], exact_outcomes: list[dict], *,
                           edition: str, store: CaptureStore) -> dict:
    baseline = score(oracle, exact_outcomes, edition=edition)
    if baseline['row_parity'] != 'exact' or not baseline['semantic_rows']['denominator']:
        raise ValueError('exact nonempty positive control required before mutation audit')
    results = []
    for mutation in VALUE_MUTATIONS:
        try:
            changed = apply_outcome_mutation(exact_outcomes, mutation)
            report = score(oracle, changed, edition=edition)
            detected = report['row_parity'] != 'exact'
            capture = store.put('scorer_mutation', {'mutation': mutation, 'outcomes': changed, 'score': report})
            results.append({'mutation': mutation, 'status': 'detected' if detected else 'missed',
                            'capture': capture, 'what_bug_this_catches': mutation})
        except InapplicableMutation as exc:
            results.append({'mutation': mutation, 'status': 'inapplicable', 'reason': str(exc)})
    receipt = {'schema_version': 1, 'edition': edition, 'oracle_sha256': digest(oracle),
               'baseline_sha256': digest(exact_outcomes), 'results': results,
               'finite_suite_status': 'passed' if all(item['status'] == 'detected' for item in results) else 'incomplete',
               'independent_audit': 'pending', 'product_acceptance': 'pending'}
    return {**receipt, 'receipt_capture': store.put('mutation_audit', receipt)}


def apply_control_mutation(candidate: dict, mutation: str) -> dict:
    changed = deepcopy(candidate)
    if mutation == 'changed_evidence':
        old = changed['evidence_sha256']
        changed['evidence_sha256'] = digest({'changed_from': old})
    elif mutation == 'stale_approval':
        # Approval retains its old mapping hash; the supplied mapping is changed.
        changed['mapping_sha256'] = digest({'changed_from': changed['mapping_sha256']})
    elif mutation == 'incomplete_load':
        changed['mapping_status'] = 'incomplete'
    else:
        raise ValueError('unknown control mutation')
    return changed


def audit_control_mutations(candidate: dict, rejection_probe: Callable[[dict], dict], *,
                            store: CaptureStore) -> dict:
    """Probe only an operator-approved fake/public adapter in later validation.

    A boolean is insufficient: retain candidate-bound rejection and durable-effect
    observations. The caller owns permission to invoke the supplied adapter.
    """
    results = []
    for mutation in CONTROL_MUTATIONS:
        changed = apply_control_mutation(candidate, mutation)
        observation = rejection_probe(deepcopy(changed))
        expected_reason = {'changed_evidence': 'dependency_mismatch', 'stale_approval': 'approval_mismatch',
                           'incomplete_load': 'incomplete_mapping'}[mutation]
        detected = (observation.get('candidate_sha256') == digest(changed)
                    and observation.get('disposition') == 'rejected'
                    and observation.get('reason') == expected_reason
                    and isinstance(observation.get('durable_before'), dict)
                    and observation.get('durable_before') == observation.get('durable_after')
                    and is_sha(observation.get('probe_code_sha256')))
        reference = store.put('control_mutation', {'mutation': mutation, 'candidate': changed,
                                                  'observation': observation})
        results.append({'mutation': mutation, 'status': 'detected' if detected else 'missed',
                        'capture': reference, 'what_bug_this_catches': mutation})
    report = {'schema_version': 1, 'results': results,
              'finite_suite_status': 'passed' if all(item['status'] == 'detected' for item in results) else 'failed',
              'product_acceptance': 'pending'}
    return {**report, 'receipt_capture': store.put('control_audit', report)}
