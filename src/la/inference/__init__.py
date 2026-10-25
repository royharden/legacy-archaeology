"""Finite byte/policy/name proposals with evidence-bound, honest coverage metadata."""
from la.contracts import REQUIRED_FIELDS, digest, sha256, validate_batch, validate_generation
from la.contracts.evidence import validate_discovery_metadata
from la.ingest.evidence import authorized_spans, make_evidence
from .alternatives import compatible_targets, disclosed_names, policy_alternatives, status_vocabulary
from .discovery import discover_fields
from .filler import declare_filler

POLICY = {'version': 4, 'max_fields': 32, 'max_alternatives': 3, 'scales': [0, 2, 3],
          'alternative_unit': 'physical_span_and_semantic_name',
          'combination_policy': 'three_complete_proposals_not_cartesian',
          'unknown_required': True}


def hypothesize(batch: dict, brief: str, mode: str = 'rules') -> dict:
    """Generate proposals only; singleton interpretations still require a ruling.

    There are <=32 physical spans and <=3 complete typed policies for each
    disclosed name option on a span. No model chooses offsets or supplies values.
    Discovery metadata declares every unoffered policy combination and cannot be
    used as ground-truth candidate recall or mapping approval.
    """
    batch = validate_batch(batch)
    if mode not in ('rules', 'mock'): raise ValueError('live mode requires separately authorized provider')
    if sha256(brief.encode('utf-8')) != batch['brief_sha256']: raise ValueError('brief identity mismatch')
    discovery = discover_fields(batch)
    vocabulary = status_vocabulary(brief)
    names = disclosed_names(brief)
    rows = [bytes.fromhex(record['raw_hex']) for record in batch['records'] if record['disposition'] == 'eligible']
    selection = authorized_spans(batch)
    candidates, fields, candidate_metadata = [], [], {}
    unknowns = list(discovery['abstention_reasons'])
    if batch['status'] != 'accepted' or not rows or batch['width'] is None:
        unknowns.append('input_not_eligible')
    else:
        for span in discovery['spans']:
            start, end = span['start'], span['end']
            raws = [raw[start:end] for raw in rows]
            evidence, seen_ordinals = [], set()
            for sample in selection:
                ordinal = sample['ordinal']
                if (ordinal not in seen_ordinals and sample['start'] <= start and end <= sample['end']
                        and batch['records'][ordinal]['disposition'] == 'eligible'):
                    evidence.append(make_evidence(batch, ordinal, start, end))
                    seen_ordinals.add(ordinal)
                if len(evidence) == 3: break
            field = {'field_id': span['field_id'], 'start': start, 'end': end,
                     'dependent_row_count': len(rows), 'dependent_ordinals': discovery['dependent_ordinals'],
                     'boundary_support': span['support'], 'boundary_reasons': span['reasons'],
                     'name_alternatives': compatible_targets(raws, brief), 'interpretations': [],
                     'evidence_count': len(evidence), 'coverage': 'unproven', 'unknown_option': 'unknown'}
            if not evidence: unknowns.append('no_permitted_evidence:' + span['field_id'])
            for target in field['name_alternatives']:
                dtype = 'decimal' if target == 'balance' else 'date' if target == 'effective_date' else 'text'
                policies, diagnostics = policy_alternatives(raws, target, vocabulary)
                ids = []
                for policy in policies:
                    value = dict(start=start, end=end, semantic_target=target, data_type=dtype,
                                 policy=policy, evidence=evidence, origin=mode,
                                 uncertainty='unconfirmed_boundary_policy_and_name')
                    candidate_id = digest(value)
                    candidates.append(dict(id=candidate_id, **value)); ids.append(candidate_id)
                    ambiguity = ['boundary', 'padding', 'semantic_name']
                    if dtype == 'decimal': ambiguity += ['scale', 'sign', 'precision']
                    if dtype == 'date': ambiguity += ['date_format', 'century_window', 'sentinel_null_vs_unknown']
                    status = None
                    if target == 'status':
                        if vocabulary['codes'] is None:
                            status = {'state': 'missing_vocabulary', 'malformed_code_claim': False,
                                      'unknown_or_unlisted_count': len(raws)}
                        else:
                            def declared_text(raw):
                                text = raw.decode('ascii')
                                if policy['trim']:
                                    text = text.lstrip(policy['padding_byte']) if policy['padding_side'] == 'left' else text.rstrip(policy['padding_byte'])
                                return text
                            status = {'state': 'disclosed', 'unlisted_count': sum(declared_text(raw) not in vocabulary['codes'] for raw in raws),
                                      'classification': 'diagnostic_for_this_unconfirmed_policy'}
                    candidate_metadata[candidate_id] = {'field_id': span['field_id'], 'dependent_row_count': len(rows),
                        'evidence_ordinals': sorted(seen_ordinals), 'uncertainty_kinds': ambiguity,
                        'policy_options_sha256': digest(diagnostics), 'status_vocabulary': status,
                        'consequence_rank': 0 if dtype == 'decimal' else 1 if dtype == 'date' else 2,
                        'approval_status': 'unconfirmed'}
                field['interpretations'].append(dict(semantic_target=target, data_type=dtype,
                    candidate_ids=ids, **diagnostics))
            fields.append(field)
        unknowns += ['boundaries_require_confirmation', 'policy_and_names_require_confirmation',
                     'unoffered_policy_requires_unknown', 'candidate_recall_not_measured']
        if not discovery['spans']: unknowns.append('no_supported_boundary_candidates')
    offered = {candidate['semantic_target'] for candidate in candidates}
    missing = [target for target in REQUIRED_FIELDS if target not in offered]
    unknowns.extend('no_candidate_for:' + target for target in missing)
    if vocabulary['codes'] is None: unknowns.append('status_vocabulary_missing_not_malformed')
    discovery.update(fields=fields, candidate_metadata=candidate_metadata,
        semantic_names_disclosed=names, semantic_names_missing_from_brief=[name for name in REQUIRED_FIELDS if name not in names],
        semantic_targets_without_candidates=missing, status_vocabulary=vocabulary,
        physical_field_count=len(fields), candidate_count=len(candidates),
        max_complete_policies_per_span_name=3, max_candidates=32 * len(REQUIRED_FIELDS) * 3,
        no_correct_option_action='unknown', null_is_not_unknown=True,
        actual_candidate_recall='not_measured', full_mapping_status='unconfirmed',
        sample_artifact_sha256=batch['samples']['artifact_sha256'],
        sample_selection_sha256=batch['samples'].get('selection_sha256'),
        dependencies={'source_sha256': batch['source_sha256'], 'framing_sha256': batch['framing_sha256'],
                      'brief_sha256': batch['brief_sha256'], 'config_sha256': batch['config_sha256']})
    discovery['discovery_sha256'] = digest({key: value for key, value in discovery.items() if key != 'discovery_sha256'})
    discovery = validate_discovery_metadata(discovery)
    value = dict(schema_version=1, source_sha256=batch['source_sha256'], framing_sha256=batch['framing_sha256'],
        brief_sha256=batch['brief_sha256'], policy_sha256=digest({'policy': POLICY,
            'sample_artifact': batch['samples']['artifact_sha256'], 'sample_selection': batch['samples'].get('selection_sha256'),
            'discovery': discovery['discovery_sha256']}), candidates=candidates,
        unknowns=sorted(set(unknowns)), mode=mode, discovery=discovery, filler=[])
    return validate_generation(dict(value, generation_sha256=digest(value)))


def candidate_diagnostics(generation: dict) -> dict:
    """Question/report consumer seam; metadata is pinned by generation identity."""
    value = validate_generation(generation)
    if digest({key: item for key, item in value.items() if key != 'generation_sha256'}) != value['generation_sha256']:
        raise ValueError('generation identity mismatch')
    return validate_discovery_metadata(value['discovery'])
