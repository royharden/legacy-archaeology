"""Closed evidence wire validators, preserving supplied keys and canonical identity.

These validators check protocol syntax and bounded metadata, not authorization,
source reconstruction, candidate correctness or conversion policy. They never
strip keys, insert defaults, reorder lists or interpret raw strings as commands.
The Annotated aliases work inside canonical Boundary models without importing
the package root (and hence without producer/schema import cycles).
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from typing import Annotated

from pydantic import BeforeValidator
from .base import Boundary

MAX_BYTES = 5 * 1024 * 1024
MAX_OBSERVED = 2**63 - 1
NAMES = ('account_ref', 'description', 'balance', 'effective_date', 'status')


def _fail(message='invalid evidence protocol'):
    raise ValueError(message)


def _integer(low=0, high=MAX_OBSERVED):
    def check(value):
        if type(value) is not int or not low <= value <= high:
            _fail('exact bounded integer required')
    return check


def _text(limit=4000, minimum=0):
    def check(value):
        if type(value) is not str or not minimum <= len(value) <= limit:
            _fail('bounded raw string required')
    return check


def _enum(*options):
    def check(value):
        if not any(type(value) is type(option) and value == option for option in options):
            _fail('unsupported exact protocol literal')
    return check


def _nullable(check):
    def validate(value):
        if value is not None:
            check(value)
    return validate


def _array(check, maximum, minimum=0):
    def validate(value):
        if type(value) is not list or not minimum <= len(value) <= maximum:
            _fail('bounded JSON array required')
        for item in value:
            check(item)
    return validate


def _shape(required, optional=None):
    optional = optional or {}
    def validate(value):
        if type(value) is not dict or not set(required) <= value.keys() or set(value) - (required.keys() | optional.keys()):
            _fail('missing or unknown protocol field')
        for key, item in value.items():
            (required.get(key) or optional[key])(item)
    return validate


def _hash(value):
    if type(value) is not str or len(value) != 64 or any(char not in '0123456789abcdef' for char in value):
        _fail('lowercase SHA256 required')


def _hex(value):
    _text(MAX_BYTES * 2)(value)
    if len(value) % 2 or any(char not in '0123456789abcdef' for char in value):
        _fail('canonical byte hex required')


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=False, allow_nan=False).encode('utf-8')).hexdigest()


def _self_hash(value, key):
    if value[key] != _digest({name: item for name, item in value.items() if name != key}):
        _fail('metadata identity mismatch: ' + key)


I = _integer()
ROW = _integer(0, 9999)
COUNT = _integer(0, 10000)
BYTE = _integer(0, MAX_BYTES)
POS = _integer(0, 256)
BOOL = _enum(False, True)
HASH_NULL = _nullable(_hash)
STRINGS = _array(_text(), 64)
REF = dict(source_sha256=_hash, framing_sha256=_hash, ordinal=ROW,
           byte_start=BYTE, length=BYTE, raw_sha256=_hash)


def _record_identity(value):
    _shape(REF)(value)
    if value['byte_start'] + value['length'] > MAX_BYTES:
        _fail('record exceeds retained source bounds')


def _raw(value, length):
    _hex(value['raw_hex'])
    raw = bytes.fromhex(value['raw_hex'])
    if len(raw) != length or hashlib.sha256(raw).hexdigest() != value['raw_sha256']:
        _fail('raw length/hash mismatch')


def _record_display(value):
    _shape(dict(REF, raw_hex=_hex, disposition=_enum('eligible', 'quarantined'), reasons=STRINGS))(value)
    _record_identity({key: value[key] for key in REF})
    _raw(value, value['length'])


def _span(value):
    _shape({'start': BYTE, 'end': BYTE})(value)
    if value['start'] >= value['end']:
        _fail('nonempty ordered span required')


def _span_evidence(value):
    _shape({'ordinal': ROW, 'start': BYTE, 'end': BYTE, 'source_sha256': _hash,
            'framing_sha256': _hash, 'byte_start': BYTE, 'raw_hex': _hex, 'raw_sha256': _hash},
           {'record_ref': _record_identity})(value)
    _span({key: value[key] for key in ('start', 'end')})
    _raw(value, value['end'] - value['start'])
    if value['byte_start'] + value['end'] - value['start'] > MAX_BYTES:
        _fail('evidence exceeds retained source bounds')
    if 'record_ref' in value:
        ref = value['record_ref']
        if (any(value[key] != ref[key] for key in ('ordinal', 'source_sha256', 'framing_sha256'))
                or value['byte_start'] != ref['byte_start'] + value['start'] or value['end'] > ref['length']):
            _fail('nested record reference/span mismatch')


def _sample(value):
    # Explicit legacy flat and current nested alternatives, not arbitrary JSON.
    optional = dict(REF, start=BYTE, end=BYTE, record_ref=_record_identity, span=_span)
    _shape({'raw_hex': _hex, 'raw_sha256': _hash}, optional)(value)
    if 'record_ref' not in value and 'ordinal' not in value:
        _fail('sample record identity required')
    if ('start' in value) != ('end' in value):
        _fail('sample span endpoints must occur together')
    if 'start' in value:
        _span({key: value[key] for key in ('start', 'end')})
    if 'span' in value and 'start' in value and value['span'] != {key: value[key] for key in ('start', 'end')}:
        _fail('conflicting sample spans')
    span = value.get('span') or ({key: value[key] for key in ('start', 'end')} if 'start' in value else None)
    if span:
        _raw(value, span['end'] - span['start'])
    else:
        _raw(value, len(value['raw_hex']) // 2)


def _sample_artifact(value):
    _shape({'source_sha256': _hash, 'authorization': _text(1000, 1),
            'records': _array(_sample, 10000)},
           {'schema_version': _enum(1), 'artifact_sha256': _hash, 'framing_sha256': _hash})(value)
    if not value['authorization'].strip():
        _fail('authorization label required')
    if 'artifact_sha256' in value:
        _self_hash(value, 'artifact_sha256')


def _selected(value):
    _shape({'ordinal': ROW, 'start': BYTE, 'end': BYTE, 'artifact_index': ROW,
            'raw_hex': _hex, 'raw_sha256': _hash})(value)
    _span({key: value[key] for key in ('start', 'end')})
    _raw(value, value['end'] - value['start'])


def _framing(value):
    if type(value) is not dict:
        _fail()
    common = {'framing': _enum('LF', 'CRLF', 'unresolved'), 'width': _nullable(_integer(1, 256))}
    version = value.get('version')
    if type(version) is not int:
        _fail('exact framing version required')
    if version == 2:
        _shape(dict(common, version=_enum(2), width_candidates=_array(_integer(1, 256), 256), terminal_newline=BOOL))(value)
    else:
        _shape({'version': _enum(3), 'kind': _enum('unmaterialized_stream_refusal'), 'framing': _enum('unresolved'),
                'width': _enum(None), 'width_candidates': _array(POS, 0),
                'terminal_newline': _nullable(BOOL), 'observation_sha256': _hash})(value)


def _observation(value):
    _shape({'schema_version': _enum(1), 'kind': _enum('caller_completed_stream_observation'),
            'source_sha256': _hash, 'input_byte_count': I, 'observed_count': _nullable(I),
            'terminal_newline': _nullable(BOOL), 'brief_sha256': _hash, 'brief_character_count': I,
            'sample_artifact_sha256': HASH_NULL, 'complete': _enum(True), 'stable_claim': BOOL,
            'identity_pins': _shape({}, {key: _hash for key in ('before_identity_sha256', 'after_identity_sha256', 'reader_policy_sha256')}),
            'stability_state': _enum('unstable', 'identity_pins_agree', 'not_independently_attested'),
            'hash_scope': _enum('complete_observed_stream'), 'source_reconstructed': _enum(False),
            'file_identity_probed_by_producer': _enum(False), 'observation_sha256': _hash})(value)
    _self_hash(value, 'observation_sha256')


def _intake(value):
    if value == {} and type(value) is dict:
        return
    stream = type(value) is dict and 'stream_observation' in value
    separator = _shape({'ordinal': ROW, 'byte_start': BYTE, 'raw_hex': _enum('', '0a', '0d0a'), 'length': _integer(0, 2)})
    histogram = _shape({'width': _integer(1, 256), 'count': COUNT})
    question = _shape({'kind': _enum('record_width'), 'options': _array(lambda item: _enum('unknown')(item) if type(item) is str else _integer(1, 256)(item), 257)})
    required = {'framing_policy': _framing, 'separators': _array(separator, 10000),
                'width_histogram': _array(histogram, 256), 'width_candidates': _array(_integer(1, 256), 256),
                'width_status': _enum('resolved', 'unresolved'), 'width_question': _nullable(question),
                'observed_record_count': _nullable(I) if stream else I,
                'materialized_record_count': COUNT, 'unmaterialized_record_count': _nullable(I) if stream else I,
                'bounded_refusal': BOOL, 'input_byte_count': I,
                'terminal_newline': _nullable(BOOL) if stream else BOOL}
    if stream:
        required.update(final_record_width_valid=_enum(None), final_record_eligible=_enum(None),
                        record_count_status=_enum('unknown', 'observed_complete_stream'),
                        source_identity_scope=_enum('complete_observed_stream_not_stable_file', 'complete_observed_stream'),
                        source_reconstruction=_enum('not_available_unmaterialized_stream'), stream_observation=_observation)
    elif type(value) is dict and 'final_record_valid' in value:
        required['final_record_valid'] = BOOL
    else:
        required.update(final_record_width_valid=BOOL, final_record_eligible=BOOL)
    _shape(required)(value)
    observed, materialized, unmaterialized = (value[key] for key in ('observed_record_count', 'materialized_record_count', 'unmaterialized_record_count'))
    if observed is None:
        if not stream or unmaterialized is not None or materialized != 0:
            _fail('unknown count must remain unknown without materialized rows')
    elif unmaterialized is None or materialized + unmaterialized != observed:
        _fail('intake count partition mismatch')
    if len(value['separators']) != materialized:
        _fail('intake materialized separator count mismatch')
    if stream:
        observation = value['stream_observation']
        if (not value['bounded_refusal'] or materialized or value['separators'] or value['width_histogram']
                or value['width_candidates'] or value['width_question'] is not None
                or value['framing_policy']['version'] != 3
                or observation['observation_sha256'] != value['framing_policy']['observation_sha256']
                or observation['observed_count'] != observed or observation['input_byte_count'] != value['input_byte_count']
                or observation['terminal_newline'] != value['terminal_newline']
                or value['record_count_status'] != ('unknown' if observed is None else 'observed_complete_stream')):
            _fail('observed refusal metadata mismatch')


def _sample_metadata(value):
    if type(value) is not dict:
        _fail()
    common = {'authorization': _text(1000), 'artifact_sha256': HASH_NULL,
              'records': _array(_record_display, 64), 'selected_ordinals': _array(ROW, 64), 'truncated': BOOL}
    if value.get('selection_policy') == 'no_stream_refusal_authority':
        required = dict(common, content_sha256=HASH_NULL, artifact_received=BOOL,
                        validation_status=_enum('unvalidated_without_source_bytes', 'not_provided'),
                        record_references_validated=_enum(False), authorized_spans=_array(_selected, 0),
                        selected_artifact_indices=_array(ROW, 0), selected_byte_count=_enum(0), authorized_count=_enum(0),
                        selection_policy=_enum('no_stream_refusal_authority'), selection_sha256=_hash)
        _shape(required, {'intake': _intake})(value)
        if value['records'] or value['selected_ordinals'] or value['authorization'] or value['truncated']:
            _fail('observed sample pins convey no authority')
        _self_selection(value)
    elif 'authorized_spans' in value:
        required = dict(common, content_sha256=HASH_NULL, authorized_spans=_array(_selected, 10000),
                        selected_artifact_indices=_array(ROW, 10000), authorized_count=COUNT,
                        selected_byte_count=_integer(0, 16384), selection_policy=_enum('ordinal-span-v1'), selection_sha256=_hash)
        _shape(required, {'intake': _intake})(value)
        _self_selection(value)
        spans = value['authorized_spans']
        if (sum(item['end'] - item['start'] for item in spans) != value['selected_byte_count']
                or len(spans) > value['authorized_count']
                or value['truncated'] != (len(spans) < value['authorized_count'])
                or sorted({item['ordinal'] for item in spans}) != value['selected_ordinals']
                or [item['artifact_index'] for item in spans] != value['selected_artifact_indices']):
            _fail('selected sample count/reference mismatch')
        if sum(record['length'] for record in value['records']) > 16384:
            _fail('selected full record byte cap exceeded')
    else:
        # Original V1 samples intentionally omit selection and content pins.
        _shape(common, {'intake': _intake})(value)


def _self_selection(value):
    if value['selection_sha256'] != _digest(value['authorized_spans']):
        _fail('sample selection identity mismatch')


SUPPORT = _shape({}, {key: COUNT for key in ('edge', 'class_transition', 'padding_transition', 'leading_sign', 'trailing_sign')})
SPAN = _shape({'start': POS, 'end': POS, 'reasons': STRINGS, 'support': COUNT,
               'field_id': _hash, 'dependent_row_count': COUNT, 'coverage': _enum('candidate_only')})


def _vocabulary(value):
    _shape({'codes': _nullable(_array(_text(32, 1), 64, 1)),
            'source': _enum(None, 'explicit_status_codes', 'explicit_status_code_list', 'explicit_status_labels'),
            'state': _enum('disclosed', 'missing_vocabulary'),
            'unknown_code_treatment': _enum('unlisted_code_diagnostic', 'declared_vocabulary_check'), 'vocabulary_sha256': _hash})(value)
    if value['codes'] is not None and any(not code.isascii() for code in value['codes']):
        _fail('ASCII status labels required')
    if value['vocabulary_sha256'] != _digest({key: value[key] for key in ('codes', 'source')}):
        _fail('status vocabulary identity mismatch')


def _interpretation(value):
    padding = _shape({'padding_byte': _enum(' '), 'padding_side': _enum('none', 'left', 'right'), 'trim': BOOL})
    axes = _shape({'padding': _array(padding, 3, 1)}, {
        'sign': _array(_enum('leading', 'trailing', 'unsigned'), 3, 1),
        'scale': _array(_enum(0, 2, 3), 3, 1), 'precision': _array(_integer(1, 1000), 3, 1),
        'format': _array(_enum('YYYYMMDD', 'YYMMDD'), 2, 1),
        'century_window': _array(_array(_integer(1, 9999), 2, 2), 3, 1),
        'sentinel': _array(_enum('preserve_or_reject', 'explicit_sql_null'), 2, 1)})
    _shape({'semantic_target': _enum(*NAMES), 'data_type': _enum('text', 'decimal', 'date'),
            'candidate_ids': _array(_hash, 3, 1), 'axes': axes, 'policy_option_count': _integer(1, 3),
            'max_policy_alternatives': _enum(3), 'combination_count': _integer(1, 10000),
            'unoffered_combination_count': _integer(0, 10000), 'coverage': _enum('bounded_proposals_not_exhaustive'),
            'unknown_option': _enum('unknown'), 'observed_left_padding': BOOL, 'observed_right_padding': BOOL,
            'observed_leading_sign': BOOL, 'observed_trailing_sign': BOOL,
            'sign_support': _shape({'leading': COUNT, 'trailing': COUNT, 'unsigned': COUNT}),
            'sentinel_lexemes': _array(_text(256), 2), 'century_windows_are_proposals': _enum(True),
            'precision_is_proposed_not_domain_fact': BOOL})(value)
    if len(value['candidate_ids']) != value['policy_option_count']:
        _fail('policy option count mismatch')
    product = 1
    for values in value['axes'].values():
        product *= len(values)
    if product != value['combination_count'] or max(0, product - value['policy_option_count']) != value['unoffered_combination_count']:
        _fail('alternative combination accounting mismatch')


def _status_diagnostic(value):
    if value is None:
        return
    if type(value) is dict and value.get('state') == 'missing_vocabulary':
        _shape({'state': _enum('missing_vocabulary'), 'malformed_code_claim': _enum(False), 'unknown_or_unlisted_count': COUNT})(value)
    else:
        _shape({'state': _enum('disclosed'), 'unlisted_count': COUNT,
                'classification': _enum('diagnostic_for_this_unconfirmed_policy')})(value)


def _candidate_metadata(value):
    if type(value) is not dict or len(value) > 480:
        _fail('bounded candidate metadata map required')
    check = _shape({'field_id': _hash, 'dependent_row_count': COUNT, 'evidence_ordinals': _array(ROW, 3),
                    'uncertainty_kinds': STRINGS, 'policy_options_sha256': _hash,
                    'status_vocabulary': _status_diagnostic, 'consequence_rank': _integer(0, 2),
                    'approval_status': _enum('unconfirmed')})
    for key, item in value.items():
        _hash(key)
        check(item)


def _filler(value):
    _shape({'schema_version': _enum(1), 'kind': _enum('explicit_filler_declaration'),
            'source_sha256': _hash, 'framing_sha256': _hash, 'brief_sha256': _hash,
            'prior_generation_sha256': _hash, 'spans': _array(_span, 32),
            'actor': _text(200, 1), 'reason': _text(4000, 1), 'evidence': _array(_span_evidence, 96),
            'approval_status': _enum('unapproved'), 'journal_events_created': _enum(0), 'declaration_sha256': _hash})(value)
    _self_hash(value, 'declaration_sha256')


def _discovery(value):
    if type(value) is not dict:
        _fail()
    if not value:
        return
    filler = {'filler_declaration': _filler, 'discovery_sha256': _hash}
    if 'version' not in value:
        if 'information_source' in value:
            _shape({'information_source': _enum('public_hand_declared_test_layout'),
                    'sample_artifact_sha256': HASH_NULL, 'sample_selection_sha256': HASH_NULL}, filler)(value)
        else:
            _shape(filler)(value)
    else:
        field = _shape({'field_id': _hash, 'start': POS, 'end': POS, 'dependent_row_count': COUNT,
                        'dependent_ordinals': _array(ROW, 10000), 'boundary_support': COUNT, 'boundary_reasons': STRINGS,
                        'name_alternatives': _array(_enum(*NAMES), 5), 'interpretations': _array(_interpretation, 5),
                        'evidence_count': _integer(0, 3), 'coverage': _enum('unproven'), 'unknown_option': _enum('unknown')})
        optional = dict(filler, date_shape_proposal_count=_integer(0, 512), date_shape_budget=_enum(16),
                        omitted_date_shape_count=_integer(0, 512), support_threshold=_shape({'numerator': _enum(3), 'denominator': _enum(4)}),
                        fields=_array(field, 32), candidate_metadata=_candidate_metadata,
                        semantic_names_disclosed=_array(_enum(*NAMES), 5), semantic_names_missing_from_brief=_array(_enum(*NAMES), 5),
                        semantic_targets_without_candidates=_array(_enum(*NAMES), 5), status_vocabulary=_vocabulary,
                        physical_field_count=_integer(0, 32), candidate_count=_integer(0, 480),
                        max_complete_policies_per_span_name=_enum(3), max_candidates=_enum(480),
                        no_correct_option_action=_enum('unknown'), null_is_not_unknown=_enum(True),
                        actual_candidate_recall=_enum('not_measured'), full_mapping_status=_enum('unconfirmed'),
                        sample_artifact_sha256=HASH_NULL, sample_selection_sha256=HASH_NULL,
                        dependencies=_shape({key: _hash for key in ('source_sha256', 'framing_sha256', 'brief_sha256', 'config_sha256')}))
        _shape({'version': _enum(1), 'source_sha256': _hash, 'framing_sha256': _hash,
                'eligible_record_count': COUNT, 'dependent_ordinals': _array(ROW, 10000), 'max_fields': _enum(32),
                'spans': _array(SPAN, 32), 'boundary_proposals': _array(_shape({'offset': POS, 'support': SUPPORT}), 257),
                'column_profiles': _array(_shape({'position': _integer(0, 255),
                    'class_counts': _shape({}, {key: COUNT for key in ('space', 'digit', 'sign', 'letter', 'other')}),
                    'constant_byte': _nullable(_integer(0, 255))}), 256),
                'coverage_status': _enum('unproven'), 'abstention_reasons': STRINGS,
                'omitted_span_count': _integer(0, 100000), 'discovery_sha256': _hash}, optional)(value)
        enriched = {'fields', 'candidate_metadata', 'semantic_names_disclosed', 'semantic_names_missing_from_brief',
                    'semantic_targets_without_candidates', 'status_vocabulary', 'physical_field_count', 'candidate_count',
                    'max_complete_policies_per_span_name', 'max_candidates', 'no_correct_option_action', 'null_is_not_unknown',
                    'actual_candidate_recall', 'full_mapping_status', 'sample_artifact_sha256', 'sample_selection_sha256', 'dependencies'}
        date_fields = {'date_shape_proposal_count', 'date_shape_budget', 'omitted_date_shape_count', 'support_threshold'}
        for group in (enriched, date_fields):
            if group.intersection(value) and not group <= value.keys():
                _fail('incomplete documented discovery variant')
        for span in value['spans'] + value.get('fields', []):
            if span['start'] >= span['end']:
                _fail('discovery span must be nonempty')
        if (len(value['dependent_ordinals']) != value['eligible_record_count']
                or len(set(value['dependent_ordinals'])) != len(value['dependent_ordinals'])):
            _fail('discovery dependent count mismatch')
        if 'fields' in value and value['physical_field_count'] != len(value['fields']):
            _fail('physical field count mismatch')
        eligible = value['eligible_record_count']
        for profile in value['column_profiles']:
            if sum(profile['class_counts'].values()) != eligible:
                _fail('column class denominator mismatch')
        for proposal in value['boundary_proposals']:
            if any(count > eligible for count in proposal['support'].values()):
                _fail('boundary support exceeds denominator')
        for span in value['spans']:
            if span['support'] > eligible or span['dependent_row_count'] != eligible:
                _fail('span support/dependency denominator mismatch')
        for field in value.get('fields', []):
            if (field['dependent_ordinals'] != value['dependent_ordinals'] or field['dependent_row_count'] != eligible
                    or field['boundary_support'] > eligible):
                _fail('field dependency denominator mismatch')
        if 'candidate_count' in value and value['candidate_count'] != len(value['candidate_metadata']):
            _fail('candidate metadata count mismatch')
    if 'discovery_sha256' in value:
        _self_hash(value, 'discovery_sha256')


def _validated(value, checker):
    checker(value)
    # Return only supplied fields, byte-for-byte values/order; never the input alias.
    return deepcopy(value)


def validate_sample_artifact(value):
    return _validated(value, _sample_artifact)


def validate_sample_metadata(value):
    return _validated(value, _sample_metadata)


def validate_intake_metadata(value):
    return _validated(value, _intake)


def validate_span_evidence(value):
    return _validated(value, _span_evidence)


def validate_discovery_metadata(value):
    return _validated(value, _discovery)


# Owner validators deliberately retain dictionaries at the public wire boundary.
# Strict recursive checks happen before Pydantic can normalize any supplied value.
RecordIdentity = Annotated[dict, BeforeValidator(lambda value: _validated(value, _record_identity))]
RecordDisplay = Annotated[dict, BeforeValidator(lambda value: _validated(value, _record_display))]
SpanEvidence = Annotated[dict, BeforeValidator(validate_span_evidence)]
PermittedSampleArtifact = Annotated[dict, BeforeValidator(validate_sample_artifact)]
SampleMetadata = Annotated[dict, BeforeValidator(validate_sample_metadata)]
IntakeMetadata = Annotated[dict, BeforeValidator(validate_intake_metadata)]
DiscoveryMetadata = Annotated[dict, BeforeValidator(validate_discovery_metadata)]


class EvidenceEnvelope(Boundary):
    """Optional explicit envelope; aliases also embed directly in owner models."""
    evidence: SpanEvidence
