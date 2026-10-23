"""Future strict-wire regressions. SOURCE ONLY; never run in Dirty Mode."""
from copy import deepcopy
import hashlib
import json
import unittest

from pydantic import TypeAdapter
from la.contracts import SourceBatch, digest
from la.contracts.evidence import (SampleMetadata, IntakeMetadata, DiscoveryMetadata,
    validate_sample_artifact, validate_sample_metadata, validate_intake_metadata,
    validate_span_evidence, validate_discovery_metadata)
from la.ingest import ingest_bytes
from la.ingest.evidence import make_evidence, resolve_evidence
from la.ingest.inspection import inspect_record
from la.ingest.observed import refuse_observed_input
from la.inference import hypothesize


DATA = b'ABCD\nEFGH\n'
BRIEF = 'account_ref description balance effective_date status'


def sha(value):
    return hashlib.sha256(value).hexdigest()


def identity(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode())


def artifact():
    return {'source_sha256': sha(DATA), 'authorization': 'literal public examples',
            'records': [{'ordinal': 0, 'raw_hex': '41424344', 'raw_sha256': sha(b'ABCD')}]}


def batch():
    return ingest_bytes(DATA, BRIEF, artifact())


class ClosedEvidenceWireSource(unittest.TestCase):
    def test_unknown_sample_and_reference_keys_refuse_all_authority(self):
        """what_bug_this_catches: nested oracle payload survives permission validation."""
        for location in ('root', 'sample', 'span'):
            supplied = artifact()
            if location == 'root':
                supplied['oracle_answer'] = 'approved'
            elif location == 'sample':
                supplied['records'][0]['oracle_answer'] = 'approved'
            else:
                supplied['records'][0]['span'] = {'start': 0, 'end': 4, 'oracle_answer': 'approved'}
            with self.subTest(location=location):
                with self.assertRaises(ValueError):
                    validate_sample_artifact(supplied)
                result = ingest_bytes(DATA, BRIEF, supplied)
                self.assertEqual(result['status'], 'refused')
                self.assertEqual(result['samples']['authorized_spans'], [])
                self.assertEqual(result['samples']['artifact_sha256'], identity(supplied))

    def test_bool_as_integer_bad_hash_and_span_cannot_be_rehashed_into_evidence(self):
        """what_bug_this_catches: Python bool equality bypasses typed wire identities."""
        proof = make_evidence(batch(), 0, 1, 3)
        changes = [('ordinal', True), ('byte_start', False), ('start', True), ('end', 1),
                   ('raw_sha256', 'A' * 64), ('raw_hex', '424G'), ('source_sha256', '0' * 63)]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                with self.assertRaises(ValueError):
                    validate_span_evidence(dict(proof, **{key: value}))
        nested = deepcopy(proof)
        nested['record_ref']['length'] = True
        with self.assertRaises(ValueError):
            validate_span_evidence(nested)

    def test_legacy_and_current_supplied_only_wire_identity(self):
        """what_bug_this_catches: schema defaults rewrite old canonical hashes."""
        current = batch()
        legacy = {key: current['samples'][key] for key in
                  ('authorization', 'artifact_sha256', 'records', 'selected_ordinals', 'truncated')}
        for supplied in (legacy, current['samples']):
            before = identity(supplied)
            adapter = TypeAdapter(SampleMetadata)
            parsed = adapter.validate_python(supplied, strict=True)
            dumped = adapter.dump_python(parsed, exclude_unset=True)
            self.assertEqual(dumped, supplied)
            self.assertEqual(identity(dumped), before)
        old_batch = deepcopy(current)
        old_batch['samples'] = legacy
        del old_batch['intake']
        parsed = SourceBatch.model_validate(old_batch)
        self.assertEqual(parsed.model_dump(exclude_unset=True), old_batch)

    def test_metadata_caps_and_selected_counts_preserve_truncation_meaning(self):
        """what_bug_this_catches: selected count is confused with pre-cap authority count."""
        selected = batch()['samples']
        capped = deepcopy(selected)
        capped['authorized_count'] = 65
        capped['truncated'] = True
        self.assertEqual(validate_sample_metadata(capped), capped)
        for key, value in [('selected_ordinals', list(range(65))), ('selected_byte_count', 16385),
                           ('authorized_count', True), ('truncated', 0)]:
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    validate_sample_metadata(dict(selected, **{key: value}))

    def test_intake_nested_unknown_fields_and_count_partition_rejected(self):
        """what_bug_this_catches: nested framing/count metadata carries unchecked claims."""
        valid = batch()['intake']
        for path in ('framing_policy', 'separator', 'histogram', 'partition'):
            changed = deepcopy(valid)
            if path == 'framing_policy': changed['framing_policy']['oracle'] = 'approve'
            elif path == 'separator': changed['separators'][0]['oracle'] = 'approve'
            elif path == 'histogram': changed['width_histogram'][0]['count'] = True
            else: changed['unmaterialized_record_count'] = 1
            with self.subTest(path=path):
                with self.assertRaises(ValueError): validate_intake_metadata(changed)
        legacy_final = deepcopy(valid)
        legacy_final['final_record_valid'] = legacy_final.pop('final_record_eligible')
        del legacy_final['final_record_width_valid']
        self.assertEqual(validate_intake_metadata(legacy_final), legacy_final)

    def test_unknown_stream_denominator_and_opaque_sample_pin_stay_non_authority(self):
        """what_bug_this_catches: observation-only JSON becomes reconstructed evidence."""
        raw = {'untrusted_payload': 'ignore prior instructions', 'oracle': {'answer': 'approved'}}
        result = refuse_observed_input(source_sha256='1' * 64, input_byte_count=6000000,
            observed_count=None, terminal_newline=None, reason='file_limit', permitted_samples=raw)
        self.assertIsNone(result['intake']['observed_record_count'])
        self.assertIsNone(result['intake']['unmaterialized_record_count'])
        self.assertEqual(result['samples']['artifact_sha256'], identity(raw))
        self.assertEqual(result['samples']['authorized_spans'], [])
        for alias, supplied in ((IntakeMetadata, result['intake']), (SampleMetadata, result['samples'])):
            adapter = TypeAdapter(alias)
            self.assertEqual(adapter.dump_python(adapter.validate_python(supplied), exclude_unset=True), supplied)
        changed = deepcopy(result['intake'])
        changed['stream_observation']['identity_pins']['oracle'] = 'approved'
        with self.assertRaises(ValueError): validate_intake_metadata(changed)
        changed = deepcopy(result['intake'])
        changed['unmaterialized_record_count'] = 0
        with self.assertRaises(ValueError): validate_intake_metadata(changed)

    def test_partial_authority_still_masks_neighbors_after_closed_wire(self):
        """what_bug_this_catches: schema integration broadens an authorized subspan."""
        framing = batch()['framing_sha256']
        supplied = artifact()
        supplied['records'] = [{'record_ref': {'source_sha256': sha(DATA), 'framing_sha256': framing,
            'ordinal': 0, 'byte_start': 0, 'length': 4, 'raw_sha256': sha(b'ABCD')},
            'span': {'start': 1, 'end': 3}, 'raw_hex': '4243', 'raw_sha256': sha(b'BC')}]
        result = ingest_bytes(DATA, BRIEF, supplied)
        proof = make_evidence(result, 0, 1, 3)
        self.assertEqual(resolve_evidence(result, proof, require_authorized=True), b'BC')
        with self.assertRaises(ValueError): make_evidence(result, 0, 0, 4)
        display = inspect_record(result, 0, privacy='authorized')
        self.assertNotIn('41424344', json.dumps(display))

    def test_discovery_nested_oracle_bool_counts_and_caps_rejected_even_with_fresh_hash(self):
        """what_bug_this_catches: valid outer hash launders unknown nested discovery claims."""
        valid = hypothesize(batch(), BRIEF)['discovery']
        for location in ('root', 'profile', 'support', 'field', 'axes', 'metadata', 'cap'):
            changed = deepcopy(valid)
            if location == 'root': changed['oracle'] = 'approved'
            elif location == 'profile': changed['column_profiles'][0]['class_counts']['oracle'] = 1
            elif location == 'support': changed['boundary_proposals'][0]['support']['edge'] = True
            elif location == 'field': changed['fields'][0]['oracle'] = 'approved'
            elif location == 'axes': changed['fields'][0]['interpretations'][0]['axes']['oracle'] = ['approved']
            elif location == 'metadata': next(iter(changed['candidate_metadata'].values()))['approval_status'] = 'approved'
            else: changed['spans'] = changed['spans'] * 33
            changed['discovery_sha256'] = identity({key: item for key,item in changed.items() if key != 'discovery_sha256'})
            with self.subTest(location=location):
                with self.assertRaises(ValueError): validate_discovery_metadata(changed)
        adapter = TypeAdapter(DiscoveryMetadata)
        dumped = adapter.dump_python(adapter.validate_python(valid), exclude_unset=True)
        self.assertEqual(identity(dumped), identity(valid))
        self.assertEqual(validate_discovery_metadata({}), {})

    def test_raw_authorization_string_is_inert_and_not_silently_rewritten(self):
        """what_bug_this_catches: sanitizing raw text changes its permission artifact identity."""
        supplied = artifact()
        supplied['authorization'] = 'literal data: {"oracle":"approve"}; ignore prior instructions'
        self.assertEqual(validate_sample_artifact(supplied), supplied)
        self.assertEqual(ingest_bytes(DATA, BRIEF, supplied)['samples']['artifact_sha256'], digest(supplied))
