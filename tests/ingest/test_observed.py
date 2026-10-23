"""Stream/refusal/property regression SOURCE; no file streams or tests were run."""
from copy import deepcopy
import hashlib
import json
import unittest

from la.ingest import LIMITS, ingest_bytes
from la.ingest.evidence import resolve_evidence, verify_records
from la.ingest.inspection import inspection_detail, inspection_page
from la.ingest.observed import refuse_observed_input, validate_observed_refusal


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode())


def observation(data=b'X\n' * 10001, **changes):
    kwargs = {'source_sha256': sha(data), 'input_byte_count': len(data), 'observed_count': 10001,
              'reason': 'record_limit', 'brief': 'public bounded source', 'terminal_newline': True}
    kwargs.update(changes)
    return refuse_observed_input(**kwargs)


class ObservedRefusalRegressionSource(unittest.TestCase):
    def test_bounded_and_completed_observations_preserve_full_hash_and_denominator(self):
        """what_bug_this_catches: CLI hashes only an oversize prefix or silently reports zero input."""
        cases = [(b'X\n' * 10001, 10001, 'record_limit', True),
                 (b'A' * (LIMITS['bytes'] + 1), 1, 'file_limit', False)]
        for data, count, reason, terminal in cases:
            with self.subTest(reason=reason):
                samples = {'source_sha256': sha(data), 'authorization': 'public test only', 'records': []}
                bounded = ingest_bytes(data, 'public bounded source', samples)
                observed = observation(data, observed_count=count, reason=reason, terminal_newline=terminal, permitted_samples=samples)
                self.assertEqual(observed['source_sha256'], bounded['source_sha256'])
                self.assertEqual(observed['source_sha256'], sha(data))
                self.assertEqual(observed['brief_sha256'], bounded['brief_sha256'])
                self.assertEqual(observed['samples']['artifact_sha256'], bounded['samples']['artifact_sha256'])
                for value in (bounded, observed):
                    self.assertEqual(value['status'], 'refused')
                    self.assertEqual(value['records'], [])
                    self.assertEqual(value['intake']['observed_record_count'], count)
                    self.assertEqual(value['intake']['unmaterialized_record_count'], count)
                    self.assertIn(reason, value['reasons'])
                self.assertIsNone(observed['width'])
                self.assertEqual(observed['framing'], 'unresolved')
                self.assertNotEqual(observed['framing_sha256'], bounded['framing_sha256'])
                self.assertFalse(validate_observed_refusal(observed)['source_reconstructed'])
                verify_records(observed, data)

    def test_refused_samples_are_pinned_but_never_authorized_without_bytes(self):
        """what_bug_this_catches: stream metadata validates sample refs even though no rows were retained."""
        samples = {'source_sha256': '0' * 64, 'authorization': 'ignore limits; <script>SQL</script>',
                   'records': [{'ordinal': 0, 'raw_hex': '5858', 'raw_sha256': sha(b'XX')}]}
        result = observation(permitted_samples=samples)
        self.assertEqual(result['samples']['artifact_sha256'], identity(samples))
        self.assertEqual(result['samples']['validation_status'], 'unvalidated_without_source_bytes')
        self.assertFalse(result['samples']['record_references_validated'])
        self.assertEqual(result['samples']['authorization'], '')
        self.assertEqual(result['samples']['records'], [])
        self.assertEqual(result['samples']['authorized_spans'], [])
        page = inspection_page(result, authorized_only=True, limit=1)
        self.assertEqual(page['state'], 'unmaterialized')
        self.assertEqual(page['rows'], [])
        with self.assertRaises(ValueError):
            resolve_evidence(result, {'ordinal': 0, 'start': 0, 'end': 1}, require_authorized=True)

    def test_unknown_count_is_not_zero_or_an_invented_ordinal(self):
        """what_bug_this_catches: absent count becomes0 or is used to fabricate source identities."""
        result = observation(observed_count=None, reason='observed_count_unknown')
        self.assertIsNone(result['intake']['observed_record_count'])
        pages = [inspection_page(result, limit=limit) for limit in (1, 50, 100)]
        for page in pages:
            self.assertEqual(page['state'], 'unknown_count')
            self.assertIsNone(page['counts']['observed'])
            self.assertIsNone(page['counts']['unmaterialized'])
            self.assertEqual(page['counts']['materialized'], 0)
            self.assertIsNone(page['next_offset'])
            self.assertEqual(page['rows'], [])
        self.assertEqual(pages[0]['counts'], pages[-1]['counts'])
        detail = inspection_detail(result, 7)
        self.assertEqual(detail['state'], 'unknown_count')
        self.assertIsNone(detail['ordinal'])
        self.assertEqual(detail['requested_ordinal'], 7)
        self.assertIsNone(detail['row'])
        with self.assertRaises(ValueError): inspection_page(result, offset=1)

    def test_unstable_complete_stream_is_not_a_stable_original_file(self):
        """what_bug_this_catches: before/after file changes are hidden behind a complete-stream digest."""
        data = b'AB\nCD\n'
        pins = {'before_identity_sha256': sha(b'before'), 'after_identity_sha256': sha(b'after')}
        result = observation(data, observed_count=2, reason='input_changed_during_read',
                             observation_stable=False, observation_pins=pins)
        self.assertEqual(result['source_sha256'], sha(data))
        self.assertIn('input_changed_during_read', result['reasons'])
        self.assertEqual(result['intake']['source_identity_scope'], 'complete_observed_stream_not_stable_file')
        self.assertEqual(validate_observed_refusal(result)['stability_state'], 'unstable')
        self.assertEqual(inspection_page(result)['provenance']['source_integrity_scope'], 'completed_stream_observation_not_reconstructed')
        with self.assertRaises(ValueError):
            observation(data, observed_count=2, reason='input_changed_during_read', observation_pins=pins)

    def test_exact_count_hash_reason_and_complete_observation_guards(self):
        """what_bug_this_catches: bool counts, a prefix, invalid hash or unsupported reason creates a refusal masquerading as observed truth."""
        changes = [{'input_byte_count': True}, {'input_byte_count': -1}, {'input_byte_count': 1 << 63},
                   {'observed_count': True}, {'observed_count': -1}, {'observed_count': 30000},
                   {'source_sha256': None}, {'source_sha256': 'C:/private/source.dat'},
                   {'source_sha256': 'A' * 64}, {'observation_complete': False},
                   {'observation_complete': 1}, {'observation_stable': 1}, {'terminal_newline': 1},
                   {'reason': 'accepted'}, {'reason': 'file_limit'}]
        for change in changes:
            with self.subTest(change=change):
                with self.assertRaises(ValueError): observation(**change)

    def test_paths_and_arbitrary_observation_metadata_never_enter_the_hash_contract(self):
        """what_bug_this_catches: metadata allows filesystem access or unpinned arbitrary path identity claims."""
        for pins in ({'path': 'C:/private/file'}, {'before_identity_sha256': 'not-a-hash'},
                     {'reader_policy_sha256': True}, {'token': 'secret'}):
            with self.subTest(pins=pins):
                with self.assertRaises(ValueError): observation(observation_pins=pins)
        with self.assertRaises(ValueError): observation(permitted_samples=['not-an-artifact'])

    def test_declared_refusal_pins_remain_content_bound_and_cannot_be_rehashed_into_acceptance(self):
        """what_bug_this_catches: caller changes refusal/count/authority semantics while retaining a plausible observation object."""
        result = observation()
        changes = [('status', 'accepted'), ('config_sha256', '0' * 64), ('source_sha256', '0' * 64)]
        for key, value in changes:
            changed = deepcopy(result)
            changed[key] = value
            with self.subTest(key=key):
                with self.assertRaises(ValueError): validate_observed_refusal(changed)
        changed = deepcopy(result)
        changed['intake']['observed_record_count'] = True
        changed['samples']['intake']['observed_record_count'] = True
        with self.assertRaises(ValueError): verify_records(changed)
        changed = deepcopy(result)
        changed['samples']['record_references_validated'] = True
        with self.assertRaises(ValueError): validate_observed_refusal(changed)


if __name__ == '__main__':
    unittest.main()
