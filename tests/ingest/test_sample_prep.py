"""Permitted-sample preparation regression SOURCE; not executed in Dirty Mode.

Expected bytes, spans and hash domains are hand-derived from the literal inputs
below with stdlib hashlib/canonical JSON, independent of the helper's code.
"""
from copy import deepcopy
import hashlib
import json
import unittest

from la.ingest import ingest_bytes
from la.ingest.sample_prep import prepare_permitted_samples

DATA = b'ABCD\nEFGH\n'
TWINS = b'SAME\nSAME\n'
BRIEF = 'account_ref description balance effective_date status'
LABEL = 'public test author; explicit selection'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def batch_for(data):
    """Frame through the real producer with a zero-grant artifact (no samples)."""
    return ingest_bytes(data, BRIEF, {'source_sha256': sha(data), 'authorization': 'no samples granted', 'records': []})


class SamplePreparationRegressionSource(unittest.TestCase):

    def test_whole_record_uses_full_bytes_and_three_hash_domains(self):
        batch = batch_for(DATA)
        artifact, receipt = prepare_permitted_samples(batch, [{'ordinal': 1}], LABEL)
        entry = artifact['records'][0]
        self.assertEqual(entry['raw_hex'], b'EFGH'.hex())
        self.assertEqual(entry['raw_sha256'], sha(b'EFGH'))
        self.assertEqual(entry['span'], {'start': 0, 'end': 4})
        self.assertEqual(entry['record_ref']['byte_start'], 5)
        self.assertEqual(entry['record_ref']['ordinal'], 1)
        self.assertEqual(entry['record_ref']['raw_sha256'], sha(b'EFGH'))
        body = {key: value for key, value in artifact.items() if key != 'artifact_sha256'}
        self.assertEqual(artifact['artifact_sha256'], sha(canonical(body)))
        self.assertEqual(receipt['content_sha256'], artifact['artifact_sha256'])
        self.assertEqual(receipt['object_sha256'], sha(canonical(artifact)))
        self.assertEqual(receipt['file_sha256'], sha(canonical(artifact) + b'\n'))
        self.assertEqual(receipt['selections'][0]['kind'], 'whole_record')
        self.assertEqual(receipt['provider_permission'], 'not_established_by_label')

    def test_partial_span_hashes_only_the_slice_and_reingests(self):
        artifact, receipt = prepare_permitted_samples(batch_for(DATA), [{'ordinal': 0, 'start': 1, 'end': 3}], LABEL)
        entry = artifact['records'][0]
        self.assertEqual((entry['raw_hex'], entry['raw_sha256']), (b'BC'.hex(), sha(b'BC')))
        self.assertEqual(entry['record_ref']['raw_sha256'], sha(b'ABCD'))
        self.assertEqual(receipt['partial_span_count'], 1)
        fresh = ingest_bytes(DATA, BRIEF, artifact)
        self.assertEqual(fresh['status'], 'accepted')
        self.assertEqual(fresh['samples']['records'], [])
        self.assertEqual([(s['ordinal'], s['start'], s['end']) for s in fresh['samples']['authorized_spans']], [(0, 1, 3)])
        self.assertEqual(fresh['samples']['artifact_sha256'], receipt['object_sha256'])

    def test_identical_bytes_at_two_ordinals_remain_two_identities(self):
        artifact, receipt = prepare_permitted_samples(batch_for(TWINS), [{'ordinal': 0}, {'ordinal': 1}], LABEL)
        refs = [entry['record_ref'] for entry in artifact['records']]
        self.assertEqual([ref['byte_start'] for ref in refs], [0, 5])
        self.assertEqual(refs[0]['raw_sha256'], refs[1]['raw_sha256'])
        self.assertEqual(receipt['selected_record_count'], 2)

    def test_explicit_full_span_is_whole_and_order_is_preserved(self):
        selections = [{'ordinal': 1, 'start': 2, 'end': 4}, {'ordinal': 0, 'start': 0, 'end': 4}]
        artifact, receipt = prepare_permitted_samples(batch_for(DATA), selections, LABEL)
        self.assertEqual([e['record_ref']['ordinal'] for e in artifact['records']], [1, 0])
        self.assertEqual([s['kind'] for s in receipt['selections']], ['partial_span', 'whole_record'])

    def test_adjacent_spans_allowed_and_inputs_not_mutated(self):
        batch = batch_for(DATA)
        selections = [{'ordinal': 0, 'start': 0, 'end': 2}, {'ordinal': 0, 'start': 2, 'end': 4}]
        before = deepcopy((batch, selections))
        _, receipt = prepare_permitted_samples(batch, selections, LABEL)
        self.assertEqual(receipt['selected_byte_count'], 4)
        self.assertEqual((batch, selections), before)

    def test_record_pin_must_match(self):
        prepare_permitted_samples(batch_for(DATA), [{'ordinal': 0, 'record_raw_sha256': sha(b'ABCD')}], LABEL)
        with self.assertRaises(ValueError):
            prepare_permitted_samples(batch_for(DATA), [{'ordinal': 0, 'record_raw_sha256': sha(b'EFGH')}], LABEL)

    def test_refusals(self):
        batch = batch_for(DATA)
        cases = {
            'empty selection': ([], LABEL),
            'not a list': ({'ordinal': 0}, LABEL),
            'blank authorization': ([{'ordinal': 0}], '   '),
            'long authorization': ([{'ordinal': 0}], 'x' * 1001),
            'boolean ordinal': ([{'ordinal': True}], LABEL),
            'string offset': ([{'ordinal': 0, 'start': '1', 'end': 3}], LABEL),
            'float offset': ([{'ordinal': 0, 'start': 1.0, 'end': 3}], LABEL),
            'unknown key': ([{'ordinal': 0, 'authorized': True}], LABEL),
            'start without end': ([{'ordinal': 0, 'start': 1}], LABEL),
            'ordinal out of range': ([{'ordinal': 2}], LABEL),
            'empty span': ([{'ordinal': 0, 'start': 2, 'end': 2}], LABEL),
            'span past record': ([{'ordinal': 0, 'start': 2, 'end': 5}], LABEL),
            'duplicate': ([{'ordinal': 0}, {'ordinal': 0}], LABEL),
            'overlap': ([{'ordinal': 0, 'start': 0, 'end': 3}, {'ordinal': 0, 'start': 2, 'end': 4}], LABEL),
            'whole over partial': ([{'ordinal': 0, 'start': 1, 'end': 2}, {'ordinal': 0}], LABEL),
        }
        for name, (selections, label) in cases.items():
            with self.subTest(name), self.assertRaises(ValueError):
                prepare_permitted_samples(batch, selections, label)

    def test_sixty_four_record_boundary(self):
        data = b''.join(bytes([65 + i % 26]) * 256 + b'\n' for i in range(65))
        batch = batch_for(data)
        _, receipt = prepare_permitted_samples(batch, [{'ordinal': i} for i in range(64)], LABEL)
        self.assertEqual(receipt['selected_byte_count'], 16384)
        with self.assertRaises(ValueError):
            prepare_permitted_samples(batch, [{'ordinal': i} for i in range(65)], LABEL)

    def test_refused_batches_are_not_exposed(self):
        for data in (b'ABCD\r\nEFGH\n', b'AB\nCD\nE\nF\n', b'ABCD'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                prepare_permitted_samples(batch_for(data), [{'ordinal': 0}], LABEL)


if __name__ == '__main__':
    unittest.main()
