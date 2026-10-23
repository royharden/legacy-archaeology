"""Inspection regression SOURCE only: never imported/collected/executed in Dirty Mode."""
from copy import deepcopy
import hashlib
import json
import unittest

from la.ingest import ingest_bytes
from la.ingest.inspection import inspection_detail, inspection_page
from la.inference import hypothesize

BRIEF = 'account_ref description balance effective_date status'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode())


def source(data=b'AB\r\nAB', records=None):
    return ingest_bytes(data, BRIEF, {'source_sha256': sha(data), 'authorization': 'public test authority',
                                    'records': [] if records is None else records})


def partial_source():
    data = b'SECRET\nPUBLIC\n'
    framing = identity({'version': 2, 'framing': 'LF', 'width': 6,
                        'width_candidates': [6], 'terminal_newline': True})
    ref = {'source_sha256': sha(data), 'framing_sha256': framing, 'ordinal': 0,
           'byte_start': 0, 'length': 6, 'raw_sha256': sha(b'SECRET')}
    sample = {'record_ref': ref, 'span': {'start': 2, 'end': 4},
              'raw_hex': '4352', 'raw_sha256': sha(b'CR')}
    return source(data, [sample])


class InspectionRegressionSource(unittest.TestCase):
    def test_source_ordinal_pagination_preserves_duplicate_bytes_and_offsets(self):
        """what_bug_this_catches: repeated bytes are deduplicated or page-relative ordinals replace source identity."""
        batch = source()
        first = inspection_page(batch, offset=0, limit=1)
        second = inspection_page(batch, offset=1, limit=1)
        self.assertEqual(first['next_offset'], 1)
        self.assertIsNone(second['next_offset'])
        left, right = first['rows'][0], second['rows'][0]
        self.assertEqual([left['ordinal'], right['ordinal']], [0, 1])
        self.assertEqual([left['record_ref']['byte_start'], right['record_ref']['byte_start']], [0, 4])
        self.assertEqual(left['record_ref']['raw_sha256'], right['record_ref']['raw_sha256'])
        self.assertNotEqual(left['record_ref'], right['record_ref'])
        self.assertEqual(left['separator']['raw_hex'], '0d0a')
        self.assertEqual(right['separator']['raw_hex'], '')
        tail = inspection_page(batch, offset=2, limit=1)
        self.assertEqual(tail['state'], 'empty')
        self.assertEqual(tail['rows'], [])

    def test_page_and_detail_bounds_reject_booleans_and_oversize_requests(self):
        """what_bug_this_catches: bool-as-int or oversized pagination defeats diagnostic output caps."""
        batch = source()
        for kwargs in ({'offset': True}, {'offset': -1}, {'offset': 3}, {'limit': 0}, {'limit': 101},
                       {'limit': True}, {'limit': '1'}, {'authorized_only': 1}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError): inspection_page(batch, **kwargs)
        for ordinal, kwargs in ((True, {}), (2, {}), (0, {'start': False}), (0, {'end': True}),
                                (0, {'start': -1}), (0, {'end': 3}), (0, {'end': 257}),
                                (0, {'start': 1, 'end': 1})):
            with self.subTest(ordinal=ordinal, kwargs=kwargs):
                with self.assertRaises(ValueError): inspection_detail(batch, ordinal, **kwargs)

    def test_authorized_only_masks_partial_neighbors_and_clips_overlays(self):
        """what_bug_this_catches: an inspection grid, separator or candidate overlay widens partial permission."""
        batch = partial_source()
        generation = hypothesize(batch, BRIEF)
        page = inspection_page(batch, offset=0, limit=2, authorized_only=True, generation=generation)
        self.assertEqual(page['access_mode'], 'permitted_spans_only')
        self.assertEqual(page['returned_record_count'], 1)
        self.assertEqual(page['not_authorized_count'], 1)
        row = page['rows'][0]
        self.assertIsNone(row['raw_hex'])
        self.assertFalse(row['record_state_disclosed'])
        self.assertEqual(row['reasons'], [])
        self.assertNotIn('raw_hex', row['separator'])
        exposed = [(cell['position'], cell['hex']) for cell in row['cells'] if not cell['redacted']]
        self.assertEqual(exposed, [(2, '43'), (3, '52')])
        self.assertTrue(all(cell['hex'] is None and cell['ascii'] is None for cell in row['cells'] if cell['redacted']))
        self.assertTrue(row['overlays'])
        self.assertTrue(all(2 <= item['start'] < item['end'] <= 4 and item['clipped'] for item in row['overlays']))
        serialized = json.dumps(page)
        self.assertNotIn('SECRET', serialized)
        self.assertNotIn(b'SECRET'.hex(), serialized)
        detail = inspection_detail(batch, 0, start=0, end=6, authorized_only=True)
        self.assertEqual(detail['row']['redacted_in_window'], 4)
        self.assertEqual(inspection_detail(batch, 1, authorized_only=True)['state'], 'not_authorized')

    def test_owner_view_is_explicit_diagnostic_and_high_bytes_are_never_replacement_text(self):
        """what_bug_this_catches: diagnostic ASCII becomes silently repaired typed output."""
        batch = source(b'A\xff\nB\x00\n')
        page = inspection_page(batch)
        self.assertEqual(page['access_mode'], 'local_owner_retained_source')
        self.assertTrue(page['diagnostic_only'])
        self.assertEqual(page['rows'][0]['cells'][1]['hex'], 'ff')
        self.assertEqual(page['rows'][0]['cells'][1]['ascii'], '\\xff')
        self.assertEqual(page['rows'][1]['cells'][1]['ascii'], '\\x00')
        self.assertIn('high_byte', page['rows'][0]['reasons'])
        self.assertEqual(page['rows'][0]['converted_values'], 'not_provided')
        self.assertNotIn('\ufffd', json.dumps(page, ensure_ascii=False))

    def test_unmaterialized_refusal_has_counts_and_no_invented_record_ref(self):
        """what_bug_this_catches: an early record-limit refusal looks like a zero-row success."""
        batch = source(b'X\n' * 10001)
        page = inspection_page(batch, limit=2)
        self.assertEqual(page['source_status'], 'refused')
        self.assertEqual(page['state'], 'unmaterialized')
        self.assertEqual(page['counts']['observed'], 10001)
        self.assertEqual(page['counts']['materialized'], 0)
        self.assertEqual(page['counts']['unmaterialized'], 10001)
        self.assertEqual(page['unmaterialized_in_page'], 2)
        self.assertEqual(page['rows'], [])
        detail = inspection_detail(batch, 1)
        self.assertEqual(detail['state'], 'unmaterialized')
        self.assertIsNone(detail['row'])

    def test_long_malformed_record_display_is_capped_without_losing_actual_width(self):
        """what_bug_this_catches: retained oversized records create an unbounded grid response."""
        batch = source(b'A' * 257 + b'\n' + b'B' * 257 + b'\n')
        row = inspection_page(batch, limit=1)['rows'][0]
        self.assertEqual(row['record_width'], 257)
        self.assertEqual(len(row['cells']), 256)
        self.assertEqual(row['outside_window_byte_count'], 1)
        self.assertIn('record_width_limit', row['reasons'])
        with self.assertRaises(ValueError): inspection_detail(batch, 0, end=257)

    def test_stale_and_rehashed_out_of_bounds_overlay_is_rejected(self):
        """what_bug_this_catches: a self-rehashed overlay is displayed outside its actual source record."""
        batch = source(b'AB\nCD\n')
        generation = hypothesize(batch, BRIEF)
        with self.assertRaises(ValueError):
            inspection_page(source(b'EF\nGH\n'), generation=generation)
        changed = deepcopy(generation)
        field = changed['candidates'][0]
        field['end'] = 3
        field['id'] = identity({key: value for key, value in field.items() if key != 'id'})
        changed['generation_sha256'] = identity({key: value for key, value in changed.items() if key != 'generation_sha256'})
        with self.assertRaises(ValueError): inspection_page(batch, generation=changed)
        tampered = deepcopy(batch)
        tampered['samples']['authorized_spans'] = [{'ordinal': 0, 'start': 0, 'end': 2, 'raw_hex': '4142', 'raw_sha256': sha(b'AB')}]
        with self.assertRaises(ValueError): inspection_page(tampered, authorized_only=True)

    def test_selected_mapping_overlay_remains_unverified_and_is_bound_to_generation(self):
        """what_bug_this_catches: a grid overlay presents mapping selection as execution or approval."""
        batch = source(b'AB\nCD\n')
        generation = hypothesize(batch, BRIEF)
        mapping = {'schema_version': 1, 'source_sha256': batch['source_sha256'],
                   'framing_sha256': batch['framing_sha256'], 'generation_sha256': generation['generation_sha256'],
                   'generation_binding': identity(generation), 'policy_sha256': generation['policy_sha256'],
                   'width': 2, 'fields': [generation['candidates'][0]], 'filler': [], 'supporting_event_ids': [],
                   'mapping_status': 'incomplete', 'unresolved': ['other_fields_unresolved']}
        mapping['mapping_sha256'] = identity(mapping)
        page = inspection_page(batch, generation=generation, mapping=mapping)
        self.assertEqual(page['provenance']['mapping_status'], 'incomplete')
        selected = [item for item in page['rows'][0]['overlays'] if item['kind'] == 'selected']
        self.assertTrue(selected)
        self.assertTrue(all(item['confirmation'] == 'selected_mapping_unverified' for item in selected))
        changed = deepcopy(mapping)
        changed['generation_binding'] = '0' * 64
        changed['mapping_sha256'] = identity({key: value for key, value in changed.items() if key != 'mapping_sha256'})
        with self.assertRaises(ValueError): inspection_page(batch, generation=generation, mapping=changed)

    def test_changed_sample_authority_and_forged_refusal_cannot_bypass_source_pins(self):
        """what_bug_this_catches: stale permission or a fake refusal flag bypasses source reconstruction."""
        batch = source(b'AB\nCD\n')
        generation = hypothesize(batch, BRIEF)
        changed_authority = deepcopy(batch)
        changed_authority['samples']['artifact_sha256'] = '0' * 64
        with self.assertRaises(ValueError): inspection_page(changed_authority, generation=generation)
        forged = deepcopy(batch)
        forged['records'][0].update(raw_hex='4158', raw_sha256=sha(b'AX'))
        forged['intake']['bounded_refusal'] = True
        forged['samples']['intake']['bounded_refusal'] = True
        with self.assertRaises(ValueError): inspection_page(forged)


if __name__ == '__main__':
    unittest.main()
