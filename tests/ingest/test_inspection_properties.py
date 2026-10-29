"""Deterministic metamorphic regression SOURCE only; not an executed property run."""
from copy import deepcopy
import hashlib
import json
import unittest

from la.ingest import ingest_bytes
from la.ingest.inspection import inspection_detail, inspection_page
from la.inference import hypothesize

BRIEF = 'account_ref description balance effective_date status'
ROWS = [b'ABCD', b'ABCD', b'EFGH', b'IJKL', b'MNOP']


def batch(partial=False):
    data = b'\n'.join(ROWS) + b'\n'
    source = hashlib.sha256(data).hexdigest()
    samples = []
    for ordinal, raw in enumerate(ROWS):
        if partial:
            # Identity-only nested ref pins data, while permission covers BC/FG/JK/NO only.
            descriptor = {'version': 2, 'framing': 'LF', 'width': 4,
                          'width_candidates': [4], 'terminal_newline': True}
            framing = hashlib.sha256(json.dumps(descriptor, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            ref = {'source_sha256': source, 'framing_sha256': framing, 'ordinal': ordinal,
                   'byte_start': ordinal * 5, 'length': 4, 'raw_sha256': hashlib.sha256(raw).hexdigest()}
            samples.append({'record_ref': ref, 'span': {'start': 1, 'end': 3},
                            'raw_hex': raw[1:3].hex(), 'raw_sha256': hashlib.sha256(raw[1:3]).hexdigest()})
        else:
            samples.append({'ordinal': ordinal, 'raw_hex': raw.hex(), 'raw_sha256': hashlib.sha256(raw).hexdigest()})
    return ingest_bytes(data, BRIEF, {'source_sha256': source, 'authorization': 'public property fixtures', 'records': samples})


class InspectionPropertySource(unittest.TestCase):
    def test_every_page_partition_preserves_original_rows_counts_and_reasons(self):
        """what_bug_this_catches: paging changes row identity, omits duplicates or alters shared denominators."""
        source = batch()
        complete = inspection_page(source, limit=100)
        expected = complete['rows']
        for size in (1, 2, 3, 5, 100):
            with self.subTest(page_size=size):
                collected, offset = [], 0
                while True:
                    page = inspection_page(source, offset=offset, limit=size)
                    self.assertEqual(page['counts'], complete['counts'])
                    collected.extend(page['rows'])
                    if page['next_offset'] is None: break
                    self.assertGreater(page['next_offset'], offset)
                    offset = page['next_offset']
                self.assertEqual(collected, expected)

    def test_window_partitions_preserve_byte_positions_refs_masks_and_visible_bytes(self):
        """what_bug_this_catches: smaller detail windows reveal previously masked bytes or renumber offsets."""
        source = batch(partial=True)
        for ordinal, raw in enumerate(ROWS):
            full = inspection_detail(source, ordinal, start=0, end=4, authorized_only=True)['row']
            expected = {cell['position']: cell for cell in full['cells'] if not cell['redacted']}
            for cut in (1, 2, 3):
                seen = {}
                for start, end in ((0, cut), (cut, 4)):
                    detail = inspection_detail(source, ordinal, start=start, end=end, authorized_only=True)
                    if detail['row'] is None: continue
                    self.assertEqual(detail['row']['record_ref'], full['record_ref'])
                    self.assertEqual(detail['row']['reasons'], full['reasons'])
                    for cell in detail['row']['cells']:
                        if not cell['redacted']: seen[cell['position']] = cell
                self.assertEqual(seen, expected)
            self.assertEqual([(pos, cell['hex']) for pos, cell in expected.items()], [(1, f'{raw[1]:02x}'), (2, f'{raw[2]:02x}')])

    def test_overlay_position_union_is_window_invariant_and_never_crosses_authority(self):
        """what_bug_this_catches: splitting ambiguity evidence changes overlays or expands partial permissions."""
        source = batch(partial=True)
        generation = hypothesize(source, BRIEF)
        def positions(row):
            result = {}
            if row:
                for item in row['overlays']:
                    result.setdefault(item.get('candidate_id', item['kind']), set()).update(range(item['start'], item['end']))
            return result
        full = positions(inspection_detail(source, 0, start=0, end=4, authorized_only=True, generation=generation)['row'])
        self.assertTrue(full)
        for cut in (1, 2, 3):
            merged = {}
            for start, end in ((0, cut), (cut, 4)):
                row = inspection_detail(source, 0, start=start, end=end, authorized_only=True, generation=generation)['row']
                for candidate, indexes in positions(row).items(): merged.setdefault(candidate, set()).update(indexes)
            self.assertEqual(merged, full)
            self.assertTrue(all(indexes <= {1, 2} for indexes in merged.values()))

    def test_all_page_shapes_reject_the_same_stale_generation(self):
        """what_bug_this_catches: stale lineage rejection depends on which row/page is visible."""
        source = batch()
        generation = hypothesize(source, BRIEF)
        changed = deepcopy(source)
        changed['samples']['artifact_sha256'] = '0' * 64
        for offset, limit in ((0, 1), (2, 2), (5, 100)):
            with self.subTest(offset=offset, limit=limit):
                with self.assertRaises(ValueError): inspection_page(changed, offset=offset, limit=limit, generation=generation)


if __name__ == '__main__':
    unittest.main()
