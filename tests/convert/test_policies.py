"""what_bug_this_catches: coercion, lost identifier zeros, sentinel confusion and rounding."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from la.contracts import digest
from la.convert import ConversionError, approve_mapping, decode_value, transform, validate_mapping
from la.inference import declare_filler
from la.review import build_mapping, questions
from review.support import RAW, answered, fixture


def field(raw, kind='text', **policy):
    target = 'balance' if kind == 'decimal' else 'effective_date' if kind == 'date' else 'description'
    base = {'padding_byte': ' ', 'padding_side': 'none', 'trim': False, 'nullable': False}
    base.update(policy)
    return {'semantic_target': target, 'data_type': kind, 'start': 0, 'end': len(raw), 'policy': base}


class DeclaredPolicies(unittest.TestCase):
    def test_hand_calculated_decimal_sign_scale_and_precision(self):
        cases = [(b'+00123', 2, 'leading', '1.23'), (b'00123-', 3, 'trailing', '-0.123'),
                 (b'00000', 0, 'unsigned', '0'), (b'-00000', 2, 'leading', '0.00'),
                 (b'999999', 3, 'unsigned', '999.999')]
        for raw, scale, sign, expected in cases:
            with self.subTest(raw=raw, scale=scale):
                self.assertEqual(decode_value(raw, field(raw, 'decimal', scale=scale, precision=6, sign=sign)), expected)
        for raw, policy in [(b'1000000', {'precision': 6}), (b'0012-', {'sign': 'leading'}),
                            (b'1.234', {}), (b' 0123', {}), (b'++123', {'sign': 'leading'})]:
            p = {'scale': 2, 'precision': 6, 'sign': 'unsigned', **policy}
            with self.subTest(raw=raw), self.assertRaises(ConversionError):
                decode_value(raw, field(raw, 'decimal', **p))

    def test_text_empty_null_identifier_zero_and_explicit_padding_are_distinct(self):
        self.assertEqual(decode_value(b'0007', field(b'0007')), '0007')
        self.assertEqual(decode_value(b'0', field(b'0')), '0')
        self.assertEqual(decode_value(b'    ', field(b'    ', padding_side='right', trim=True)), '')
        self.assertEqual(decode_value(b' A ', field(b' A ')), ' A ')
        self.assertEqual(decode_value(b'  AB', field(b'  AB', padding_side='left', trim=True)), 'AB')
        self.assertIsNone(decode_value(b'9999', field(b'9999', sentinels={'9999': 'null'}, nullable=True)))
        with self.assertRaises(ConversionError):
            decode_value(b' AB ', field(b' AB ', padding_side='right', trim=True))
        for raw in (b'\xffABC', b'A\x00BC'):
            with self.subTest(raw=raw), self.assertRaises(ConversionError): decode_value(raw, field(raw))
        with self.assertRaises(ConversionError):
            decode_value(b'9999', field(b'9999', sentinels={'9999': 'null'}, nullable=False))

    def test_dates_require_calendar_and_explicit_century_window(self):
        self.assertEqual(decode_value(b'20240229', field(b'20240229', 'date', format='YYYYMMDD')), '2024-02-29')
        self.assertEqual(decode_value(b'700101', field(b'700101', 'date', format='YYMMDD', century_window=[1970, 2069])), '1970-01-01')
        self.assertEqual(decode_value(b'690101', field(b'690101', 'date', format='YYMMDD', century_window=[1970, 2069])), '2069-01-01')
        for raw in (b'20230229', b'20241301', b'00000000'):
            with self.subTest(raw=raw), self.assertRaises(ConversionError):
                decode_value(raw, field(raw, 'date', format='YYYYMMDD'))
        with self.assertRaises(ConversionError):
            decode_value(b'240229', field(b'240229', 'date', format='YYMMDD'))
        self.assertIsNone(decode_value(b'        ', field(b'        ', 'date', format='YYYYMMDD',
                                                        nullable=True, sentinels={'        ': 'null'})))

    def test_status_only_uses_disclosed_vocabulary(self):
        f = field(b'X'); f['semantic_target'] = 'status'
        self.assertEqual(decode_value(b'X', f), 'X')
        f['policy']['allowed_codes'] = ['A', 'B']
        with self.assertRaises(ConversionError): decode_value(b'X', f)


class MappingAndOutcomes(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_every_ordinal_once_and_duplicate_business_records_survive(self):
        batch, generation, store, mapping = answered(self.root)
        outcomes = transform(batch, mapping)
        self.assertEqual([o['record_ref']['ordinal'] for o in outcomes], [0, 1, 2])
        self.assertEqual([o['outcome'] for o in outcomes], ['converted'] * 3)
        self.assertEqual(outcomes[0]['values'], {'account_ref': '0007', 'description': 'AB', 'balance': '0.00', 'effective_date': '2024-02-29', 'status': 'A'})
        self.assertEqual(outcomes[1]['values'], {'account_ref': '0007', 'description': '', 'balance': '1.23', 'effective_date': '2024-03-01', 'status': 'B'})
        self.assertEqual(outcomes[0]['values'], outcomes[2]['values'])
        self.assertNotEqual(outcomes[0]['record_ref'], outcomes[2]['record_ref'])

    def test_malformed_value_is_one_quarantine_without_partial_typed_row(self):
        invalid = RAW[1][:14] + b'20230229' + RAW[1][22:]
        batch, generation = fixture(raw_rows=[RAW[0], invalid, RAW[2]])
        batch, generation, store, mapping = answered(self.root, batch, generation)
        outcomes = transform(batch, mapping)
        self.assertEqual([o['outcome'] for o in outcomes], ['converted', 'quarantined', 'converted'])
        self.assertEqual(outcomes[1]['values'], {})
        self.assertEqual(outcomes[1]['reasons'], ['invalid_calendar_date'])
        self.assertEqual(outcomes[1]['evidence']['failure_span'], {'start': 14, 'end': 22, 'semantic_target': 'effective_date'})

    def test_missing_interpretation_never_becomes_raw_text_or_approval(self):
        batch, generation = fixture()
        from la.review import RulingStore
        store = RulingStore(self.root / 'incomplete.sqlite'); store.bind_generation(generation)
        mapping = build_mapping(batch, generation, store)
        self.assertEqual(mapping['mapping_status'], 'incomplete')
        outcomes = transform(batch, mapping)
        self.assertTrue(all(o['outcome'] == 'unresolved' and o['values'] == {} for o in outcomes))
        with self.assertRaises(ValueError): approve_mapping(mapping, 'test_author', 'cannot approve unknown')

    def test_filler_is_explicit_and_invalidates_prior_answers(self):
        batch, generation = fixture(filler=True)
        batch, generation, store, mapping = answered(self.root, batch, generation)
        self.assertEqual(mapping['mapping_status'], 'incomplete')
        changed = declare_filler(batch, generation, [{'start': 23, 'end': 25}], actor='test_author', reason='declared trailing filler')
        store.bind_generation(changed)
        with self.assertRaises(ValueError): store.projection(generation)
        self.assertEqual(build_mapping(batch, changed, store)['mapping_status'], 'incomplete')
        for q in questions(changed):
            c = next(c for c in changed['candidates'] if c['semantic_target'] == q['semantic_target'])
            store.answer(changed, q['id'], c['id'], 'test_author', 'reaffirm after filler declaration', 0, 'filler-' + q['semantic_target'])
        self.assertEqual(build_mapping(batch, changed, store)['mapping_status'], 'complete')

    def test_overlap_duplicate_name_missing_field_and_uncovered_bytes_fail(self):
        batch, generation, store, mapping = answered(self.root)
        for mutation in ('overlap', 'duplicate_name', 'missing_field', 'uncovered'):
            m = deepcopy(mapping)
            if mutation == 'overlap': m['fields'][1]['start'] = 0
            elif mutation == 'duplicate_name': m['fields'][1]['semantic_target'] = m['fields'][0]['semantic_target']
            elif mutation == 'missing_field': m['fields'].pop()
            else: m['fields'][0]['start'] += 1
            for f in m['fields']: f['id'] = digest({k: v for k, v in f.items() if k != 'id'})
            m['mapping_sha256'] = digest({k: v for k, v in m.items() if k != 'mapping_sha256'})
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): validate_mapping(batch, m, require_complete=True)
