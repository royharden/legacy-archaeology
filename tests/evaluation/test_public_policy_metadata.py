"""Public metadata correction preserves values/bytes, not invalid policy axes."""
from copy import deepcopy
import unittest

from evaluation.corpus import development_layouts, build_development_variant
from evaluation.generator import canonical_records, serialize
from la.review.policy import validate_policy


class PublicPolicyMetadata(unittest.TestCase):
    def test_all_public_policies_are_legal_and_century_is_yymmdd_only(self):
        """what_bug_this_catches: oracle broker demands a forbidden YYYYMMDD window."""
        for layout in development_layouts():
            for field in layout['fields']:
                with self.subTest(variant=layout['variant_id'], field=field['semantic_target']):
                    validate_policy(field)
                    if field['data_type'] == 'date':
                        self.assertEqual('century_window' in field['policy'],
                                         field['policy']['format'] == 'YYMMDD')

    def test_metadata_correction_preserves_every_serialized_public_batch(self):
        """what_bug_this_catches: wire repair silently changes canonical inputs or rows."""
        for layout in development_layouts():
            old = deepcopy(layout)
            date = next(f for f in old['fields'] if f['data_type'] == 'date')
            date['policy']['century_window'] = [1970, 2069]
            balance = next(f for f in layout['fields'] if f['data_type'] == 'decimal')
            for batch in range(10):
                records = canonical_records(10000 + int(layout['variant_id'][-2:]) * 100 + batch,
                    scale=balance['policy']['scale'], precision=balance['policy']['precision'],
                    unsigned=balance['policy']['sign'] == 'unsigned')
                self.assertEqual(serialize(records, layout), serialize(records, old))
        self.assertEqual(build_development_variant('dev-01')['edition'], 'public-development-v3')
        with self.assertRaisesRegex(ValueError, 'retired v2'):
            build_development_variant('dev-01', edition='public-development-v2')


if __name__ == '__main__':
    unittest.main()
