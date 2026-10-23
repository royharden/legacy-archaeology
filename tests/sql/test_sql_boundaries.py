"""what_bug_this_catches: interpolated business data and duplicate-record collapse."""
from copy import deepcopy
import tempfile
import unittest

from la.convert import sql_artifacts
from review.support import answered


class SqlBoundaries(unittest.TestCase):
    def test_data_parameters_provenance_key_and_declared_types(self):
        with tempfile.TemporaryDirectory() as root:
            _, _, _, mapping = answered(root)
        ddl, sql, columns = sql_artifacts(mapping)
        self.assertIn('PRIMARY KEY ("source_sha256", "ordinal")', ddl)
        self.assertIn('numeric(6,2)', ddl)
        self.assertIn('"effective_date" date NOT NULL', ddl)
        self.assertEqual(sql.count('%s'), len(columns))
        self.assertNotIn('0007', sql)
        self.assertNotIn('ON CONFLICT', sql)
        self.assertNotIn('UPSERT', sql.upper())

    def test_vocabulary_enters_ddl_as_hex_not_sql_source(self):
        with tempfile.TemporaryDirectory() as root:
            _, _, _, mapping = answered(root)
        hostile = "A'); DROP TABLE migrated_records; --"
        status = next(f for f in mapping['fields'] if f['semantic_target'] == 'status')
        status['policy']['allowed_codes'] = [hostile]
        ddl, _, _ = sql_artifacts(mapping)
        self.assertNotIn(hostile, ddl)
        self.assertIn(hostile.encode('ascii').hex(), ddl)

    def test_incomplete_sql_is_a_refusal_not_generic_text_fallback(self):
        ddl, sql, columns = sql_artifacts({'mapping_status': 'incomplete'})
        self.assertIn('INCOMPLETE', ddl)
        self.assertIn('BLOCKED', sql)
        self.assertEqual(columns, [])
        self.assertNotIn('CREATE TABLE', ddl)

    def test_direct_sql_api_rejects_nonallowlisted_column_names(self):
        with tempfile.TemporaryDirectory() as root:
            _, _, _, mapping = answered(root)
        mapping['fields'][0]['semantic_target'] = 'balance"; DROP TABLE x; --'
        with self.assertRaises(ValueError): sql_artifacts(mapping)
