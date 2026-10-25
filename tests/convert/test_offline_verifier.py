"""what_bug_this_catches: self-rehashed bundles gaining authority and silent proof gaps.

All cases are test SOURCE in Dirty Mode; no verifier or test is executed here.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from la.convert import (approve_mapping, export_bundle, transform, verify_bundle,
                        write_verification_receipt)
from la.postgres import TargetConfig, database_check, validate_bundle
from la.review import canonical, digest
from review.support import RAW, answered, bundle_inputs, fixture


class OfflineVerifier(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.batch, self.generation, self.store, self.mapping = answered(self.root)
        self.outcomes = transform(self.batch, self.mapping)
        self.approval = approve_mapping(self.mapping, 'regression_author', 'explicit complete mapping')
        self.bundle = self.root / 'bundle'
        self.manifest = export_bundle(self.bundle, self.batch, self.mapping, self.outcomes, self.approval,
                                      generation=self.generation, rulings=self.store, **bundle_inputs(self.batch))

    def check(self, *, pinned=True):
        return verify_bundle(self.bundle, expected_bundle_sha256=self.manifest['bundle_sha256'] if pinned else None)

    def codes(self, result):
        return {d['code'] for d in result['differences']}

    def repin(self, name, data):
        if not isinstance(data, bytes): data = (canonical(data) + '\n').encode()
        (self.bundle / name).write_bytes(data)
        manifest = json.loads((self.bundle / 'manifest.json').read_text())
        manifest['files'][name] = hashlib.sha256(data).hexdigest()
        manifest['bundle_sha256'] = digest({k: v for k, v in manifest.items() if k != 'bundle_sha256'})
        (self.bundle / 'manifest.json').write_text(canonical(manifest) + '\n')
        return manifest

    def test_consistent_manifest_without_external_bundle_pin_is_untrusted(self):
        result = self.check(pinned=False)
        self.assertEqual(result['integrity_status'], 'verified')
        self.assertEqual(result['pin_origin'], 'manifest_only')
        self.assertEqual(result['pin_status'], 'missing')
        self.assertFalse(result['loadable'])
        self.assertIn('external_bundle_pin_required', self.codes(result))

    def test_matching_external_pins_bind_candidate_without_claiming_target_acceptance(self):
        result = verify_bundle(self.bundle, expected_bundle_sha256=self.manifest['bundle_sha256'],
                               expected_source_sha256=self.batch['source_sha256'],
                               expected_mapping_sha256=self.mapping['mapping_sha256'])
        self.assertTrue(result['loadable'])
        self.assertEqual(result['differences'], [])
        self.assertEqual(result['pin_status'], 'matched')
        self.assertTrue(result['target_authority_required'])
        self.assertEqual(result['target_validation'], 'not_run')
        self.assertEqual(result['row_parity'], 'not_run')
        self.assertEqual(result['product_acceptance'], 'pending')

    def test_source_or_mapping_pin_alone_does_not_authorize_approval_bytes(self):
        result = verify_bundle(self.bundle, expected_source_sha256=self.batch['source_sha256'],
                               expected_mapping_sha256=self.mapping['mapping_sha256'])
        self.assertEqual(result['pin_status'], 'partial')
        self.assertFalse(result['loadable'])
        with self.assertRaises(ValueError):
            validate_bundle(self.bundle, expected_source_sha256=self.batch['source_sha256'])

    def test_incorrect_and_invalid_external_pins_are_visible(self):
        for expected, code in [('f' * 64, 'external_pin_mismatch'), ('not-a-sha', 'invalid_external_pin')]:
            with self.subTest(expected=expected):
                result = verify_bundle(self.bundle, expected_bundle_sha256=expected)
                self.assertFalse(result['loadable'])
                self.assertIn(code, self.codes(result))

    def test_missing_original_inputs_is_incomplete_even_with_matching_bundle_pin(self):
        manifest = self.repin('inputs.json', {'schema_version': 1, 'brief': None, 'permitted_samples': None})
        result = verify_bundle(self.bundle, expected_bundle_sha256=manifest['bundle_sha256'])
        self.assertEqual(result['integrity_status'], 'incomplete')
        self.assertFalse(result['loadable'])
        self.assertIn('original_inputs_not_embedded', self.codes(result))

    def test_intake_config_relabeling_cannot_survive_reconstruction(self):
        batch = deepcopy(self.batch); batch['config_sha256'] = 'f' * 64
        self.repin('source.json', batch)
        result = self.check(pinned=False)
        self.assertEqual(result['integrity_status'], 'failed')
        self.assertIn('intake_config_sample_lineage_mismatch', self.codes(result))

    def test_self_rehashed_altered_values_swapped_and_duplicated_refs_fail(self):
        originals = (self.bundle / 'rows.jsonl').read_bytes()
        for mutation in ('value', 'swapped', 'duplicate', 'missing'):
            rows = deepcopy(self.outcomes)
            if mutation == 'value': rows[1]['values']['balance'] = '123.00'
            elif mutation == 'swapped': rows[0], rows[1] = rows[1], rows[0]
            elif mutation == 'duplicate': rows[1] = deepcopy(rows[0])
            else: rows.pop()
            data = ''.join(canonical(row) + '\n' for row in rows).encode()
            self.repin('rows.jsonl', data)
            with self.subTest(mutation=mutation):
                result = self.check(pinned=False)
                self.assertEqual(result['integrity_status'], 'failed')
                self.assertFalse(result['loadable'])
                self.assertTrue(self.codes(result) & {'duplicate_record_ref', 'deterministic_outcome_mismatch'})
            self.repin('rows.jsonl', originals)

    def test_sql_and_load_instruction_changes_are_detected_without_execution(self):
        for member in ('schema.sql', 'migrate.sql', 'LOAD.md'):
            original = (self.bundle / member).read_bytes()
            self.repin(member, original + b'\nDROP SCHEMA unrelated CASCADE;\n')
            result = self.check(pinned=False)
            self.assertEqual(result['integrity_status'], 'failed')
            self.assertTrue(self.codes(result) & {'deterministic_sql_mismatch', 'deterministic_load_instructions_mismatch'})
            self.repin(member, original)

    def test_stale_producer_code_pin_is_not_current_verified_load_source(self):
        manifest = json.loads((self.bundle / 'manifest.json').read_text())
        manifest['producer_code_sha256'] = 'f' * 64
        manifest['bundle_sha256'] = digest({k: v for k, v in manifest.items() if k != 'bundle_sha256'})
        (self.bundle / 'manifest.json').write_text(canonical(manifest))
        result = verify_bundle(self.bundle, expected_bundle_sha256=manifest['bundle_sha256'])
        self.assertEqual(result['integrity_status'], 'incomplete')
        self.assertIn('current_code_mismatch', self.codes(result))
        self.assertFalse(result['loadable'])

    def test_missing_sequence_or_duplicate_ruling_event_rejects_lineage(self):
        original = json.loads((self.bundle / 'rulings.json').read_text())
        for mutation in ('sequence', 'duplicate', 'approval'):
            lineage = deepcopy(original)
            if mutation == 'sequence': lineage['events'][0]['sequence'] = 9
            elif mutation == 'duplicate': lineage['events'].append(deepcopy(lineage['events'][0]))
            else: lineage['events'][0]['reason'] = 'not the committed event'
            self.repin('rulings.json', lineage)
            result = self.check(pinned=False)
            self.assertEqual(result['integrity_status'], 'failed')
        self.repin('rulings.json', original)

    def test_member_escape_unknown_files_and_duplicate_json_are_rejected(self):
        (self.bundle / 'unexpected.sql').write_text('SELECT 1')
        self.assertTrue(self.codes(self.check()) & {'member_count_limit', 'unexpected_member'})
        (self.bundle / 'unexpected.sql').unlink()
        original = (self.bundle / 'manifest.json').read_bytes()
        (self.bundle / 'manifest.json').write_bytes(b'{"schema_version":1,"schema_version":1}')
        self.assertIn('duplicate_json_member', self.codes(self.check()))
        (self.bundle / 'manifest.json').write_bytes(original)
        manifest = json.loads(original)
        manifest['files']['../outside.json'] = 'a' * 64
        manifest['bundle_sha256'] = digest({k: v for k, v in manifest.items() if k != 'bundle_sha256'})
        (self.bundle / 'manifest.json').write_text(canonical(manifest))
        # The closed manifest schema may reject traversal before member-set
        # comparison. Both paths must still fail integrity and block loading.
        result=self.check()
        self.assertEqual(result['integrity_status'],'failed')
        self.assertFalse(result['loadable'])
        self.assertTrue(self.codes(result) & {'referenced_member_set_mismatch','invalid_artifact'})

    def test_symlink_member_and_root_are_refused(self):
        path = self.bundle / 'LOAD.md'; original = path.read_bytes(); path.unlink()
        outside = self.root / 'outside'; outside.write_bytes(original)
        try: path.symlink_to(outside)
        except OSError:
            path.write_bytes(original)
            self.skipTest('OS did not permit this test-owned symlink')
        self.assertIn('member_path_escape', self.codes(self.check()))
        root_link = self.root / 'bundle-link'
        root_link.symlink_to(self.bundle, target_is_directory=True)
        self.assertIn('bundle_path_link_escape', self.codes(verify_bundle(root_link)))

    def test_member_and_total_byte_limits_are_enforced_before_parsing(self):
        from la.convert.bundle import MEMBER_LIMITS
        limits = dict(MEMBER_LIMITS, **{'source.json': 1})
        with patch('la.convert.bundle.MEMBER_LIMITS', limits):
            self.assertIn('member_size_limit', self.codes(self.check()))
        with patch('la.convert.bundle.TOTAL_LIMIT', 1):
            self.assertIn('total_size_limit', self.codes(self.check()))

    def test_verification_receipt_is_immutable_separate_and_hash_bound(self):
        result = self.check()
        output = self.root / 'verification.json'
        before = {p.name: p.read_bytes() for p in self.bundle.iterdir()}
        write_verification_receipt(output, result)
        self.assertEqual(json.loads(output.read_text()), result)
        with self.assertRaises(FileExistsError): write_verification_receipt(output, result)
        with self.assertRaises(ValueError): write_verification_receipt(self.bundle / 'audit.json', result)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.bundle.iterdir()})
        forged = dict(result, loadable=False)
        with self.assertRaises(ValueError): write_verification_receipt(self.root / 'forged.json', forged)

    def test_target_refuses_unpinned_authorized_config_before_driver(self):
        config = TargetConfig('explicit-authority', 'disposable', 'leastpriv', 'pinned-version', 17)
        with patch('la.postgres.execution.driver_and_connect', side_effect=AssertionError('must not connect')):
            result = database_check(self.bundle, dsn='unused', authorized=True, target_config=config)
        self.assertEqual(result['target_validation'], 'not_run')
        self.assertEqual(result['reason'], 'external_expected_bundle_pin_required')

    def test_target_wrong_pin_returns_structured_offline_failure_without_driver(self):
        config = TargetConfig('explicit-authority', 'disposable', 'leastpriv', 'pinned-version', 17,
                              expected_bundle_sha256='f' * 64)
        with patch('la.postgres.execution.driver_and_connect', side_effect=AssertionError('must not connect')):
            result = database_check(self.bundle, dsn='unused', authorized=True, target_config=config)
        self.assertEqual(result['target_validation'], 'failed')
        self.assertEqual(result['execution_status'], 'refused_before_connection')
        self.assertIn('external_pin_mismatch', self.codes(result['verification']))
        self.assertEqual(result['verification']['target_validation'], 'not_run')

    def test_entire_alternate_valid_bundle_does_not_match_external_original_pin(self):
        changed = [b'0008' + RAW[0][4:], RAW[1], RAW[2]]
        batch, generation = fixture(raw_rows=changed)
        batch, generation, store, mapping = answered(self.root / 'other', batch, generation)
        approval = approve_mapping(mapping, 'different_author', 'alternate explicit source')
        other = self.root / 'other-bundle'
        manifest = export_bundle(other, batch, mapping, transform(batch, mapping), approval,
                                 generation=generation, rulings=store, **bundle_inputs(batch))
        self.assertNotEqual(manifest['source_sha256'], self.manifest['source_sha256'])
        result = verify_bundle(other, expected_bundle_sha256=self.manifest['bundle_sha256'])
        self.assertEqual(result['integrity_status'], 'verified')
        self.assertEqual(result['pin_status'], 'mismatch')
        self.assertFalse(result['loadable'])
