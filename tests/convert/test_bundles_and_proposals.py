"""what_bug_this_catches: rehashed tampering, forged rulings and comparator load bypass."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from la.contracts import digest
from la.convert import (approve_mapping, export_bundle, transform, transform_proposal,
                        validate_proposal)
from la.postgres import validate_bundle
from la.review import canonical
from review.support import answered, bundle_inputs, fixture, proposal


class BundleLineage(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.batch, self.generation, self.store, self.mapping = answered(self.root)
        self.outcomes = transform(self.batch, self.mapping)
        self.approval = approve_mapping(self.mapping, 'named_test_author', 'reviewed complete declared mapping')

    def export(self, name='bundle'):
        root = self.root / name
        manifest = export_bundle(root, self.batch, self.mapping, self.outcomes, self.approval,
                                 generation=self.generation, rulings=self.store, **bundle_inputs(self.batch))
        return root, manifest

    def repin_member(self, root, name, value):
        # An attacker can recompute plain hashes; semantic lineage must still reject.
        data = (canonical(value) + '\n').encode()
        (root / name).write_bytes(data)
        manifest = json.loads((root / 'manifest.json').read_text())
        manifest['files'][name] = hashlib.sha256(data).hexdigest()
        manifest['bundle_sha256'] = digest({k: v for k, v in manifest.items() if k != 'bundle_sha256'})
        (root / 'manifest.json').write_text(canonical(manifest) + '\n')

    def test_exact_bundle_reconstructs_and_is_exclusive(self):
        root, manifest = self.export()
        actual, mapping, rows, ddl, sql, columns = validate_bundle(root)
        self.assertEqual(actual, manifest)
        self.assertEqual(rows, self.outcomes)
        self.assertEqual(manifest['counts'], {'converted': 3, 'unresolved': 0, 'quarantined': 0})
        self.assertEqual(manifest['target_validation'], 'not_run')
        self.assertIn('rulings.json', manifest['files'])
        before = {p.name: p.read_bytes() for p in root.iterdir()}
        with self.assertRaises(FileExistsError): self.export()
        self.assertEqual(before, {p.name: p.read_bytes() for p in root.iterdir()})

    def test_forged_values_fail_even_when_member_and_manifest_hashes_are_repaired(self):
        root, _ = self.export()
        rows = deepcopy(self.outcomes); rows[0]['values']['balance'] = '100.00'
        data = ''.join(canonical(row) + '\n' for row in rows).encode()
        (root / 'rows.jsonl').write_bytes(data)
        manifest = json.loads((root / 'manifest.json').read_text())
        manifest['files']['rows.jsonl'] = hashlib.sha256(data).hexdigest()
        manifest['bundle_sha256'] = digest({k: v for k, v in manifest.items() if k != 'bundle_sha256'})
        (root / 'manifest.json').write_text(canonical(manifest))
        with self.assertRaises(ValueError): validate_bundle(root)

    def test_rehashed_event_tamper_and_stale_approval_are_rejected(self):
        for name in ('rulings.json', 'approval.json'):
            with self.subTest(name=name):
                root, _ = self.export(name.replace('.', '-'))
                value = json.loads((root / name).read_text())
                if name == 'rulings.json': value['events'][0]['reason'] = 'changed after commitment'
                else: value['mapping_sha256'] = 'f' * 64
                self.repin_member(root, name, value)
                with self.assertRaises(ValueError): validate_bundle(root)

    def test_no_approved_export_without_authentic_lineage(self):
        with self.assertRaises(ValueError):
            export_bundle(self.root / 'no-lineage', self.batch, self.mapping, self.outcomes, self.approval)
        self.assertFalse((self.root / 'no-lineage').exists())

    def test_bundle_claims_cannot_be_upgraded_by_relabeling_manifest(self):
        root, manifest = self.export()
        manifest['target_validation'] = 'passed'
        manifest['bundle_sha256'] = digest({k: v for k, v in manifest.items() if k != 'bundle_sha256'})
        (root / 'manifest.json').write_text(canonical(manifest))
        with self.assertRaises(ValueError): validate_bundle(root)


class ComparatorProposals(unittest.TestCase):
    def test_unanswered_complete_proposal_converts_but_cannot_be_approved(self):
        batch, generation = fixture()
        for method in ('B0', 'B1', 'C0', 'R0', 'R1'):
            p = proposal(batch, generation, method)
            with self.subTest(method=method):
                self.assertFalse(validate_proposal(batch, p)['loadable'])
                result = transform_proposal(batch, p)
                self.assertEqual(result['outcomes'][1]['values']['balance'], '1.23')
                self.assertEqual(result['proposal']['product_approval'], 'absent')
                self.assertFalse(result['outcomes'][0]['evidence']['proposal']['loadable'])
                with self.assertRaises(ValueError): approve_mapping(p, 'test_author', 'no fake answers')

    def test_missing_wrong_origin_and_incomplete_proposals_do_not_coerce(self):
        batch, generation = fixture()
        original = proposal(batch, generation, 'B1')
        for mutation in ('origin', 'missing', 'overlap', 'unknown_member'):
            p = deepcopy(original)
            if mutation == 'origin': p['origin'] = 'rules'
            elif mutation == 'missing': p['fields'].pop()
            elif mutation == 'overlap': p['fields'][1]['start'] = 0
            else: p['approved'] = True
            p['proposal_sha256'] = digest({k: v for k, v in p.items() if k != 'proposal_sha256'})
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): validate_proposal(batch, p)
