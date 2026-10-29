"""Hand-authored target-observation regression SOURCE; no database access."""
from copy import deepcopy
import unittest

from evaluator_support import gold, product_rows, mapping
from evaluation.artifacts import digest
from evaluation.target import score_execution_receipt, score_target

BUNDLE = 'b' * 64


def sealed_receipt(*, wrong_amount=False, producer_match=True):
    rows = product_rows()[:3]
    for row in rows:
        row['mapping_sha256'] = mapping()['mapping_sha256']
    if wrong_amount:
        rows[0]['values']['balance'] = '999.99'
    target = {'database': 'synthetic', 'role': 'synthetic', 'host': '127.0.0.1',
              'port': 29999, 'server_version_num': 170000, 'scope': 'disposable_local_test'}
    artifact = {'schema_version': 1, 'bundle_sha256': BUNDLE, 'run_id': 'fake-run',
                'namespace': 'la_' + 'c' * 32, 'target': target,
                'capture': 'fresh_connection_after_commit', 'rows': rows}
    artifact['observations_sha256'] = digest(artifact)
    receipt = {'schema_version': 1, 'bundle_sha256': BUNDLE, 'run_id': 'fake-run',
               'namespace': artifact['namespace'], 'target': target, 'committed': True,
               'execution_status': 'committed_readback', 'observations': rows,
               'observation_artifact': artifact, 'producer_projection_match': producer_match,
               'identity': {'bundle_sha256': BUNDLE, 'mapping_sha256': mapping()['mapping_sha256'],
                            'source_sha256': mapping()['source_sha256']}}
    receipt['receipt_sha256'] = digest(receipt)
    return receipt


class TargetLineage(unittest.TestCase):
    def test_actual_rows_score_but_producer_flag_never_accepts_target(self):
        """what_bug_this_catches: producer_projection_match substitutes for oracle."""
        exact = score_execution_receipt(gold(), sealed_receipt(), mapping(), bundle_sha256=BUNDLE, edition='test')
        self.assertEqual(exact['row_parity'], 'exact')
        self.assertEqual(exact['target_validation'], 'indeterminate')
        wrong = score_execution_receipt(gold(), sealed_receipt(wrong_amount=True), mapping(),
                                         bundle_sha256=BUNDLE, edition='test')
        self.assertEqual(wrong['target_validation'], 'failed')
        self.assertEqual(wrong['score']['semantic_rows']['denominator'], 3)
        self.assertEqual(wrong['score']['semantic_rows']['numerator'], 2)

    def test_hash_bundle_commit_and_target_lineage(self):
        """what_bug_this_catches: correct rows from wrong/uncommitted target are accepted."""
        tampered = sealed_receipt()
        tampered['observation_artifact']['rows'][0]['values']['balance'] = '0.00'
        with self.assertRaises(ValueError):
            score_execution_receipt(gold(), tampered, mapping(), bundle_sha256=BUNDLE, edition='test')
        for field, value in (('committed', False), ('bundle_sha256', 'e' * 64), ('namespace', 'wrong')):
            with self.subTest(field=field):
                receipt = sealed_receipt()
                receipt[field] = value
                receipt['receipt_sha256'] = digest({k: v for k, v in receipt.items() if k != 'receipt_sha256'})
                with self.assertRaises(ValueError):
                    score_execution_receipt(gold(), receipt, mapping(), bundle_sha256=BUNDLE, edition='test')

    def test_not_run_and_lost_ack_are_distinct(self):
        """what_bug_this_catches: missing/unknown commit is converted to a pass."""
        for status, expected in (('not_run', 'not_run'), ('commit_outcome_unknown', 'indeterminate')):
            receipt = {'execution_status': status, 'reason': 'synthetic'}
            receipt['receipt_sha256'] = digest(receipt)
            report = score_execution_receipt(gold(), receipt, mapping(), bundle_sha256=BUNDLE, edition='test')
            self.assertEqual(report['target_validation'], expected)
            self.assertEqual(report['row_parity'], 'not_run')
        self.assertEqual(score_target(gold(), None, bundle_sha256=BUNDLE,
                                     mapping_sha256='a' * 64, edition='test')['target_validation'], 'not_run')


if __name__ == '__main__':
    unittest.main()
