"""Future result-publication regression SOURCE; no construction-time execution."""
from copy import deepcopy
import tempfile
import unittest
from pathlib import Path

from la.report.results import not_run_rows,projection,publish,validate_row,usage_totals


class ResultPublicationTests(unittest.TestCase):
    def synthetic_failed_suite(self,store):
        """Synthetic future-test data, never represented as product/evaluator output."""
        from la.report.results import METHODS
        arms=[]
        for method in METHODS:
            raw=dict(method=method,input_sha256='a'*64,mapping=None,outcomes=[],questions=[],answers=[],
                     attempts=[],status='failed',error_type='SyntheticFailure')
            raw_ref=store.put('arm_raw',raw)
            rate={'numerator':0,'denominator':2,'rate':0.0}
            score={name:deepcopy(rate) for name in ('semantic_rows','semantic_fields','all_record_outcomes')}
            score.update(aggregates={'cardinality_reconciled':False},row_parity='mismatch')
            arm=dict(method=method,edition='synthetic',variant_id='public-synthetic',split='development',mode='mock',
                status='failed',error_type='SyntheticFailure',input_sha256='a'*64,score=score,captures=[raw_ref],
                request_attempts=0,failed_attempts=0,usage=[],questions_asked=0,questions_answered=0,
                known_cost_subtotal='0',known_total_cost='0',unknown_liabilities=[],latency_seconds=0.0,
                target_validation='not_run',target_report={'target_validation':'not_run','batches':[]})
            arm['receipt_capture']=store.put('arm_receipt',arm)
            arms.append(arm)
        manifest=dict(edition='synthetic',variant_id='public-synthetic',split='development',mode='mock',
                      input_sha256='a'*64,pins={},results=arms)
        declaration=store.put('suite_declaration',dict(edition='synthetic',split='development',mode='mock',
                                                       variants=[{'id':'public-synthetic'}]))
        return store.put('suite_report',dict(declaration=declaration,manifests=[store.put('variant_manifest',manifest)],
                                            summary={'benchmark_status':'not_run'}))

    def test_actual_capture_loader_preserves_every_failed_no_output_arm(self):
        """what_bug_this_catches: a capture consumer drops failed arms before calculating quality."""
        from evaluation.artifacts import CaptureStore
        from scripts.results import rows_from_suite
        with tempfile.TemporaryDirectory() as root:
            store=CaptureStore(root); rows=rows_from_suite(store,self.synthetic_failed_suite(store))
            self.assertEqual(len(rows),5)
            self.assertTrue(all(row['status']=='failed' and row['semantic_rows']['denominator']==2 for row in rows))

    def test_capture_loader_rejects_report_with_predeclared_variant_omitted(self):
        """what_bug_this_catches: immutable-looking report hides an unfavorable declared variant."""
        from evaluation.artifacts import CaptureStore
        from scripts.results import rows_from_suite
        with tempfile.TemporaryDirectory() as root:
            store=CaptureStore(root); ref=self.synthetic_failed_suite(store)
            suite=store.get(ref); declaration=store.get(suite['declaration'])
            declaration['variants'].append({'id':'omitted-synthetic'})
            suite['declaration']=store.put('suite_declaration',declaration)
            with self.assertRaises(ValueError): rows_from_suite(store,store.put('suite_report',suite))

    def test_not_run_contains_all_arms_splits_without_fake_zero_measurements(self):
        """what_bug_this_catches: a template looks like fifteen executed zero-cost successes."""
        rows=not_run_rows()
        self.assertEqual(len(rows),15)
        for row in rows:
            self.assertIsNone(row['known_total_cost'])
            self.assertIsNone(row['semantic_rows']['denominator'])
            self.assertEqual(row['target_validation'],'not_run')
            self.assertEqual(row['product_acceptance'],'pending')

    def test_failed_or_missing_arm_cannot_disappear_from_projection(self):
        """what_bug_this_catches: result publication selects only favorable arm rows."""
        with self.assertRaises(ValueError):
            projection(not_run_rows()[1:],visibility='not_run',source_suite_sha256=None,edition_state='uninitialized')

    def test_raw_prompt_value_or_private_path_cannot_enter_closed_rows(self):
        """what_bug_this_catches: hidden raw strings leak through a generic report serializer."""
        for key in ('prompt','raw_text','oracle','private_path'):
            row=deepcopy(not_run_rows()[0]); row[key]='sensitive synthetic marker'
            with self.assertRaises(ValueError): validate_row(row)
        row=not_run_rows()[0]; row['variant_id']='C:/private/hidden-source'
        with self.assertRaises(ValueError): validate_row(row)

    def test_unknown_usage_stays_unknown_and_cached_reasoning_are_separate(self):
        """what_bug_this_catches: missing usage becomes zero or reasoning is double-counted."""
        attempts=[{'usage':{'input_tokens':8,'output_tokens':5,'input_tokens_details':{'cached_tokens':3},
                            'output_tokens_details':{'reasoning_tokens':2}}}, {'usage':None}]
        self.assertTrue(all(value is None for value in usage_totals(attempts).values()))
        self.assertEqual(usage_totals(attempts[:1]),dict(input_tokens=8,output_tokens=5,cached_tokens=3,reasoning_tokens=2))

    def test_unknown_liability_cannot_be_a_known_zero(self):
        """what_bug_this_catches: a failed billed attempt is laundered as zero-cost success."""
        row=not_run_rows()[0]; row.update(status='failed',unknown_liability_count=1,cost_known=True,known_total_cost='0')
        with self.assertRaises(ValueError): validate_row(row)

    def test_public_route_rejects_heldout_even_with_safe_fields(self):
        """what_bug_this_catches: safe-looking projections bypass hidden-edition authority."""
        with self.assertRaises(ValueError):
            projection(not_run_rows(),visibility='public',source_suite_sha256='a'*64,edition_state='public')

    def test_retired_route_requires_actual_replay_not_relabeled_originals(self):
        """what_bug_this_catches: old results are advertised as a fresh unseen run."""
        with self.assertRaises(ValueError):
            projection(not_run_rows(),visibility='retired-replay',source_suite_sha256='a'*64,edition_state='retired')

    def test_immutable_repeat_retains_identical_manifest_and_refuses_tampering(self):
        """what_bug_this_catches: a report path overwrites historical or partly modified output."""
        with tempfile.TemporaryDirectory() as root:
            value=projection(not_run_rows(),visibility='not_run',source_suite_sha256=None,edition_state='uninitialized')
            first=publish(value,root); second=publish(value,root)
            self.assertEqual(first,second)
            path=Path(first['jsonl']); path.write_bytes(b'altered synthetic result')
            with self.assertRaises(ValueError): publish(value,root)


if __name__=='__main__': unittest.main()
