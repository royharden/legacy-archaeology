"""Future adapter regression SOURCE; no capture, signature or target effects executed."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from la.contracts import digest
from scripts.target_experiment import artifact_from,execute,parser


class CaptureAdapterTests(unittest.TestCase):
    def test_schema2_failure_retains_validated_v3_observation_and_partial_effect(self):
        """what_bug_this_catches: an adapter failure discards earlier captured target evidence."""
        from evaluation.artifacts import CaptureStore
        from scripts.results import target_batch_captures,captured
        with tempfile.TemporaryDirectory() as root:
            store=CaptureStore(root)
            normal=store.put('target_observation_v3',{'schema_version':3})
            partial=store.put('failed_load_observation',{'schema_version':3})
            body=dict(schema_version=2,batch_id='synthetic',method='R1',mode='mock',phase_scope=None,
                observation=normal,effect_captures=[partial],stages={'observe':'captured','failed_load':'captured','recovery':'unavailable'},
                stage_errors=[{'stage':'recovery','error_type':'SyntheticFailure'}],grade={'target_validation':'failed'})
            batch=dict(body,receipt_capture=store.put('target_arm_failure',body))
            with patch('scripts.results.captured',wraps=captured) as reads:
                target_batch_captures(store,batch)
            self.assertIn('target_observation_v3',[call.args[2] for call in reads.call_args_list])
            self.assertIn('failed_load_observation',[call.args[2] for call in reads.call_args_list])

    def test_schema2_missing_observation_remains_missing(self):
        """what_bug_this_catches: missing observations become invented normal v2 captures."""
        from evaluation.artifacts import CaptureStore
        from scripts.results import target_batch_captures
        with tempfile.TemporaryDirectory() as root:
            store=CaptureStore(root)
            body=dict(schema_version=2,observation=None,observation_schema_version=None,effect_captures=[],phase_scope=None,
                stages={'observe':'missing','failed_load':'not_run','recovery':'not_run'},stage_errors=[])
            batch=dict(body,receipt_capture=store.put('target_arm_receipt',body))
            target_batch_captures(store,batch)
            self.assertIsNone(batch['observation'])

    def test_tampered_candidate_wrapper_refused_without_external_effect(self):
        """what_bug_this_catches: an untrusted CLI path label bypasses immutable candidate content pins."""
        with tempfile.TemporaryDirectory() as root:
            body=dict(schema_version=1,kind='evaluation-candidate',payload={'kind':'disposable_evaluation_candidate'})
            value=dict(body,receipt_sha256=digest(body))
            self.assertEqual(artifact_from(value,Path(root)),body['payload'])
            value['payload']=dict(value['payload'],oracle='synthetic-secret')
            with self.assertRaises(ValueError): artifact_from(value,Path(root))

    def test_product_artifact_cannot_escape_explicit_operator_root(self):
        """what_bug_this_catches: a bundle artifact names another app or private directory."""
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(ValueError):
                artifact_from({'kind':'product_bundle','bundle_path':'../outside'},Path(root))

    def test_open_forwards_exact_external_pins_and_never_reads_dsn(self):
        """what_bug_this_catches: offline inspection silently connects or chooses a latest capture."""
        with tempfile.TemporaryDirectory() as root:
            (Path(root)/'experiment').mkdir()
            manifest={key:None for key in ('schema_version','kind','experiment_id','experiment_sha256','candidate',
                'authority_sha256','target_config_sha256','observer_code_sha256','capture_status','requested_operations',
                'operations','omissions','target_validation','row_parity','product_acceptance')}
            args=parser().parse_args(['--operator-root',root,'open','--experiment','experiment',
                '--expected-experiment-sha256','a'*64,'--expected-candidate-sha256','b'*64,
                '--expected-authority-sha256','c'*64])
            with (patch('la.postgres.open_target_experiment',return_value=SimpleNamespace(manifest=manifest)) as opened,
                  patch('la.app.observations.target_dsn',side_effect=AssertionError('offline inspection read DSN'))):
                result=execute(args)
            self.assertEqual(opened.call_args.kwargs,dict(expected_experiment_sha256='a'*64,
                expected_candidate_sha256='b'*64,expected_authority_sha256='c'*64))
            self.assertEqual(result,manifest)

    def test_later_recovery_selection_requires_original_prior_pin(self):
        """what_bug_this_catches: later recovery gets selected by recency or unrelated predecessor."""
        with self.assertRaises(SystemExit):
            parser().parse_args(['--operator-root','synthetic','select-recovery',
                '--artifact','artifact.json','--signed-authority','signed.json','--target-config','config.json',
                '--public-trust-root','public','--public-trust-profile','profile.json',
                '--experiment','experiment','--expected-experiment-sha256','a'*64,
                '--expected-candidate-sha256','b'*64,'--expected-authority-sha256','c'*64,
                '--expected-reconciliation-sha256','d'*64])


if __name__=='__main__': unittest.main()
