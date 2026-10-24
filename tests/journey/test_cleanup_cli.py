"""what_bug_this_catches: cleanup reachable from an inactive/example grant, a DSN argument,
load authority standing in for cleanup authority, env access before offline checks, a
destructive retry after an uncertain attempt, leaked connections and raw facts in output.

Future regression SOURCE only: written in Dirty Mode, never imported/collected/executed.
All database and signature boundaries are patched; nothing here is target evidence.
"""
from contextlib import ExitStack
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from la.review import digest
from scripts import cleanup as cli

NAMESPACE = 'la_' + 'a' * 32
SHA = lambda label: digest('synthetic ' + label)  # noqa: E731 - labels, not evidence
EXAMPLE = Path(__file__).resolve().parents[2] / 'config' / 'cleanup-grant.example.json'


def grant(**changes):
    value = json.loads(EXAMPLE.read_text(encoding='utf-8'))
    value.update(active=True, expected_experiment_sha256=SHA('experiment'),
                 expected_original_observation_sha256=SHA('observation'),
                 expected_cleanup_authority_sha256=SHA('cleanup authority'), namespace=NAMESPACE)
    value.update(changes)
    return value


def receipt(state='committed', action='cleanup'):
    facts = {'inspected': True, 'namespace_exists': False, 'classes': [['secret', 'raw']], 'rows': [{'raw': 'local only'}]}
    return {'cleanup_sha256': SHA('receipt'), 'action': action, 'state': state, 'binding': {'namespace': NAMESPACE},
            'prior_cleanup_sha256': SHA('intent'), 'issues': [], 'before': facts, 'ownership': facts, 'after': facts,
            'transaction': {'statements': [SHA('s1'), SHA('s2'), SHA('s3')], 'commit_attempted': True, 'commit_returned': True},
            'target_validation': 'not_run', 'row_parity': 'not_run', 'product_acceptance': 'pending'}


class Operator(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for name in ('operator', 'target-captures/EXACT_EXPERIMENT_ID', 'cleanup-receipts/EXACT_NAMESPACE', 'trust'):
            (self.root / name).mkdir(parents=True)
        for name in ('operator/target-artifact.json', 'operator/signed-target-authority.json',
                     'operator/signed-cleanup-authority.json', 'operator/disposable-target-config.json'):
            (self.root / name).write_text('{}', encoding='utf-8')
        self.body = {'kind': 'disposable_target_cleanup_authority', 'authority_sha256': SHA('cleanup authority'),
                     'namespace': NAMESPACE, 'operations': ['cleanup', 'reconcile_cleanup']}

    def write_grant(self, **changes):
        (self.root / 'grant.json').write_text(json.dumps(grant(**changes)), encoding='utf-8')

    def args(self, command, *extra):
        base = ['--operator-root', str(self.root), command]
        if command != 'inspect':
            base += ['--grant', 'grant.json', '--public-trust-root', str(self.root / 'trust'), '--public-trust-profile', 'p.json']
        if command in ('run', 'reconcile'): base += ['--expected-namespace', NAMESPACE]
        return cli.parser().parse_args(base + list(extra))

    def boundaries(self, stack, *, dsn=AssertionError('environment read before offline checks'), refuse=None):
        # The real dedicated-authority check is covered by tests/postgres/test_cleanup.py; here it is a boundary.
        self.verifier = MagicMock(name='verifier')
        stack.enter_context(patch('la.app.public_trust.public_keys', return_value=({}, {})))
        stack.enter_context(patch('la.postgres.TargetAuthorityVerifier', return_value=self.verifier))
        self.authorize = stack.enter_context(patch('la.postgres.authorize_cleanup', side_effect=refuse))
        stack.enter_context(patch('la.postgres.TargetConfig'))
        stack.enter_context(patch('scripts.target_experiment.artifact_from', side_effect=lambda value, root: value))
        stack.enter_context(patch('la.postgres.cleanup_binding', return_value={'namespace': NAMESPACE}))
        kwargs = {'side_effect': dsn} if isinstance(dsn, Exception) else {'return_value': dsn}
        return stack.enter_context(patch('la.app.observations.target_dsn', **kwargs))

    def test_no_dsn_argument_exists_only_an_environment_name(self):
        with self.assertRaises(SystemExit):
            cli.parser().parse_args(['--operator-root', '.', 'run', '--grant', 'g', '--public-trust-root', 't',
                                     '--public-trust-profile', 'p', '--expected-namespace', NAMESPACE, '--dsn', 'postgres://x'])

    def test_shipped_example_and_inactive_grants_never_run(self):
        with self.assertRaises(ValueError):  # placeholder pins
            cli.load_grant(EXAMPLE.parent, EXAMPLE.name, require_active=False)
        self.write_grant(active=False)
        self.assertFalse(cli.load_grant(self.root, 'grant.json', require_active=False)['active'])
        with ExitStack() as stack, self.assertRaises(ValueError):
            self.boundaries(stack)
            cli.execute(self.args('run'))

    def test_offline_refusals_precede_any_environment_access(self):
        refused = ValueError('dedicated signed cleanup authority scope mismatch')
        cases = {'retyped namespace': (dict(), 'la_' + 'b' * 32, None),
                 'library authority refusal (load kind, old code pin, scope, operation)': (dict(), None, refused),
                 'grant namespace differs from creation': (dict(namespace='la_' + 'c' * 32), None, None)}
        for label, (changes, retyped, refuse) in cases.items():
            self.write_grant(**changes)
            with self.subTest(label), ExitStack() as stack, self.assertRaises(ValueError):
                self.boundaries(stack, refuse=refuse)
                args = self.args('run')
                if retyped: args.expected_namespace = retyped
                cli.execute(args)

    def test_full_library_authority_check_runs_with_exact_binding_and_operation(self):
        self.write_grant()
        with ExitStack() as stack:
            self.boundaries(stack, dsn=None)
            stack.enter_context(patch.object(cli, 'prior_attempts', return_value=[]))
            with self.assertRaises(ValueError):  # stops at the unset DSN, after authorization
                cli.execute(self.args('run'))
        self.authorize.assert_called_once_with({}, self.verifier, SHA('cleanup authority'), {'namespace': NAMESPACE}, 'cleanup')

    def test_settled_intents_do_not_block_but_open_attempts_do(self):
        root = self.root / 'cleanup-receipts' / 'EXACT_NAMESPACE'
        intent = dict(receipt('prepared'), cleanup_sha256=SHA('intent'), prior_cleanup_sha256=None)
        rolled = dict(receipt('rolled_back'), cleanup_sha256=SHA('rolled'), prior_cleanup_sha256=SHA('intent'))
        lone = dict(receipt('prepared'), cleanup_sha256=SHA('lone'), prior_cleanup_sha256=None)
        values = {item['cleanup_sha256']: item for item in (intent, rolled, lone)}
        for sha in values: (root / f'cleanup-{sha}.json').write_text('{}', encoding='utf-8')
        with patch('la.postgres.open_target_cleanup', side_effect=lambda path, expected_cleanup_sha256: values[expected_cleanup_sha256]):
            open_attempts = cli.prior_attempts(root, NAMESPACE)
        self.assertEqual({item['cleanup_sha256'] for item in open_attempts}, {SHA('rolled'), SHA('lone')})
        self.assertEqual([item['state'] for item in open_attempts if item['state'] in cli.NO_RETRY_STATES], ['prepared'])

    def test_uncertain_prior_attempt_refuses_destructive_retry(self):
        self.write_grant()
        for state in cli.NO_RETRY_STATES:
            with self.subTest(state), ExitStack() as stack, self.assertRaises(ValueError):
                self.boundaries(stack)
                stack.enter_context(patch.object(cli, 'prior_attempts', return_value=[receipt(state)]))
                cli.execute(self.args('run'))

    def test_run_opens_distinct_connections_closes_both_and_hides_raw_facts(self):
        self.write_grant()
        connections = [MagicMock(name='writer'), MagicMock(name='observer')]
        with ExitStack() as stack:
            self.boundaries(stack, dsn='postgresql://synthetic-never-connect')
            stack.enter_context(patch.object(cli, 'prior_attempts', return_value=[receipt('refused'), receipt('rolled_back')]))
            stack.enter_context(patch('la.postgres.target.driver_and_connect', return_value=(None, MagicMock(side_effect=connections))))
            run = stack.enter_context(patch('la.postgres.cleanup_target_namespace', return_value=receipt()))
            result = cli.execute(self.args('run'))
        kwargs = run.call_args.kwargs
        self.assertIs(kwargs['connection'], connections[0]); self.assertIs(kwargs['observer_connection'], connections[1])
        self.assertTrue(all(connection.close.called for connection in connections))
        self.assertEqual((result['state'], result['statements_executed'], result['namespace_present_after']), ('committed', 3, False))
        self.assertNotIn('local only', json.dumps(result)); self.assertNotIn('before', result)

    def test_unset_dsn_environment_does_nothing(self):
        self.write_grant()
        with ExitStack() as stack, self.assertRaises(ValueError):
            self.boundaries(stack, dsn=None)
            stack.enter_context(patch.object(cli, 'prior_attempts', return_value=[]))
            stack.enter_context(patch('la.postgres.target.driver_and_connect', side_effect=AssertionError('no connection without DSN')))
            cli.execute(self.args('run'))

    def test_reconcile_requires_receipt_from_the_grant_root_and_is_read_only(self):
        self.write_grant()
        (self.root / 'elsewhere.json').write_text('{}', encoding='utf-8')
        with ExitStack() as stack, self.assertRaises(ValueError):
            self.boundaries(stack)
            cli.execute(self.args('reconcile', '--receipt', 'elsewhere.json', '--expected-cleanup-sha256', SHA('x')))
        inside = 'cleanup-receipts/EXACT_NAMESPACE/cleanup-' + SHA('x') + '.json'
        (self.root / inside).write_text('{}', encoding='utf-8')
        connection = MagicMock(name='observer')
        with ExitStack() as stack:
            self.boundaries(stack, dsn='postgresql://synthetic-never-connect')
            stack.enter_context(patch('la.postgres.target.driver_and_connect', return_value=(None, MagicMock(return_value=connection))))
            stack.enter_context(patch('la.postgres.open_target_cleanup', return_value=receipt('indeterminate')))
            stack.enter_context(patch('la.postgres.cleanup_target_namespace', side_effect=AssertionError('reconcile never removes')))
            reconcile = stack.enter_context(patch('la.postgres.reconcile_target_cleanup', return_value=receipt('observed_absent', 'reconcile_cleanup')))
            result = cli.execute(self.args('reconcile', '--receipt', inside, '--expected-cleanup-sha256', SHA('x')))
        self.assertIs(reconcile.call_args.kwargs['observer_connection'], connection)
        self.assertEqual(self.authorize.call_args.args[-1], 'reconcile_cleanup')
        self.assertTrue(connection.close.called)
        self.assertEqual(result['state'], 'observed_absent')

    def test_plan_prints_unsigned_body_without_contacting_anything(self):
        self.write_grant(active=False, expected_cleanup_authority_sha256='REPLACE_LATER')
        with ExitStack() as stack:
            self.boundaries(stack)
            stack.enter_context(patch('la.postgres.target.driver_and_connect', side_effect=AssertionError('plan never connects')))
            result = cli.execute(self.args('plan', '--authority-id', 'cleanup-1', '--operations', 'cleanup', 'cleanup'))
        body = result['unsigned_cleanup_authority_body']
        self.assertEqual(body['operations'], ['cleanup'])
        self.assertEqual(body['authority_sha256'], digest({k: v for k, v in body.items() if k != 'authority_sha256'}))
        self.assertEqual((result['authority_created'], result['database_contacted']), (False, False))

    def test_receipt_root_scan_is_bounded(self):
        root = self.root / 'cleanup-receipts' / 'EXACT_NAMESPACE'
        for index in range(cli.MAX_RECEIPTS + 1): (root / f'other-{index}.txt').write_text('x', encoding='utf-8')
        with self.assertRaises(ValueError):
            cli.prior_attempts(root, NAMESPACE)


if __name__ == '__main__':
    unittest.main()
