"""Addition003-only real cleanup tests; no legacy switch or general cleanup.

Only the newly created, recorded namespace of each case may be dropped, through
the product RESTRICT path. Refused cases, sentinel and all older schemas remain.
"""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from la.postgres import (TargetConfig, TargetAuthorityVerifier, prepare_evaluation_candidate_v2,
    collect_target_experiment, open_target_experiment, cleanup_binding, cleanup_target_namespace,
    reconcile_target_cleanup, open_target_cleanup)
from la.postgres import cleanup as cleanup_module
from la.postgres.target import driver_and_connect, owned_namespace
from la.review import canonical, digest
from postgres.test_controlled_target import phase_intent
from review.support import fixture, proposal

ADDITION_SHA = 'ad318670c3b02258d60d81570e6ee025d3b74311a0d37e98b85a28ebcef727ad'


def public_signers():
    """Two ephemeral test signers; only public keys/signatures are persisted."""
    signers, public, issuers = {}, {}, {}
    for key_id in ('m1-load-test', 'm1-cleanup-test'):
        key = Ed25519PrivateKey.generate()
        public[key_id] = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        issuers[key_id] = ('M1-RV2-public-test', 'target_authority')
        def sign(body, key=key, key_id=key_id):
            return dict(schema_version=1, algorithm='Ed25519', issuer='M1-RV2-public-test',
                key_id=key_id, role='target_authority', payload=deepcopy(body), payload_sha256=digest(body),
                signature=key.sign(canonical(body).encode()).hex())
        signers[key_id] = sign
    return TargetAuthorityVerifier(issuers, public), signers


class M1RealCleanup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get('M1_RV2_CLEANUP_AUTHORIZED') != 'ADDITION003_RESTRICT_ONLY':
            raise unittest.SkipTest('Addition003 explicit narrow opt-in is required')
        cls.evidence = Path(os.environ['M1_RV2_CLEANUP_EVIDENCE']).resolve(strict=True)
        cls.dsn = 'host=127.0.0.1 port=21800 dbname=m1_rv2 user=m1_rv2 sslmode=disable'
        cls.base = TargetConfig('M1-RV2-Addition003', 'm1_rv2', 'm1_rv2', '3.3.6', 17,
                               port=21800, server_host='172.17.0.8', server_port=21800)
        _, connect = driver_and_connect(cls.dsn, cls.base)
        cls.connect = staticmethod(connect)
        with cls.connect() as connection, connection.cursor() as cursor:
            cursor.execute('SELECT current_user,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls '
                           'FROM pg_roles WHERE rolname=current_user')
            role = cursor.fetchone()
            if role != ('m1_rv2', False, False, False, False, False):
                raise AssertionError('normal M1 role required')
            cursor.execute('SELECT nspname,oid::text FROM pg_namespace WHERE pg_get_userbyid(nspowner)=current_user')
            cls.older = dict(cursor.fetchall())
        cls.sentinel = owned_namespace('la_' + uuid.uuid4().hex)
        cls.sentinel_value = 'M1-RV2-Addition003-' + uuid.uuid4().hex
        with cls.connect() as connection, connection.cursor() as cursor:
            cursor.execute(f'CREATE SCHEMA "{cls.sentinel}"')
            cursor.execute(f'CREATE TABLE "{cls.sentinel}".guard_sentinel (value text NOT NULL)')
            cursor.execute(f'INSERT INTO "{cls.sentinel}".guard_sentinel VALUES (%s)', (cls.sentinel_value,))
        (cls.evidence / 'protected-before.json').write_text(json.dumps(dict(
            addition_sha256=ADDITION_SHA, older_namespaces=cls.older,
            sentinel=cls.sentinel, sentinel_value=cls.sentinel_value, role=list(role)), indent=2))

    def setUp(self):
        self.root = self.evidence / (self._testMethodName + '-' + uuid.uuid4().hex)
        self.root.mkdir()
        self.verifier, self.signers = public_signers()
        batch, generation = fixture()
        self.artifact = prepare_evaluation_candidate_v2(batch, proposal(batch, generation),
            edition='public-m1-cleanup-Addition003', evaluation_phase='T1', split='development',
            evaluation_plan_sha256=digest('PB-M1-R03-Addition003-cleanup-tests'))
        body = phase_intent(self.artifact)
        self.authority = self.signers['m1-load-test'](body)
        self.config = replace(self.base, authority_reference=body['authority_sha256'],
                              expected_candidate_sha256=self.artifact['descriptor']['candidate_sha256'])
        self.manifest = collect_target_experiment(self.artifact, self.authority, capture_root=self.root,
            experiment_id='creation', dsn=self.dsn, target_config=self.config, authority_verifier=self.verifier)
        self.experiment = self.root / 'creation'
        snapshot = open_target_experiment(self.experiment, expected_experiment_sha256=self.manifest['experiment_sha256'])
        self.original = snapshot.observations['normal_readback']
        self.assertEqual(self.original['commit_state'], 'committed')
        self.namespace = owned_namespace(self.original['attempt']['namespace'])
        self.assertNotIn(self.namespace, self.older)
        self.assertNotEqual(self.namespace, self.sentinel)
        self.binding = cleanup_binding(self.experiment, self.artifact, self.authority,
            expected_experiment_sha256=self.manifest['experiment_sha256'],
            expected_original_observation_sha256=self.original['observation_sha256'],
            target_config=self.config, authority_verifier=self.verifier)
        self.cleanup_body = dict(self.binding, schema_version=1, kind='disposable_target_cleanup_authority',
            authority_id='M1-RV2-Addition003-' + uuid.uuid4().hex, scope='owned_disposable_namespace',
            operations=['cleanup', 'reconcile_cleanup'])
        self.cleanup_body['authority_sha256'] = digest(self.cleanup_body)
        self.cleanup_authority = self.signers['m1-cleanup-test'](self.cleanup_body)
        self.receipts = self.root / 'receipts'; self.receipts.mkdir()
        self.allowed_sql = [f'DROP TABLE "{self.namespace}"."candidate_execution" RESTRICT',
                            f'DROP TABLE "{self.namespace}"."migrated_records" RESTRICT',
                            f'DROP SCHEMA "{self.namespace}" RESTRICT']
        # Actual read-only catalogs and exact allowlist are persisted BEFORE any DROP.
        candidate, _, marker, _ = cleanup_module._context(self.experiment, self.artifact, self.authority,
            expected_experiment_sha256=self.manifest['experiment_sha256'],
            expected_original_observation_sha256=self.original['observation_sha256'],
            target_config=self.config, authority_verifier=self.verifier)
        with self.connect() as connection:
            cleanup_module._begin(connection, read_only=True)
            facts = cleanup_module._facts(connection, self.config, candidate, self.namespace, read_only=True)
            proof_error = None
            try: cleanup_module._ownership(connection, self.config, candidate, self.namespace, marker, facts)
            except ValueError as exc: proof_error = str(exc)
            toast = [int(row[5]) for row in facts['classes'] if row[2] == 'r' and row[5] != '0']
            with connection.cursor() as cursor:
                cursor.execute("SELECT c.oid::text,c.relname,c.relkind::text FROM pg_class c WHERE c.oid=ANY(%s::oid[]) "
                    "OR c.oid IN (SELECT indexrelid FROM pg_index WHERE indrelid=ANY(%s::oid[])) ORDER BY c.oid", (toast, toast))
                automatic = cursor.fetchall()
        self.save('creation-and-drop-allowlist', dict(addition_sha256=ADDITION_SHA,
            namespace=self.namespace, binding=self.binding, original_observation=self.original,
            exact_drop_sql=self.allowed_sql, actual_catalog=facts, automatic_owned_toast=automatic,
            ownership_proof_error=proof_error, protected_sentinel=self.sentinel,
            signed_cleanup_authority=self.cleanup_authority, target_config=self.config.public()))
        self.executed_drops = []

    def save(self, name, value):
        (self.root / (name + '.json')).write_text(json.dumps(value, indent=2), encoding='utf-8')

    def tearDown(self):
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(f'SELECT value FROM "{self.sentinel}".guard_sentinel')
            self.assertEqual(cursor.fetchall(), [(self.sentinel_value,)])
            cursor.execute('SELECT nspname,oid::text FROM pg_namespace WHERE pg_get_userbyid(nspowner)=current_user')
            after = dict(cursor.fetchall())
        self.assertTrue(all(after.get(name) == oid for name, oid in self.older.items()))
        self.save('protected-after', dict(older_namespace_oids_unchanged=True, sentinel_unchanged=True,
                                        executed_drop_sql=self.executed_drops))

    def run_cleanup(self, *, authority=None, authority_pin=None, fail_after_first_drop=False):
        real_execute = cleanup_module.StatementTrace.execute
        def guarded(trace, sql, parameters=None):
            if sql.lstrip().upper().startswith('DROP'):
                self.assertIn(sql, self.allowed_sql)
                self.assertNotIn('CASCADE', sql.upper())
                self.executed_drops.append(sql)
            value = real_execute(trace, sql, parameters)
            if fail_after_first_drop and sql == self.allowed_sql[0]:
                # Real PostgreSQL 22012 after an actual DROP, in the same transaction.
                trace.cursor.execute('SELECT 1 / 0')
            return value
        with self.connect() as writer, self.connect() as observer, patch.object(cleanup_module.StatementTrace, 'execute', guarded):
            result = cleanup_target_namespace(self.experiment, self.artifact, self.authority,
                authority or self.cleanup_authority, expected_experiment_sha256=self.manifest['experiment_sha256'],
                expected_original_observation_sha256=self.original['observation_sha256'],
                expected_cleanup_authority_sha256=authority_pin or self.cleanup_body['authority_sha256'],
                target_config=self.config, authority_verifier=self.verifier, cleanup_verifier=self.verifier,
                connection=writer, observer_connection=observer, receipt_root=self.receipts)
        self.save('result', result)
        return result

    def reconcile(self, result):
        with self.connect() as observer:
            value = reconcile_target_cleanup(self.experiment, self.artifact, self.authority, self.cleanup_authority,
                expected_experiment_sha256=self.manifest['experiment_sha256'],
                expected_original_observation_sha256=self.original['observation_sha256'],
                expected_cleanup_authority_sha256=self.cleanup_body['authority_sha256'],
                cleanup_receipt_path=self.receipts / ('cleanup-' + result['cleanup_sha256'] + '.json'),
                expected_cleanup_sha256=result['cleanup_sha256'], target_config=self.config,
                authority_verifier=self.verifier, cleanup_verifier=self.verifier,
                observer_connection=observer, receipt_root=self.receipts)
        self.save('reconciliation', value)
        return value

    def exists(self):
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute('SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=%s)', (self.namespace,))
            return cursor.fetchone()[0]

    def test_success_prepared_final_and_fresh_absence(self):
        """what_bug_this_catches: a cleanup success flag hides remaining objects or lost intent."""
        result = self.run_cleanup()
        self.assertEqual(result['state'], 'committed', result)
        self.assertEqual(self.executed_drops, self.allowed_sql)
        self.assertFalse(self.exists())
        final_path = self.receipts / ('cleanup-' + result['cleanup_sha256'] + '.json')
        self.assertEqual(open_target_cleanup(final_path, expected_cleanup_sha256=result['cleanup_sha256']), result)
        prepared = open_target_cleanup(self.receipts / ('cleanup-' + result['prior_cleanup_sha256'] + '.json'),
                                       expected_cleanup_sha256=result['prior_cleanup_sha256'])
        self.assertEqual(prepared['state'], 'prepared')
        self.assertEqual(prepared['cleanup_id'], result['cleanup_id'])
        self.assertEqual(prepared['transaction']['statements'], [])
        self.assertEqual(self.reconcile(result)['state'], 'observed_absent')
        self.save('archive-input', dict(path=str(final_path), cleanup_sha256=result['cleanup_sha256']))

    def test_wrong_authority_and_stale_pin_refuse_before_drop(self):
        """what_bug_this_catches: load authority or stale namespace digest grants cleanup."""
        with self.assertRaises(ValueError): self.run_cleanup(authority=self.authority)
        body = deepcopy(self.cleanup_body); body['marker_sha256'] = digest('stale marker')
        body['authority_sha256'] = digest({k: v for k, v in body.items() if k != 'authority_sha256'})
        with self.assertRaises(ValueError):
            self.run_cleanup(authority=self.signers['m1-cleanup-test'](body), authority_pin=body['authority_sha256'])
        self.assertEqual(self.executed_drops, [])
        self.assertTrue(self.exists())

    def test_wrong_marker_refuses_and_retains_namespace(self):
        """what_bug_this_catches: same-role objects with a different creation marker get dropped."""
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(f'UPDATE "{self.namespace}".candidate_execution SET payload=%s', ('changed marker',))
        result = self.run_cleanup()
        self.assertEqual((result['state'], result['transaction']['statements']), ('refused', []))
        self.assertTrue(self.exists())

    def test_extra_object_refuses_without_removing_it(self):
        """what_bug_this_catches: cleanup removes an unlisted member in the same namespace."""
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(f'CREATE TABLE "{self.namespace}".unlisted_object (value int)')
        result = self.run_cleanup()
        self.assertEqual((result['state'], self.executed_drops), ('refused', []))
        self.assertTrue(self.exists())

    def test_external_dependency_refuses_without_cascade(self):
        """what_bug_this_catches: an external view is lost through a cascading cleanup."""
        dependent = owned_namespace('la_' + uuid.uuid4().hex)
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(f'CREATE SCHEMA "{dependent}"')
            cursor.execute(f'CREATE VIEW "{dependent}".linked_view AS SELECT ordinal FROM "{self.namespace}".migrated_records')
        self.save('retained-external-dependency', dict(namespace=dependent, view='linked_view'))
        result = self.run_cleanup()
        self.assertEqual((result['state'], self.executed_drops), ('refused', []))
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(f'SELECT count(*) FROM "{dependent}".linked_view')
            self.assertEqual(cursor.fetchone()[0], 3)

    def test_actual_commit_ack_loss_requires_read_only_reconciliation(self):
        """what_bug_this_catches: ambiguous cleanup commit is retried or declared confirmed."""
        real_commit = cleanup_module._commit_cleanup
        def suppress_ack(connection):
            real_commit(connection)
            raise OSError('controlled application acknowledgement suppression after real commit')
        with patch.object(cleanup_module, '_commit_cleanup', suppress_ack): result = self.run_cleanup()
        self.assertEqual(result['state'], 'indeterminate', result)
        self.assertTrue(result['transaction']['commit_attempted'])
        self.assertFalse(result['transaction']['commit_returned'])
        self.assertFalse(self.exists())
        before = list(self.executed_drops)
        self.assertEqual(self.reconcile(result)['state'], 'observed_absent')
        self.assertEqual(self.executed_drops, before)

    def test_real_sql_error_rolls_back_drop_and_reconciles_present(self):
        """what_bug_this_catches: transactional DROP failure is reported as committed/absent."""
        result = self.run_cleanup(fail_after_first_drop=True)
        self.assertEqual(result['state'], 'rolled_back', result)
        self.assertEqual(result['transaction']['sqlstate'], '22012')
        self.assertTrue(result['transaction']['rollback_returned'])
        self.assertFalse(result['transaction']['commit_attempted'])
        self.assertEqual(self.executed_drops, self.allowed_sql[:1])
        self.assertTrue(self.exists())
        self.assertEqual(self.reconcile(result)['state'], 'observed_present')

    def test_operator_cli_plan_run_inspect_reconcile(self):
        """what_bug_this_catches: library cleanup works but the explicit operator path cannot run."""
        for name, value in [('artifact', self.artifact), ('original-signed', self.authority),
                            ('cleanup-signed', self.cleanup_authority), ('target', self.config.public())]:
            self.save(name, value)
        profile = dict(schema_version=1,
            trusted_issuers={k: dict(issuer=v[0], role=v[1]) for k, v in self.verifier.trusted_issuers.items()},
            public_keys={k: v.hex() for k, v in self.verifier.public_keys.items()})
        self.save('public-trust', profile)
        grant = dict(schema_version=1, kind='disposable_cleanup_grant', active=True, artifact='artifact.json',
            original_signed_authority='original-signed.json', cleanup_signed_authority='cleanup-signed.json',
            target_config='target.json', experiment='creation', receipt_root='receipts', namespace=self.namespace,
            expected_experiment_sha256=self.manifest['experiment_sha256'],
            expected_original_observation_sha256=self.original['observation_sha256'],
            expected_cleanup_authority_sha256=self.cleanup_body['authority_sha256'])
        self.save('grant', grant)
        os.environ['M1_RV2_CLEANUP_DSN'] = 'postgresql://m1_rv2@127.0.0.1:21800/m1_rv2'
        base = [sys.executable, '-B', '-m', 'scripts.cleanup', '--operator-root', str(self.root)]
        trust = ['--grant', 'grant.json', '--public-trust-root', str(self.root), '--public-trust-profile', 'public-trust.json']
        def cli(command, extra):
            result = subprocess.run(base + [command] + extra, capture_output=True, text=True, timeout=60)
            self.save('cli-' + command, dict(argv=base + [command] + extra, exit_code=result.returncode,
                                            stdout=result.stdout, stderr=result.stderr, cwd=str(Path.cwd())))
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)
        plan = cli('plan', trust + ['--authority-id', self.cleanup_body['authority_id'], '--operations', 'cleanup', 'reconcile_cleanup'])
        self.assertEqual(plan['unsigned_cleanup_authority_body'], self.cleanup_body)
        result = cli('run', trust + ['--expected-namespace', self.namespace, '--dsn-env', 'M1_RV2_CLEANUP_DSN'])
        self.assertEqual(result['state'], 'committed', result)
        self.assertFalse(self.exists())
        relative = 'receipts/cleanup-' + result['cleanup_sha256'] + '.json'
        inspected = cli('inspect', ['--receipt', relative, '--expected-cleanup-sha256', result['cleanup_sha256']])
        self.assertEqual(inspected['state'], 'committed')
        later = cli('reconcile', trust + ['--expected-namespace', self.namespace, '--dsn-env', 'M1_RV2_CLEANUP_DSN',
                    '--receipt', relative, '--expected-cleanup-sha256', result['cleanup_sha256']])
        self.assertEqual(later['state'], 'observed_absent')


if __name__ == '__main__': unittest.main()
