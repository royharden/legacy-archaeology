"""what_bug_this_catches: partial commits, stale retries, broken CAS and replay drift."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from la.contracts import digest
from la.review import RulingStore, build_mapping, questions
from review.support import answered, fixture


class DurableRulings(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.batch, self.generation = fixture()
        self.store = RulingStore(self.root / 'rulings.sqlite')
        self.store.bind_generation(self.generation)
        self.question = questions(self.generation)[0]
        self.option = self.question['options'][0]['id']

    def answer(self, revision=0, request='answer-1', option=None):
        return self.store.answer(self.generation, self.question['id'], option or self.option,
                                 'named_test_author', 'hand-checked choice', revision, request)

    def test_exact_retry_and_compare_and_swap_preserve_old_receipt(self):
        first = self.answer()
        self.assertEqual(self.answer(), first)
        with self.assertRaises(ValueError): self.answer(request='cas-loser')
        second = self.answer(1, 'correction', 'unknown')
        self.assertEqual(self.answer(), first)
        self.assertEqual(second['revision'], 2)
        self.assertEqual(len(self.store.events()), 2)
        self.assertEqual(self.store.projection(self.generation)['answers'][self.question['id']]['option_id'], 'unknown')
        with self.assertRaises(ValueError): self.answer(1, 'answer-1')

    def test_failure_before_receipt_commit_leaves_no_event_or_projection(self):
        # A receipt failure must roll back event + projection in the same transaction.
        with closing(sqlite3.connect(self.store.path)) as db, db:
            db.execute("CREATE TRIGGER fail_receipt BEFORE INSERT ON receipts BEGIN SELECT RAISE(ABORT,'injected precommit crash'); END")
        with self.assertRaises(sqlite3.IntegrityError): self.answer()
        with closing(sqlite3.connect(self.store.path)) as db, db:
            for table in ('events', 'projection', 'receipts'):
                self.assertEqual(db.execute('SELECT count(*) FROM ' + table).fetchone()[0], 0)

    def test_restart_replay_and_projection_repair_are_journal_bound(self):
        self.answer()
        original = self.store.projection(self.generation)
        restarted = RulingStore(self.store.path)
        self.assertEqual(restarted.replay(self.generation), original)
        with closing(sqlite3.connect(self.store.path)) as db, db:
            db.execute('DELETE FROM projection')
        with self.assertRaises(ValueError): restarted.projection(self.generation)
        self.assertEqual(restarted.replay(self.generation, rebuild=True), original)
        self.assertEqual(restarted.projection(self.generation), original)
        with closing(sqlite3.connect(self.store.path)) as db, db:
            with self.assertRaises(sqlite3.IntegrityError): db.execute('UPDATE events SET payload=?', ('{}',))
            with self.assertRaises(sqlite3.IntegrityError): db.execute('DELETE FROM events')

    def test_stale_generation_cannot_reauthorize_historical_retry(self):
        self.answer()
        changed = deepcopy(self.generation)
        changed['brief_sha256'] = digest('different domain brief')
        changed['generation_sha256'] = digest({k: v for k, v in changed.items() if k != 'generation_sha256'})
        self.store.bind_generation(changed)
        with self.assertRaises(ValueError): self.answer()
        with self.assertRaises(ValueError): self.store.replay(self.generation)

    def test_two_writers_have_one_cas_winner(self):
        barrier = threading.Barrier(2)
        def write(number):
            barrier.wait()
            try:
                self.answer(request='parallel-' + str(number))
                return 'committed'
            except ValueError:
                return 'conflict'
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(write, (1, 2)))
        self.assertEqual(sorted(results), ['committed', 'conflict'])
        self.assertEqual(len(self.store.events()), 1)

    def test_export_failure_never_publishes_partial_final_or_loses_committed_event(self):
        self.answer()
        destination = self.root / 'events.jsonl'
        with patch('la.review.os.link', side_effect=OSError('injected publication crash')):
            with self.assertRaises(OSError): self.store.export(destination)
        self.assertFalse(destination.exists())
        self.assertEqual(len(self.store.events()), 1)
        self.store.export(destination)
        exported = [json.loads(line) for line in destination.read_text().splitlines()]
        self.assertEqual(exported, self.store.events())
        with self.assertRaises(FileExistsError): self.store.export(destination)

    def test_unknown_and_tampered_support_never_complete_mapping(self):
        self.answer(option='unknown')
        self.assertEqual(build_mapping(self.batch, self.generation, self.store)['mapping_status'], 'incomplete')
        projection = self.store.projection(self.generation)
        projection['answers'][self.question['id']]['reason'] = 'tampered after commit'
        with self.assertRaises(ValueError): build_mapping(self.batch, self.generation, projection)

    def test_question_budget_survives_changed_generation_of_same_source(self):
        for number in range(13):
            generation = deepcopy(self.generation)
            for candidate in generation['candidates']:
                candidate['uncertainty'] = 'edition-' + str(number)
                candidate['id'] = digest({k: v for k, v in candidate.items() if k != 'id'})
            generation['generation_sha256'] = digest({k: v for k, v in generation.items() if k != 'generation_sha256'})
            self.store.bind_generation(generation)
            question = questions(generation)[0]
            def submit():
                return self.store.answer(generation, question['id'], 'unknown', 'test_author', 'uncertain', 0, 'budget-' + str(number))
            if number < 12: submit()
            else:
                with self.assertRaises(ValueError): submit()
        self.assertEqual(len(self.store.events()), 12)

    def test_committed_state_recovers_generation_identity_after_restart(self):
        # what_bug_this_catches: JSON pointer caches becoming a second authority.
        before = self.store.current_state()
        self.assertEqual(before['status'], 'bound')
        self.assertEqual(before['generation'], self.generation)
        self.assertEqual(before['source_sha256'], self.batch['source_sha256'])
        restarted = RulingStore(self.store.path)
        self.assertEqual(restarted.current_state(), before)
        same = restarted.bind_generation(self.generation, expected_state_token=before['state_token'])
        self.assertEqual(same['state_token'], before['state_token'])

    def test_generation_cas_rejects_stale_token_and_prevents_aba(self):
        first = self.store.current_state()
        changed = deepcopy(self.generation)
        changed['brief_sha256'] = digest('changed brief')
        changed['generation_sha256'] = digest({k: v for k, v in changed.items() if k != 'generation_sha256'})
        second = self.store.bind_generation(changed, expected_state_token=first['state_token'])
        third = self.store.bind_generation(self.generation, expected_state_token=second['state_token'])
        self.assertEqual(third['generation_binding'], first['generation_binding'])
        self.assertGreater(third['generation_epoch'], first['generation_epoch'])
        self.assertNotEqual(third['state_token'], first['state_token'])
        with self.assertRaises(ValueError):
            self.store.bind_generation(changed, expected_state_token=first['state_token'])
        self.assertEqual(self.store.current_state(), third)
        self.assertEqual(self.store.events(), [])  # Generation metadata is not a fabricated answer.

    def test_answer_commit_advances_state_and_historical_retry_token_stays_historical(self):
        before = self.store.current_state()
        receipt = self.answer()
        after = self.store.current_state()
        self.assertEqual(receipt['state_token'], after['state_token'])
        self.assertEqual(after['head_event_id'], receipt['event_id'])
        self.assertEqual(after['journal_sequence'], receipt['sequence'])
        self.assertEqual(after['state_revision'], before['state_revision'] + 1)
        self.answer(1, 'later-correction', 'unknown')
        self.assertEqual(self.answer(), receipt)
        self.assertNotEqual(receipt['state_token'], self.store.current_state()['state_token'])
        with self.assertRaises(ValueError):
            self.store.bind_generation(self.generation, expected_state_token=receipt['state_token'])

    def test_failed_answer_does_not_advance_committed_state_token(self):
        before = self.store.current_state()
        with closing(sqlite3.connect(self.store.path)) as db, db:
            db.execute("CREATE TRIGGER fail_atomic_receipt BEFORE INSERT ON receipts BEGIN SELECT RAISE(ABORT,'fail'); END")
        with self.assertRaises(sqlite3.IntegrityError): self.answer()
        self.assertEqual(self.store.current_state(), before)

    def test_legacy_active_binding_migrates_without_inventing_generation_payload(self):
        old_path = self.root / 'legacy.sqlite'
        with closing(sqlite3.connect(old_path)) as db, db:
            db.execute('CREATE TABLE active(singleton INTEGER PRIMARY KEY,binding TEXT NOT NULL)')
            db.execute('INSERT INTO active VALUES(1,?)', (digest(self.generation),))
        migrated = RulingStore(old_path)
        legacy = migrated.current_state()
        self.assertEqual(legacy['status'], 'legacy_binding_requires_rebind')
        self.assertIsNone(legacy['generation'])
        recovered = migrated.bind_generation(self.generation, expected_state_token=legacy['state_token'])
        self.assertEqual(recovered['status'], 'bound')
        self.assertEqual(recovered['generation'], self.generation)
        self.assertGreater(recovered['generation_epoch'], legacy['generation_epoch'])
        self.assertEqual(migrated.events(), [])

    def test_concurrent_generation_transition_has_one_state_cas_winner(self):
        initial = self.store.current_state()
        barrier = threading.Barrier(2)
        def transition(number):
            generation = deepcopy(self.generation)
            generation['brief_sha256'] = digest('transition-' + str(number))
            generation['generation_sha256'] = digest({k: v for k, v in generation.items() if k != 'generation_sha256'})
            barrier.wait()
            try:
                self.store.bind_generation(generation, expected_state_token=initial['state_token'])
                return 'committed'
            except ValueError:
                return 'conflict'
        with ThreadPoolExecutor(max_workers=2) as pool:
            result = list(pool.map(transition, (1, 2)))
        self.assertEqual(sorted(result), ['committed', 'conflict'])
        self.assertEqual(self.store.current_state()['generation_epoch'], initial['generation_epoch'] + 1)
