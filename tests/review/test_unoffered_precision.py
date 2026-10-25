"""A legal unoffered precision is not authorized by equivalent sample values."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from la.contracts import FieldCandidate, digest
from la.convert import approve_mapping, decode_value, transform
from la.inference.alternatives import policy_alternatives, status_vocabulary
from la.review import RulingStore, build_mapping, questions
from review.support import fixture


class UnofferedPrecision(unittest.TestCase):
    def test_legal_unoffered_precision_requires_unknown_until_explicit_offered_choice(self):
        """what_bug_this_catches: equal decoded samples authorize nearest-policy coercion or loading."""
        raws = [b'+00125', b'-00050']
        batch, generation = fixture(raw_rows=[b'0007AB  +0012520240229A',
                                              b'0008CD  -0005020240301B'])
        template = next(c for c in generation['candidates'] if c['semantic_target'] == 'balance')
        policies, diagnostics = policy_alternatives(raws, 'balance', status_vocabulary('balance'))
        self.assertEqual(len(policies), 3)
        self.assertEqual({p['scale'] for p in policies}, {0, 2, 3})
        self.assertEqual({p['precision'] for p in policies}, {5})
        self.assertIn(18, diagnostics['axes']['precision'])
        balances = []
        for policy in policies:
            candidate = dict(template, policy=deepcopy(policy))
            candidate['id'] = digest({k: v for k, v in candidate.items() if k != 'id'})
            balances.append(candidate)
        # Other four fields are declared public test fixtures, isolating this
        # ruling boundary; this is not an inference-quality demonstration.
        generation['candidates'] = [c for c in generation['candidates']
                                    if c['semantic_target'] != 'balance'] + balances
        generation['policy_sha256'] = digest('public finite precision ruling regression')
        generation['generation_sha256'] = digest({k: v for k, v in generation.items()
                                                   if k != 'generation_sha256'})
        offered = next(c for c in balances if c['policy']['scale'] == 2)
        hypothetical = deepcopy(offered)
        hypothetical['policy']['precision'] = 18  # An advertised legal axis, not an oracle value.
        hypothetical['id'] = digest({k: v for k, v in hypothetical.items() if k != 'id'})
        FieldCandidate.model_validate(hypothetical)
        self.assertNotIn(hypothetical['id'], {c['id'] for c in balances})
        self.assertEqual([decode_value(raw, offered) for raw in raws], ['1.25', '-0.50'])
        self.assertEqual([decode_value(raw, hypothetical) for raw in raws], ['1.25', '-0.50'])
        question_list = questions(generation)
        balance_question = next(q for q in question_list if q['semantic_target'] == 'balance')
        self.assertEqual(len(balance_question['options']), 4)  # Three complete choices plus unknown.
        self.assertNotIn(hypothetical['id'], {option['id'] for option in balance_question['options']})
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'rulings.sqlite'
            store = RulingStore(path)
            store.bind_generation(generation)
            for question in question_list:
                if question['semantic_target'] == 'balance':
                    continue
                candidate = next(c for c in generation['candidates']
                                 if c['semantic_target'] == question['semantic_target'])
                store.answer(generation, question['id'], candidate['id'], 'regression_author',
                             'public declared fixture', 0, 'other-'+question['semantic_target'])
            before = store.current_state()
            with self.assertRaises(ValueError):
                store.answer(generation, balance_question['id'], hypothetical['id'], 'regression_author',
                             'legal but not offered; must refuse', 0, 'unoffered')
            self.assertEqual(store.current_state(), before)
            self.assertEqual(len(store.events()), 4)
            store.answer(generation, balance_question['id'], 'unknown', 'regression_author',
                         'required precision has no offered option', 0, 'unknown-precision')
            reopened = RulingStore(path)
            projection = reopened.replay(generation)
            self.assertEqual(projection['answers'][balance_question['id']]['option_id'], 'unknown')
            self.assertEqual(len(reopened.events()), 5)
            incomplete = build_mapping(batch, generation, reopened)
            self.assertEqual(incomplete['mapping_status'], 'incomplete')
            with self.assertRaises(ValueError):
                approve_mapping(incomplete, 'regression_author', 'sample equivalence is insufficient')
            outcomes = transform(batch, incomplete)
            self.assertTrue(all(row['outcome'] == 'unresolved' and row['values'] == {} for row in outcomes))
            # Positive control: only an explicit new choice authorizes the
            # offered physical precision, with no claim it equals precision18.
            reopened.answer(generation, balance_question['id'], offered['id'], 'regression_author',
                            'explicitly select physical precision5', 1, 'explicit-offered')
            complete = build_mapping(batch, generation, reopened)
            self.assertEqual(complete['mapping_status'], 'complete')
            self.assertEqual([row['values']['balance'] for row in transform(batch, complete)], ['1.25', '-0.50'])


if __name__ == '__main__':
    unittest.main()
