"""what_bug_this_catches: explanation inventing decisions or widening sample permission."""
from copy import deepcopy
import unittest

from la.contracts import digest, sha256
from la.ingest import ingest_bytes
from la.ingest.evidence import make_evidence
from la.review import question_context, questions
from review.support import BRIEF, RAW, fixture


class QuestionContext(unittest.TestCase):
    def test_context_preserves_offered_question_identity_and_unknown(self):
        batch, generation = fixture()
        result = question_context(batch, generation, options_limit=1, examples_limit=0)
        self.assertEqual(result['questions'], questions(generation))
        self.assertEqual(result['context_sha256'], digest({k: v for k, v in result.items() if k != 'context_sha256'}))
        for question in result['questions']:
            context = result['contexts'][question['id']]
            self.assertFalse(context['presentation_is_ranking'])
            self.assertEqual(context['approval'], 'absent')
            self.assertEqual(context['unknown']['state'], 'abstained')

    def test_partial_authorization_never_exposes_neighbor_cells(self):
        batch, generation = fixture()
        data = b'\r\n'.join(RAW)
        span = RAW[0][8:14]
        samples = {'source_sha256': sha256(data), 'authorization': 'balance span only',
                   'records': [{'ordinal': 0, 'start': 8, 'end': 14,
                                'raw_hex': span.hex(), 'raw_sha256': sha256(span)}]}
        batch = ingest_bytes(data, BRIEF, samples)
        generation = deepcopy(generation)
        for candidate in generation['candidates']:
            candidate['evidence'] = [make_evidence(batch, 0, 8, 14)] if candidate['semantic_target'] == 'balance' else []
            candidate['id'] = digest({k: v for k, v in candidate.items() if k != 'id'})
        generation['generation_sha256'] = digest({k: v for k, v in generation.items() if k != 'generation_sha256'})
        result = question_context(batch, generation, examples_limit=1)
        def inspect(value):
            if isinstance(value, dict):
                if {'position', 'redacted', 'hex'} <= value.keys() and not value['redacted']:
                    self.assertTrue(8 <= value['position'] < 14)
                for child in value.values(): inspect(child)
            elif isinstance(value, list):
                for child in value: inspect(child)
        inspect(result)

    def test_stale_and_boolean_limits_are_rejected(self):
        batch, generation = fixture()
        with self.assertRaises(ValueError): question_context(batch, generation, options_limit=True)
        with self.assertRaises(ValueError): question_context(batch, generation, examples_limit=4)
        changed = deepcopy(batch); changed['brief_sha256'] = 'f' * 64
        with self.assertRaises(ValueError): question_context(changed, generation)
