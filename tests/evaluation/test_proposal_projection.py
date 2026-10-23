"""Evaluator-only proposal/Question adapter regression SOURCE; injected fakes only."""
from copy import deepcopy
import unittest

from evaluator_support import visible
from evaluation.adapters import project_product_question, validate_evaluator_proposal, transform_evaluator_proposal
from evaluation.artifacts import digest


class ProposalProjection(unittest.TestCase):
    def test_question_keeps_binding_locally_and_offers_no_new_values(self):
        """what_bug_this_catches: relaxing broker wire exposes product/private metadata."""
        question = {'id': 'q', 'schema_version': 1, 'semantic_target': 'balance',
                    'source_sha256': 'a' * 64, 'generation_binding': 'b' * 64,
                    'prompt': 'Choose offered scale', 'options': [{'id': 'scale2', 'value': 2}, {'id': 'unknown'}],
                    'evidence': []}
        projected = project_product_question(question)
        self.assertNotIn('generation_binding', projected['question'])
        self.assertNotIn('semantic_target', projected['question'])
        self.assertEqual(projected['question']['options'], [{'id': 'scale2'}, {'id': 'unknown'}])
        self.assertEqual(projected['provenance']['generation_binding'], 'b' * 64)
        self.assertEqual(projected['provenance']['source_question_sha256'], digest(question))

    def test_proposal_transform_never_confers_product_approval(self):
        """what_bug_this_catches: no-answer baselines fabricate approval/ruling events."""
        proposal = {'schema_version': 1, 'kind': 'evaluator_proposal', 'method': 'B1', 'origin': 'model',
                    'source_sha256': 'a' * 64, 'framing_sha256': 'b' * 64, 'width': 7,
                    'fields': [], 'filler': [], 'proposal_sha256': 'c' * 64}
        calls = []
        def ingest(data, brief, samples):
            return {'source_sha256': 'a' * 64, 'framing_sha256': 'b' * 64, 'width': 7}
        def validate(batch, candidate):
            calls.append(deepcopy(candidate))
            return {'validation_status': 'complete_proposal', 'loadable': False, 'product_approval': 'absent'}
        mapped = validate_evaluator_proposal(proposal, visible(), ingest=ingest, validate_proposal=validate)
        def transform(batch, candidate):
            calls.append(deepcopy(candidate))
            return {'proposal': {'loadable': False, 'product_approval': 'absent'}, 'outcomes': []}
        self.assertEqual(transform_evaluator_proposal(visible(), mapped, ingest=ingest,
                                                       transform_proposal=transform), [])
        self.assertEqual(calls[1]['origin'], 'model')
        self.assertNotIn('supporting_event_ids', calls[1])
        self.assertNotIn('mapping_status', calls[1])
        self.assertFalse(mapped['loadable'])
        self.assertEqual(calls[1]['proposal_sha256'], digest({k: v for k, v in calls[1].items() if k != 'proposal_sha256'}))


if __name__ == '__main__':
    unittest.main()
