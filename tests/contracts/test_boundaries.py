"""Regression SOURCE only; not imported, collected or executed in Dirty Mode."""
import unittest
import ast
import tomllib
from pathlib import Path
from copy import deepcopy

from pydantic import ValidationError
from la.contracts import digest, validate_generation, validate_batch, FieldCandidate, RecordRef, sha256


def generation(**extra):
    value = dict(schema_version=1, source_sha256='1'*64, framing_sha256='2'*64,
                 brief_sha256='3'*64, policy_sha256='4'*64, candidates=[], unknowns=[], mode='rules', **extra)
    return dict(value, generation_sha256=digest(value))


class BoundaryTests(unittest.TestCase):
    def test_absent_optional_metadata_preserves_original_hash(self):
        """what_bug_this_catches: materialized defaults silently stale old identities."""
        old = generation()
        self.assertEqual(validate_generation(old), old)
        self.assertNotIn('discovery', validate_generation(old))
        self.assertNotIn('filler', validate_generation(old))

    def test_emitted_metadata_and_filler_participate_in_hash(self):
        """what_bug_this_catches: new diagnostics/filler escaped generation binding."""
        value = generation(discovery={}, filler=[{'start': 2, 'end': 3}])
        validated = validate_generation(value)
        self.assertEqual(validated, value)
        mutated = deepcopy(value); mutated['filler'][0]['end'] = 4
        self.assertNotEqual(digest({k:v for k,v in mutated.items() if k != 'generation_sha256'}), value['generation_sha256'])

    def test_unknown_field_and_wrong_typed_metadata_refused(self):
        """what_bug_this_catches: permissive extra fields smuggle model offsets/SQL."""
        for extra in ({'sql': 'DROP TABLE users'}, {'schema_version': True}, {'discovery': []}, {'filler': [{'start': True, 'end': 2}]}):
            with self.subTest(extra=extra), self.assertRaises(ValidationError):
                validate_generation(dict(generation(), **extra))

    def test_candidate_semantic_type_and_policy_are_strict(self):
        """what_bug_this_catches: boolean scale/coerced numeric identifiers cross boundary."""
        field = dict(start=0, end=4, semantic_target='balance', data_type='decimal',
                     policy={'scale': 2, 'sign': 'leading'}, evidence=[], origin='rules', uncertainty='unconfirmed')
        field['id'] = digest(field)
        self.assertEqual(FieldCandidate.model_validate(field).data_type,'decimal')
        for change in ({'data_type': 'text'}, {'policy': {'scale': True}}, {'policy': {'sql': 'SELECT 1'}}, {'end': 0}):
            changed = dict(field, **change)
            changed['id'] = digest({k:v for k,v in changed.items() if k != 'id'})
            with self.subTest(change=change), self.assertRaises(ValidationError):
                FieldCandidate.model_validate(changed)

    def test_malformed_and_changed_identities_refused(self):
        """what_bug_this_catches: well-shaped JSON is mistaken for content-bound evidence."""
        for source in ('not-a-hash', 'A'*64):
            value = generation(); value['source_sha256'] = source
            value['generation_sha256'] = digest({k:v for k,v in value.items() if k != 'generation_sha256'})
            with self.assertRaises(ValidationError): validate_generation(value)
        value = generation(); value['unknowns'].append('changed after hashing')
        with self.assertRaises(ValidationError): validate_generation(value)
        with self.assertRaises(ValidationError):
            RecordRef.model_validate(dict(source_sha256='1'*64, framing_sha256='2'*64, ordinal=0,
                byte_start=0, length=2, raw_sha256=sha256(b'AB'), raw_hex='4143', disposition='eligible', reasons=[]))

    def test_batch_optional_intake_default_does_not_rewrite_preserved_artifact(self):
        """what_bug_this_catches: optional source diagnostics silently materialize in old pins."""
        value = dict(schema_version=1, source_sha256='1'*64, framing_sha256='2'*64, framing='unresolved',
            encoding='ASCII', declared_format={'encoding':'ASCII'}, width=None, status='refused', reasons=['empty_input'],
            records=[], brief_sha256='3'*64, samples=dict(authorization='',artifact_sha256=sha256(b'public empty permission artifact'),
                records=[],selected_ordinals=[],truncated=False), config_sha256='4'*64)
        self.assertEqual(validate_batch(value),value)
        emitted = dict(value,intake={})
        self.assertEqual(validate_batch(emitted),emitted)

    def test_inference_wheel_has_no_evaluator_module_or_import(self):
        """what_bug_this_catches: evaluator/oracle code is shipped into inference boundary."""
        root=Path(__file__).resolve().parents[2]
        config=tomllib.loads((root/'pyproject.toml').read_text(encoding='utf-8'))
        self.assertEqual(config['tool']['hatch']['build']['targets']['wheel']['packages'],['src/la'])
        for file in (root/'src/la').rglob('*.py'):
            tree=ast.parse(file.read_text(encoding='utf-8'))
            for node in ast.walk(tree):
                modules=[alias.name for alias in node.names] if isinstance(node,ast.Import) else [node.module or ''] if isinstance(node,ast.ImportFrom) else []
                self.assertFalse(any(name=='evaluation' or name.startswith('evaluation.') for name in modules),str(file))


if __name__ == '__main__': unittest.main()
