"""Future strict-wire regression SOURCE. No schema/app imports executed in construction."""
import ast
from copy import deepcopy
from pathlib import Path
import unittest

from pydantic import ValidationError
from la.contracts import validate_batch,validate_generation,digest,sha256,Question
from la.contracts.protocol import options_wire,outcome_evidence_wire,filler_wire
from la.providers.wire import request_pins,settlement_fields


class NestedProtocolTests(unittest.TestCase):
    def test_real_producer_roundtrip_preserves_all_supplied_pins_and_absence(self):
        """what_bug_this_catches: nested validation adds defaults and invalidates actual producer identity."""
        from la.ingest import ingest_bytes
        from la.inference import hypothesize
        batch=ingest_bytes(b'ABCD\nEFGH\n','account_ref',None)
        self.assertEqual(validate_batch(batch),batch)
        gen=hypothesize(batch,'account_ref',mode='rules')
        self.assertEqual(validate_generation(gen),gen)
        self.assertEqual(digest({k:v for k,v in gen.items() if k!='generation_sha256'}),gen['generation_sha256'])

    def test_source_sample_protocol_cannot_smuggle_oracle_or_unknown_nested_keys(self):
        """what_bug_this_catches: an authorized outer object carries hidden arbitrary nested metadata."""
        from la.ingest import ingest_bytes
        original=ingest_bytes(b'ABCD\nEFGH\n','account_ref',None)
        for target in ('samples','intake'):
            changed=deepcopy(original); changed[target]['oracle']='synthetic-private-marker'
            with self.assertRaises(ValidationError): validate_batch(changed)
        changed=deepcopy(original)
        changed['intake']['separators'][0]['gold']='synthetic-private-marker'
        with self.assertRaises(ValidationError): validate_batch(changed)

    def test_unknown_refused_denominator_stays_none(self):
        """what_bug_this_catches: unknown stream count becomes a false measured zero."""
        from la.ingest.observed import refuse_observed_input
        batch=refuse_observed_input(source_sha256=sha256(b'opaque'),input_byte_count=6,observed_count=None,
                                    reason='observed_count_unknown')
        checked=validate_batch(batch)
        self.assertIsNone(checked['intake']['observed_record_count'])
        self.assertIsNone(checked['intake']['unmaterialized_record_count'])
        self.assertEqual(checked['records'],[])
        self.assertEqual(checked['samples']['authorized_spans'],[])

    def test_legacy_generation_absent_optional_metadata_not_materialized(self):
        """what_bug_this_catches: old immutable generations get rewritten by nested-model defaults."""
        legacy=dict(schema_version=1,source_sha256='a'*64,framing_sha256='b'*64,brief_sha256='c'*64,
                    policy_sha256='d'*64,candidates=[],unknowns=[],mode='rules')
        legacy['generation_sha256']=digest(legacy)
        self.assertEqual(validate_generation(legacy),legacy)
        self.assertNotIn('discovery',validate_generation(legacy))

    def test_unknown_question_option_cannot_carry_a_hidden_layout(self):
        """what_bug_this_catches: unknown option becomes an unvalidated arbitrary payload channel."""
        self.assertEqual(options_wire([{'id':'unknown'}]),[{'id':'unknown'}])
        with self.assertRaises(ValueError): options_wire([{'id':'unknown','sql':'synthetic'}])

    def test_bool_as_position_and_unknown_outcome_evidence_refused(self):
        """what_bug_this_catches: truthy positions or unrecognized evidence fields survive shared models."""
        with self.assertRaises(ValueError): filler_wire([{'start':True,'end':2}])
        with self.assertRaises(ValueError): outcome_evidence_wire({'raw_hex':'41','oracle':{}})
        with self.assertRaises(ValueError): outcome_evidence_wire({'raw_hex':'41','failure_span':{'start':0,'end':1,'semantic_target':'balance','sql':'x'}})

    def test_provider_protocol_rejects_unknown_pins_without_stripping_them(self):
        """what_bug_this_catches: caller protocol keys leak arbitrary data into durable receipts."""
        with self.assertRaises(ValueError): request_pins({'oracle_sha256':'a'*64})
        with self.assertRaises(ValueError): request_pins({'candidate_count':True})
        with self.assertRaises(ValueError): request_pins({'evaluation_phase':'T1'})

    def test_vendor_usage_categories_survive_exactly_even_when_unsupported(self):
        """what_bug_this_catches: schema cleanup drops cached/reasoning/unknown billed categories."""
        raw={'input_tokens':10,'input_tokens_details':{'cached_tokens':4},'output_tokens':5,
             'output_tokens_details':{'reasoning_tokens':2},'future_vendor_category':{'opaque':'inert'}}
        before=deepcopy(raw)
        self.assertEqual(settlement_fields({'raw_usage':raw})['raw_usage'],before)
        self.assertEqual(raw,before)
        with self.assertRaises(ValueError): settlement_fields({'verified':True,'raw_usage':raw})

    def test_schema_children_import_only_canonical_base_not_producer_roots(self):
        """what_bug_this_catches: nested model imports create contracts/producer initialization cycles."""
        root=Path(__file__).resolve().parents[2]/'src/la/contracts'
        for name in ('base.py','evidence.py','protocol.py'):
            tree=ast.parse((root/name).read_text(encoding='utf-8'))
            for node in ast.walk(tree):
                modules=([a.name for a in node.names] if isinstance(node,ast.Import) else
                         [node.module or ''] if isinstance(node,ast.ImportFrom) else [])
                self.assertFalse(any(m.startswith(('la.inference','la.review','la.convert','la.providers','la.contracts')) for m in modules))


if __name__=='__main__': unittest.main()
