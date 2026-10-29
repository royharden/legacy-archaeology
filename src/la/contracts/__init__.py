"""Strict v1 wire boundaries and canonical identities. Decimal values stay strings."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Literal
from pydantic import Field, model_validator,field_validator
from .base import Boundary
from .protocol import policy_wire,filler_wire,options_wire,outcome_evidence_wire,closed,text,identity
from .evidence import SampleMetadata,IntakeMetadata,DiscoveryMetadata,SpanEvidence

REQUIRED_FIELDS = ('account_ref', 'description', 'balance', 'effective_date', 'status')

def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')

def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()

def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

class RecordRef(Boundary):
    source_sha256: str
    framing_sha256: str
    ordinal: int = Field(ge=0,le=9999)
    byte_start: int = Field(ge=0,le=5*1024*1024)
    length: int = Field(ge=0,le=5*1024*1024)
    raw_sha256: str
    raw_hex: str
    disposition: Literal['eligible', 'quarantined']
    reasons: list[str]

    @model_validator(mode='after')
    def raw_identity(self):
        try:
            raw = bytes.fromhex(self.raw_hex)
        except ValueError:
            raise ValueError('invalid record hex') from None
        if raw.hex() != self.raw_hex or len(raw) != self.length or sha256(raw) != self.raw_sha256:
            raise ValueError('record bytes/length/hash mismatch')
        return self

class SourceBatch(Boundary):
    schema_version: Literal[1] = 1
    source_sha256: str
    framing_sha256: str
    framing: str
    encoding: Literal['ASCII'] = 'ASCII'
    declared_format: dict[str, str]
    width: int | None = Field(ge=1,le=256)
    status: Literal['accepted', 'refused']
    reasons: list[str]
    records: list[RecordRef] = Field(max_length=10000)
    brief_sha256: str
    samples: SampleMetadata
    config_sha256: str
    intake: IntakeMetadata = Field(default_factory=dict)

    @field_validator('declared_format',mode='before')
    @classmethod
    def declared_wire(cls,value):
        # Historical artifacts could emit just encoding; absent declarations are
        # preserved, while new producers emit all three explicit declarations.
        closed(value,{'encoding'},{'record_family','numeric'})
        for item in value.values(): text(item,128)
        return value

class FieldCandidate(Boundary):
    id: str
    start: int = Field(ge=0,le=255)
    end: int = Field(gt=0,le=256)
    semantic_target: str
    data_type: Literal['text', 'decimal', 'date']
    policy: dict[str, Any]
    evidence: list[SpanEvidence] = Field(max_length=64)
    origin: Literal['rules', 'mock']
    uncertainty: str

    @field_validator('policy',mode='before')
    @classmethod
    def policy_shape(cls,value): return policy_wire(value)

    @model_validator(mode='after')
    def valid_interpretation(self):
        if self.end <= self.start: raise ValueError('candidate span must be nonempty')
        if self.semantic_target not in REQUIRED_FIELDS: raise ValueError('unknown semantic target')
        expected = 'decimal' if self.semantic_target=='balance' else 'date' if self.semantic_target=='effective_date' else 'text'
        if self.data_type!=expected: raise ValueError('semantic target/type mismatch')
        allowed={'padding_byte','padding_side','trim','nullable','allowed_codes','scale','precision','sign','format','century_window','sentinels'}
        if set(self.policy)-allowed: raise ValueError('unknown policy field')
        if 'scale' in self.policy and (type(self.policy['scale']) is not int or self.policy['scale'] not in (0,2,3)):
            raise ValueError('unsupported scale')
        if 'sign' in self.policy and self.policy['sign'] not in ('unsigned','leading','trailing'):
            raise ValueError('unsupported sign policy')
        if 'format' in self.policy and self.policy['format'] not in ('YYYYMMDD','YYMMDD'):
            raise ValueError('unsupported date policy')
        if 'padding_side' in self.policy and self.policy['padding_side'] not in ('none','left','right'):
            raise ValueError('unsupported padding side')
        for name in ('trim','nullable'):
            if name in self.policy and type(self.policy[name]) is not bool: raise ValueError('policy booleans must be typed')
        value = self.model_dump(exclude_unset=True)
        if digest({k:v for k,v in value.items() if k != 'id'}) != self.id:
            raise ValueError('candidate identity mismatch')
        return self

class MappingSpec(Boundary):
    schema_version: Literal[1] = 1
    source_sha256: str
    framing_sha256: str
    generation_sha256: str
    generation_binding: str
    policy_sha256: str
    width: int | None = Field(ge=1,le=256)
    fields: list[FieldCandidate] = Field(max_length=32)
    filler: list[dict[str, int]]
    supporting_event_ids: list[str]
    mapping_status: Literal['complete', 'incomplete']
    unresolved: list[str]
    mapping_sha256: str

    @field_validator('filler',mode='before')
    @classmethod
    def filler_shape(cls,value): return filler_wire(value)

    @field_validator('supporting_event_ids',mode='before')
    @classmethod
    def event_identity_list(cls,value):
        if type(value) is not list or len(value)>32: raise ValueError('bounded supporting event identities required')
        for event in value: identity(event)
        return value

class OutcomeRef(Boundary):
    source_sha256: str
    framing_sha256: str
    ordinal: int = Field(ge=0,le=9999)
    byte_start: int = Field(ge=0,le=5*1024*1024)
    length: int = Field(ge=0,le=5*1024*1024)
    raw_sha256: str

class RowOutcome(Boundary):
    schema_version: Literal[1] = 1
    record_ref: OutcomeRef
    mapping_sha256: str
    outcome: Literal['converted', 'unresolved', 'quarantined']
    values: dict[str, str | None]
    reasons: list[str]
    evidence: dict[str, Any]

    @field_validator('evidence',mode='before')
    @classmethod
    def outcome_evidence(cls,value): return outcome_evidence_wire(value)

    @field_validator('values',mode='before')
    @classmethod
    def typed_values(cls,value):
        closed(value,(),REQUIRED_FIELDS)
        for item in value.values():
            if item is not None: text(item,4096)
        return value

class Question(Boundary):
    schema_version: Literal[1] = 1
    id: str
    semantic_target: str
    generation_binding: str
    source_sha256: str
    prompt: str = Field(max_length=4000)
    options: list[dict[str, Any]]
    evidence: list[SpanEvidence] = Field(max_length=6)

    @field_validator('options',mode='before')
    @classmethod
    def offered_options(cls,value): return options_wire(value)

class Approval(Boundary):
    schema_version: Literal[1] = 1
    mapping_sha256: str
    source_sha256: str
    generation_binding: str
    actor: str
    reason: str
    approval_sha256: str

class AnswerEvent(Boundary):
    schema_version: Literal[1] = 1
    generation_binding: str
    question_id: str
    option_id: str
    actor: str
    reason: str
    expected_revision: int = Field(ge=0)
    request_id: str
    revision: int = Field(ge=1)
    previous_event_id: str | None
    old_option_id: str | None
    semantic_target: str
    source_sha256: str
    generation_sha256: str
    brief_sha256: str
    policy_sha256: str
    timestamp: str
    event_id: str

    @field_validator('option_id','old_option_id',mode='before')
    @classmethod
    def offered_identity(cls,value):
        if value is not None and value!='unknown': identity(value)
        return value

class MigrationBundle(Boundary):
    schema_version: Literal[1] = 1
    source_sha256: str
    mapping_sha256: str
    generation_binding: str
    approval_sha256: str | None
    config_sha256: str
    supporting_event_ids: list[str]
    producer_code_sha256: str
    files: dict[str, str]
    columns: list[str]
    counts: dict[str, int]
    record_count: int
    mapping_status: Literal['complete','incomplete']
    transformation_status: Literal['complete','partial','not_run','failed']
    target_validation: Literal['not_run','passed','failed','indeterminate']
    row_parity: Literal['not_run','exact','mismatch','incomplete']
    bundle_sha256: str

    @field_validator('files',mode='before')
    @classmethod
    def member_pins(cls,value):
        closed(value,{'mapping.json','source.json','schema.sql','migrate.sql','rows.jsonl',
                      'unresolved.jsonl','quarantine.jsonl','approval.json'}, {'rulings.json','inputs.json','LOAD.md'})
        for pin in value.values(): identity(pin)
        return value

    @field_validator('columns',mode='before')
    @classmethod
    def column_names(cls,value):
        allowed={'source_sha256','ordinal','raw_sha256',*REQUIRED_FIELDS}
        if (type(value) is not list or len(value)>8 or any(type(column) is not str for column in value)
                or len(value)!=len(set(value)) or any(column not in allowed for column in value)):
            raise ValueError('known unique migration columns required')
        return value

    @field_validator('counts',mode='before')
    @classmethod
    def outcome_counts(cls,value):
        from .protocol import integer
        closed(value,{'converted','unresolved','quarantined'})
        for count in value.values(): integer(count,0,10000)
        return value

class Generation(Boundary):
    schema_version: Literal[1] = 1
    source_sha256: str
    framing_sha256: str
    brief_sha256: str
    policy_sha256: str
    generation_sha256: str
    candidates: list[FieldCandidate] = Field(max_length=480)
    unknowns: list[str]
    mode: Literal['rules', 'mock']
    discovery: DiscoveryMetadata = Field(default_factory=dict)
    filler: list[dict[str, int]] = Field(default_factory=list)

    @field_validator('filler',mode='before')
    @classmethod
    def filler_shape(cls,value): return filler_wire(value)

    @model_validator(mode='after')
    def content_identity(self):
        value = self.model_dump(exclude_unset=True)
        if digest({k:v for k,v in value.items() if k != 'generation_sha256'}) != self.generation_sha256:
            raise ValueError('generation content hash mismatch')
        ids = [candidate.id for candidate in self.candidates]
        if len(ids) != len(set(ids)):
            raise ValueError('duplicate candidate identity')
        for span in self.filler:
            if set(span) != {'start', 'end'} or not 0 <= span['start'] < span['end']:
                raise ValueError('invalid explicit filler span')
        return self

def validate_batch(value: dict) -> dict:
    # Optional additive diagnostics must not materialize absent fields and alter
    # already-pinned producer hashes. Supplied diagnostics remain hash-bound.
    return SourceBatch.model_validate(value).model_dump(exclude_unset=True)

def validate_generation(value: dict) -> dict:
    return Generation.model_validate(value).model_dump(exclude_unset=True)
