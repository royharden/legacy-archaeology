"""Strict v1 wire boundaries and canonical identities. Decimal values stay strings."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator

REQUIRED_FIELDS = ('account_ref', 'description', 'balance', 'effective_date', 'status')

def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')

def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()

def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

class Boundary(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)

    @model_validator(mode='before')
    @classmethod
    def hash_shapes(cls, value):
        if isinstance(value, dict):
            if 'schema_version' in value and type(value['schema_version']) is not int:
                raise ValueError('schema_version must be an exact integer')
            ids = {'id', 'event_id', 'previous_event_id', 'question_id', 'generation_binding'}
            for key, item in value.items():
                if item is None or key not in cls.model_fields: continue
                if key.endswith('_sha256') or key in ids:
                    if type(item) is not str or len(item) != 64 or any(c not in '0123456789abcdef' for c in item):
                        raise ValueError('invalid SHA256 identity: '+key)
        return value

class RecordRef(Boundary):
    source_sha256: str
    framing_sha256: str
    ordinal: int = Field(ge=0)
    byte_start: int = Field(ge=0)
    length: int = Field(ge=0)
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
    width: int | None
    status: Literal['accepted', 'refused']
    reasons: list[str]
    records: list[RecordRef]
    brief_sha256: str
    samples: dict[str, Any]
    config_sha256: str
    intake: dict[str, Any] = Field(default_factory=dict)

class FieldCandidate(Boundary):
    id: str
    start: int = Field(ge=0)
    end: int = Field(gt=0)
    semantic_target: str
    data_type: Literal['text', 'decimal', 'date']
    policy: dict[str, Any]
    evidence: list[dict[str, Any]]
    origin: Literal['rules', 'mock']
    uncertainty: str

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
    width: int | None
    fields: list[FieldCandidate]
    filler: list[dict[str, int]]
    supporting_event_ids: list[str]
    mapping_status: Literal['complete', 'incomplete']
    unresolved: list[str]
    mapping_sha256: str

class OutcomeRef(Boundary):
    source_sha256: str
    framing_sha256: str
    ordinal: int = Field(ge=0)
    byte_start: int = Field(ge=0)
    length: int = Field(ge=0)
    raw_sha256: str

class RowOutcome(Boundary):
    schema_version: Literal[1] = 1
    record_ref: OutcomeRef
    mapping_sha256: str
    outcome: Literal['converted', 'unresolved', 'quarantined']
    values: dict[str, str | None]
    reasons: list[str]
    evidence: dict[str, Any]

class Question(Boundary):
    schema_version: Literal[1] = 1
    id: str
    semantic_target: str
    generation_binding: str
    source_sha256: str
    prompt: str
    options: list[dict[str, Any]]
    evidence: list[dict[str, Any]]

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
    expected_revision: int
    request_id: str
    revision: int
    previous_event_id: str | None
    old_option_id: str | None
    semantic_target: str
    source_sha256: str
    generation_sha256: str
    brief_sha256: str
    policy_sha256: str
    timestamp: str
    event_id: str

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

class Generation(Boundary):
    schema_version: Literal[1] = 1
    source_sha256: str
    framing_sha256: str
    brief_sha256: str
    policy_sha256: str
    generation_sha256: str
    candidates: list[FieldCandidate]
    unknowns: list[str]
    mode: Literal['rules', 'mock']
    discovery: dict[str, Any] = Field(default_factory=dict)
    filler: list[dict[str, int]] = Field(default_factory=list)

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
