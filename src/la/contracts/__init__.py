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

class SourceBatch(Boundary):
    schema_version: Literal[1] = 1
    source_sha256: str
    framing_sha256: str
    framing: str
    encoding: Literal['ASCII'] = 'ASCII'
    width: int | None
    status: Literal['accepted', 'refused']
    reasons: list[str]
    records: list[RecordRef]
    brief_sha256: str
    samples: dict[str, Any]
    config_sha256: str

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

def validate_batch(value: dict) -> dict:
    return SourceBatch.model_validate(value).model_dump()

def validate_generation(value: dict) -> dict:
    return Generation.model_validate(value).model_dump()
