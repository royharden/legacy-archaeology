# Complete-stream observations and unmaterialized refusal

Source only under Dirty Mode; no files were streamed, product code imported,
or regression assertions executed. D7 owns actual bounded chunk reads, canonical
input-root containment and before/after file identity observation. This producer
does not open paths, probe files or independently verify caller observations.

```python
from la.ingest.observed import refuse_observed_input, validate_observed_refusal

refuse_observed_input(
    *, source_sha256, input_byte_count, observed_count, reason,
    brief='', permitted_samples=None, terminal_newline=None,
    observation_stable=True, observation_complete=True,
    declared_encoding='ASCII', declared_record_type='fixed-width',
    declared_numeric='ascii', declared_family=None, observation_pins=None,
)
```

Only a refused SourceBatch can be produced. `records=[]`, width null, framing
unresolved; no separator, data record, candidate, sample authority or approval is
invented. Accepted bounded inputs continue through existing `ingest_bytes`.

`source_sha256` must be the exact lowercase64-hex SHA256 of the **complete observed
stream**. Prefix/incomplete observations (`observation_complete=False`) and
missing/invalid hashes raise ValueError: the existing required SourceBatch hash
cannot honestly identify an absent full stream. Never save a truncated prefix
as original source.dat or use a prefix hash as source identity. If reading is
interrupted before EOF, the caller retains its read-error state instead of
fabricating a SourceBatch original hash.

Exact nonnegative signed64 integers are required for byte/count observations;
booleans are rejected. `observed_count=None` is explicitly unknown, never0.
Known counts cannot exceed bytes or be0 for nonempty input. Terminal newline
may be bool or None (unobserved). Empty bytes require the actual SHA256 of empty
bytes and cannot claim a terminal newline.

Reason must be applicable to supplied observations and one of file_limit,
record_limit, brief_limit, unsupported_encoding, unsupported_record_family,
unsupported_packed_decimal, unsupported_numeric, input_changed_during_read or
observed_count_unknown. Limits/config/declarations are pinned and shared with
bounded intake through `limits.py`; caller parameters cannot raise those caps.
All applicable refusal reasons are retained. No caller reason can create an
accepted batch or falsely assert a limit that was not exceeded.

Observation pins accept only before_identity_sha256, after_identity_sha256 and
reader_policy_sha256. Values are SHA256 strings, never paths, raw stat objects,
credentials or arbitrary metadata. Different before/after identity pins cannot
claim stable observation. An unstable completed read still hashes exactly its
observed bytes, with explicit complete_observed_stream_not_stable_file scope.
Absent identity attestations are labeled not_independently_attested. The
producer never claims it probed identity or reconstructed source bytes.

## Hashes, unknown denominators and sample pins

`intake.stream_observation` hashes its exact supplied object excluding
observation_sha256. It pins full-stream source/byte/count/terminal observations,
brief hash/count, optional sample artifact hash, stability/policy/identity claims
and explicit no-reconstruction/no-probe flags. `intake.framing_policy` uses this
distinct unmaterialized descriptor, never an accepted record-framing identity:

```json
{"version":3,"kind":"unmaterialized_stream_refusal","framing":"unresolved","width":null,"width_candidates":[],"terminal_newline":null,"observation_sha256":"<observation hash>"}
```

Framing SHA hashes that exact descriptor. Source SHA remains the full observed
stream hash. V2 bounded refusal and V3 streamed refusal therefore preserve the
same full source hash/counts when known, with distinct framing/config provenance.
No RecordRef exists until real bytes are framed.

Permitted samples are bounded JSON-hashed (16MiB string bytes,200000 nodes,
depth12) but **unvalidated_without_source_bytes**. Malformed JSON structure or
oversized pin input raises ValueError. Sample references cannot become authorized
from metadata alone: authorization is empty, records/authorized_spans are empty,
record_references_validated is false. An absent artifact is explicitly not_provided.

`validate_observed_refusal(batch)` checks observation/hash/count/config/sample
and refusal lineage without asserting absent raw bytes. `verify_records` invokes
it for stream refusals; optional actual source bytes, if supplied later, must
match the complete hash and known byte/count/terminal observations. Evidence
resolution on an unmaterialized ordinal fails; no fake raw sample is created.

Inspection known-count refusals retain normal unmaterialized paging. Unknown
counts use `state=unknown_count`, counts.observed/unmaterialized=None, no rows,
next_offset/scanned_stop=None, and page offset0 only. Detail carries ordinal=None
plus requested_ordinal and no row/ref, never a claim that that ordinal exists.
Authorized-only requests may inspect this refusal metadata but expose no bytes
or granted sample permission. Source integrity scope remains
completed_stream_observation_not_reconstructed.

Future source regressions are test_observed.py and test_inspection_properties.py;
they were not collected or executed. D7 HTML escaping, actual file race behavior
and all runtime assertions remain unverified. IDENTITY.md V1/V2 semantics and
ordinary bounded intake signatures remain unchanged.
