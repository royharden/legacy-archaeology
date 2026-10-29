# Source and framing identities

This is a wire specification for independent consumers. Evaluator serializers
must implement it independently; importing inference/ingest algorithms is not
required or appropriate for canonical gold construction.

`sha256(bytes)` is the lower-case SHA256 hex digest of those exact bytes.
`digest(object)` hashes JSON encoded as UTF-8, sorted object keys, compact `,`/`:`
separators, Unicode retained (`ensure_ascii=False`), and no NaN/Infinity. Arrays
retain order. Source identity hashes the entire original file including all
separators. No decoding, stripping, newline replacement, or record sorting occurs.

## Framing-v1: initial candidate, legacy identity only

The initial implementation hashed this exact object (no version field):

```json
{"framing":"CRLF","width":2,"terminal_newline":false}
```

`framing` is `LF`, `CRLF`, or `unresolved`; `width` is the unique most frequent
positive data-byte length no greater than256, otherwise JSON null. A width tie
was refused. New intakes use v2; old pins are not silently rewritten into v2.

## Framing-v2: current producer

Hash the following exact descriptor, with the actual values substituted:

```json
{"version":2,"framing":"CRLF","width":2,"width_candidates":[2],"terminal_newline":false}
```

Widths count data bytes after removing only the actual LF or CRLF separator.
Histogram candidates exclude width0 and widths greater than256. `width_candidates`
is the ascending list tied for highest frequency; `width` is its only member
when unique, otherwise null. `framing` is determined from actual terminated
records; mixed styles are `unresolved` and refused. Bare CR data is refused.
`terminal_newline` records whether the original source ends with LF.

For exact bytes `AB\r\nCD`, records are `(ordinal=0,byte_start=0,length=2)` and
`(ordinal=1,byte_start=4,length=2)`. Separators are hex `0d0a` at offset2 and empty
hex at offset6. No synthetic final record or separator is inserted. For
`AB\nCD\n`, the second start is3 and separators are `0a` at offsets2 and5.
For `AB\nC`, observed lengths1 and2 tie: candidates `[1,2]`, width null, both
ordinals retained with unresolved-width reasons. An unterminated final record
is eligible only when its observed length and content satisfy the selected
framing/ASCII conditions; short/high-byte records retain their ordinal.

`SourceBatch.intake.framing_policy` contains the v2 descriptor. Separators retain
ordinal, absolute byte_start, length, and raw_hex. For materialized input,
concatenating every data record with its separator reconstructs source bytes
and must reproduce source_sha256. Byte offsets are zero-based; spans are
half-open. Duplicate raw data at different ordinals remains distinct.

Before splitting, limit/declaration refusals hash original bytes and count
observed LF-framed records (`LF count +1` if nonempty and not LF-terminated).
Those refusals may materialize no records. Intake records observed, materialized
and unmaterialized counts; an empty records array does not assert zero input.

## Record and span evidence

RecordRef identity is the exact tuple of `source_sha256`, `framing_sha256`,
`ordinal`, `byte_start`, `length`, and `raw_sha256` (data bytes only). Record
display dictionaries additionally contain raw_hex, disposition, reasons.

Evidence has record ordinal, relative start/end, source/framing hashes,
absolute byte_start=`record.byte_start+start`, and the exact span raw_hex and
raw_sha256. Generated evidence also carries the complete nested identity-only
record_ref. `resolve_evidence(batch,evidence,source=None,require_authorized=False)`
validates identities/range/hashes; `require_authorized=True` also requires
containment in a selected permitted span. `verify_records(batch,source=None)`
checks record/source reconstruction where retained framing metadata is present.

Permitted sample artifacts have schema_version1 (optional for the legacy API),
source_sha256, optional framing_sha256, nonempty authorization, records, and
optional artifact_sha256. The latter, if supplied, hashes the artifact without
that self-hash field. Batch samples.artifact_sha256 hashes the entire artifact;
samples.content_sha256 is the hash excluding the self-hash field.

Legacy sample entries contain ordinal/raw_hex/raw_sha256 and authorize that
exact whole record. Full identity fields, if supplied, must match. Partial
entries should contain complete identity-only record_ref, span `{start,end}`,
and span raw_hex/raw_sha256. Unknown fields, mismatched refs/spans/hashes,
duplicate `(ordinal,start,end)`, or invalid authorization refuse the entire
artifact; valid neighbors do not retain authorization after a refusal.

Selection sorts authorized entries by `(ordinal,start,end)`, takes bounded
entries with at most64 distinct ordinals and16384 raw span bytes, and records
original artifact indices/truncation. `selection_sha256` hashes that selected
span list, including artifact_index. Whole samples.records contains only
selected whole-record authorizations; it never expands partial authorization.

## Candidate and explicit filler lineage

`hypothesize(batch,brief,mode='rules')` emits finite proposals and an empty
filler list. `declare_filler(batch,generation,spans,*,actor,reason)` returns a new
generation with explicitly declared filler spans and content-bound decision
provenance in discovery.filler_declaration. Whitespace is never automatically
approved as filler. The declaration creates no journal events or approval.
New generation/policy hashes invalidate prior generation-bound rulings; real
supporting rulings and the normal mapping/approval lifecycle remain required.

Candidate IDs hash their exact dict excluding id. Generation identity hashes
its exact supplied dict excluding generation_sha256, including explicitly
supplied discovery/filler fields. Absent optional fields in legacy generations
must not be materialized before checking a legacy hash.
