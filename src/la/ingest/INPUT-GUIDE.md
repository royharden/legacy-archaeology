# Preparing source bytes, briefs and permitted evidence

This guide describes constructed source behavior and hand-authored teaching
inputs. The app, parser, candidate generator, tests, models, database and reports
have not been executed during Dirty Mode. A documented expectation is not a saved
result. Later commands require the separately authorized activation phase.

Start with the [three public teaching examples](../../../examples/intake/README.md).
They demonstrate full permission, partial permission and a declared refusal.
Their layouts/bytes are already public and known; they are never fresh holdout.
The canonical public-development-v2 fixture remains separately owned by the
evaluator and is not replaced by these examples.

## 1. Keep original bytes and a concept-only brief

Supply a small synthetic fixed-width account ledger, without real customer data.
Use the exact canonical concepts `account_ref`, `description`, `balance`,
`effective_date`, `status` in the brief. Explain business concepts and, if known,
the actual allowed status codes. Do not disclose offsets, widths, chosen field
order, implied scale or the answer to the ambiguity being studied in the brief.

The [ledger brief](../../../examples/intake/ambiguous-ledger/brief.md) is one
concrete template. `status (O = open, C = closed)` or an explicitly labeled
`status_codes: ["O", "C"]` discloses a vocabulary. Missing vocabulary must remain
unknown/unlisted-code diagnostics; observed characters alone are not a codebook.
Canonical semantic IDs are case-sensitive, not aliases for a scorer to rename.

Preserve original line endings, whitespace, signs and leading zeros. Do not open
and resave source.dat in a tool that normalizes CRLF/LF, trims trailing spaces or
converts encoding. `account_ref` is text, not an integer that can lose zeros.
The teaching inputs' local Git attributes preserve their pinned file bytes.

The [identity contract](IDENTITY.md) defines exact hashes, framing-v1/v2,
RecordRefs and half-open byte spans. Use it as schema authority, together with
the actual producer/strict shared contracts; the tables here are authoring advice.

## 2. Author an explicit sample artifact

The source file being visible to the local owner is distinct from permission to
send arbitrary records to a provider or show them in an authorized-only view.
Samples are a separate, source-bound artifact with a nonempty authorization label.
The label records provenance; it does not appoint a human reviewer or prove OS
account isolation.

Use the actual [whole-record artifact](../../../examples/intake/ambiguous-ledger/samples.json)
or [partial artifact](../../../examples/intake/partial-window/samples.json) as a
concrete input, not a generated output capture. Both have static pins in their
neighboring pins.json. Do not copy hashes between different sources.

For whole records, each exact ordinal/reference and complete record raw_hex/hash
must match supplied source data. Identical bytes at two ordinals require two
different record identities if both are authorized. Do not deduplicate them.

For partial records, use the complete six-part identity-only `record_ref` and a
relative span `{start,end}`, plus only that span's raw_hex/raw_sha256. The nested
record_ref hash is for the entire data record; the outer raw_sha256 is for the
authorized slice. RecordRef byte_start is the absolute **record** start; emitted
evidence byte_start is the absolute **slice** start. Do not confuse the two.

The partial teaching artifact identifies an11-byte record at absolute0 but
authorizes `[4,8)` only. Its slice is `PRIV` at absolute4–7. Providing the full
record identity/hash does not grant `LEFT`, `ATE`, the CRLF bytes or ordinal1.
Full-record raw bytes must not be substituted for that partial raw_hex field.

Artifact source/framing/ref/span/hash mismatches, out-of-range/boolean identity
integers, duplicate exact references or unknown fields refuse authorization.
Valid neighboring entries do not survive an invalid artifact as new permission.
Keep integer fields actual JSON integers, not booleans, decimal strings or floats.

An optional artifact self-hash hashes canonical JSON excluding that self-hash
field. The full artifact object hash includes it. A JSON **file** hash also
includes its final LF. The three domains differ; [IDENTITY.md](IDENTITY.md)
defines the canonical encoding. Static pins.json files make these distinctions
explicit without claiming the app validated them.

## 3. Know what bounded selection does

Intake selects authorized entries deterministically by ordinal/start/end, with
at most64 distinct records and16384 raw span bytes. Original artifact indices,
selection identity and truncation are recorded. Whole samples.records includes
only actual whole-record grants; partial grants remain selected spans.

The actual provider prompt may truncate further to its fixed byte cap, recording
sample/candidate omissions and prompted IDs. A prompt subset is advisory and
cannot declare omitted candidates incorrect or approved. Never replace selected
samples with arbitrary convenient file rows. Reordering/changing the artifact or
authorization changes its pins and can invalidate dependent generation/decisions.

## 4. Predict framing/refusal states honestly

| Input condition | Intended source behavior, not an observed run |
|---|---|
| Consistent ASCII LF or CRLF | Retain data/separators, exact offsets and distinct ordinals |
| Final data record has no terminal newline | Retain it; it must still satisfy selected width/content conditions |
| Short or empty internal record | Retain ordinal/bytes; quarantine wrong_length and blank_record as applicable |
| Byte greater than127 in a frameable record | Retain exact hex and high_byte reason; do not replacement-decode a typed value |
| Mixed LF/CRLF or internal bare CR | Explicit framing refusal, with retained materialized rows where framing was attempted |
| Tied plausible modal record widths | width remains null, sorted width candidates plus unknown; no arbitrary encounter-order winner |
| Empty or separator-less input | Explicit refusal; a lone unframed line is not silently assumed supported |
| File/record/brief limit or unsupported declaration | Refusal may occur before record materialization; keep full source/observation identity and denominator |
| Interrupted/incomplete stream | A prefix hash cannot identify an original source; retain caller read-error state instead of fabricating an accepted batch |
| Complete stream with changed before/after identity | Refused unstable observed stream, not a stable original-file claim |
| Record count genuinely unobserved | observed/unmaterialized remain null with unknown_count; never zero or invented RecordRefs |

Supported caps are5MiB including separators,10000 observed records,256 supported
data bytes per record and4000 brief characters. Candidate construction caps32
physical spans, at most five disclosed semantic-name options and at most three
complete policies per span/name. These are distinct units; up to480 candidate
policies is not480 inferred fields. Finite choices do not guarantee true-boundary
or true-policy recall. Use unknown if the correct option is absent.

ASCII transport does not make every control character a valid business value.
Diagnostic views escape controls/high bytes; declared conversion policy still
decides validity. Do not assume tabs, Unicode replacements, packed decimals,
EBCDIC, mixed record families or arbitrary copybooks are supported.

Offsets count bytes, not displayed characters. In the CRLF teaching file, the
second record starts at13, not12; its final data byte is at23 and source ends at24.
Every materialized ordinal contributes once. For early refusals, input count is
materialized plus unmaterialized when known; an empty records array is not proof
of zero input. Original bounded bytes may still be retained even when records
were not materialized. Oversize streamed inputs must not persist a prefix as
source.dat. See [STREAM-REFUSAL.md](STREAM-REFUSAL.md) for this separate provenance.

## 5. Inspect evidence before choosing an interpretation

Use [INSPECTION.md](INSPECTION.md) for bounded page/detail APIs and
[EXPLANATIONS.md](../inference/EXPLANATIONS.md) for concrete ambiguity producers.
Diagnostic ASCII, hex, byte rulers, profiles and clipped candidate overlays are
not converted values. A selected/ranked candidate is not an approval.

Owner inspection is explicitly local_owner_retained_source. Authorized-only
inspection shows permitted intersections with null/masked neighboring cells,
omits separator raw bytes and partial-record reasons, and never widens a sample
grant through an explanation or prompt. Pages use original ordinals, not a
filtered renumbering. Refused/unmaterialized/unknown states remain visible.

Questions should be answerable from actual offered evidence and known business
facts, with unknown available. For the ledger's literal `+001750`, these are
different decisions: field boundary, leading sign, scale0/2/3, precision and name.
Six digit date shapes do not establish a century. Blank/all-nines becoming SQL
NULL must be explicitly selected and nullable; unsupported zero dates have no
null shortcut. Declared padding is different from preserved spaces; empty text,
numeric zero and SQL NULL remain distinct. A generic digit-run label is not
evidence that a span is account_ref or balance.

The explanation API bounds examples and proves emitted slices against actual
source/framing/sample hashes. Zero/capped/no-authorized examples remain explicit;
it does not fill missing facts with model confidence. Omitted combinations and
unmeasured candidate recall are reasons to abstain, not force a nearby choice.

## 6. Declare filler and preserve decision lineage

Whitespace is not automatically filler. `declare_filler(batch,generation,spans,
*,actor,reason)` creates a new, content-bound explicit declaration and new
generation/policy identity. It creates no journal event, approval or permission
to load. The CLI's later declare-filler command consumes an actual spans file
and explicit actor/reason; D7 owns its caller surface.

Changed source requires a fresh immutable run; changed source/brief/sample/
candidate/policy/evidence dependencies invalidate affected rulings and approval.
Never patch old retained bytes, reuse an unrelated run ID, guess the newest
generation, import JSONL as journal authority or invent supporting events. Exact
answer retries return their historical receipt; stale generation/revision/CAS
must refuse. SQLite remains decision authority, and prior artifacts remain
available for their original source.

Incomplete mappings cannot be approved/loaded and unresolved bytes cannot
masquerade as typed TEXT. Mapping, transformation, semantic parity, target
validation, benchmark and independent product acceptance are separate statuses.
A pin check, source construction or hand expectation does not mark any of those
runtime outcomes passed. Follow D7's main README/docs for the complete future
CLI/activation path and actual returned IDs; the examples ship no fabricated
answers, approvals, output rows, captures, timing, scores or human-study claims.
