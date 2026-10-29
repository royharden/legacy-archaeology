# Evidence wire boundaries

`la.contracts.evidence` owns the recursive evidence, sample, intake and discovery
protocol validators. They reject unknown keys at every documented structured
level, exact-type errors (including boolean row counts), malformed lowercase
SHA256/hex, invalid spans, oversized arrays and inconsistent local counts/pins.
They do not authorize source bytes or approve a mapping. The evidence resolver,
sample authorizer, observation validator and review/conversion owners retain
those contextual checks.

The exported `RecordIdentity`, `RecordDisplay`, `SpanEvidence`,
`PermittedSampleArtifact`, `SampleMetadata`, `IntakeMetadata` and
`DiscoveryMetadata` are Pydantic `Annotated[dict, BeforeValidator(...)]` aliases.
They retain the public dictionary API. The matching five `validate_*` helpers
return copied dictionaries with supplied keys/values/list order intact. No
default fields are inserted. Parent models must dump with `exclude_unset=True`
when computing existing identities. The module imports only the canonical
`contracts.base.Boundary`, standard-library helpers and Pydantic; it never
imports producers, review, conversion or the contracts package root.

Supported explicit alternatives:

- Permitted artifact: legacy flat sample references or current full nested
  record references with optional partial spans. Schema version and framing pin
  remain optional in the legacy artifact; a supplied version must be integer1.
- Span evidence: original eight-field proof, or the same proof with a complete
  nested six-field record reference. Nested offsets and span lengths agree.
- Sample metadata: original five-field result; current selected-span result;
  observation-only pins with no record authority. An optional intake copy stays
  optional. `authorized_count` counts validated entries before selection caps;
  the selected count may be smaller only with `truncated=True`.
- Intake: absent legacy metadata represented by `{}`; version2 retained framing
  with the original `final_record_valid` flag or the current two final flags;
  version3 unmaterialized completed-stream refusal. Unknown stream counts remain
  `None`, never zero, and provide no materialized records or sample authority.
- Discovery: empty legacy metadata; bounded byte profiles; enriched finite
  alternatives/coverage metadata; explicit filler declaration on an empty
  legacy discovery; the literal public hand-declared regression-layout marker.
  Supplied discovery/declaration hashes cover their exact supplied dictionaries.

Current caps include 10,000 input references/retained rows, 64 selected ordinals,
16,384 selected bytes, 256 column profiles, 257 boundary proposals, 32 physical
fields and 480 candidate diagnostic entries. Observation-only byte/row counters
use nonnegative signed64 integers. They are not retained-source offsets.
Format declaration strings have at most128 characters in both the direct intake
producer and shared `SourceBatch` consumer. Use explicit supported declarations
such as `ASCII`, `fixed-width` and `ascii`; an unsupported declaration is a
refusal, not an encoding-detection request.

Legacy whole-record permissions remain usable through current inspection,
explanation, inference and filler consumers. `authorized_spans(batch)` creates
an ephemeral selection view only after checking exact retained record matches,
the original ordinal list, an explicit authorization label and the selected
row/byte caps. It never inserts `authorized_spans`, `selection_sha256` or intake
defaults into the old batch. The reported selection hash remains `None` when
the historical wire object supplied none. The view also omits unavailable
original artifact indices. New generation/proof outputs may use
current shapes without rewriting the input identity. A supplied current span
list, including an empty one, always controls permission; consumers never fall
back to whole records when current span metadata is present. Changed source
references or full samples outside that span list reject before display.

Raw authorization labels, actor/reason strings, diagnostic strings and byte hex
are bounded data, never instructions. In the completed-stream refusal API, the
original bounded sample JSON remains an **opaque hash-only input** because no
source bytes exist to validate it. Unknown keys there are preserved in its
artifact hash; they never become protocol fields or evidence authority. Once a
caller supplies an actual permission artifact for byte authorization, the
closed artifact schema applies. Invalid artifacts clear all selected authority
and retain their supplied artifact hash in the refused result.

Construction has only static source evidence. Pydantic parsing/serialization,
legacy/current roundtrips, partial masks and consumer regressions must be
executed in the later authorized runtime validation phase.
