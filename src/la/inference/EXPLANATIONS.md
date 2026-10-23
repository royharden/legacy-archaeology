# Content-bound ambiguity explanations

Source constructed under Dirty Mode; functions and seven regression declarations
were not imported, collected or executed. Runtime/privacy behavior is unverified.

```python
from la.inference.explanation import explain_candidate, explain_layout

explain_candidate(batch, generation, candidate_id, *,
                  authorized_only=True, examples_limit=3)
explain_layout(batch, generation, *, authorized_only=True,
               offset=0, limit=8, examples_limit=1)
```

Examples limit0–3, exact integers excluding bool. Layout pages at most8 physical
span groups, within32 total spans/480 candidates and3 policies per span/name.
Offset is a physical-field index. These are plain data producers, with no I/O,
model/SQL execution, evaluator imports, HTML or new shared schema. D7 must escape
all strings; markup in bytes remains inert diagnostic content.

Each candidate explanation carries source/framing/brief/config/sample-selection/
policy/generation provenance, source/refusal counts, exact proposed span/type/name,
offered alternative IDs and bounded typed policy summaries. Summaries are not
substitute policy objects for a ruling: D5 uses the actual offered candidate ID
and original generation. Sentinel summaries expose blank/all-nines pattern, width
and null action, not unpermitted raw lexemes. Typed policy hash binds the exact
original proposal. No observed pattern establishes business meaning or approval.

Decision text names the actual byte range and offered scales/names. Numeric digits
do not establish scale/sign/precision; calendar shape does not establish format,
century or nullable sentinel policy; missing vocabulary does not invent malformed
codes. Declared omitted combination counts are producer metadata, not measured
candidate recall. Missing counts remain unknown. Every output retains
correct_policy_available=not_established and no_correct_option_action=unknown.

`candidate_id='unknown'` returns abstained. An absent valid SHA ID returns
not_offered, with no fabricated candidate/ranges/examples. Invalid/path-like IDs
reject. A presentation representative in layout output is explicitly not a
selected/ranked policy; nothing becomes approved or loadable from an explanation.

Examples use real bounded inspection and evidence resolution. Authorized mode
only reveals selected permitted intersections, with neighboring cells masked and
partial-record reasons redacted. Each emitted visible-evidence slice carries the
six-part RecordRef, relative/absolute span, hex and SHA resolving to actual bytes.
At most8 proof slices/example are emitted with omissions counted. Masked example
windows never gain a fake full-span raw hash/value. Diagnostic ASCII/hex and
visible-byte pattern counts are labeled; typed_value=not_inferred. Source profile
statistics outside permission are not copied as observed lexemes. Owner mode is
separately labeled local_owner_retained_source.

Dependent impact reports eligible/quarantined/unmaterialized layout row counts,
not a predicted correct-field total. Zero examples is capped_to_zero, unavailable
permission is no_authorized_examples, and refused/unknown input counts remain
explicit. Generation/candidate/source/sample pins and exact candidate evidence
ranges are validated before producing any offered explanation. A proof for a
different byte span cannot explain a candidate merely because its bytes hash.

Output explanation_sha256 binds the complete diagnostic result. D5 question and
D7 report adapters should preserve pins/status and select unknown when no true
choice exists. Actual test source is tests/inference/test_explanation.py; no
assertions passed or measured quality/security result is claimed.
