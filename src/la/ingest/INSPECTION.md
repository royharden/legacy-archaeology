# Bounded diagnostic inspection API

Source constructed under Dirty Mode. No inspection function or regression case
was executed. Runtime/privacy behavior remains unverified; these in-process
Python views do not establish OS account isolation or hidden-corpus custody.

```python
from la.ingest.inspection import inspection_page, inspection_detail

inspection_page(batch, *, offset=0, limit=50, authorized_only=False,
                generation=None, mapping=None)
inspection_detail(batch, ordinal, *, start=0, end=None,
                  authorized_only=False, generation=None, mapping=None)
```

Inputs/outputs are plain dictionaries. No files, networks, databases, provider
calls, mutation, imports of evaluator code, HTML generation, or target execution
are performed by these functions. D7 owns UI/CLI and must HTML-escape every string.
Printable ASCII, including markup, is still untrusted data.

## Paging and diagnostic cells

`offset` is an original source ordinal, not a filtered-result index. Integer
arguments reject booleans, negatives, and out-of-range requests. Page limit1–100;
default50. Offset equal to observed count returns an empty terminal page.
`next_offset` advances across scanned source ordinals even if none is authorized.

Each row displays at most256 bytes. Owner pages start at relative byte0;
authorized pages start at the first permitted span in that record. Detail uses
the requested start and an end defaulting to at most256 bytes later. An explicit
span longer than256 bytes is rejected. Nonempty records require nonempty detail
spans. Empty malformed records can be inspected as empty diagnostic rows.

Top-level wire keys:

- `schema_version`, `state`, `access_mode`, `diagnostic_only`, `source_status`,
  `source_reasons`, `counts`, `provenance`, `limits`, `inspection_sha256`.
- Pages: `offset`, `limit`, `scanned_stop`, `next_offset`, `rows`,
  `returned_record_count`, `not_authorized_count`, `unmaterialized_in_page`.
- Details: `ordinal`, `row`; unmaterialized details have `row=None`,
  `reason=record_bytes_not_materialized`, and `requested_span`.

States are `available`, `empty`, `not_authorized`, or `unmaterialized`. Refusal is
also retained separately as source_status/reasons. Denominators preserve observed,
materialized, unmaterialized, eligible and quarantined counts. A refused source
with no materialized bytes does not create imaginary RecordRefs or show zero input.

Row keys include the six-part original `record_ref`, ordinal, actual record_width,
declared_width, disposition/reasons, separator metadata, display window,
byte_positions ruler, cells, overlays, omitted counts, and diagnostic flags.
Each cell has relative position, absolute byte_start, hex, ascii, and redacted.
Printable ASCII is literal diagnostic data; controls/high bytes use escaped
tokens such as `\\xff` or `\\x00`, never replacement decoding. `raw_hex` is only
the visible window when every cell is visible; otherwise null. It is never a
promise that a whole record or a typed converted value is present.
`converted_values=not_provided`, and outside_window_byte_count reports truncation.

## Authorization and provenance

Owner mode is explicitly `local_owner_retained_source`. Authorized mode is
`permitted_spans_only`: it validates selected-span hash/bytes through the actual
evidence resolver, with at most64 distinct records/16384 span bytes. Selection
complexity is limited to256 spans and384 unique evidence validations; excessive
complexity refuses rather than expanding authority. Legacy batches without the
current exact selected-span proof cannot silently gain authorized view access.

Only records intersecting permitted spans appear. Unauthorized cells are null
and redacted; no raw field or neighboring-byte dump carries them elsewhere.
Partial-only rows hide full-record disposition/reasons. Source/RecordRef pins
and lengths remain identity metadata from the authorized artifact. Separator
bytes are not data-span authorization, so authorized rows omit separator raw_hex.
Mapping unresolved text and generation unknown text are withheld in authorized
mode (counts retained); owner views include bounded lists for explanation.

Provenance carries source/framing/brief/config, sample artifact/selection,
policy/generation and mapping pins when supplied. Source integrity scope says
whether retained source was reconstructed or only hashes/metadata were available.
Current generation sample pins must match batch authorization. Invalid identities,
changed raw bytes, stale source/brief/generation/mapping or out-of-range spans
raise ValueError; no fallback view widens access after a failure.

## Candidate and selected overlays

Generation and mapping content hashes are checked, along with candidate IDs,
source/framing/brief pins, declared-width bounds and authorized evidence. With
both supplied, the mapping generation hash/binding/policy must match exactly.
Candidates remain unconfirmed; selected mapping spans remain
`selected_mapping_unverified`; filler is declared_not_approval. No inspection
receipt asserts loadability, approval, parity, target or product acceptance.

Overlays are clipped to actual record/display bounds and permitted span
intersections. Original unpermitted start/end ranges are not copied alongside
the clipped range. Selected/filler overlays are prioritized before candidate
overlays; at most128 per record are returned, with omitted_overlay_count visible.
No raw candidate evidence, policy sentinel values, discovery profiles or whole
generation/mapping objects are dumped into a privacy-scoped view.

Future regression source is `tests/ingest/test_inspection.py`; it has not run.
The existing framing-v1/v2 and RecordRef contract remains in `IDENTITY.md`.
