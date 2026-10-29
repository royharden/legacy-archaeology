# Public intake teaching inputs

These three small inputs are hand-authored public material with known layouts.
They are not benchmark gold, unseen holdout, saved application output, or a claim
that inference found the layout. No application, parser, generator, test, model
or database was run to prepare them. Only literal file authoring, standard-library
hashlib/canonical JSON pins, and static inspection were used.

Read the [practical input/evidence guide](../../src/la/ingest/INPUT-GUIDE.md) first.
The existing [public development fixture](../../fixtures/dev/account-dev-01/)
remains D6's separate authority; these teaching inputs do not replace or copy it.

The shipped [catalog.json](catalog.json) indexes exact relative source/brief/sample/
pin paths, declaration flags and static byte/hash identities for these three
examples. Its hand_derived_expectations are explicitly unexecuted teaching notes,
not parser results or benchmark gold. Resolve paths relative to the catalog's
directory; use each actual samples.json for authorization, not the catalog's
permission summary. catalog_sha256 hashes canonical catalog JSON excluding that
self-hash field; the file also ends with LF. See [catalog consumer guidance](CATALOG.md).

| Example | Authored bytes | Intended teaching point | Hand-derived expectation, not a capture |
|---|---:|---|---|
| [ambiguous-ledger](ambiguous-ledger/EXPECTATIONS.md) | 52 | Full authorization, reordered fields, scale/sign/date/name questions | Two25-byte LF records, starts0/26; intake can be eligible but policy/mapping is unconfirmed |
| [partial-window](partial-window/EXPECTATIONS.md) | 24 | CRLF, valid final line without newline, genuine partial permission | Two11-byte records, starts0/13; only ordinal0 `[4,8)` (`PRIV`) is permitted |
| [declared-ebcdic](declared-ebcdic/EXPECTATIONS.md) | 10 | An explicit unsupported declaration | With `--encoding EBCDIC`, refused/unmaterialized records; the literal file itself is ASCII, not an encoding detector test |

Each directory contains exact `source.dat`, concept-only `brief.md`, explicitly
scoped `samples.json`, and static `pins.json`. The source examples are tiny;
oversize behavior is explained without shipping a large artificial file. The
local `.gitattributes` preserves the pinned input/JSON/brief bytes across checkout.
Changing bytes or line endings invalidates pins rather than silently repairing
them. Never edit hashes to conceal a source change.

## Unexecuted future commands

After Roy closes Dirty Mode and INT authorizes normal activation/dependencies,
from the outer shell, the future local CLI commands can be:

```powershell
la --root .la-teaching ingest source.dat --input-root legacy-archaeology/examples/intake/ambiguous-ledger --brief brief.md --samples samples.json
la --root .la-teaching hypothesize RUN --mode rules
la --root .la-teaching questions RUN
la --root .la-teaching inspect RUN --offset 0 --limit 2
la --root .la-teaching explain RUN --examples 1
la --root .la-teaching report RUN
```

`RUN` is the actual returned identity, not a precomputed or fabricated run ID.
Use offered question/option IDs from the actual command if making a later
explicit decision. The examples ship no answer events, chosen mapping, approval,
converted rows, score, report capture or measured result.

For the scoped evidence example, ingest its directory and later use:

```powershell
la --root .la-teaching inspect PARTIAL_RUN --authorized-only
la --root .la-teaching detail PARTIAL_RUN 0 --start 0 --end 11 --authorized-only
la --root .la-teaching report PARTIAL_RUN --authorized-only
```

The owner's normal inspection can see its own retained bytes. Authorized-only
views must not expose `LEFT`, `ATE` or the unapproved second record through raw
rows, neighboring cells, explanations or prompts. All literal bytes are already
public here; the permission difference demonstrates data handling, not a verified
OS/account security boundary.

For the unsupported declaration, the relevant unexecuted input command is:

```powershell
la --root .la-teaching ingest source.dat --input-root legacy-archaeology/examples/intake/declared-ebcdic --brief brief.md --samples samples.json --encoding EBCDIC
```

The exact source SHA values for D7 links are:

- ambiguous-ledger: `cdec66c0427a59dc7b7125b9c18af4fb1750d6ba24ed10a84cef2c17a69caa13`
- partial-window: `e61799548394443c26ed2b0edf4bc54aac801c8d0fbd48a1d3085fda7c93c692`
- declared-ebcdic: `61308b5fa050ea21cd1d100186b4676ce3f8c554ba4a4d0f69e4fdb5bb6726bd`

Per-example `pins.json` also distinguishes sample content hash (excluding the
self-hash field), complete artifact object hash, and exact JSON file hash
(including final LF). These are different byte domains; do not interchange them.
