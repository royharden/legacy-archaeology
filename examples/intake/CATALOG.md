# Using the shipped example catalog

`catalog.json` is a small public teaching index. It is not SourceBatch, an
authorization receipt, transformed output, benchmark corpus/gold or proof that
the CLI ran. execution_status is not_run and each expectation is labeled
unexecuted_hand_expectation. The three source/brief/sample/pin filesets remain
unchanged from their original literal teaching edition.

Resolve each entry's paths relative to this directory. `paths.source`, `brief`,
`samples`, `pins` and `expectations` refer to actual shipped files, with no private
or absolute machine paths. `declarations` supplies the public encoding/record-type/
numeric CLI flags; the declared-EBCDIC entry must retain that unsupported flag
rather than silently reading it as the default ASCII case.

`static_pins` distinguishes source bytes/count, brief file hash, sample file hash,
sample object hash excluding/including the self-hash field, and pins.json file
hash. The source/brief/sample and schema authority remain their actual files plus
[IDENTITY.md](../../src/la/ingest/IDENTITY.md). The catalog adds no permission and
does not duplicate record schemas. Its permission_note is a teaching summary;
the exact samples.json artifact decides full/partial authorization.

catalog_sha256 hashes canonical UTF-8 JSON with sorted compact keys, no NaN and
Unicode retained, excluding that field itself. The actual file additionally ends
with LF. This byte-pinned index can be linked by D7 without copying the canonical
D6 public development fixture or inventing an adapter/provider/target authority.

## Intended unexecuted entry path

1. Choose an example ID and verify the shipped path/file pins as data. Review its
   EXPECTATIONS.md for known layout/disclosure limits.
2. Use that source directory as the CLI's input root, with source.dat, brief.md,
   samples.json and the catalog declaration flags. The [example README](README.md)
   gives exact future commands from the outer shell; none ran here.
3. Retain the actual returned run ID. Rules hypotheses, questions, explain,
   inspect and report may expose unresolved choices. Do not read known author
   layout or hand expectations as an answer event or approval.
4. Full and partial sampling differ. Authorized partial output/prompt examples
   must stay within ordinal0 `[4,8)` (`PRIV`); normal owner inspection may view
   all owner-retained bytes. Both are labeled by their actual access mode.
5. Choose unknown if a true option is absent. Repeating an exact ingest/request
   must preserve identity rather than create duplicate decisions. A changed
   source or sample needs its own pinned intake; stale committed artifacts must
   refuse rather than silently rewrite themselves.

The catalog's hand state descriptions cover eligible/refused intake, byte/record
counts, unanswered incomplete mapping, blocked pre-approval load and unmeasured
quality. They are future assertions, not current measured outcomes. They do not
promise discovery recall, a correct inferred layout, converted values, target
readback, parity or independent acceptance.

## Consumer regression source

`tests/inference/test_shipped_intake_examples.py` contains seven authored future
unittest methods using actual shipped artifacts and public D7 CLI/report/prompt/
explain and D5 journal/compiler calls. It does not mock a transport or fabricate
provider/target success. Its mutated copies live only in a future temporary test
directory; shipped input bytes are never edited by a test.

Assertions cover exact catalog/file identities, unanswered/unknown and exact
retry behavior, full/partial sample scope, explicit unsupported declaration,
stale source/sample refusal with old artifacts retained, and escaped diagnostic
markup in a deliberate new literal mutation. Expectations are independent literal
values or non-acceptance states, not an assertion that inference must magically
recover every layout. No module, fixture, CLI, stream, SQLite store, renderer,
test or generator was imported/collected/executed during construction.

Runtime/privacy/integration remain unverified. Use the already documented later
test command only after Dirty Mode closure and explicit activation authority.
