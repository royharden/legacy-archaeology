# Consumer journey regression source

`test_consumer_journeys.py` contains five authored unittest methods, not executed
results. Dirty Mode permits source authoring and AST parsing only. No module,
fixture, test, CLI, report renderer, SQLite store, crypto helper, provider, file
stream or database target was invoked while authoring this package.

These future tests use actual public consumers, with no monkeypatch/mock echo:

- `la.app.cli.parser()` and `execute(args)` with an explicit temporary run root;
  real ingest/hypothesize rules/inspect/questions/answer/approve/export/transform/
  status/report calls. No real target/provider command is used.
- `la.app.artifacts.load_run(root,run_id)` and
  `la.app.recovery.current_generation(run,batch,store)`.
- `RulingStore.current_state`, `bind_generation(...,expected_state_token=...)`,
  actual durable answers/events and `build_mapping(batch,generation,store)`.
- D5 `transform`/`sql_artifacts` and actual CLI-approved bundle compilation,
  preserving external target validation as not_run.
- D7 `build_prompt(batch,brief,generation=...)` (pure allowlisted prompt source,
  no transport) and actual static `render_report`/CLI report artifact consumers.
- D4 bounded/stream-refusal, authorized inspection, explanation and resolver APIs.

The future temporary directory owns every created source/sample/journal/report/
bundle file. `setUp` creates it only when the test eventually executes; it did not
run here. No production data, credentials, external account, Docker, listener,
database DSN, live provider or hidden fixture is used. Rules mode is explicit.

## Independent expected behavior

Oversize fixture is a fixed repeated literal longer than5MiB; full expected SHA
is independently calculated over that complete literal. CLI must retain a refused
observation without prefix source.dat, show observed/unmaterialized1, and never
render zero observed input. Unknown-count refusal is also passed to the actual
report consumer without inventing a record or zero denominator.

Partial fixture grants exactly bytes `[2,4)` (`CR`) of `SECRET`. Evidence slices,
the actual provider prompt and authorized report cannot reveal its neighbors or
the entirely unapproved `PUBLIC` record. Owner inspection is separately expected
to show retained owner bytes. Question options must stay within actual offered
IDs plus unknown; no full-span evidence is fabricated for partial permission.

An actual unknown answer is repeated with the same request ID; future assertions
require one committed event after reopening, unresolved rows with empty values,
incomplete DDL/load instructions, blocked approval/transform and no load rows.

The complete mapping journey explicitly hand-declares a public literal layout;
it does not claim inference discovered the correct spans. It creates no fake
events: actual CLI answers commit five real simulated-actor rulings, followed by
real product approval/compiler source. Expected duplicate rows independently
contain account_ref `0001`, description `ALPHA`, balance `12.25`, date `2024-02-29`
and status `A`, at original ordinals0/1 and offsets0/27. No converter output is
used to derive these expectations. The test does not score inference quality.

Changing input bytes must create a separate run, leave old retained bytes,
approval and bundle untouched, and prevent the old mapping from transforming the
new source. A separate real journal exercises A→B→A CAS epoch/token rejection;
it does not corrupt the approved run to manufacture that transition. Static
reports must HTML-escape `<script>`/`<svg/on>` while retaining incomplete/not_run/
pending states.

Consumer adapters were read from current source; they may evolve under their
owners. Any concrete future failure needs owner triage. These tests do not assert
that an unimplemented CLI explanation subcommand exists: explanation is consumed
through its published API, with D7/D5 adapter work owned by those seats.

After explicit Dirty Mode closure/runtime authorization and normal dependency
setup, the existing documented stdlib discovery command for tests/inference can
include this file. That command was not run; no passing assertions, end-to-end
runtime behavior, parity, privacy security or product acceptance is claimed.
