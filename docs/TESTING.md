# Regression source and deferred execution

Tests were authored in Dirty Mode and have **not** been imported, collected or
executed. AST syntax parsing is the performed check. The cases and assertions are
not evidence of runtime success, coverage, independence or product acceptance.

D7's suites use stdlib unittest; no new test dependency, lockfile, CI or environment
was needed. After Dirty Mode closure and separately authorized Python3.12/dependency
setup, run from the product root:

```console
uv run python -m unittest discover -s tests/contracts -p "test_*.py"
uv run python -m unittest discover -s tests/providers -p "test_*.py"
uv run python -m unittest discover -s tests/journey -p "test_*.py"
```

The managed environment must already be established in that later phase. These
commands have not run here. Other owners' regression suites have their own source
instructions and are not claimed by this document.

Contracts cases cover strict extras/types/hash shapes, changed candidate/generation
identity, raw-record hashes, optional intake/discovery/filler serialization and
inference wheel/evaluator import separation. Provider cases use only injected
synthetic transports and local temporary SQLite; never real keys/network/accounts.
They cover exact cached/reasoning accounting, missing authority, unexpected model
or usage, crash reservations, single-flight across runs, counted failures,
one-attempt malformed B1, unknown-liability/CAS reconciliation and immutable export.
Prompt cases hand-author an AB-only sample span and assert CD/EFGH never leak,
stale content refuses and invented IDs/SQL/offset output is rejected.

The journey uses two hand-authored36-byte account records and explicit test-only
policies. Expected12.34/-5.00 amounts, calendar dates and leading-zero identifiers
are written by hand. It records actual future journal API events rather than
fabricating receipts. It checks exact retry/CAS, replay, approved export lineage,
source/path rejection, unresolved no-load rows, stale approval invalidation and
malicious actor HTML escaping. It does not assert candidate inference recall,
call evaluator gold code, connect to a database or claim independent parity from
row counts. Actual evaluator/target/product verification remains separate.

Every case identifies `what_bug_this_catches`. Concrete source issues found while
authoring strengthened shared hash/raw-record/generation/candidate validation and
kept wrong-model billing liability unknown. Assertions remain unexecuted until the
later activation phase; any failure there must remain visible and be repaired.
