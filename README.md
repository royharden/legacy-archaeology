# Legacy archaeology

Local CLI and static report for a narrow synthetic fixed-width ASCII account ledger. It retains source bytes, proposes finite interpretations, records explicit rulings in SQLite, and creates hash-bound PostgreSQL migration candidates. Required concepts are account_ref, description, balance, effective_date and status. Ambiguity remains incomplete until resolved; unresolved raw bytes never become typed text.

This source was constructed in Dirty Mode. Runtime, integration, database verification, benchmark and product acceptance have **not run**. Dependency versions are declared ranges, not a tested lock. No production migration is supported. The live adapter is source only with activation gates closed. The inference wheel contains only `src/la`; evaluator code and fixtures remain separate.

[Regression source and later commands](docs/TESTING.md) document the authored
contract/provider/journey cases. They have not been imported, collected or executed.
[Explanation/target evidence consumers](docs/EVIDENCE.md) document bounded ambiguity
facts, signed target intent, common non-loadable evaluator targets and independent
effect grading. No real observations or authority are supplied by the source.

After the authorized environment activation phase, use Python 3.12 and install with `uv sync`. Example commands (not executed during construction):

```console
la ingest source.dat --input-root fixtures/dev/account-dev-01 --brief brief.md --samples samples.json
la hypothesize RUN --mode rules
la questions RUN
la answer RUN QUESTION OPTION --actor actual-participant --reason "reviewed bytes" --revision 0 --request-id unique-request
la export RUN
la approve RUN --actor actual-participant --reason "reviewed complete mapping"
la transform RUN
la report RUN
```

`RUN` is the hash returned by ingest. All commands use the `.la-runs` store by default; set `--root PATH` before the command to declare another store. Input paths must resolve within `--input-root`; run/bundle paths must resolve within `--root`, including symlinks. Existing source and generation artifacts are preserved. Repeated exact answer requests return their historical receipt; stale generation or revision is rejected.

Samples must be an explicitly authorized JSON artifact with `source_sha256`, a nonempty `authorization` label, and exact record references/bytes/hashes. Partial-span authorization is supported: unauthorized bytes from the rest of a record never enter prompts. Deterministic selection uses at most64 distinct authorized records and a fixed prompt byte limit, with selection/omission pins. Rules/mock are distinctly labeled. Live mode is wired through explicit provider config/authority and refuses absent activation; it never silently becomes mock. [Provider activation](docs/PROVIDERS.md) documents the unverified Responses source adapter, conservative SQLite single-flight accounting, usage categories, unknown-liability stop/reconciliation and separate one-attempt B1 comparator. No API/model/price activation is approved here.

Limits: 5 MiB, 10,000 records, 256 bytes per record, 4,000-character brief, at most32 physical spans with bounded semantic/policy alternatives, 12 review questions, and three attempted product requests per layout. Consistent LF or CRLF with ASCII is supported; a valid final record can omit its terminal newline. Tied plausible widths stay unresolved; mixed separators, bare CR, empty/oversize input and unsupported declarations retain explicit refusal diagnostics. Every materialized row retains its ordinal, including identical duplicates and quarantines. Candidate recall is not measured: use unknown when no correct option exists. Arbitrary copybooks, EBCDIC, packed decimal and mixed layouts are excluded. See [limits](docs/LIMITS.md).

The report contains an escaped byte grid, partial typed preview, consequential offered choices, ruling history and six separate readiness dimensions. Load rows require explicit approval of the complete current mapping. Immutable bundles include actual generation/journal lineage; execution and evaluation create separate receipts. Source changes require a new run; changed interpretation/rulings invalidate dependent approval. [CLI and evaluator commands](docs/CLI.md) document the public failure walk, actual injected evaluator runners/replay, and separately authorized target execution/recovery source. Target readiness requires committed fresh readback and independent oracle/negative-effect evidence. No hidden custody, benchmark success or product acceptance is claimed. See [architecture](docs/ARCHITECTURE.md) for boundaries.

Ready future evaluator caller factories and non-secret configuration shapes are documented in [config/README.md](config/README.md). [Local result publication](docs/RESULTS.md) consumes immutable captures, retains failed arms and unknown costs, and requires signed approval for active hidden projections. [Public intake teaching examples](examples/intake/README.md) explain genuine partial-span authorization and explicit unsupported declarations; they are known, hand-authored material, not benchmark output. Every command remains unexecuted during Dirty Mode.
