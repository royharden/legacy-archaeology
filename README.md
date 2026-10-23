# Legacy archaeology

Local CLI and static report for a narrow synthetic fixed-width ASCII account ledger. It retains source bytes, proposes finite interpretations, records explicit rulings in SQLite, and creates hash-bound PostgreSQL migration candidates. Required concepts are account_ref, description, balance, effective_date and status. Ambiguity remains incomplete until resolved; unresolved raw bytes never become typed text.

This source was constructed in Dirty Mode. Runtime, integration, database verification, benchmark and product acceptance have **not run**. Dependency versions are declared ranges, not a tested lock. No production migration is supported. The live adapter is source only with activation gates closed. The inference wheel contains only `src/la`; evaluator code and fixtures remain separate.

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

Samples must be an explicitly authorized JSON artifact with `source_sha256`, a nonempty `authorization` label, and `records` containing exact `ordinal`, `raw_sha256` and `raw_hex`. Only the first 64 authorized records enter prompt evidence. Rules/mock are distinctly labeled; the CLI live mode refuses rather than silently becoming mock. The offline ledger records zero requests and zero liability because no calls occur. A source-only OpenAI Responses REST adapter in `la.providers.live` serves the separately activated B1 evaluator interface. It requires explicit authority, model/API verification, dated price evidence and token/cost caps before lazily reading `OPENAI_API_KEY`; its API/version compatibility has not been verified. Unknown billed liability blocks later calls, and B1 receives exactly one attempt without repair.

Limits: 5 MiB, 10,000 records, 256 bytes per record, 4,000-character brief, 32 proposed spans, three scale alternatives, 12 review questions. Consistent LF or CRLF with ASCII is supported; separatorless, mixed separators, bare CR, ambiguous widths and empty input are refused with retained hashes. High-byte and wrong-length framed records are quarantined with ordinals. The heuristic has deliberately limited candidate recall: unknown is required when no correct option exists. It does not infer arbitrary copybooks, EBCDIC, packed decimal or mixed layouts.

The report escapes imported content and contains no viewer/server. Bundle creation is distinct from actual loading. `database-check` is separately authorized and defaults to `not_run` without authority/DSN; target readiness requires committed readback and independent oracle comparison. Evaluation tools expose public development interfaces only; no hidden custody or benchmark success is claimed. See [architecture](docs/ARCHITECTURE.md) for boundaries and deferred activation.
