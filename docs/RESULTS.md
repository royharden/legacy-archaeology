# Local result publication source

No commands in this document were executed during Dirty Mode. Report publication
is source, not measured quality, target acceptance or permission to run providers.

`scripts/results.py` consumes evaluator-owned immutable captures, independently
checks their hashes and typed lineage, and writes content-addressed projection,
JSONL, Markdown and manifest files. No output file contains raw prompts, source
records, oracle values, credential strings or private capture paths. The output
includes every method and variant, including failed and no-output arms, full
metric numerators/denominators, usage categories, failed/request counts, known
cost subtotals, unknown liability counts and immutable source/config/model pins.
Mapping, transformation, row parity, target validation, benchmark and product
acceptance are separate. Product acceptance remains pending. Missing measurements
are null or not_run, never a synthetic zero or a passed target.

Future commands, from the product root with its existing dependencies available:

```console
python scripts/results.py --out LOCAL_REPORT_ROOT not-run
python scripts/results.py --out LOCAL_REPORT_ROOT suite --capture-root EVALUATOR_CAPTURES --suite-sha256 ACTUAL_SUITE_CAPTURE_SHA --visibility public
```

The not-run entrypoint creates fifteen explicitly unexecuted arm/split rows with
unknown metrics/costs. It does not generate an input corpus or perform evaluation.
Public publication refuses heldout captures. Suite SHA is the actual suite_report
capture identity, returned by the evaluator result, not a common CLI wrapper hash.
All capture references must already exist under the declared evaluator root.

For an active hidden edition, use `--visibility active-hidden --registry
EVALUATOR_REGISTRY --edition EXACT_EDITION --preview`. This returns a private
projection capture and an **unsigned** approval payload template. The candidate
projection is retained only in the already private CaptureStore; no Markdown or
JSONL is published. An external run owner must review that exact safe projection
and independently sign the payload with Ed25519. Rerun without --preview using
`--approval SIGNED_APPROVAL --public-trust-root OPERATOR_ROOT
--public-trust-profile PROFILE.json`. The configured run_owner key must verify
the exact edition, suite/projection/publisher-code pins, visibility and registry
head. No signature is minted here. A changed registry head requires a fresh
explicit preview/approval. Variant identifiers are hashed aliases on this route;
the closed numeric projection cannot carry arbitrary diff values or error text.

Retired replay uses `--visibility retired-replay --registry EVALUATOR_REGISTRY
--edition EXACT_EDITION --replay-sha256 ACTUAL_REPLAY_SHA` for each original variant.
The actual registry must record retirement, and actual immutable replay_receipt
captures must bind every original manifest/arm receipt. Replay does not rerun the
model, transformation or target. Current target/transformation/benchmark states
are not_run, original states remain explicitly attributed, and costs describe
the original recorded attempts. fresh_holdout=false on every published projection.

Repeated identical publication verifies and returns the same immutable directory.
Different content produces a different report identity. Put `--supersedes
PRIOR_REPORT_SHA` before the subcommand to link a verified existing report under
the same output root; historical files are preserved. Unexpected or altered
members fail rather than being replaced. Interrupted stages are retained for
explicit inspection. No output is pushed, hosted or published remotely.

Known source limitation: a provider call whose output fails parsing can have a
known billed local provider receipt while the evaluator conservatively records
unknown liability. Actual operator reconciliation is required in both ledgers;
the publisher never substitutes local provider cost into an immutable unknown
evaluator attempt or rewrites old captures. New receipts/reports must retain
explicit lineage and supersession.

Capture adapters additionally accept D6 target-arm payload schema2, nullable normal observations, exact v2/v3 observation capture kinds and retained effect captures in failures. No stage failure is dropped, no v3 payload is downgraded, and no missing normal observation is fabricated. D6's separate portable archive signed-release and approved_projection caller is scripts/archive.py; source interfaces are reconciled against the actual owner exports before its package handoff. The independent existing-store replay path is scripts/replay.py and never creates a fresh unseen run or reruns a target/model.
