# Independent evaluator source

## Normal-mode development validation

`python -m evaluation.public_check --out <new-owned-directory>` executes all five
arms on six public development variants and rescores their immutable captures.
It has no live or hidden mode. R1 selects only offered policies matching the
public serializer layout and labels those answers `agent_provisional`.

PB-M1-R03 initially ran 119 inherited evaluator tests: 118 passed; one failed
because Windows checkout converted a pinned LF `.dat` fixture to CRLF. Restoring
the exact tracked bytes fixed that input corruption without changing gold.
An independent audit then found two scorer defects: missing `value` could pass
as typed NULL, and invalid-identity quarantines were omitted from precision.
`semantic-v3` closes typed observations and counts every quarantine prediction.
Prior evidence remains preserved; these changes do not rewrite historical scores.

The first six-variant public run produced zero exact valid rows for every arm
(full denominator 5,820 valid rows per arm). Offline B1 failed; the finite-candidate
arms mostly abstained. This is a measured limitation, not benchmark success.
Public development/replay never establishes hidden custody or product acceptance.

Reviewer-owned `tests/e2e/test_database_retained.py` separately exercises the
authorized M1 database, real commit/new-connection readback against hand literals,
catalog types/precision, SQL NULL, constraints, rollback and controlled lost ACK.
It retains successful schemas and artifacts and uses no destructive cleanup.
Its opt-in and concrete target pins are intentionally specific to the assigned
M1 RV2 lane; ordinary test discovery skips it. Target claims bind the actual
product commit, environment, image and logs recorded by the run operator.

The remainder of this document records the inherited construction state and
interfaces. Statements that code was unexecuted describe that historical phase.

Dirty Mode construction only: no generator, scorer, benchmark or product runtime
has been executed. All benchmark results remain `not_run`; product acceptance is
pending. This evaluator belongs outside the inference distribution.

`score(oracle_records, outcomes, edition='development')` in `evaluation.scorer`
accepts normalized typed semantic fields. `score_product(oracle_records,
outcomes, mapping, edition='development')` adapts the product `values` wire shape;
types come from the submitted mapping, never from the oracle. Both return full
five-field and valid-row denominators, all-input outcome accuracy, identity
diagnostics, reason-specific quarantine precision/recall and aggregate checks.
No best-permutation, alias, business-key or aggregate repair is performed.
`aggregate_variant_reports` publishes micro rates and descriptive macro variation.

Public `fixtures/dev/account-dev-01` is hand-authored development data, never a
fresh holdout. Its oracle includes every source identity. `generator.py` constructs
canonical values before independent serialization; source only, not executed.
Malformed replacement specifications are applied only after serialization and
must preserve their canonical linkage and intended reason labels.

Later validation must audit generator edges and scorer mutations independently,
exercise actual product joins, and reconcile target readback. Public fixtures and
source review establish no custody boundary. During construction D3 inspected
the ingest framing hash identity seam; it imports/copies no parser or converter.
The framing digest is the shared documented identity contract, not an oracle
decoding algorithm.

`benchmark.py` defines B0/B1/C0/R0/R1 budgets, the 6/4/8-variant corpus
contract, T0 commitment and T2 hash freeze, custody eligibility, a twelve-question
offered-ID simulated SME, and report skeletons. `runner.py` now implements
`run_variant(case, ports, store, mode='mock', ...)`, `run_suite(cases, ports,
store, split=..., ...)`, `summarize_suite(manifests)` and `replay_archive(...)`.
These are executable source interfaces; none has been executed in construction.

### Portable archives

`archive.py` plans, exports, reads and replays signed public/retired evaluation
archives and releases owner-approved aggregate projections of active hidden
results. Planning closes over every transitively reached capture (failed and
partial attempts included) and refuses reachable hidden payloads unless the
registry actually retired the edition; replay only rescores with a scorer in this
checkout and never reruns models, targets or cleanup. The full contract, return
shapes and known limits are in [ARCHIVE.md](ARCHIVE.md); regression source is
`tests/evaluation/test_archive.py` (unexecuted).

`RunnerPorts` injects heuristic, finite candidates, questions, mapping resolution,
common mapping validation/conversion, provider, token counter and optional target
observer functions. It imports no product code. A `VariantCase` has identical
allowlisted visible input for all five arms and ten `BatchCase` values; gold and
sealed offered-choice policy stay evaluator-only. B1 invokes the bounded provider
gateway once without repairs. R1 returns only offered IDs with `agent_provisional`
provenance. Provider adapters are trusted capabilities, not a Python sandbox;
they must use the gateway rather than make untracked calls. Real OS isolation,
provider compatibility and custody evidence remain later prerequisites.

`CaptureStore(existing_owned_root)` creates canonical SHA256-addressed exclusive
files for raw requests/replies, proposals, outcomes and receipts. It never overwrites
failed outputs. An arm failure/no-output preserves the full oracle denominator.
Public/retired replay verifies capture hashes and rescoring never calls a model.
Hidden replay requires an edition-bound retirement receipt. Live/hidden execution
requires explicit authority, T2 pins, external custody evidence and a capture-root
binding; a hidden suite retains a one-edition marker even after cancellation.
No active hidden assets are constructed by these interfaces.

`corpus.development_layouts()` and `build_development_variant('dev-01')` through
`dev-06` construct six distinct public layout combinations. Canonical semantic
records come first, then independent serialization, then declared malformed-byte
replacement and final source/ordinal identities. Each source builder returns ten
100-record batches with 30 malformed records total, five of each declared kind.
The hand-authored `fixtures/dev/corpus-v2.json` is a descriptor, not generated
batches. No new corpus has been generated here. `variant_case` adapts public
corpus objects to runner cases. The first batch supplies the same authorized
inference samples for every arm; each mapping is then applied to every batch.
Local builders reject hidden/validation creation. `request_external_edition`
requires explicit external evaluator capability, edition/seal/root/custody pins,
and a heldout freeze with at least two sealed unseen combinations.

`mutation_audit.apply_outcome_mutation` implements the eleven normalized outcome
mutations listed in `mutations.json`; `audit_scorer_mutations` first requires an
exact nonempty positive control. Missing prerequisites are inapplicable, never a
pass. Control mutations separately probe changed evidence, stale approval and
incomplete load against an injected rejection adapter, retaining candidate-bound
rejection and before/after durable observations. Audit source has not executed.
The scorer is now `semantic-v2`; invalid RecordRefs and malformed wire fields
remain failures in complete denominators. R0 resolved-but-wrong fields are named.

`adapters.project_product_question` returns `{question, provenance}`; only
`question` crosses the broker. `validate_evaluator_proposal` and
`transform_evaluator_proposal` inject `ingest`, `validate_proposal` and
`transform_proposal` functions from the integration owner. They consume D5's
non-loadable `la.convert.proposal` API without manufacturing ruling events or
approvals. D7 wraps them as the runner validation/transform callbacks. No product
module is imported into evaluator source or canonical generation.

`target.score_execution_receipt(oracle, receipt, mapping, bundle_sha256=...,
edition=...)` directly consumes D5's sealed `database_check`/`reconcile_commit`
receipt and its `{bundle_sha256,run_id,namespace,target,capture,rows,
observations_sha256}` observation artifact. It verifies both hashes and lineage,
then independently scores actual rows. Exact parity remains `indeterminate` for
full target acceptance when concrete negative effects are absent; adapter
`producer_projection_match` and rollback booleans do not substitute.
`target.score_target` also accepts richer committed fresh-readback observations
with observed column types, separate connection provenance and explicit
rollback/constraint/recovery effects. `observe_and_score` is a separate explicitly
authorized injected target action; ordinary inference orchestration never invokes
the target. All target execution and security behavior remains unverified.
`mutations.json` specifies the finite later negative audit. `edges.md` records
hand-calculated expectations. `not_run_report()` returns all arm/split entries
with null measurements; none should be displayed as measured zero or success.

Regression source is under `tests/evaluation/`: hand-written gold checks complete
denominators, semantic/type/null/scale/date errors, missing/extra/duplicate/swapped
identities, false quarantine, cancelling amounts and drop+duplicate. Fake-port
cases cover one-shot B1, identical inputs, offered-only R1/unknown, unknown cost,
live/hidden refusal, empty output, immutable/tampered captures, retirement/replay,
non-loadable proposals and actual D5 target receipt lineage. Public corpus cases
use hand-calculated byte strings and the documented framing-v2 descriptor.
No test imports a product parser/converter to construct canonical gold.

After Dirty Mode closes and INT authorizes execution, the future outer-shell
command is `python -m unittest discover -s legacy-archaeology/tests/evaluation -p "test_*.py"`.
The original scorer/runner cases use the standard library. New custody signature
cases additionally require the optional `cryptography` dependency after authorized
setup. This command has
**not** been executed, collected or imported here. AST parsing confirms source
syntax only; assertions, generators, real target behavior and benchmark
performance remain unverified.

Public `account-dev-01` is explicitly development edition v2. Its sole date-null
lexeme is now `99999999`; zero-date lexemes remain invalid under the selected
policy. Canonical semantic values were retained unchanged while exact source,
sample and framing-v2 RecordRef hashes were reauthored from the literal bytes.
Initial public files are preserved in Git history and dated local backups; no
measured result was rewritten and neither public edition is unseen holdout.

Custody/edition application source is documented in [CUSTODY.md](CUSTODY.md).
`eligibility.py`, `edition_registry.py` and `canary.py` implement closed T0/T2/T3
identities, actual Ed25519 receipt verification, append-only unique attempts/arms,
captured-effect checks, retirement and a future approved canary collector. Legacy
custody booleans cannot authorize a heldout run. No registry, collector, crypto
operation or custody test has executed during construction.

`target_effects.TargetExpectation` and `grade_target` consume the actual closed
D5 v2 target observation/negative-effect wire. Full W7 grading requires exact
canonical readback with observed catalog types/nullability/precision, six actual
SQLSTATE/rollback effects in separate fresh namespaces, a separate failed-load
durable-absence capture and a genuine unknown-commit predecessor plus exact
fresh durable-marker/readback reconciliation. Every observation is bound to
externally configured candidate/authority/target/observer pins. Missing evidence
is indeterminate; failed/mismatched effects fail. Legacy v1 helpers retain parity
diagnostics but cannot set full target validation passed.

`target_runner.TargetPorts` injects D5 prepare/grant/observe and optional actual
failed-load/recovery collectors without passing oracle data. `run_variant` and
`run_suite` accept optional `target_ports` and `target_freeze_sha256`; all five
methods use the same path and immutable receipts. Default target state remains
not_run; incomplete methods are not loaded. Protected custody is rechecked before
target batches. Real controlled failure/recovery collectors and DB execution
remain separately authorized later; no target port has run in construction.

Public T1 live development/validation authority is documented in
[T1-LIVE.md](T1-LIVE.md). `public_live` adds signed public catalogs/attempts,
source-pinned D7 `BillingAdapter`, conservative request reservations, unchanged
raw cached/reasoning usage, signed actual-bill reconciliation and optional
T1-selection-to-T2 lineage in the same edition journal. It grants no hidden access.
The actual D5 phase-v2 candidate and controlled v3 collectors are consumed through
injected ports. Precision matches D5's declared max1000. All source/regression,
crypto, provider, accounting, database and custody execution remains unverified.
