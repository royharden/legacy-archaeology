# Custody and edition enforcement source

This feature has not executed. No canary was opened/listed, no OS identity was
probed, no accounts/ACLs were created, no signer keys were provisioned, no edition
journal was opened, and no hidden assets exist from construction. Structural
source checks and synthetic unit-source fixtures do not establish OS custody.

## Closed identities

`evaluation.eligibility.make_commitment(...)` seals the complete 18-variant T0
family: six development, four validation, eight heldout. Each variant binds actual
source bytes across ten batches, all visible inference/batch metadata, authorized
sample artifacts, brief, independent canonical/oracle records and layout hashes.
`variant_identity(case)` computes those identities without decoding any candidate
output. The commitment also includes edition, a fresh nonce and externally sealed
assets hash. It contains hashes, never hidden source/spec/seed/oracle contents.

`make_freeze(commitment, pins)` binds T2 to the same edition/nonce/T0. All eleven
release/config/prompt/sample/taxonomy/model/price/caps/scorer/floors/ranker pins are
required. `validate_commitment`, `validate_freeze` and `validate_suite` reject
unknown fields, wrong types, stale hashes and mixed subjects. T3 specifies one
attempt, exact ordered methods B0/B1/C0/R0/R1, all eight ordered heldout IDs, mode,
freeze, nonce and evaluator capture-root hash.

Legacy `benchmark.seal_commitment`/`freeze_configuration` remain descriptive
compatibility helpers. `hidden_run_eligibility` always returns `eligible=False`
and labels JSON flags structural/unverified. None authorizes protected execution.
Default public rules/mock execution remains usable without pretending custody.

## Observations and public-key verification

`ReceiptVerifier(trusted_issuers, public_keys)` accepts distinct configured raw
32-byte Ed25519 public keys by key ID and exact issuer/role. It verifies concrete
signatures through a lazy `cryptography` import; a callback/boolean is not a
verification backend. Missing dependency or unsupported verification fails
closed. Trust configuration must come from the evaluator operator's approved
setup, never a candidate-supplied JSON trust store. No signer/private key exists
in application or collector source. Actual key provisioning is deferred.

Every signed envelope has exactly `schema_version`, `algorithm` (`Ed25519`),
`issuer`, `key_id`, `role`, `payload`, `payload_sha256`, `signature` (128 lower-case
hex characters). The canonical JSON payload is the signed message. See the
[official Ed25519 API](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/)
for the public-key verification contract; dependency version/runtime compatibility
must be pinned and validated at later activation, not inferred from this source.

`canary.collect_canary(request, authority_receipt=..., verifier=...)` is future
collector source only. It accepts only an exact owner-signed `collect_canary`
request for explicitly approved evaluator-owned CANARY paths. It never changes
cwd, spawns, impersonates or changes permissions. It observes native Windows
token SID or Linux effective UID/GID plus host, checks the actual collector and
approved bounded public source/config artifact hashes, then attempts absolute
open, relative open of the same canary, and directory listing. It reads no
canary bytes and retains no listing names. Missing/access-success/unsupported
observations fail closed through `CanaryProbeFailure`, preserving only result
codes/identity pins. An external trusted evaluator witness must separately
establish canary existence/ownership, process provenance and sign the observation;
the inference collector holds no signing key and cannot attest itself.

`validate_custody(...)` requires that actual signed canary observation and six
distinct signed external isolation reviews: inherited handles, oracle broker,
network route, inference distribution, prompt allowlist, independent custody
review. Each review binds the same edition/freeze/nonce/host/identity/probe and
its own actual captured effect artifact. A source/config snapshot or repeated
prose is not an effect. The context checks underlying capture bytes/hashes,
closed observation fields and candidate pins, not just review assertions. These
properties remain unverified until their real capture/review happens.

## Durable edition and attempt authority

`EditionRegistry(path, CaptureStore(existing_owned_root))` explicitly opens an
evaluator-owned SQLite journal only when called later. `register`, `freeze`,
`disposition`, `finish`, `events`, `state`, `head`, and `export` are public APIs.
Every mutation uses a unique request ID, global head CAS and a canonical chained
event in one transaction. Exact retries return historical `JournalReceipt` with
`newly_created=False`; they never authorize re-execution. Different content under
the same request ID or competing head fails before mutation. JSON captures are
immutable exports rebuilt from committed sequence, never another authority.
Connections close on all paths; committed events survive a later export failure.

T0 registration rejects reused edition nonce/sealed assets and known exposed,
retired or consumed canonical gold relabeled as a new hidden edition. It also
rejects heldout gold duplicated in that family's public splits. Expose/retire
dispositions require exact owner-signed action/head/edition authority. A running
attempt must finish/cancel before retirement. Failed/partial/cancelled/no-output
attempts remain consumed, and their raw captures are retained. This registry
cannot reconstruct unrecorded outside exposure: external custody review must
establish that the declared edition was genuinely unseen. Deleting/resetting the
journal is not a supported recovery mechanism.

`EligibilityContext(registry, commitment, freeze, suite, probe_receipt,
review_receipts, authority_receipt, verifier)` verifies signed receipts and all
underlying captures from the evaluator store. Publish signed envelopes with
`store.put('signed_evidence', receipt)` and underlying effect bodies with
`store.put('isolation_capture', body)` before constructing it. Exact closed field
shapes are in `eligibility.py` and `edition_registry.py`; source is authoritative.
The owner authority binds suite/freeze/nonce/mode, capture root, registry path,
host/inference principal, collector pin and live spend-authority pin when needed.

## Runner and replay integration

`run_suite(..., eligibility=context, attempt_request_id=..., expected_registry_head=...)`
checks actual inputs against T0 and ordered T3 before registering the one attempt.
`run_variant(..., eligibility=context)` is used only inside that predeclared suite
for protected runs. Each variant/method has its own unique committed start/finish;
a replayed arm cannot hide inside an otherwise unique suite attempt. Pins,
revocation/exposure and captured custody are checked before/after every arm.
No-output rows preserve denominators. Completion requires all unique arm results;
exceptions/cancellation preserve captures and append a nonpassing terminal state.
An interrupted process leaves a consumed running attempt, never automatic retry.

Public rules/mock cases do not need hidden custody. Live/protected execution
requires the exact registered context; no live-to-mock fallback occurs. The
T3 implementation admits complete heldout suites only. Public T1 live authority
is now a distinct context in [T1-LIVE.md](T1-LIVE.md), without requiring a final
freeze. A public or previously exposed fixture is never hidden.

`retire_archive(..., registry=...)` and
`replay_archive(..., retirement_ref=..., registry=...)` require actual committed
signed retirement and the same consumed frozen attempt for heldout material.
A release boolean/hash cannot relabel an archive. Replay keeps original failed
arms, hashes and denominators and is never a model rerun or fresh holdout.

All new regression source is unexecuted. The custody-signature tests additionally
need the optional `cryptography` dependency at later authorized setup; no package
was installed or imported for this construction. Fixed synthetic test seeds are
test-only data, never operational credentials or observed custody receipts.

## Captured-prompt hidden-identifier scan (leak_scan.py)

The plan requires logging the exact provider prompts and scanning captures for hidden identifiers. `evaluation/leak_scan.py` is that scanner, as source only; it has not been run.

**What it matches.** Matching is exact or substring only, never fuzzy:
- every 64-hex window of each hex run (case-insensitive), against the full fingerprints;
- every 16-hex window at any offset of each fingerprint, so a truncated or sliced hash still counts;
- heldout variant IDs, case-insensitively, unless glued to a letter or digit: `heldout-00.` and `heldout-00-batch` hit, `xheldout-00x` does not.

**The hidden set.** `hidden_identifiers(commitment, cases=None)` derives it:
- **From T0:** heldout variant IDs, their `oracle_sha256`, `canonical_sha256` and `layout_sha256`, plus `sealed_assets_sha256`.
- **From evaluator-held heldout cases (optional):** per-row `digest(fields)` for converted rows, and `digest(row)` for every row. Each case's oracle must equal its T0 commitment.
- **Deliberately excluded:** visible-input hashes (source, samples, brief, visible), which legitimately appear in permitted prompts, and generic hashes of empty or null values such as `digest([])` for an empty layout.

Nothing beyond the commitment and those cases is read.

**Choosing what to scan.** The scanned captures are the gateway `provider_request` captures. Choose them with one of:
- `attempt_request_refs(store, registry, edition)`, which walks one TERMINAL protected attempt (arm receipt → `arm_raw.attempts[].request_capture`);
- `requests_from_arm_receipts(store, arm_refs)`, for any explicit arm receipts such as a T1 or validation rehearsal with the frozen prompt pins.

**Limits.** Inputs are bounded: 512 requests, 1 MiB each, 64 MiB in total, 20,000 fingerprints. An empty or non-request scan refuses. The fragment index holds 49 entries per fingerprint (about 800k, roughly 100 MB at realistic heldout sizes); hits are deduplicated while scanning, so a dirty scan's memory stays bounded by distinct hit groups.

**What `record_leak_scan(...)` writes.** It writes two immutable captures and signs nothing:
1. **`leak_scan`:** the closed report. It holds the identifier-set hash, counts, an optional bounded `subject` naming what was scanned (attempt ID, arm receipts), method, scanner code hash, scanned refs, `hit_count` (distinct request/category/match groups) and `occurrence_count` (matching windows: one 20-hex leaked fragment counts as 5), at most 100 hits and `result`. Hits keep only a category, match kind and request hash; hidden values are never copied into the report.
2. **`isolation_capture` (kind `prompt_allowlist`):** its subject is that report. `observed_value` is `visible_only` only when there are zero hits; otherwise it is `hidden_identifier_found`.

An external `isolation_reviewer` signs the `prompt_allowlist` receipt citing the isolation capture's `capture_sha256`. `EligibilityContext.validate()` accepts only `visible_only`, so any hit refuses eligibility. `eligibility.py` is unchanged.

**After the fact.** For a post-attempt re-scan of the T3 attempt itself, reporting callers use `assert_clean(store, leak_scan_ref)`. It refuses results whose scan found a hit.

**What it does not do:**
- Reviewers must check the report's `subject` and `requests` actually cover the attempt or rehearsal being certified; the eligibility check itself only reads `observed_value`. For T3, the allowlist receipt precedes `begin()`, so the scanned prompts are a rehearsal with the frozen prompt pins; the real T3 prompts are guarded afterwards only by `assert_clean`, which no runner/reporting caller invokes yet.
- It cannot see prompts that never reached a capture (for example a crash before an arm receipt). Custody of the capture store remains a precondition.
- It cannot recognise hidden truth paraphrased or re-encoded beyond hex case and truncation, for example as decimal values or base64. Those stay with the human isolation reviewer.
- Regression source lives in `tests/evaluation/test_leak_scan.py`. It is unexecuted.
