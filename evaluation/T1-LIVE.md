# Public T1 live authority — constructed source, runtime unverified

No provider/crypto/SQLite/test/target call has executed in this construction.
No operational authority, key, price verification or spend approval exists from
these source files. Public/retired development material remains exposed. T1
authority never authorizes hidden access or substitutes a public plan for T2.

## Public catalog and signed scope

`make_public_catalog(cases, *, visibility='public', nonce,
corpus_commitment_sha256=None)` binds named development **or** validation inputs,
including actual source bytes, all visible metadata, permitted samples, brief,
independent oracle/canonical/layout identities. `validate_catalog` rejects mixed
or hidden splits. At most six development/four validation variants are admitted;
an explicitly named subset is a trial, not a complete hidden benchmark.

Use `EditionRegistry.register_public(catalog, request_id=..., expected_head=...)`.
This appends exposed T1 registration in the same journal as T0/T2/T3, never a
second decisions database. `visibility='retired'` labels reused retired material;
it cannot make that material unseen. Signed attempts and every arm/request are
unique, including failures. Historical exact retries do not execute again.

Optional `corpus_commitment_sha256` links public inputs to a complete T0 family
sealed **before** tuning. An unlinked catalog is an exploratory public trial and
cannot establish the T1 selection lineage used for hidden promotion. Linked T1
cannot begin/reserve/continue tuning after that family's T2/T3/exposure.

`PublicLiveContext(registry, catalog, authority_receipt, verifier, billing)` uses
the concrete `ReceiptVerifier(trusted_issuers, public_keys)` Ed25519 backend.
The owner-signed payload has exact fields:

`schema_version=1, stage='T1', action='execute_public_live', edition, split,
mode='live', attempt_id, catalog_sha256, nonce, pins, provider, model,
model_version, billing_config_sha256, billing_code_sha256, price, caps,
not_after_utc, capture_root_sha256, registry_sha256, authority_sha256`.

`pins` has the eleven provisional configuration hashes used by the T2 contract;
these are experiment pins, not a final freeze. Model identity hashes the exact
`{provider,model,model_version}` object. The payload self-hash excludes
authority_sha256. Store its signed envelope as `signed_evidence` before use.

`price` exact fields are schema_version, provider, model, currency='USD',
as_of_date, rates_per_million, evidence_sha256, price_sha256. Rates are exact
decimal strings for input_tokens, cached_input_tokens and output_tokens. Cached
rate cannot exceed full-input rate. The card's own hash excludes price_sha256;
`pins.price_sha256` binds that complete versioned card. Its separately approved
vendor/evidence artifact hash is `price.evidence_sha256`.

`caps` exact fields are max_input_tokens (1..8000), max_output_tokens (1..2000),
max_product_requests (0..3 per layout/method), max_b1_requests=1,
max_questions (0..12/layout), max_total_requests (1..1000), price_max_age_days
(1..30) and total_usd (exact nonnegative string). Authority expires at a zoned
UTC instant; future/stale dated prices refuse new calls. Current vendor/model/API
and actual price evidence still require explicit operator activation later.

## One pricing truth and exact gateway bridge

`BillingAdapter(config, calculate_usage_cost)` receives D7's actual pure
`la.providers.live.priced_usage` function from the trusted evaluator-command
factory. The evaluator imports no product module and implements no second
pricing formula. It hashes that function's actual bounded .py source file and
the exact credential-free D7 config; both must match the signed T1 payload.

The config uses D7's exact live configuration fields, including requested model,
returned model_version, all three rates, dated price/version/evidence pins,
API pin, token bounds and transport cap. Transport/gateway token bounds must
match. Legacy activation flags in that config are not this evaluator's authority:
the concrete signature and exact scope remain required.

Gateway base request fields stay mode, method, attempt, prompt, prompt_sha256,
max_input_tokens, max_output_tokens, allow_retries, allow_repairs. T1 adds exactly
provider, model, price_sha256, evaluation_phase='T1',
evaluation_authority_sha256. Here **gateway price_sha256 is the native D7
price_evidence_sha256**, not the price-card self-hash. D7 verifies these extras
against its trusted context before transport and carries evaluation_phase and
evaluation_authority_sha256 into the actual CallLedger receipt. Its run namespace
must distinguish the authority/attempt/source/method, not reuse an old trial.

The provider reply retains output, raw usage, cost_status, known_cost, provider,
requested model, evidence price_sha256 and the actual provider_receipt. The
consumer validates native model_version/returned_model, config/price/API/authority
pins, gateway prompt/source/method/T1 scope and receipt hash. Raw cached input,
reasoning, total and other categories are never dropped or silently rewritten.
D7's pinned pricing function decides supported categories and cost. Its result
must match the actual billing receipt and envelope; an inconsistent false zero
is unknown, not corrected into an invented billing fact. Unsupported categories
or mismatched pins remain unknown and block further liability.

The evaluator reserves full bounded input/output at the approved uncached rate
before calling the provider. This is a conservative **reservation**, not billed
cost. Actual cost remains D7 CallLedger's fact. EditionRegistry records the
authorization/reservation and immutable reference/copy of that real receipt.
Every attempted/failed request counts. Outstanding reservations/unknown cost
block further live trials across editions in this journal; no automatic retry.

`context.reconcile_liability(signed_receipt, request_id=...)` needs an actual
immutable billing_observation containing the native **reconciled D7 receipt**,
its usage/amount/evidence/source/prompt/T1 scope, plus a matching owner-signed
reconcile_public_liability action. It never clears unknown cost using a success
flag, resets counts or introduces a competing evaluator price. Recording a late
billing/terminal receipt is allowed after grant expiry; authorizing a new call is
not. D7 transport and evaluator journals must reconcile to the same billing fact.

## Runner and chronology APIs

Use `context.begin(request_id=..., expected_head=...)`, then
`run_variant(..., mode='live', pins=context.pins, eligibility=context, freeze=None)`
for an explicitly named individual trial. The caller then publishes the terminal
result and invokes `context.finish_suite(status,capture,request_id=...)`.
`run_suite(..., split='development'|'validation', mode='live', pins=context.pins,
eligibility=context, attempt_request_id=..., expected_registry_head=...,
freeze=None)` handles begin/finish automatically for declared ten100-record-batch
variants. Default public rules/mock behavior is unchanged. Missing T1 authority
never silently changes a requested live call into mock.

`select_configuration(owner_signed_selection, request_id=...)` preserves the
actual terminal report capture, selected provisional pins, basis and rationale.
Unknown cost disqualifies cost-based selection. For hidden promotion, a linked
T0 must precede the T1 trial. `make_freeze(t0,pins,selection_sha256=...)` optionally
binds that real committed selection. Registry freeze rejects active linked T1
trials, mismatched selection/configuration or unlinked exploratory results. No
post-T2/T3 tuning is permitted for the linked family. A final freeze alone still
does not grant T3 custody, hidden access, provider execution or product acceptance.

## Actual D5 phase and controlled-effect bridge

`TargetPorts` adds optional `prepare_v2(visible,mapping,method,edition,phase_scope)`.
Wrap D5 `prepare_evaluation_candidate_v2(batch,proposal,*,edition,evaluation_phase,
split,evaluation_plan_sha256=None,freeze_sha256=None)`. T1 scope is
`{evaluation_phase:'T1',split:public_split,
evaluation_plan_sha256:context.validate()['authority_sha256'],freeze_sha256:None}`.
No T1 hash is labeled a final T2 freeze. A missing phase adapter remains not_run.
`TargetGrant(authority_envelope, expectation, verifier)` now requires a concrete
Ed25519 evaluator verifier with role target_authority. D5 also verifies that same
signed intent with its own TargetAuthorityVerifier; all actual target pins match.

Wrap `collect_controlled_failed_load` and `collect_controlled_lost_ack` as
TargetPorts.failed_load/recovery; their independently authorized operations are
controlled_failed_load/controlled_commit_ack. Recovery returns prior/reconciled;
an unavailable reconciled observation stays missing. D5 v3 controlled boundaries
retain actual first-insert/error/rollback absence or driver-commit/application-ACK
suppression and durable recovery. Grading labels controlled_application_ack
separately from observed_lost_commit_ack and never claims a simulated network
failure. Ordinary known-commit readback recovery cannot satisfy lost-ACK evidence.
All grader catalog precision bounds match D5: max(1,scale)..1000, exact observed
values retained. No target, transport or billing operation was run here.
