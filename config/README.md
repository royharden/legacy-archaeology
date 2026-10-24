# Caller configuration examples

These are unexecuted source templates. String placeholders deliberately fail closed;
they are not credentials, signatures, captured results or granted authority. Copy
them to an operator-owned root and supply independently approved actual documents.
Nothing reads a key, DSN or provider environment variable on import. The installed
inference wheel excludes `evaluation/` and `scripts/`.

`public-mock.example.json` is the ready offline factory shape. Use `--mode rules`
or `--mode mock` explicitly. No model call or product approval results from either.
The public development corpus is known material and cannot establish unseen quality.

`t1.example.json` selects `scripts.eligibility_factory:factory` and
`scripts.product_ports:factory`. The signed catalog is public development or
validation only. The operator's signed `execute_public_live` payload must bind the
exact catalog, nonce, registry/capture roots, provisional FREEZE_KEYS pins, provider,
requested/returned model versions, dated price evidence, expiry and caps, plus
`billing_config_sha256` and `billing_code_sha256`. The latter is the actual SHA256
of `src/la/providers/live.py`; the former is canonical SHA256 of the exact provider
configuration. Actual contract: `evaluation/public_live.py` `validate_authority`
and `BillingAdapter`. No factory signs or supplies activation authority.

The billing config has exactly: authorized, activation_verified, authority_id,
model, model_version, price_version, price_evidence_date, price_evidence_sha256,
input_usd_per_million, cached_input_usd_per_million, output_usd_per_million,
total_cap_usd, max_output_tokens, max_input_tokens, api_version_pin. Boolean flags
alone do not grant T1: concrete Ed25519 verification binds every config byte and
pricing source. `provider` is `openai-responses`. Prices/caps are exact decimal
strings. No price is populated here. Cached input uses its distinct rate;
reasoning is included in output tokens and is not billed twice. Unsupported raw
categories, wrong returned model, missing receipt or arithmetic mismatch remain
unknown and block further liability. Local provider-ledger and evaluator-ledger
liabilities both need their own actual external billing reconciliation; one
receipt does not silently clear the other ledger.

`t3.example.json` names actual T0/T2/T3 metadata and six signed isolation reviews.
It is a protected rules/mock template; live additionally needs the separately
approved provider config/spend authority and frozen model/pricing pins. Underlying
canary/isolation captures must already exist in the evaluator CaptureStore under
the signed hashes. The factory verifies and retains supplied signed envelopes,
then validates actual registry/custody history before case access. It does not
create isolation observations, or turn a boolean into custody. See
`evaluation/eligibility.py` and `evaluation/edition_registry.py` for closed schemas.
All signed public profiles contain public keys only; see `docs/EVIDENCE.md`.

`t3-live.example.json` is the protected live template. Its eligibility packet adds
`scope_receipt`: the separately signed T3 spend scope (role run_owner) that the
signed suite authority pins as `spend_authority_sha256`. The factory verifies and
retains it, then returns D6's `ProtectedLiveContext`. `scripts/eval.py` accepts it
only for `--mode live --split heldout --ports scripts.product_ports:factory`. Before
any provider wiring it records `t3_scope_admitted` with `t3_admission_request_id`
at `expected_registry_head` (the head the scope was signed against), then starts the
suite at the exact admission event head. The product provider receives the T3
trusted view (phase T3, scope hash as authority); D6's meter wraps it to reserve and
settle every call in the edition registry. A live heldout suite without an admitted
scope is refused, never run with an unmetered provider. A PublicLiveContext or T1
authority never authorizes heldout. Unknown T3 liability is reconciled through the
native provider ledger receipt (evaluation_phase T3, billing_evidence_sha256) and
D6's signed `reconcile_liability`. The template grants nothing and fails validation.

`target-context.example.json` is supplied as `target_context` in a suite config
with `--target-factory scripts.target_ports:factory`. `candidate-grants.json` maps
each exact prepared candidate SHA256 to relative signed_authority, target_config,
expectation filenames. Optional stored effects: failed_load, prior, reconciled.
Alternatively select `collect_failed_load: true` and `collect_lost_ack: true`.
Those selections require separate signed controlled_failed_load and
controlled_commit_ack operations before DSN access; flags alone grant nothing.
The latter explicitly suppresses the application ACK after observed driver commit;
it is not evidence of a network fault. Missing effects remain indeterminate.

Phase-aware target preparation uses D5 `prepare_evaluation_candidate_v2` through
D6 `TargetPorts.prepare_v2`. T1 uses evaluation_phase=T1, explicit public split,
evaluation_plan_sha256 equal to its signed live authority hash, freeze_sha256=null.
T3 retains the final T2 freeze and null development-plan pin. Each separately signed
target authority and external expectation must match that exact descriptor.
Product operations instead use the `la database-observe`/`database-recover`
commands with independently supplied signed product-bundle authority/config and
external bundle pin. Product approval is never fabricated by evaluator proposals.

The inactive experiment-grants.example.json adds an exact experiment reference to the target grant index. Remove both later-recovery keys to use original captured effects. Otherwise supply the explicit selected later record SHA and exact original prior SHA (JSON null only for actually absent prior). These callbacks read pinned immutable captures without a DSN or new target action. See docs/CAPTURE-REPLAY.md for the separate collect/open/reconcile/select-recovery commands; placeholders grant nothing and deliberately fail validation.
