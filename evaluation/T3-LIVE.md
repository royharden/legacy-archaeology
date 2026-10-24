# Protected T3 live billing authority (source contract)

`evaluation/protected_live.py` adds the source path for the single five-arm, eight-heldout-variant live suite. It is source only. Nothing here has been imported, run, signed, priced or billed. The module mints no keys or authority and makes no claim about current vendors, models or prices. Exact cross-owner signatures are in `agentops/seams/T3-LIVE-API.md`.

## Authority layering

1. **Custody**: the exact `EligibilityContext` (T0 commitment, T2 freeze, T3 live suite, signed canary/isolation receipts, suite authority). `PublicLiveContext` and any T1 authority are refused as T3 authority.
2. **Spend scope**: a separate Ed25519 `run_owner` envelope (`action='authorize_protected_live_spend'`). Through its pins it binds:
   - the edition, commitment, freeze, suite and attempt, plus the edition nonce;
   - a fresh scope nonce;
   - the exact T2 pins;
   - the provider, model, model version and API version;
   - the D7 billing config and pricing-code SHA256;
   - the dated price card;
   - the caps;
   - the expiry;
   - the capture root, the registry path and the registry head at signing.

   The suite authority's `spend_authority_sha256` must equal the digest of this envelope. The frozen pins must agree: `price_sha256` is the card hash, `model_sha256` is digest(provider/model/version) and `caps_sha256` is digest(caps).
3. **Admission**: `ProtectedLiveContext.admit()` appends `t3_scope_admitted` to the existing EditionRegistry chain before `run_suite` begins the attempt. It is allowed only while the edition is frozen, unconsumed and unexposed, and only at the signed registry head. Admission also requires the suite authority to pin this exact envelope, and records that suite authority's envelope hash. It refuses a T1 authority hash or nonce, a replayed scope nonce, and any unknown live liability.
4. **Enforced metering**: the registry dispatches every event to `fold_protected_event`. A `mode='live'` `attempt_started` is refused unless the admitted scope names the same suite and the attempt's `authority_sha256` equals the recorded suite authority hash. That proves the suite was admitted, not that its provider calls are metered. The D4 `runner.py` hook that calls `require_protected_ports` (before `begin` and before each live heldout arm) closes raw-provider wiring. Until it lands, an operator could wire the raw D7 provider after admission.

## Metering

`ProtectedProviderPort` is placed in `RunnerPorts.provider`. D6 does not edit `runner.py` (D4 runner hooks 4–5 are required; see the seam); its gateway still enforces single flight, the B1/product budgets and no retry inside an arm. Each call goes through these steps:

1. Revalidate custody, scope and expiry.
2. Map the prompt source to one declared heldout case.
3. Run the token preflight with the injected counter.
4. Durably append `t3_request_reserved` (registry CAS) before transport.
5. Send the exact T3 extras to D7's `provider_port`: provider, model, price evidence, `evaluation_phase='T3'` and the scope SHA as `evaluation_authority_sha256`.
6. Settle through `BillingAdapter.price(..., phase='T3')`. This is the same single D7 `priced_usage` truth used by T1; there is no second formula or journal.

The registry fold enforces these rules:

| Rule | Enforcement |
|---|---|
| Request caps | Per heldout variant across all ten batches (one mapping session per layout): B0 0, B1 exactly 1, C0/R0/R1 each at most `max_product_requests` (≤3), attempt total at most `max_total_requests` (≤80) |
| USD | Known cost plus a conservative full-input+output reserve must stay within `total_usd` |
| Single flight | No reservation while any T3 call is reserved or unknown; the D4 `_append` hook extends this across T1/T3 and every edition |
| B1 completion | `arm_finished` B1 completed requires exactly one known call |
| Suite completion | `attempt_finished` completed requires every T3 call known |
| Known cost | Must retain the actual D7 receipt: T3 phase, scope SHA, raw usage equal to settled usage, receipt self-hash, pinned pricing code |

A call whose actual known cost exceeds its reserve, or whose usage exceeds the signed token caps, is settled truthfully as known and then fails the arm; later reservations see the actual spend.

A raising pricing check, or a reply that cannot be serialised, still settles the reservation as `unknown` with an `error_type`; it is never left reserved. Settlement of the exact reserved call is accepted even after exposure or attempt end. Such a call is also stored with a durable `overrun` mark, so the arm and suite cannot be marked completed even if an adapter swallows the error. On overrun the port raises `T3OverrunError(known_cost)`. `runner.py` is not T3-aware, so the gateway item and arm receipt list that call as an unknown liability while the registry holds the known cost (optional runner hook 6).

Cached, reasoning and raw usage categories are kept verbatim. An unsupported category, a mismatch, a timeout or a transport loss settles as `unknown` with `known_cost=null`. That fails the arm and halts every later live reservation. `reconcile_liability()` needs both of these, bound to the call's prompt/source/method:
- a signed `reconcile_protected_liability` receipt;
- an actual `billing_observation` capture whose native D7 receipt is `status='reconciled'` with `evaluation_phase='T3'`.

Reconciliation skips the custody/exposure gate and the pricing-code pin (it checks only the scope signature, scope validity and the admitted scope), so a liability stays reconcilable after the edition is exposed or retired. There is no cost, arm or edition substitution.

## Known limits and dependencies

- **D4 hook:** requires the D4 `edition_registry.py` hook (`'t3': None`, `fold_protected_event` dispatched for every event of the edition, and `assert_no_unknown_live_liability` in `_append` including live `attempt_started`). Without it, every `t3_*` append fails closed with `unknown registry event type`.
- **D7 phase support:** requires D7 `provider_port`/`wire.request_pins` to accept `evaluation_phase='T3'` from `trusted_authority()`, plus the factory/CLI wiring described in the seam.
- **Question cap:** the signed `max_questions` (≤12) is enforced only once the D4 `runner.py` hook calls `question_cap(ports)`; until then only `_questions`' fixed 12 applies.
- **Lost reservation:** a crash after `t*_request_reserved` but before transport is cleared by `void_unsent_reservation` (seam Amendment A1/A1.1). That needs a signed `run_owner` void plus a D7 `CallLedger.fence_unsent` attestation: an atomic tombstone proving no D7 attempt and blocking any later one. Until D7 ships the fence, voids fail closed.
- **Cross-edition liability check:** in `admit()` the scan is non-atomic. The atomic check is the D4 `_append` hook.
- **Validation still owed:** actual custody/isolation, key provisioning, price evidence approval, provider activation, an owner-authorized live suite and all regression execution are deferred. See `tests/evaluation/test_protected_live.py` (unexecuted).
