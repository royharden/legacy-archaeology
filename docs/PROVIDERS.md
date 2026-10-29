# Provider activation and accounting

Rules and mock are offline. Mock is a disclosed deterministic rules simulation;
it is never reported as a provider response. Rankings order finite candidate IDs,
remain advisory, and cannot supply offsets, policies, SQL, transformed values or
mapping approval. Unranked candidates remain available for review. The B1 full
mapping comparator is a separate one-attempt interface requiring a deterministic
mapping validator; without one its proposal is explicitly `unvalidated`.

Source construction only: no provider, model, API version, price, credential or
paid activation has been verified. No provider call has been performed. Dirty
Mode must be closed and authority obtained before activation or runtime checks.

Later live activation uses `la --root <store> hypothesize <run> --mode live
--provider-config <relative-config.json>`. The JSON config is contained under the
declared run root; it must contain exactly these fields:

- `authorized`, `activation_verified`: actual boolean authority after verification.
- `authority_id`, `model`, `model_version`, `api_version_pin`: approved identity and
  verified Responses transport/model snapshot compatibility. An unexpected returned
  model snapshot or incomplete response fails. These labels do not verify themselves.
- `price_version`, `price_evidence_date`, `price_evidence_sha256`: dated pricing
  evidence, including exact usage-category treatment.
- `input_usd_per_million`, `cached_input_usd_per_million`,
  `output_usd_per_million`, `total_cap_usd`: nonnegative exact decimal strings;
  cap must be positive. Cached price cannot exceed full input price.
- `max_input_tokens` at most 8000; `max_output_tokens` at most 2000.

No credentials belong in that packet. `OPENAI_API_KEY` is an environment variable
name; only an explicitly activated transport reads it. There is no silent
live-to-mock fallback or automatic retry. Transport failures, malformed output and
missing-key attempts count. Product ranking gets at most three attempts per layout
run, including regeneration/repairs; B1 gets exactly one independently labeled
attempt. Use the same run identity for all repairs. A new identity is a new
experiment and must not disguise a retry in benchmark accounting.

Prompt construction validates source/brief/generation/candidate identities and
exact permitted sample references. It selects at most 64 authorized records in
ordinal order, removes trailing selected rows and then candidate options until the
fixed 8000-byte cap fits. Selection/omission counts and hashes are logged; a request
that still cannot fit refuses. Byte length is used as a conservative input-token
upper bound; actual tokenizer/API compatibility remains a later activation check.
Only the bounded brief, permitted records, source pins and code-generated candidate
descriptions enter ranking prompts. Candidate evidence from arbitrary rows is
excluded. Every imported string is inert JSON data.

`<store>/provider-accounting.sqlite` is the paid-call authority across its runs.
One `BEGIN IMMEDIATE` transaction checks request counts, all outstanding liability
and the shared cap before reserving. Committed reservation precedes transport;
process death leaves it outstanding. Known billed usage replaces the reserve;
missing/unrecognized usage remains unknown and blocks every further call. Failed
attempts are never reset. Output reasoning tokens are included in output totals,
not charged twice. Raw usage categories are retained; unsupported categories require
reconciliation instead of assuming zero. Non-model spans have a separate event kind.

`CallLedger.export()` creates content-addressed immutable JSON snapshots with all
events and attempts. `CallLedger.reconcile()` requires explicit authority, billing
evidence SHA256, exact prior receipt digest and actual cost; it appends an event and
updates the projection atomically without deleting history or resetting attempt
counts. Reserved rows after a crash also require this explicit reconciliation.
Legacy nonempty `calls` tables refuse audited migration rather than losing prior
liability. Keep one ledger per authorized budget; copying it or choosing a different
root is not additional spend authority. Root backup/SQLite/export artifacts must
remain private; never place credentials or hidden assets in prompts or exports.

Deferred checks: actual response/status/model/usage wire compatibility, tokenizer
bounds, pricing categories, authority provenance, concurrent/crash reservations,
unknown-liability billing reconciliation, immutable exports, option-order/injection
cases and malformed one-pass comparator output. No runtime check has run here.
