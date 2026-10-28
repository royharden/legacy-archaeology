# Target observation v2 — constructed source, runtime unverified

No API below has been invoked in Dirty Mode. No database/crypto/driver behavior is verified. No target/parity/product success flag is emitted. Independent evaluator grading remains required.

Public source APIs from `la.postgres`:

- `prepare_evaluation_candidate(batch,proposal,*,edition,freeze_sha256)` returns `{kind:'disposable_evaluation_candidate',descriptor,batch,proposal}`. It structurally validates a complete strict proposal and uses the same deterministic converter/SQL compiler for B0/B1/C0/R0/R1. Descriptor includes source/framing/mapping(proposal)/config/sample/code/SQL/outcome pins, method, frozen edition, complete counts, candidate_sha256, product_loadable:false, product_approval:absent. No product AnswerEvent/MappingSpec/approval is fabricated. Incomplete proposals fail explicitly. No gold is an input.
- Product artifact for this v2 port is exactly `{kind:'product_bundle',bundle_path}` and must pass offline source/lineage/code verification against externally configured bundle pins.
- `TargetAuthorityVerifier(trusted_issuers,public_keys)` is concrete lazy Ed25519 verification, compatible with the evaluator signed-receipt envelope. Operator-configured public key bytes only; callbacks/always-true verifiers and signing keys are not accepted. Missing cryptography fails closed without installation.
- `target_observer_v2(artifacts,authority,*,dsn=None,target_config=None,negative_kinds=(),authority_verifier=None)` uses one disposable transaction/fresh-readback implementation for all five arms and product candidates. `authority` is a signed envelope, not a success boolean. Missing DSN produces explicit not_run after verified authorization. TargetConfig retains role/driver/server/database/loopback requirements and appends `expected_candidate_sha256` for evaluator candidates. Product bundle pins remain separate and mandatory on the product path.
- `reconcile_target_candidate(artifacts,authority,original,*,dsn=None,target_config=None,authority_verifier=None)` only observes durable marker/rows for an original indeterminate write, same execution/namespace/candidate/config/authority/code pins. It never loads/upserts/retries. Original hash is linked; actual fresh marker rows/query hashes are retained. An absent/mismatched marker remains indeterminate.
- `validate_target_observation`, `validate_negative_effect` perform closed wire/identity checks, not independent acceptance. `write_target_observation(destination,observation)` publishes an immutable sibling receipt, never inside a frozen bundle.

Signed envelope exact keys match evaluator custody: `schema_version=1, algorithm='Ed25519', issuer,key_id,role='target_authority',payload,payload_sha256,signature` (128 lowercase hex). Signature covers canonical UTF8 payload. Trusted issuer/key mappings are operator configuration outside candidate JSON. Payload exact keys:

`schema_version=1,kind='disposable_target_authority',authority_id,scope,candidate_sha256,source_sha256,method,edition,freeze_sha256,observer_code_sha256,operations,authority_sha256`.

Scope is product_bundle or disposable_evaluation; product method/edition/freeze are null. Evaluation binds the actual frozen method/edition/candidate/source. Operations is an explicit unique subset of load/negative_probes/reconcile. authority_sha256 hashes payload excluding itself. TargetConfig.authority_reference must match that external signed authority pin. `observer_code_pin()` publishes current observer source identity. No authority body uses `authorized`, `passed`, `oracle_success` or caller verification booleans.

Observation exact top-level keys:

`schema_version=2,kind='target_observation',candidate,authority_sha256,target_config_sha256,observer_code_sha256,attempt,target,commit_state,readback,negative_effects,recovery,issues,observation_sha256`.

attempt: execution_id,attempt_id,namespace,write_connection_id,read_connection_id,prior_observation_sha256. Actual connection IDs hash server PID plus backend_start. commit_state is not_run/committed/failed/indeterminate. target is null before observation or the actual database/role/host/port/server_version_num/authority_reference/scope/driver_version. Credentials/DSNs never enter the wire.

readback is null or `{capture,query_sha256,columns,rows,rows_sha256}`. capture is fresh_connection_after_commit or fresh_connection_reconciliation. columns are actual five-item catalog tuples serialized as lists; rows retain full six-part RecordRef, mapping/proposal hash, outcome=converted and exact string Decimal/date/text/NULL values. Decimal readback is never rounded to conceal differences. Source-ordinal keys retain identical duplicate business rows. Hashes use canonical sorted compact UTF8 JSON.

Each negative effect exact keys:

`schema_version=1,kind='negative_effect',probe_kind,candidate_sha256,source_sha256,authority_sha256,target_config_sha256,observer_code_sha256,execution_id,attempt_id,namespace,target,before,transaction,after,transaction_state,issues,effect_sha256`.

Deliberate probe kinds: rollback/nonnull/check/numeric_overflow/duplicate_identity/invalid_date. Each uses a fresh owned namespace, actual first-row insertion as applicable, actual server exception class/SQLSTATE and SQL+parameter hash, explicit rollback, then a distinct fresh observer. No disclosed vocabulary yields check=not_applicable rather than a fake successful check. Missing server error remains explicit even when rollback absence is observed. A failed real load additionally collects failed_load effects without pretending the failure was a successful probe.

before/after are actual `{connection_id,query_sha256,namespace_exists,table_exists,rows,rows_sha256,rows_capture}`. Catalog booleans come from database query results; rows are all persisted source_sha256/ordinal/raw_sha256 provenance, capped10000, or empty when the relation was actually absent. These are observations, never caller rollback_ok flags. transaction is actual `{connection_id,statement_sha256,sqlstate,error_class}`. Missing observations are null, not synthetic empty success. transaction_state is not_run/not_applicable/rolled_back/indeterminate; independent grading must compare before/error/after and all pins, not trust this label alone.

recovery is null or `{prior_observation_sha256,marker_query_sha256,marker_rows,marker_rows_sha256,read_connection_id}`. A normal commit never manufactures lost-ACK evidence. Persist and pass both original indeterminate and reconciled observations to the independent grader.

Original issues distinguish `commit_acknowledgement_unknown` from `committed_readback_unavailable` after a received commit ACK. Reconciliation issues distinguish `reconciled_lost_commit_acknowledgement` from `reconciled_known_commit_readback`. Only the former original/recovery lineage can support a lost-ACK claim; a committed run with a later read error is ordinary readback recovery.

Public bundle helpers for CLI source: `la.convert.producer_code_pin()` and `bundle_limits()`. Limits distinguish raw5MiB from encoded source/rows/rulings32MiB, inputs16MiB, twelve members and total128MiB. Use code+actual input/approval identity in immutable cache destinations; do not overwrite old-code bundles.

## Additive phase and controlled-collector contracts — V5F source

`prepare_evaluation_candidate_v2(batch,proposal,*,edition,evaluation_phase,split,evaluation_plan_sha256=None,freeze_sha256=None)` emits evaluation descriptor schema2 = schema1 evaluator keys plus evaluation_phase/split/evaluation_plan_sha256. T1 permits development/validation, requires a named development evaluation-plan/config SHA, and freeze_sha256 must be null. T3 requires the final T2 freeze SHA and evaluation_plan_sha256=null; split is explicit. T1 cannot access heldout or substitute its plan hash into a final freeze field. D6 owns actual phase eligibility/custody and the meaning/approval of the supplied pin. Source alone does not establish those facts. The legacy explicit-freeze constructor is retained unchanged; same deterministic compiler/converter serves all methods/phases.

Signed authority payload schema2 adds those exact phase keys and must match descriptor version/scope/phase/split/plan/freeze. Outer signed envelope remains schema1 Ed25519, role target_authority. New separately granted operations controlled_failed_load and controlled_commit_ack are never implied by load/negative_probes/reconcile. Existing schema1 candidate/authority and observation schema2 remain supported. Product approval/load gates are unchanged.

`collect_controlled_failed_load(artifacts,authority,*,dsn=None,target_config=None,authority_verifier=None)` requires load plus controlled_failed_load. In the common transaction it actually inserts one valid row, queries its uncommitted provenance, then executes fixed code-owned SELECT1/0 before commit. It captures actual error/trace and fresh before/after durable absence. Missing rows/driver/authority/observations do not become successful effects.

`collect_controlled_lost_ack(artifacts,authority,*,dsn=None,target_config=None,authority_verifier=None)` requires load, controlled_commit_ack and reconcile before it starts. It observes the real driver commit returning, then deliberately raises at after_driver_commit_before_application_ack. This is explicitly controlled application ACK suppression, not an unobserved network failure. It returns exactly `{prior,reconciled}`; reconciled is null if no actual indeterminate write exists. Otherwise ordinary read-only reconciliation verifies the actual durable execution marker and fresh rows, linked to the original hash, without any INSERT retry. It never rewrites a normal completed receipt into indeterminate. Normal known-commit read failures retain the separate E issue codes above.

Controlled observations use schema_version3 = the exact v2 observation keys plus controlled_fault. The exact controlled_fault keys are operation,boundary,state,network_loss_claimed,driver_commit_returned,application_ack_delivered,trigger_statement_sha256,boundary_sha256,injected_error_class,partial_write. Operation is controlled_failed_load or controlled_commit_ack; its code-pinned boundary is after_first_insert_before_commit or after_driver_commit_before_application_ack respectively. state is not_reached/injected/unsupported. network_loss_claimed is always false. Driver return/application ACK fields are explicitly captured program state; they are not independent acceptance booleans. Partial_write is null or actual `{connection_id,query_sha256,rows,rows_sha256}` from the uncommitted write connection.

An injected failed-load observation requires an actual target/write connection, one observed partial row, real statement/error metadata and failed/indeterminate state before any commit. A controlled ACK observation requires observed driver return plus the actual ControlledAcknowledgementSuppressed class; a committed result additionally requires actual reconciliation readback/marker. Preserve the original fault in the reconciled observation. Independent grading must inspect all actual effects/lineage and distinguish controlled application boundary coverage from general network resilience. No probe, crypto, transaction or test has been run in this construction phase.

## Pinned experiment facade — V5G source

Public `la.postgres` exports:

```python
manifest = collect_target_experiment(
    artifact, signed_authority, capture_root=existing_owned_directory,
    experiment_id="operator_unique_capture", dsn=explicit_disposable_dsn,
    target_config=config, authority_verifier=verifier)
callbacks = target_experiment_callbacks(
    existing_owned_directory / manifest["experiment_id"],
    expected_experiment_sha256=externally_retained_manifest_pin,
    expected_candidate_sha256=externally_retained_candidate_pin,
    expected_authority_sha256=externally_retained_authority_pin)
```

These are future opt-in calls after Dirty Mode closure and operator authorization. The facade never reads an environment variable or creates authority. Supply an actual `TargetConfig`, concrete public-key `TargetAuthorityVerifier`, signed target_authority envelope and explicit DSN. Pin database, least-privilege role, exact driver version, server major, loopback host and authorized port. Evaluation requires expected_candidate_sha256; product bundles retain their separately pinned bundle/source/mapping and actual approval gates. Prepare the phase-aware candidate before obtaining a signature. T1 uses development/validation plus evaluation_plan_sha256 and no freeze; T3 uses the final T2 freeze and no plan substitution. Observer source edits invalidate old authority pins.

The signature must explicitly grant all five operations: load, negative_probes, controlled_failed_load, controlled_commit_ack, reconcile. The facade verifies every operation/candidate/source/phase/config/code scope before connecting. Missing/invalid authority is a refused manifest, missing DSN is not_run, missing driver or target facts remain explicit observations/omissions. It never installs dependencies, signs, retries a load, upserts, deduplicates, or grants product acceptance.

Each invocation exclusively creates capture_root/experiment_id. It immediately writes immutable normal_readback, each of six separately namespaced negative effects, a derived normal observation retaining that same raw readback and exact effect lineage, failed_load and its embedded absence effect, ack_prior, then ack_reconciled. The predecessor-only `collect_controlled_ack_predecessor` makes publication possible before a later reconciliation failure. A receipt from an earlier stage survives a later failure. The fixed controlled ACK boundary truthfully means driver commit returned but application acknowledgement was suppressed; network_loss_claimed remains false.

`experiment.json` is a neutral content-bound inventory of capture paths, byte and semantic hashes, actual execution/attempt/namespace/state, operation status and omissions. capture_status collected means required captures exist, including any explicit unobserved facts; it never means the effects passed independent grading. target_validation and row_parity stay not_run, product_acceptance pending. The normal raw receipt is never rewritten into unknown-ACK. No receipt/DSN is stored in a frozen migration bundle. Limits: 32 captures, 32MiB per observation, 8MiB per effect, 256MiB total initial captures, 256KiB manifest. Paths reject escape, links/junctions and noncanonical components; publication is exclusive and immutable. Filesystem ownership/custody and authentic execution remain operator responsibilities; content hashes alone do not establish them.

`open_target_experiment(path,*,expected_experiment_sha256,expected_candidate_sha256=None,expected_authority_sha256=None)` rechecks the external manifest pin, every member's byte/content hash, closed wire, source/config/observer/candidate scope, role/attempt/state and derived lineage. It does not connect or silently select a recent experiment. Retain the manifest pin through an independent trusted handoff. `target_experiment_callbacks` uses that reader and exposes the exact D6 `(artifact,signed_authority)` methods observe, failed_load and recovery. They return defensive copies or explicit None, check the complete artifact/envelope pins, and never connect. Plug these bound methods into D6 `TargetPorts`; D6 retains its own prepare/prepare_v2, operator `TargetGrant`/`ReceiptVerifier`, independently configured `TargetExpectation`, custody, oracle and `grade_target`. No evaluator or gold code is imported into the product wheel.

`reconcile_target_experiment(path,artifact,signed_authority,*,expected_experiment_sha256,dsn=None,target_config=None,authority_verifier=None)` only reads the original pinned ack_prior candidate/namespace/marker. It calls the existing read-only reconciler, never any load collector, and writes a separate immutable reconciliations observation and content-bound record linked to the parent experiment and original observation. Repeated calls create distinct actual read attempts without rewriting the experiment. Missing predecessor/DSN remains not_run; failures remain indeterminate. A returned reconciliation record is an explicit later artifact; original callbacks intentionally continue exposing the original pinned capture set. Consumers choosing a later recovery must explicitly retain/check that record and use the existing observation validator plus their independent expectation/grade; there is no recency overlay.

Regression source includes explicit no-DSN/refused grants and wrong phase/source/candidate checks, pin/member tampering, partial publication with absent effects, actual D6 TargetPorts/grade_target interfaces, and opt-in disposable journeys covering all six effects, failed-load absence, application ACK predecessor/recovery and repeated read-only recovery after an injected later observer outage. These tests have not been imported, collected or run in Dirty Mode.

## Explicit later recovery selection — V5H source

G's original `target_experiment_callbacks` remains pinned to its original capture set. Use a separate H selection to consume a later immutable reconciliation record; no reader chooses newest or overwrites those original callbacks:

```python
selected = target_reconciliation_callbacks(
    experiment_path, artifact, signed_authority,
    expected_experiment_sha256=original_experiment_pin,
    expected_reconciliation_sha256=explicit_later_record_pin,
    expected_prior_observation_sha256=original_prior_pin,
    target_config=config, authority_verifier=verifier)
# D6 retains prepare/prepare_v2, actual TargetGrant and independent expectation.
# TargetPorts(..., observe=selected.observe,
#             failed_load=selected.failed_load, recovery=selected.recovery)
selection_receipt = selected.projection()  # neutral source labels/history, no grade
```

The exact same keyword-only inputs to `open_target_reconciliation` return a snapshot with experiment, oldest-to-selected records, observations keyed by record pin, source_label, selected and observation. The original prior pin is mandatory; None is accepted only when the pinned experiment actually has no ack_prior. Signed authority/config are explicit caller inputs, never environment lookups. The reader verifies the full artifact/envelope hashes, concrete public-key signature, closed original candidate/source/phase/plan-or-freeze/config/authority/observer identities and every immutable referenced capture. It authenticates archived code identity against that signed capture, not against whichever source happens to be installed today. It never authorizes execution. Creating any new reconciliation still uses the existing current-code authority check, exact original candidate/namespace and read-only marker collector.

New `reconcile_target_experiment(...,previous_reconciliation_sha256=None)` records use schema2: closed G record keys plus previous_reconciliation_sha256. A supplied previous pin is verified for the same original prior/experiment/scope before any read-only attempt. The reader also accepts closed schema1 G records as terminal records without inventing ordering. Links are explicit causal selection, not a wall-clock or recency claim. All records, including not_run/indeterminate and capture-publication failures, remain visible; chain limit16 and combined later-record/capture bytes256MiB supplement per-record256KiB and per-observation32MiB limits. Exact hash-derived POSIX paths only; links/junctions, traversal, duplicate/unknown JSON fields, duplicate captures/attempts, missing chain members and altered byte/content pins refuse.

`selected.observe(artifact,signed_authority)` and failed_load return defensive copies from the original experiment. recovery returns exactly original prior plus the explicitly selected later observation, including an actual indeterminate read. When that selected record has no observation, reconciled is None even if an earlier/original reconciliation had one. Nothing falls back to an earlier success. If both original prior and selected observation are absent, recovery is None. D6's actual TargetPorts and independent grade_target decide whether the preserved observations satisfy target requirements; the product neither copies scorer logic nor imports evaluator/gold.

projection identifies original_experiment normal/failed-load sources and explicit_later_record recovery source, exact selected experiment/record/prior pins, ordered history with record links, capture status, actual commit state, observation/attempt/namespace and retained issues. It always keeps target_validation/row_parity not_run and product_acceptance pending. Source labels distinguish controlled_application_ack_suppression (observed driver return, deliberate application boundary, no network claim), unknown_driver_commit_acknowledgement (driver acknowledgement actually unknown) and known_commit_readback_failure (driver returned, later observation failed). Unreached/unclassified original attempts stay explicit. Conflicting labels or a later receipt that relabels the original boundary refuse.

Future regression source covers external parent/prior/candidate/authority/config/code mismatches, omission/tamper/path escape/unknown fields, legacy schema1 and failed-chain retention, exact selection without fallback, no-load/offline reads and source-label conflicts. The existing opt-in actual-target recovery journey now explicitly chains two read-only attempts, consumes the last through these callbacks and the real D6 grade_target contract with a hand-declared oracle/schema, and verifies original callbacks remain unchanged. None of these sources have been imported/collected/executed in Dirty Mode.
