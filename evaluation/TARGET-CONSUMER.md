# Target consumer compatibility — source contract, runtime unverified

`evaluation.target_effects.validate_target_observation(value, *, expectation)` accepts only closed schema2/3, validates exact external candidate/authority/target/observer identity, and returns a defensive copy. This is structural validation, never independent target acceptance. `grade_target(oracle,observation,*,expectation,prior=None,failed_load=None,recovery_observation=None,edition='development')` remains the independent semantic/effect scorer; only scorer receives oracle.

| Input | Version and required kind | Consumer |
| --- | --- | --- |
| Legacy evaluation candidate | schema1 disposable_evaluation_candidate, real final freeze | TargetExpectation |
| Phase candidate | schema2 disposable_evaluation_candidate + evaluation_phase/split/evaluation_plan_sha256 | TargetExpectation |
| Target signature | envelope1 Ed25519 role target_authority; body1/2 matches candidate version | TargetGrant(authority,expectation,verifier=None); concrete ReceiptVerifier required |
| Normal observation | schema2 target_observation | validate_target_observation / grade_target |
| Controlled observation | schema3 = schema2 + exact controlled_fault | same consumer, no version downgrade |
| Negative effect | schema1 negative_effect; actual namespace/connections/SQLSTATE | nested wire validation and independent grade |
| Recovery callback | None or exactly {prior,reconciled}; missing stages remain None | TargetPorts.recovery |
| Billing bridge | BillingAdapter(config,calculate_usage_cost) with actual D7 priced_usage | PublicLiveContext; exact native raw/price/config/model/API pins in T1-LIVE.md |
| Target arm publication | schema2 receipt/failure, described below | D7 evaluator result publisher |

`TargetPorts(prepare,grant,observe,failed_load=None,recovery=None,prepare_v2=None)` is unchanged. `prepare_v2(visible,mapping,method,edition,phase_scope)` wraps actual D5 phase constructor. T1 phase_scope has actual case.split development/validation, signed public authority SHA as evaluation_plan_sha256, freeze_sha256=None. T3 has final T2 freeze and plan=None; phase split/freeze must equal actual case/runner scope before any callback. Neither candidate nor target authority grants evaluator hidden custody. Live calls still require proper evaluator eligibility.

`run_target_arm(case,mapping,method,store,ports,*,freeze_sha256,mode,preflight=None,phase_scope=None)` invokes controlled failed_load only with load+controlled_failed_load, and recovery only with load+controlled_commit_ack+reconcile in the verified signature. Missing controlled permissions produce not_authorized/missing effects, never invoke the callback or imply control authority. Independent grade_target still accepts genuine legacy schema2 unknown-driver-ACK captures supplied directly; normal load authority alone cannot authorize executing a new controlled collector. D7 factories serving previously stored observations must preserve the actual original operation authority, not mint permissions from file presence.

For future authorized offline capture consumption:

```python
# Illustrative callable composition only; not executed by this construction.
callbacks = target_experiment_callbacks(explicit_path,
    expected_experiment_sha256=external_manifest_pin,
    expected_candidate_sha256=external_candidate_pin,
    expected_authority_sha256=external_authority_pin)
ports = TargetPorts(prepare, grant, callbacks.observe,
    failed_load=callbacks.failed_load, recovery=callbacks.recovery,
    prepare_v2=prepare_v2)
```

D5 reader validates its immutable inventory and exact artifact/intent. Evaluator independently validates actual returned observations against TargetExpectation, then grades rows/types/nullability/catalog precision through1000, complete record identities, six real negative effects, failed-load durable absence and recovery. Archived code/instructions never execute merely because a hash matches.

A v3 injected failed-load must bind actual partial provenance/query/write connection, exact trigger statement and error class to failed_load transaction SQLSTATE22012 and fresh rollback absence. Missing before/transaction/after observations remain indeterminate. Genuine unknown driver ACK is schema2 with commit_acknowledgement_unknown / reconciled_lost_commit_acknowledgement. Controlled schema3 recovery preserves identical boundary facts and controlled_application_ack_suppressed / reconciled_controlled_application_ack. Received-ACK readback failure cannot satisfy either. Added issues prevent a clean recovery claim. Report recovery_kind and recovery_scope describe this exact distinction; network_loss_proven is false even when unknown ACK is observed. Missing reconciled readback remains indeterminate.

Publication: successful target_arm_receipt payload schema2 retains edition/method/mode/batch_id/candidate_sha256/authority_sha256/observation/effect_captures/grade/product_acceptance. Adds candidate_schema_version, observation_schema_version (nullable), phase_scope, stages and stage_errors. stages has observe/failed_load/recovery = not_run/not_configured/not_authorized/missing/unavailable/returned/captured/partial. stage_errors holds only stage and exception class, never exception message. observation is None when unobserved; otherwise CaptureStore reference kind target_observation_v2 OR target_observation_v3 matching actual wire. effect_captures reference actual failed_load_observation/unknown_commit_observation/recovery_observation without rewriting their schema.

A malformed later wire yields target_arm_failure schema2 retaining any earlier validated observation/effect_captures plus phase_scope/stages/stage_errors; all valid inputs stay in score denominator. Failed adapter invocation preserves previous captures and becomes a missing effect/indeterminate outcome. Do not require every failure to have a normal observation, do not hardcode target_observation_v2, and do not drop failure effect references. Actual D7 scripts/results.py currently hardcodes v2 normal capture; D7 owns adapting that source. CaptureStore outer envelope remains schema1 (content-addressed identity), distinct from payload version2 and D5 observation versions2/3.

Required inputs are actual prepared visible-only artifact, externally pinned target/catalog/observer expectation, concrete signed intent/public verifier, and genuine immutable observation set. Hashes alone are not execution/custody proof. No DSN/key/permission, capture-set, target run, billing call or independent runtime result was created here.
