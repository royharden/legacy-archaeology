# Target capture and authorized replay source

These commands are future operator steps. No demo/test/provider/database/crypto/
custody/parity/benchmark or cleanup operation ran during source construction.

Start with an actual product bundle carrying its approval and externally pinned
bundle hash, or an explicitly non-loadable evaluation candidate prepared for the
actual method/edition/phase/plan. Supply independent target config, an exact signed
target-authority envelope, and an explicitly chosen public-key profile. No adapter
creates a key, signs authority or infers the latest candidate. Capture roots must
already exist, be operator-owned, stay outside frozen bundles and satisfy D5's
all-parent symlink/junction checks. The capture CLI emits neutral identities and
states; raw readback/effect rows stay in the declared private capture tree.

Future collection, using an existing owned root and a fresh child ID:

```console
python scripts/target_experiment.py --operator-root ROOT collect --artifact operator/candidate.json --signed-authority operator/signed.json --target-config operator/target.json --public-trust-root PUBLIC_ROOT --public-trust-profile profile.json --capture-root target-captures --experiment-id OWNED_UNIQUE_ID --dsn-env LA_DISPOSABLE_TARGET_DSN
```

All five operations must be separately signed: load, negative_probes,
controlled_failed_load, controlled_commit_ack, reconcile. Flags or the narrow load
grant cannot authorize more. Signature/candidate/config/operations are checked
before DSN lookup. An existing child ID never triggers another load. A missing
DSN yields actual not_run capture entries; observed stage failures remain partial
with every available immutable receipt and omission. D5 persists normal readback,
six negative effects, failed-load absence, explicit application-ACK predecessor
and reconciliation separately. The combined normal observation identifies its
actual raw parents. It does not turn a committed result into lost acknowledgement.

`open` requires --experiment RELATIVE_PATH, --expected-experiment-sha256,
--expected-candidate-sha256 and --expected-authority-sha256. It validates pinned
manifest/member bytes and returns only a neutral summary; it reads no DSN or
provider environment. It does not grade parity/effects or grant product acceptance.

`reconcile` adds the same original artifact/signature/config/public-trust inputs
to those exact experiment pins. Only read-only reconciliation of the original ACK
predecessor is attempted; no INSERT/load retry occurs. Optional
--previous-reconciliation-sha256 explicitly links an existing earlier record.
Missing predecessor/DSN/effects remain not_run/indeterminate. New immutable records
preserve the original manifest, namespaces, attempts and captured identities.

`select-recovery` requires the original experiment/candidate/authority pins, exact
--expected-reconciliation-sha256 and --expected-prior-observation-sha256. Use the
literal `absent` for the latter only when the original prior is actually absent.
It verifies archived signed scope and selected record/member/chain hashes without
requiring an old observer to become today's execution authority. It reads no DSN
and chooses no recency fallback. Its projection labels normal/failed effects as
original and recovery as the explicitly selected later record, retaining every
intermediate indeterminate/not_run state. A selected record without an observation
remains missing; it never falls back to an earlier successful recovery.

For independent grading, `scripts.target_ports:factory` can serve pinned captures
instead of making a connection. An entry in its exact candidate-grant index adds
`experiment: {path, expected_experiment_sha256}`. Optional explicit later selection
adds both expected_reconciliation_sha256 and expected_prior_observation_sha256
(JSON null only for an absent original prior). See the deliberately inactive
`config/experiment-grants.example.json`. Do not mix this reference with new
collector selections or separate stored effects. The actual D5 callbacks recheck
the full original artifact and signed envelope. D6 TargetGrant/TargetExpectation
and grade_target independently decide effects; the facade never emits passed.
Archived code pins identify captured lineage; they do not authorize new writes
under old source. The inference wheel remains evaluator-free.

The final local suite/report path uses `scripts/eval.py` and `scripts/results.py`
as described in RESULTS.md. All five arms, failed variants, full denominators,
known/unknown costs and separate acceptance states remain visible. Active hidden
raw archive/export is forbidden; only an exact signed approved safe projection
may leave the private evaluator store. Public/retired raw replay must use D6's
actual release-authorized bounded archive interface when published, never copy
arbitrary trees, select recency, execute archived code or relabel an old run unseen.

Existing-store replay is available through `python scripts/replay.py --operator-root ROOT --capture-root EVALUATOR_CAPTURES --manifest-sha256 EXACT_VARIANT_MANIFEST_SHA --oracle RELATIVE_ORACLE_JSON`. Public development/validation captures use their actual known oracle. Heldout additionally requires --registry and --retirement-sha256 naming the actual signed-disposition-backed retirement capture; the adapter verifies retirement/freeze/terminal attempt before opening the oracle file. It bounds original arm capture members/bytes and calls the actual D6 replay_archive, returning only replay capture identity and explicit not_run target/transformation/benchmark states. It executes no archived code/model or target operation. It does not copy or release a portable archive; that separate D6 release interface is pending.

D6 target-arm schema2 publication is consumed without rewriting it. Normal references retain target_observation_v2/v3 kinds; observation can be null. Both receipt and failure retain earlier effect_captures, phase_scope, stages and stage_errors. The result publisher verifies all retained member pins, including effects captured before a later adapter failure, and never demands a fabricated normal observation. Stage exception classes stay private capture metadata; raw exception messages are not projected.

Portable archive caller source is scripts/archive.py. Its plan/export packet shape is config/archive-plan.example.json: exact edition, public/retired visibility, actual variant-manifest references, relative actual-case file and credential-free configuration file. It checks hidden/public or actual-retired disposition before case/oracle file access. `plan` returns only an unsigned release payload template; export reconstructs the exact plan and requires the independent signed release and concrete run_owner public verifier. The user supplies an exact external archive manifest SHA for read/replay, and replay writes only to an explicitly selected existing result CaptureStore. Active hidden uses the separate `projection` action with the exact signed approval, edition and registry head; it retains only the owner's approved closed view in an immutable local receipt. No key, release or retirement is minted. Final ArchivePlan/ArchiveSnapshot return-shape reconciliation remains pending the D6 implementation; these source adapters are not a claim of verified API execution.
