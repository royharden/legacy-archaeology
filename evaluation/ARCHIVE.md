# Portable evaluator archives — API guide

Source: `evaluation/archive.py` (evaluator-only; the `src/la` wheel never imports it).
Status: constructed under Dirty Mode. **No archive, signature, replay or projection has been run.** Everything below describes source behavior that later validation must exercise.

## What an archive is

A signed, read-only package of an evaluation edition's public or retired history: the requested variant manifests, every capture they transitively reach (including failed and partial attempts), the exact source/oracle cases, a credential-free configuration, inert copies of the evaluator code and the edition's registry history. It is NOT a fresh holdout, an executed benchmark or product acceptance. Active hidden data is never exported raw; it can only leave as an owner-approved aggregate projection.

## Functions

```python
plan_archive(store, *, cases, manifest_refs, configuration, registry, visibility) -> ArchivePlan
export_archive(plan, destination, *, signed_release, verifier) -> dict
read_archive(path, *, expected_archive_sha256, verifier) -> ArchiveSnapshot
replay_portable_archive(path, *, expected_archive_sha256, verifier, result_store, scorer_version='semantic-v1') -> dict
approved_projection(store, reference, *, signed_approval, verifier, registry, expected_edition, expected_registry_head) -> dict
```

Every refusal raises `ValueError`. Nothing returns partial success. `export_archive` may also raise `FileExistsError` because it never overwrites.

### plan_archive

- `store`/`registry`: the existing evaluator `CaptureStore` and the `EditionRegistry` on the same root. Neither path may be a symlink or a Windows symlink/junction. OneDrive cloud placeholders are not name surrogates, so they are allowed.
- `manifest_refs`: the requested roots. 1..64 unique `variant_manifest` references. Several prior attempts of one variant are allowed.
- `cases`: one `VariantCase` for each DISTINCT variant that the transitive closure reaches. 1..18, all from one edition. The plan refuses when any reached `variant_manifest`, `arm_receipt` or `suite_declaration` names a variant without a supplied case, or when a supplied case is never reached. Split, `input_sha256` and the oracle commitment must match exactly.
- `configuration`: a closed dict `{schema_version: 1, edition, pins, values}`. Roots must carry exactly these `pins`. Secret-like keys are refused at any depth (`api_key`, `password`, `dsn`, `*_access_token`, …). `values.auxiliary_captures` may optionally list up to 32 `target_cleanup_observation` refs (see below).
- `visibility`: `'public'` or `'retired'`. `'retired'` requires an actual `retired` registry disposition with no running attempt. A retired edition can never be archived as public.
- Graph entry points are exactly: roots, the edition's history events and `values.auxiliary_captures`. A typed capture reference anywhere else in the configuration, or inside a case, refuses.
- Hidden-data closure: a reached capture containing `split == 'heldout'`, `evaluation_phase == 'T3'` or `visibility == 'sealed'` is hidden. One hidden capture anywhere in the closure refuses the whole archive unless the archive is retired and the registry agrees, so unmarked provider requests or raw outputs reached through a heldout receipt never ship. Any reached payload whose top-level `edition` differs from the archive edition refuses.
- Crafted shapes (missing keys, wrong types) refuse as `ValueError`, never `KeyError` or `TypeError`.
- Bounds are checked from reference metadata and file stats before bytes are read: 512 members, 32 MiB per member, 256 MiB total.
- Head and history come from one `EditionRegistry.snapshot()` read.
- Returns `ArchivePlan`. It writes nothing: no archive, no journal, no signature.

### ArchivePlan

- `.manifest` is a closed dict with these keys: `schema_version`, `kind='evaluation_archive'`, `edition`, `visibility`, `registry_head_sha256`, `history`, `roots`, `inputs`, `configuration`, `auxiliary`, `provenance{corpus_sha256, freeze_sha256, modes}`, `scorer{schema_version, version, code_sha256}`, `members[{path, kind, sha256, bytes}]` and `archive_sha256`. `archive_sha256` is the digest of the manifest without that key. It is the external pin that every reader must supply.
- `.release_payload` is an unsigned template: `{schema_version: 1, action: 'release_evaluation_archive', edition, visibility, archive_sha256, registry_head_sha256, allowed_kinds, not_after_utc: None, nonce: None, authority_sha256: None}`. To complete it, the owner:
  1. sets `nonce` (sha256 hex) and a zoned ISO `not_after_utc`;
  2. sets `authority_sha256 = digest(body without authority_sha256)`;
  3. signs the body as role `run_owner` (Ed25519 `ReceiptVerifier` envelope).

  `allowed_kinds` must equal the archive's member kinds exactly.

### export_archive

This function validates the plan again, verifies the release (it must not be expired) and exclusively creates `destination` (`xb`) under an existing, non-link parent. The packet is a canonical stored ZIP:

- order: `manifest.json`, `release.json`, then members sorted by path;
- timestamps 1980-01-01, mode 0600 regular, `create_system` 3;
- no compression, extras, comments, ZIP64 or data descriptors.

It returns this closed dict:

`{schema_version, archive_sha256, edition, visibility, registry_head_sha256, release_sha256, packet_sha256, member_count, packet_bytes, stochastic_model_rerun: False, fresh_holdout: False}`

If a write is interrupted, an incomplete file remains. `read_archive` refuses that file, and the module never deletes it.

### read_archive / ArchiveSnapshot

`read_archive` requires the external `archive_sha256` pin and a trusted `run_owner` release. The release is not checked against the current time here, because it authorized the export when the export happened. Before any member bytes are allocated, it checks:

- one disk, no comment, central directory ending exactly at the end-of-central-directory record;
- local headers contiguous from offset 0 and identical to the central entries (CRC, sizes, name, no flags or extras);
- canonical member order;
- every declared size within bounds.

It then reads the members (zipfile checks CRCs) and rebuilds the full closure from the bytes alone:

- every capture is reached, with no extra or unlisted members;
- closed input, configuration and batch schemas;
- `variant_identity` recomputed;
- the transitive hidden-data, edition and case checks;
- the root pins and all five original arms, with arm receipts unchanged;
- provenance recomputed.

Extraction never happens and no code is imported. A `ZipFile` or `struct` error maps to `ValueError`.

`ArchiveSnapshot` exposes `.manifest`, `.release` (the parsed signed envelope) and `.get(reference, *, kind=None)`, a validated capture payload that duck-types `CaptureStore.get` for `runner.rescore_captured_manifest`.

### replay_portable_archive

This function only rescores captured outputs with a scorer implemented in THIS checkout (`SUPPORTED_SCORERS = {'semantic-v1'}`). Archived code is inert, and the original stochastic model, database, target and cleanup operations are never rerun. It returns this closed dict:

`{schema_version, mode: 'replay', label, edition, visibility, archive_sha256, release_sha256, provenance, original_scorer, scorer_version, scorer_code_sha256, scorer_code_matches_original, compatibility, configuration, auxiliary_count, results, stochastic_model_rerun: False, fresh_holdout: False, target_validation: 'not_run', product_acceptance: 'pending', replay_capture}`

- `compatibility` is `'supported'`: `label` is `'rescored-with-version'`. `results` holds one entry per root: `{variant_id, manifest, original_mode, original_arms, results}`.
  - `original_arms` holds, for each arm: `method`, `status`, `error_type`, `mode`, `evaluation_phase`, `request_attempts`, `failed_attempts`, `usage`, `known_total_cost`, `unknown_liabilities`, `target_validation` and `receipt`.
  - `results` is the output of `rescore_captured_manifest`.
- `compatibility` is `'unsupported_scorer'`: `label` is `'not_rescored_unsupported_scorer'` and `results` is `None`.

The receipt is stored in `result_store` as kind `portable_replay_receipt`.

### approved_projection

This is the only route by which active hidden results leave. Head and folded state come from ONE `EditionRegistry.snapshot()` read, and the head must equal `expected_registry_head`.

The signed body (`release_evaluation_projection`, role `run_owner`, not expired) has these keys: `schema_version, action, edition, registry_head_sha256, projection_sha256, capture_sha256, not_after_utc, nonce, authority_sha256`.

The projection capture (kind `approved_aggregate_projection`) is closed: `schema_version, edition, split, mode, scope='aggregate_diff_only', corpus_sha256, freeze_sha256, attempt_id, metrics[≤40 {method, metric, numerator, denominator, value, baseline_value}], counts{variants, arms, failed, partial, unknown_cost}, projection_sha256`. It must match the TERMINAL frozen attempt; `split` must be `'heldout'` (suites are exactly the commitment's heldout variants and carry no split field), `attempt_id`/`mode` must equal the suite's.

It returns this closed dict:

`{schema_version, kind: 'approved_evaluation_projection', edition, projection, approval_sha256, registry_head_sha256, raw_exported: False}`

## Cleanup auxiliary (reconciled to D5 CLEANUP-API FINAL)

The operator stores a D5 cleanup receipt (the `cleanup-<cleanup_sha256>.json` object) verbatim as the payload of a `target_cleanup_observation` capture: `CaptureStore.put('target_cleanup_observation', receipt)`. It is then named in `configuration.values.auxiliary_captures`. The receipt's file bytes are `canonical(payload) + "\n"`, so the original file can be reproduced from the archive, keyed by its own `cleanup_sha256`.

The evaluator never imports `la.postgres`, so the archive mirrors only closed identity and neutrality:

- the exact FINAL top-level key set;
- `schema_version` 1 and `kind == 'target_cleanup'`;
- `cleanup_id` is 32 hex characters;
- `action` is `cleanup` or `reconcile_cleanup`, with a state allowed for that action;
- `issues` is a list of at most 10;
- `target_validation` and `row_parity` are `not_run`, and `product_acceptance` is `pending`;
- the self-pin `cleanup_sha256 = digest(receipt without cleanup_sha256)` holds.

Full semantic validation, including catalog snapshots, binding and lineage, is D5's `validate_target_cleanup` on the product side. These receipts are archived, listed in `manifest.auxiliary` and counted in replay as `auxiliary_count`. They are never scored or reinterpreted as rollback or negative-probe evidence, and replay never reruns cleanup.

## Known limits (deferred validation)

- Every path above is unexecuted. Ed25519, ZIP round-trips, registry folds and scorer compatibility have not been exercised.
- The hidden-data scan is content-based (`split`, `evaluation_phase` and `visibility` keys at any depth) and refuses the whole archive on any marked capture. An unmarked hidden capture reachable only from unmarked parents, for example a history edge straight to an unmarked raw output, would not be caught. Producers must keep these markers on receipts, manifests and declarations.
- Registry history in the manifest is metadata: event payloads, hashes and IDs. Commitment hashes of heldout variants are treated as non-secret, matching T1 catalog practice.
- Custody of the archive file and of the evaluator store is an OS/operator concern. These checks establish identity, not custody.
- Future regression source: `tests/evaluation/test_archive.py`. It has not been run.
