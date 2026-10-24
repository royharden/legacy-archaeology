# Disposable namespace cleanup (operator command)

Constructed source, runtime unverified. Nothing here has run against any database, and building it authorizes no cleanup.

`scripts/cleanup.py` removes ONE namespace that an earlier target experiment created, after proving it still holds exactly what that run created. It is a separate operator command. Evaluation never calls it, and it has no default or latest target, no arbitrary SQL and no automatic retry. The library contract is `la.postgres.cleanup_target_namespace` / `reconcile_target_cleanup`; the operator guide with every ownership check is in `src/la/postgres/OBSERVATIONS.md`.

## Inputs

All paths are relative to `--operator-root`. A grant (`config/cleanup-grant.example.json`, shipped `"active": false`) pins:

| Field | Meaning |
|---|---|
| `artifact`, `original_signed_authority`, `target_config` | the exact inputs of the original experiment |
| `experiment`, `expected_experiment_sha256` | the pinned immutable experiment directory |
| `expected_original_observation_sha256` | the creation observation (committed or indeterminate) whose namespace is removed |
| `cleanup_signed_authority`, `expected_cleanup_authority_sha256` | a separately signed `disposable_target_cleanup_authority`; the load/probe authority never grants cleanup |
| `namespace` | the exact `la_<32 hex>` namespace; must equal the creation observation's |
| `receipt_root` | an existing directory that receives immutable `cleanup-<sha256>.json` receipts |

The DSN is read only from the environment variable named by `--dsn-env` (default `LA_DISPOSABLE_TARGET_DSN`), after every offline check, and only for `run`/`reconcile`. The value is never printed or stored. Public verification keys come from `--public-trust-root/--public-trust-profile`.

## Commands

```text
python scripts/cleanup.py --operator-root ROOT plan --grant G --public-trust-root T --public-trust-profile P \
    --authority-id ID --operations cleanup reconcile_cleanup
python scripts/cleanup.py --operator-root ROOT run --grant G --public-trust-root T --public-trust-profile P \
    --expected-namespace la_<hex> [--dsn-env NAME]
python scripts/cleanup.py --operator-root ROOT reconcile --grant G --public-trust-root T --public-trust-profile P \
    --expected-namespace la_<hex> --receipt R --expected-cleanup-sha256 S [--dsn-env NAME]
python scripts/cleanup.py --operator-root ROOT inspect --receipt R --expected-cleanup-sha256 S
```

- `plan` works offline. It verifies the original experiment and authority and prints the exact unsigned cleanup authority body, including its `authority_sha256`, for an offline signer. It never signs, connects or writes.
- `run` needs an active grant. The retyped `--expected-namespace` must equal the grant's. Before any environment access, the cleanup authority must pass the library's full check: signature, closed keys, scope, digest and every binding pin, including the current cleanup code pin. `run` refuses if the receipt root already holds an open `prepared` intent, or a `committed` or `indeterminate` cleanup, for that namespace. An intent whose own final receipt is `refused`/`rolled_back` is settled and does not block. It opens two connections (writer and observer) and closes them afterwards.
- The no-retry guard is scoped to the grant's `receipt_root`. Keep one receipt root per namespace (the example uses `cleanup-receipts/<namespace>`); never point a grant at a fresh root to get around an uncertain attempt. Even then, the library re-proves exact ownership before any drop, so a removed namespace is refused rather than touched.
- `reconcile` needs an active grant and `reconcile_cleanup`. It is read-only (server-enforced READ ONLY), links to one exact prior receipt from the grant's receipt root, and never repeats removal.
- `inspect` works offline. It validates one receipt by its exact hash, plus the prepared intent linked beside it.

Output is a neutral summary with: state, namespace, issues, statements executed, commit attempted/returned, whether the namespace was present after, and a next-step hint. Raw catalog and readback facts stay in the local receipt. `target_validation`/`row_parity` always stay `not_run` and `product_acceptance` stays `pending`.

## Reading the state

| State | Meaning | Next |
|---|---|---|
| `refused` | nothing destructive ran (ownership, target or authority checks failed) | read `issues`; fix inputs or leave the namespace |
| `prepared` | only the pre-destructive intent exists (crash mid-run) | `reconcile`; never rerun |
| `rolled_back` | drops ran and were rolled back; nothing removed | inspect; a new attempt is allowed |
| `committed` | commit returned and the observer saw the namespace absent | done |
| `indeterminate` | outcome unknown (lost acknowledgement, unobservable after-state) | `reconcile`; never rerun |
| `observed_absent` / `observed_present` | reconciliation facts | absent = removed. Present after an uncertain attempt = the receipt root stays blocked; deciding whether to remove it is a manual operator decision with a new, separately signed grant reviewed by a person. Never work around it with a fresh receipt root |

Errors exit with `la_cleanup: <ErrorType>` and print no secret material. Pre-authority failures write no receipt.
