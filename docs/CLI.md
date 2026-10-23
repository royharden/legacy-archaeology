# Local commands and later activation

All examples are future commands. None has run during Dirty Mode construction.
After the separately authorized setup phase, use Python3.12 and establish the
declared dependencies. No tested lockfile is supplied. Invoke commands from the
product root; `--root` precedes the subcommand.

```console
la --root .la-runs ingest source.dat --input-root fixtures/dev/account-dev-01 --brief brief.md --samples samples.json
la --root .la-runs hypothesize RUN --mode rules
la --root .la-runs questions RUN
la --root .la-runs declare-filler RUN --spans explicit-spans.json --actor actual-participant --reason "reviewed unused bytes"
la --root .la-runs answer RUN QUESTION OPTION --actor actual-participant --reason "reviewed permitted bytes" --revision 0 --request-id unique-request
la --root .la-runs history RUN
la --root .la-runs replay RUN
la --root .la-runs preview RUN
la --root .la-runs export RUN
la --root .la-runs approve RUN --actor actual-participant --reason "reviewed complete mapping"
la --root .la-runs transform RUN
la --root .la-runs status RUN
la --root .la-runs report RUN
la --root .la-runs rulings-export RUN
la --root .la-runs provider-export RUN
```

`RUN` is the64-character intake identity. Retained source, brief, samples and batch
manifest are rechecked on each operation. Incomplete mapping exports remain
non-loadable; preview may show resolved values and unresolved/quarantine evidence.
Only transform requires and records the current complete-mapping approval.
Re-answering a question changes the mapping lineage and invalidates its prior
approval. Unknown stays unresolved, distinct from an explicitly selected null.
Earlier approvals/bundles/reports remain immutable. An interrupted intake/export
is preserved, refuses automatic reuse and needs explicit recovery/new storage.
Filler declarations are explicit new generations with actor/reason and invalidate
old generation-bound answers/approvals; they do not create journal events or approval.

`python scripts/demo.py --fixture account-dev-01 --mode mock` is a public
hand-mapping walk, not inference-quality evidence. It records real journal events
through the public API with `agent_provisional` provenance, replays them, exports
actual lineage, scores public parity and seeds wrong amount/target/drop/duplicate
failures. A missing/invalid fixture policy refuses; it is never silently repaired.
The current fixture is D6's public-development-v2: explicit common policies,
99999999 date-null sentinel and framing-v2 RecordRefs. Its source SHA256 is
84ff2a0b1da15ab0d0820ea03fea9cdcbfd95979cff261dc6cad5da4e9d960a7;
the earlier incompatible zero-date edition remains historical. Demo receipts bind
the actual layout/oracle edition and source hash. No Roy participation or
successful parity is implied by this source.

Evaluator scripts remain outside the inference wheel. Public/retired files must
be inside the explicit evaluator `--evidence-root`. Captures and receipts are
immutable and retain failed/no-output arms and all denominators.

```console
python scripts/eval.py --evidence-root EVALROOT contract
python scripts/eval.py --evidence-root EVALROOT --out captures parity --evidence public-projection.json
python scripts/eval.py --evidence-root EVALROOT --out captures replay --evidence retired-replay.json
python scripts/eval.py --evidence-root EVALROOT --out captures suite --split development --mode mock --cases public-cases.json --config run-config.json --ports scripts.product_ports:factory
python scripts/eval.py --evidence-root EVALROOT --out captures target --evidence target-projection.json
```

Parity projection: `oracle_records`, `outcomes`, `mapping`, optional development
edition/split. Replay projection: `manifest_ref`, `oracle_records`, optional
`retirement_ref`; hidden captures require verified edition-bound retirement.
Target projection: oracle records, mapping/source/bundle hashes, edition, and
either D5 `execution_receipt` plus mapping or D6's concrete `observation` envelope.
D5 receipt scoring remains indeterminate after exact parity while concrete
negative-effect evidence is pending. A producer pass flag cannot establish it.

Suite cases contain variants with variant_id/edition/visible/batches/accepted_choices
and optional expected_layout. Each batch has batch_id/visible/oracle. Full split
cardinality is6/4/8 variants, each ten100-record batches. `run-config.json` carries
pins and optional authority/freeze/custody plus a non-secret `port_context`.
Default product factory context allows only provider_config, ledger_path, run and
use_ranker; do not put gold, accepted choices, expected layout or evaluator storage
handles in it. The factory creates B0 bounded deterministic first-cover heuristics,
finite C0/R0 unresolved proposals and R1 offered-ID proposals; B1 is separately
model-originated. Complete proposals use D5's non-loadable deterministic seam.
The same layout proposal is explicitly rebound to each batch's source identity;
this never reuses a product approval. No oracle reaches a callback.

The default mock B1 returns no full mapping and fails honestly; it does not look
up public gold or simulate provider quality. To trial a verified live provider,
provide actual approved config and spend bounds. Live/heldout commands require
`--evaluator-authorized` and the runner's exact authority/T2/custody pins before
case access. These metadata gates do not establish OS custody; real separate-account
read/list/handle/broker denial and independent review remain mandatory. Active
hidden assets are never generated by the CLI. A trusted factory is code execution
capability and must be pinned/audited with the release.

The evaluator writes `evaluation/<hash>.json` receipt envelopes. For a current
source/mapping, `la report RUN --evaluation-receipt relative/path.json` displays a
hash-checked explicit evaluator receipt. Reported parity/target states identify
their supplied provenance. Product acceptance remains pending. This is evidence
display, not an independent-review appointment or an inference-wheel evaluator.

Target source commands, after separate authorization and agent-ports claim/check:

```console
la --root .la-runs database-check RUN/bundles/BUNDLE --authorized --authority target-authority.json --target-config target-config.json
la --root .la-runs database-rollback RUN/bundles/BUNDLE --authorized --authority target-authority.json --target-config target-config.json
la --root .la-runs database-constraints RUN/bundles/BUNDLE --authorized --authority target-authority.json --target-config target-config.json
la --root .la-runs database-reconcile RUN/bundles/BUNDLE --namespace OWNED_NAMESPACE --execution-receipt RUN/execution/RECEIPT.json --authorized --authority target-authority.json --target-config target-config.json
```

Authority packet requires authorized=true, authority_id, exact bundle_sha256,
local_disposable_target=true and least_privilege_role=true. TargetConfig contains
authority_reference matching authority_id, database, role, driver_version,
server_major, explicit host/port, scope and statement_timeout_ms as defined by
`la.postgres.TargetConfig`. URI DSN comes only from the named `LA_TEST_DATABASE_DSN`
environment variable after authority checks; use `--dsn-env NAME` to select a name,
never a DSN argument. The wrapper restricts host to127.0.0.1, explicit claimed
20000–29999 port, excludes20178/20179 and refuses URI option indirection. D5 also
checks actual target identity, least-privilege role and driver/server pins.
Missing authority/config/DSN records not_run without a connection.
The `scripts/database_check.py --bundle ...` wrapper routes through this same CLI.

Actual execute/readback, rollback, constraints and read-only lost-ACK reconciliation
return separate immutable execution receipts outside the bundle. Unknown commit
stays indeterminate and never grants an automatic retry. Do not infer completed
target or product validation from schema generation, a parser, mock, commit ACK,
producer projections or command exit status.
