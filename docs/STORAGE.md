# Run storage and restart behavior

Source construction only. No crash, filesystem, concurrent process or runtime
scenario below has executed. Windows uses file fsync plus atomic local publication;
portable Python does not provide directory fsync there, so power-loss durability
is not established. Unsupported filesystem hardlink/rename/lock operations fail
closed instead of overwriting frozen bytes. Later activation must verify the actual
local filesystem and SQLite behavior.

Normal run identity binds original source, brief, permitted-sample artifact and
producer config. Complete observed-stream refusals additionally bind the producer
stream-observation identity, avoiding reuse across distinct file observations.
Files are retained under a declared canonical root; paths/junctions/symlinks that
resolve outside it refuse. JSON reads reject duplicate keys, nonfinite numbers,
depth above32 and noncanonical committed artifacts where required. Public input
JSON may be pretty-printed; retained output is canonical.

Representations have separate caps:5MiB retained source bytes,16KiB brief bytes
(the producer also enforces4000 characters),16MiB generic JSON,32MiB ordinary
members/output and4KiB cache pointers. D5's compiler/verifier has named member caps
and128MiB total bundle cap. These are encoded-artifact budgets, not a5MiB cap on
JSON/hex/RecordRef expansion. Supported framing is additionally bounded to10000
records of at most256 data bytes. Oversize/malformed artifacts refuse explicitly.

Input reading uses64KiB chunks. A single pass hashes/counts the complete stream,
keeps at most5MiB buffered, and checks file identity/size/timestamps before/after
and against the path after closing. Oversize bytes are not persisted. D4's refusal
producer receives exact completed-stream SHA/counts and hashed identity/policy
observations; unstable completed reads remain labeled unstable, never stable
original files. Missing/incomplete prefix observations cannot create a SourceBatch.
Streamed refusal saves source-observation.json and no source.dat, materializes no
records and never claims sample references validated without source bytes.

Immutable files are fsynced into exclusive same-directory stages, then published
with an exclusive hard link. An exact retry compares existing bytes; conflicting
frozen content fails. Intake's run.json is the final commit marker. An interrupted
intake can finish only on an exact input retry whose existing members all match.
Reports bind input and renderer-code hashes; bundles use their final content hash,
which includes current producer code, actual brief/samples and authentic lineage.
Old-code bundles retain their paths; recompilation produces a new immutable
destination. Exact bundle retries compare every member against freshly compiled
source and never trust a self-rehashed untrusted manifest as target authority.

Bundles publish by same-parent staging-directory rename under a process lock.
Only a stage created in the current call with exactly its known compiler members
is removed on an identical retry. Crashed/foreign stages are retained, ignored as
commits and exposed through bounded `la storage-inspect RUN` diagnostics. There is
no broad cleanup or automatic deletion of historical artifacts. Approval and report
exact retries complete cache publication without rewriting immutable content.

Each CLI run uses a nonwaiting Windows/POSIX OS file lock; process death releases
the lock, and a leftover lock filename is not a lease. Busy operations refuse for
explicit retry, with no heartbeat/sleep loop. Cache replacement uses fsynced atomic
replace and content-bound compare-and-swap. A bounded corrupt mutable pointer can
be replaced only with its exact raw-byte token; oversized/escaped cache files fail
closed. Frozen corrupt archives are never overwritten.

SQLite RulingStore.current_state is generation authority: actual stored generation,
binding, monotonic epoch, state revision, journal head and state token. Commands
CAS bind_generation against that snapshot. current-generation.json and generation
archive files are recoverable caches of the committed authority. Missing caches
rebuild from it; legacy binding-only state requires exactly one retained matching
generation, never recency. A→B→A retains a different epoch. JSONL is never imported
as a second ruling authority. Approvals remain pinned to current mapping/event
lineage; prior approvals cannot authorize a changed mapping.

Transformation/execution/evaluation/verification receipts stay separate from
immutable bundles. Current transformation state checks its pinned bundle against
the actual offline verifier/current code. Product acceptance remains pending;
target/parity/benchmark states are never inferred from a parser, aggregate count,
source declaration or producer passed flag.

Inspection commands use D4's actual bounded page/detail API. Local-owner and
permitted-span-only access modes are explicit. Permitted-only reports omit full
source/rulings/free text/typed previews and reject attached unrestricted evaluator
receipts; byte cells, separators and overlays follow the producer masks. Every
HTML string is escaped, including diagnostic ASCII and overlays. Diagnostic byte
inspection is separate from typed preview and approved load data.
