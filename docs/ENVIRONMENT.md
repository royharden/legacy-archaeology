# Reproducible local environment

Use Python 3.12.13 and uv 0.11.19. `uv.lock` records exact resolved versions,
artifact hashes, and optional dependencies. The build backend is pinned too.
Each checkout owns its interpreter under `.venv/toolchain` and environment under
`.venv/runtime`; do not share a writable environment between lanes.

From any working directory, run the script by its absolute path. The initial
Python only runs this stdlib bootstrap; the application uses downloaded 3.12.13.

```powershell
python C:\path\to\checkout\scripts\bootstrap.py --all-extras --build
$repo = 'C:\path\to\checkout'
$python = "$repo\.venv\runtime\Scripts\python.exe"
& $python --version
& "$repo\.venv\runtime\Scripts\la.exe" --help
```

The bootstrap installs only into this checkout, uses a frozen lock, preserves
extraneous installed packages (`--inexact`), and never reads a dotenv file.
Without `--all-extras` it installs only inference runtime dependencies; optional
evaluator/driver packages are for development. Build tools require `--build`.
Bootstrap does not run tests, connect to databases, or call providers.

## Tests without changing cwd

The inherited tests are stdlib unittest modules with leaf-local helper imports.
Top-level discovery may collect only package-marked subdirectories. Run each
leaf separately, and record actual counts. Use a fresh process per leaf to avoid
collisions between helper module names. This does not establish hidden custody.

```powershell
$env:PYTHONPATH = "$repo\src;$repo;$repo\tests;$repo\tests\evaluation"
& $python -m unittest discover -s "$repo\tests\contracts" -p 'test_*.py'
& $python -m unittest discover -s "$repo\tests\journey" -p 'test_*.py'
# Repeat for convert, inference, ingest, providers, review, sql, evaluation.
```

Real PostgreSQL tests are separate and require explicit disposable-target
authority. Leave `LA_TEST_DISPOSABLE_AUTHORIZED` unset for keyless diagnostics;
do not enable destructive cleanup cases under a no-delete instruction. No live
provider or hidden benchmark is part of environment verification.

## Wheel boundary

```powershell
& $python -m build --wheel --no-isolation --outdir "$repo\.venv\dist" $repo
```

Hatch includes only `src/la` in the inference wheel. Repository `evaluation`,
fixtures, tests and scripts stay outside it. Evaluation dependencies are an
optional extra, not bundled evaluator source. Inspect the wheel archive and
install it into a separate environment without checkout paths to verify this
boundary; development editable imports alone cannot prove it.
