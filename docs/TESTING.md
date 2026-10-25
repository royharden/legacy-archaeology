# Public local verification

Use the pinned project Python environment. From any directory:

```powershell
& '<checkout>/.venv/runtime/Scripts/python.exe' '<checkout>/scripts/test_local.py' --out '<evidence-directory>'
```

Select a focused suite with repeated `--suite providers` or `--suite journey` options.
Each suite runs in a fresh interpreter with this checkout's source and test helpers.
Subprocesses inherit the caller's working directory; discovery and import roots use
absolute checkout paths. Both the receipt and each suite result record that actual
working directory as `cwd`. Under the current run orders, invoke from the OUTER shell.
The runner continues after a failure, preserves complete logs and their SHA256 hashes,
records commands and return codes in a unique `results.json`, and exits nonzero if
any suite fails or times out. A timeout terminates the suite subprocess and remains
an explicit failure. No test count is a substitute for inspecting failed assertions.

This runner uses public fixtures and fake transports. It clears ambient disposable
target authorization. Evaluator suites belong to the evaluator owner; database
end-to-end tests require a separately assigned loopback target and resource receipt.
The runner never claims target validation, hidden-corpus custody, benchmark success,
or independent acceptance of its own tests. RV2 cross-reviews RV1 test changes;
INT records combined-tree acceptance after review.
