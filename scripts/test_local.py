"""Run public keyless test suites in separate processes; retain every result."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SUITES = ('contracts', 'ingest', 'inference', 'review', 'convert', 'sql',
          'providers', 'postgres', 'journey', 'e2e')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', action='append', choices=SUITES)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=300)
    args = parser.parse_args(argv)
    if args.timeout < 1:
        parser.error('--timeout must be positive')
    caller_cwd = str(Path.cwd())
    # Each invocation retains a distinct receipt, including failures and timeouts.
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    output = args.out.resolve() / stamp
    output.mkdir(parents=True, exist_ok=False)
    environment = os.environ.copy()
    environment['PYTHONPATH'] = os.pathsep.join(map(str, (
        ROOT/'src', ROOT, ROOT/'tests', ROOT/'tests/evaluation')))
    # Ambient target authority must never activate optional disposable DB tests.
    environment.pop('LA_TEST_DISPOSABLE_AUTHORIZED', None)
    results = []
    for suite in args.suite or SUITES:
        folder = ROOT/'tests'/suite
        if not folder.is_dir():
            continue
        command = [sys.executable, '-m', 'unittest', 'discover', '-s', str(folder),
                   '-p', 'test_public_*.py' if suite == 'e2e' else 'test_*.py']
        start = time.monotonic()
        status = 'completed'
        with (output/(suite+'.log')).open('wb') as log:
            try:
                code = subprocess.run(command, env=environment, stdout=log,
                                      stderr=subprocess.STDOUT, timeout=args.timeout,
                                      check=False).returncode
            except subprocess.TimeoutExpired:
                code, status = None, 'timeout'
        result = dict(suite=suite, command=command, cwd=caller_cwd,
                      returncode=code, status=status,
                      elapsed_seconds=round(time.monotonic()-start, 3),
                      log=suite+'.log',
                      log_sha256=hashlib.sha256((output/(suite+'.log')).read_bytes()).hexdigest())
        results.append(result)
        print(json.dumps(result), flush=True)
    passed = bool(results) and all(r['returncode'] == 0 for r in results)
    receipt = dict(schema_version=1, scope='public-keyless-local', python=sys.version,
                   executable=sys.executable, cwd=caller_cwd, suites=results, passed=passed,
                   target_validation='not_run', hidden_benchmark='not_run')
    (output/'results.json').write_text(json.dumps(receipt, indent=2)+'\n', encoding='utf-8')
    print('Receipt: '+str(output/'results.json'), flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
