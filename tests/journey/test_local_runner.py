"""Behavioral regression for the public runner's caller-directory contract."""
from __future__ import annotations

from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


class LocalRunnerCwdTests(unittest.TestCase):
    def test_suite_process_preserves_caller_cwd_and_receipt_agrees(self):
        # Retain the synthetic suite and its evidence, including on a failed assertion.
        fixture_root = Path(tempfile.mkdtemp(prefix='la-runner-cwd-'))
        suite = fixture_root / 'tests' / 'contracts'
        suite.mkdir(parents=True)
        (suite / 'test_cwd.py').write_text(
            'import os\n'
            'import unittest\n'
            'class CwdProbe(unittest.TestCase):\n'
            '    def test_report_actual_cwd(self):\n'
            '        print("RUNNER_FIXTURE_CWD=" + os.getcwd(), flush=True)\n',
            encoding='utf-8',
        )
        runner_path = Path(__file__).resolve().parents[2] / 'scripts' / 'test_local.py'
        spec = importlib.util.spec_from_file_location('local_runner_cwd_probe', runner_path)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        caller_cwd = Path.cwd()
        evidence = fixture_root / 'evidence'
        with patch.object(runner, 'ROOT', fixture_root), redirect_stdout(io.StringIO()):
            code = runner.main(['--suite', 'contracts', '--timeout', '30',
                                '--out', str(evidence)])
        receipts = list(evidence.glob('*/results.json'))
        self.assertEqual(code, 0)
        self.assertEqual(len(receipts), 1)
        receipt = json.loads(receipts[0].read_text(encoding='utf-8'))
        result = receipt['suites'][0]
        log = (receipts[0].parent / result['log']).read_text(encoding='utf-8')
        actual_cwd = next(line.split('=', 1)[1] for line in log.splitlines()
                          if line.startswith('RUNNER_FIXTURE_CWD='))
        self.assertEqual(Path(actual_cwd), caller_cwd)
        self.assertEqual(Path(receipt['cwd']), Path(actual_cwd))
        self.assertEqual(Path(result['cwd']), Path(actual_cwd))
        self.assertEqual(Path.cwd(), caller_cwd)


if __name__ == '__main__':
    unittest.main()
