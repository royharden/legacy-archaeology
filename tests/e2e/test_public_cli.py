"""Public hand-mapped journey through a fresh CLI process for every command."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

from journey import test_cli as helpers


class PublicCliProcesses(unittest.TestCase):
    def invoke(self, *arguments, success=True):
        command=[sys.executable, '-c', 'from la.app import main; main()',
                 '--root',str(self.fixture.root),*arguments]
        result=subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
        if success:
            self.assertEqual(result.returncode,0,result.stderr)
            return json.loads(result.stdout)
        self.assertNotEqual(result.returncode,0,result.stdout)
        return result

    def setUp(self):
        # Reuse only the declared public bytes/policies, never generated oracle
        # values. Ingest itself runs through the real CLI in a fresh process.
        self.fixture=helpers.CliJourneyTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.call=self.invoke
        self.fixture.setUp()

    def test_restart_retry_approval_rows_and_incomplete_refusal(self):
        """what_bug_this_catches: CLI process restart loses CAS state or loads incomplete data."""
        run=self.fixture.run_id
        self.invoke('transform',run,success=False)
        incomplete=self.invoke('export',run)
        self.assertEqual(incomplete['manifest']['mapping_status'],'incomplete')
        self.assertEqual((Path(incomplete['bundle'])/'rows.jsonl').read_bytes(),b'')
        questions=self.invoke('questions',run)['questions']
        first_args=None
        for question in questions:
            args=('answer',run,question['id'],self.fixture.ids[question['semantic_target']],
                  '--actor','agent_provisional','--reason','public hand-declared process regression',
                  '--revision','0','--request-id','process-'+question['id'])
            answer=self.invoke(*args)
            if first_args is None:
                first_args=args
                self.assertEqual(self.invoke(*args),answer)
        self.assertEqual(len(self.invoke('history',run)['events']),5)
        self.assertEqual(len(self.invoke('replay',run)['answers']),5)
        self.invoke('approve',run,'--actor','agent_provisional','--reason','public process regression')
        transformed=self.invoke('transform',run)
        bundle=Path(transformed['bundle'])
        manifest=(bundle/'manifest.json').read_bytes()
        rows=[json.loads(line)['values'] for line in (bundle/'rows.jsonl').read_text().splitlines()]
        self.assertEqual(rows,[
            dict(account_ref='000001',description='Alpha',balance='12.34',effective_date='2024-02-29',status='A'),
            dict(account_ref='000002',description='Beta',balance='-5.00',effective_date='2024-03-01',status='C')])
        self.assertEqual(transformed['states']['row_parity'],'not_run')
        self.assertEqual(transformed['states']['target_validation'],'not_run')
        question=questions[0]
        self.invoke('answer',run,question['id'],'unknown','--actor','agent_provisional',
                    '--reason','reopen public policy','--revision','1','--request-id','process-reopen')
        status=self.invoke('status',run)
        self.assertEqual(status['states']['mapping_status'],'incomplete')
        self.assertIsNone(status['approval'])
        self.invoke('transform',run,success=False)
        self.assertEqual((bundle/'manifest.json').read_bytes(),manifest)
