"""Consumer tests for separately pinned loopback connection and server identity."""
from dataclasses import replace
import unittest

from target_effects_support import expectation, observations, seal
from evaluation.target_effects import validate_target_observation


class ForwardedTarget(unittest.TestCase):
    def test_actual_private_server_and_loopback_connection_are_preserved(self):
        """what_bug_this_catches: Docker NAT is rejected or relabeled as loopback."""
        original = expectation()
        target = dict(original.target, host='172.17.0.8', connection_host='127.0.0.1',
                      connection_port=21800)
        expected = replace(original, target=target)
        observed = observations(expected)[0]
        validated = validate_target_observation(observed, expectation=expected)
        self.assertEqual(validated['target']['host'], '172.17.0.8')
        self.assertEqual(validated['target']['connection_host'], '127.0.0.1')

    def test_forwarding_never_authorizes_remote_connection_or_unpinned_server(self):
        """what_bug_this_catches: forwarded identity bypasses local target scope."""
        original = expectation()
        target = dict(original.target, host='172.17.0.8', connection_host='127.0.0.1',
                      connection_port=21800)
        for change in ({'connection_host': '192.168.1.1'}, {'connection_port': 20178},
                       {'host': '8.8.8.8'}, {'host': '0.0.0.0'}, {'host': '::1%zone'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                replace(original, target={**target, **change}).validate()
        expected = replace(original, target=target)
        observed = observations(expected)[0]
        observed['target']['host'] = '172.17.0.9'
        seal(observed, 'observation_sha256')
        with self.assertRaisesRegex(ValueError, 'actual target'):
            validate_target_observation(observed, expectation=expected)


if __name__ == '__main__':
    unittest.main()
