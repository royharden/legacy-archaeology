"""Future canary collector unit SOURCE with OS calls mocked; no real probes."""
import unittest
from unittest.mock import patch

import evaluator_support  # Future discovery path only; no fixture construction on import.
from evaluation.canary import _probe, observed_identity


class CanaryCollection(unittest.TestCase):
    def test_denied_missing_and_accessible_are_distinct_without_contents(self):
        """what_bug_this_catches: missing/error/success is mislabeled access denied."""
        with patch('evaluation.canary.os.open', side_effect=PermissionError(13, 'synthetic')):
            denied = _probe('absolute_open', 'CANARY-only')
        with patch('evaluation.canary.os.open', side_effect=FileNotFoundError(2, 'synthetic')):
            missing = _probe('relative_open', 'CANARY-only')
        with patch('evaluation.canary.os.open', return_value=123), patch('evaluation.canary.os.close') as close:
            accessible = _probe('absolute_open', 'CANARY-only')
            close.assert_called_once_with(123)
        self.assertEqual(denied['result'], 'denied')
        self.assertEqual(missing['result'], 'error')
        self.assertEqual(accessible['result'], 'accessible')
        for observation in (denied, missing, accessible):
            self.assertEqual(set(observation), {'operation', 'result', 'errno', 'winerror', 'exception_type'})

    def test_unsupported_platform_never_uses_environment_username(self):
        """what_bug_this_catches: environment USER/USERNAME becomes identity proof."""
        with patch('evaluation.canary.platform.system', return_value='UnsupportedOS'):
            with self.assertRaises(ValueError):
                observed_identity()


if __name__ == '__main__':
    unittest.main()
