import unittest
import subprocess

#  Run: python3 -m unittest ss_unittests.py
class TestSecretsynth(unittest.TestCase):
    def test_dry_run(self):
        # Run the command and capture the output
        result = subprocess.run(['python3', 'secretsynth.py', '--dry-run', '--owners', 'foo,bar', '--org-type', 'orgs'], capture_output=True)

        # Check that the command completed successfully
        self.assertEqual(result.returncode, 0)

    def test_invalid_args(self):
        # Run the command with an invalid argument and capture the output
        result = subprocess.run(['python3', 'secretsynth.py', '--invalid-arg'], capture_output=True)

        # Check that the command failed
        self.assertNotEqual(result.returncode, 0)

    def test_skip_all_scanners(self):
        # Run the command with arguments to skip all scanners and capture the output
        result = subprocess.run(['python3', 'secretsynth.py', '--org-type', 'users', '--owners', 'swell-consulting', '--skip-ghas', '--skip-trufflehog', '--skip-gitleaks', '--skip-noseyparker'], capture_output=True)

        # Check that the command completed successfully
        self.assertEqual(result.returncode, 0)

    def test_skip_only_run_gitleaks(self):
        # Run the command with arguments to skip some scanners and capture the output
        result = subprocess.run(['python3', 'secretsynth.py', '--org-type', 'users', '--owners', 'swell-consulting', '--skip-ghas', '--skip-trufflehog', '--skip-noseyparker'], capture_output=True)

        # Check that the command completed successfully
        self.assertEqual(result.returncode, 0)

if __name__ == '__main__':
    unittest.main()