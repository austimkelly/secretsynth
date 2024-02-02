import unittest
import subprocess

class TestSecretsynth(unittest.TestCase):
    def test_dry_run(self):
        # Run the command and capture the output
        result = subprocess.run(['python3', 'secretsynth.py', '--dry-run', '--owners', 'foo,bar', '--org-type', 'orgs'], capture_output=True)

        # Check that the command completed successfully
        self.assertEqual(result.returncode, 0)

if __name__ == '__main__':
    unittest.main()