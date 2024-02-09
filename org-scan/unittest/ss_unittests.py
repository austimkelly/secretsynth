import unittest
import subprocess
import pexpect

SECRETSYNTH="../secretsynth.py"

#  Run: python3 -m unittest ss_unittests.py
class TestSecretsynth(unittest.TestCase):
    def test_1_dry_run(self):
        # Run the command and capture the output
        result = subprocess.run(['python3', SECRETSYNTH, '--dry-run', '--owners', 'foo,bar', '--org-type', 'orgs'], capture_output=True)

        print(result.stderr)
        # Check that the command completed successfully
        self.assertEqual(result.returncode, 0)

    def test_2_invalid_args(self):
        # Run the command with an invalid argument and capture the output
        result = subprocess.run(['python3', SECRETSYNTH, '--invalid-arg'], capture_output=True)

        print(result.stderr)
        # Check that the command failed
        self.assertNotEqual(result.returncode, 0)

    def test_3_skip_all_scanners(self):
        # Run the command with arguments to skip all scanners and capture the output
        result = subprocess.run(['python3', SECRETSYNTH, '--org-type', 'users', '--owners', 'swell-consulting', '--skip-ghas', '--skip-trufflehog', '--skip-gitleaks', '--skip-noseyparker'], capture_output=True)

        print(result.stderr)
        # Check that the command completed successfully
        self.assertEqual(result.returncode, 0)

    def test_4_skip_only_run_gitleaks(self):
        # Run the command with arguments to skip some scanners and capture the output
        result = subprocess.run(['python3', SECRETSYNTH, '--org-type', 'users', '--owners', 'swell-consulting', '--skip-ghas', '--skip-trufflehog', '--skip-noseyparker'], capture_output=True, text=True)

        # Check that the command completed successfully
        #print(result.stdout)
        print(result.stderr)
        self.assertEqual(result.returncode, 0)

    def test_5_skip_only_run_trufflehog(self):
        # Run the command with arguments to run trufflehog but skip all others
        result = subprocess.run(['python3', SECRETSYNTH, '--org-type', 'users', '--owners', 'swell-consulting', '--skip-ghas', '--skip-gitleaks', '--skip-noseyparker'], capture_output=True, text=True)

        # Check that the command completed successfully
        print(result.stderr)
        self.assertEqual(result.returncode, 0)

    def test_999_clean(self):
        # Run the command
        child = pexpect.spawn(f'python3 {SECRETSYNTH} --clean')

        # Expect the end of the prompt for user input
        child.expect('\(y/n\):')

        # Print the output before the expect call
        print("Output before expect:", child.before.decode())

        # Send 'y' as input
        child.sendline('y')

        # Wait for the command to complete
        child.expect(pexpect.EOF)

        # Print the output after the expect call
        print("Output after expect:", child.before.decode())

        # Wait for the process to finish executing
        child.wait()

        # Check that the command completed successfully
        self.assertEqual(child.exitstatus, 0)

if __name__ == '__main__':
    unittest.main()