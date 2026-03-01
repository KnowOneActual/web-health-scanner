import unittest
import subprocess
import sys
import os

class TestCLI(unittest.TestCase):
    def setUp(self):
        # Add src to PYTHONPATH
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = os.path.join(os.getcwd(), "src")

    def test_cli_help(self):
        """Test that the CLI can be run as a module and displays the help message."""
        result = subprocess.run(
            [sys.executable, "-m", "web_health_scanner", "--help"],
            capture_output=True,
            text=True,
            env=self.env
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Run a full website health check and audit.", result.stdout)

if __name__ == "__main__":
    unittest.main()
