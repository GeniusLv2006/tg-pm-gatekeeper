from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "review-tunnel.sh"


class ReviewTunnelTests(unittest.TestCase):
    def run_script(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        for name in (
            "TG_REVIEW_HOST",
            "TG_REVIEW_PORT",
            "TG_REVIEW_SOCKET",
            "TG_REVIEW_SSH_CONFIG",
        ):
            environment.pop(name, None)
        return subprocess.run(
            [str(SCRIPT), *arguments],
            text=True,
            capture_output=True,
            env=environment,
            check=False,
        )

    def test_help_documents_generic_configuration(self) -> None:
        result = self.run_script("-h")
        self.assertEqual(result.returncode, 0)
        self.assertIn("SSH_TARGET", result.stdout)
        self.assertIn("TG_REVIEW_HOST", result.stdout)
        self.assertNotIn("bv", result.stdout)

    def test_ssh_target_is_required(self) -> None:
        result = self.run_script()
        self.assertEqual(result.returncode, 2)
        self.assertIn("SSH target is required", result.stderr)

    def test_local_port_is_validated_before_connecting(self) -> None:
        result = self.run_script("-p", "70000", "user@server.example")
        self.assertEqual(result.returncode, 2)
        self.assertIn("1 to 65535", result.stderr)

    def test_remote_socket_must_be_absolute(self) -> None:
        result = self.run_script(
            "-s", "relative/review.sock", "user@server.example"
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("absolute path", result.stderr)


if __name__ == "__main__":
    unittest.main()
