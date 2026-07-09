# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "dashboard-tunnel.sh"
LEGACY_SCRIPT = Path(__file__).parents[1] / "scripts" / "review-tunnel.sh"


class ReviewTunnelTests(unittest.TestCase):
    def run_script(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        for name in (
            "TG_REVIEW_HOST",
            "TG_REVIEW_PORT",
            "TG_REVIEW_SOCKET",
            "TG_REVIEW_SSH_CONFIG",
            "TG_DASHBOARD_HOST",
            "TG_DASHBOARD_PORT",
            "TG_DASHBOARD_SOCKET",
            "TG_DASHBOARD_SSH_CONFIG",
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
        self.assertIn("TG_DASHBOARD_HOST", result.stdout)
        self.assertIn("TG_REVIEW_*", result.stdout)
        self.assertIn("-o", result.stdout)
        self.assertNotIn("bv", result.stdout)

    def test_legacy_wrapper_delegates_with_deprecation_notice(self) -> None:
        result = subprocess.run(
            [str(LEGACY_SCRIPT), "-h"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("dashboard-tunnel.sh", result.stdout)
        self.assertIn("deprecated", result.stderr)

    def test_open_option_launches_default_browser(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pid_file = root / "ssh.pid"
            opened_file = root / "opened.url"
            fake_ssh = root / "ssh"
            fake_curl = root / "curl"
            fake_open = root / "open"
            fake_ssh.write_text(
                "#!/bin/sh\n"
                'case "$*" in *"cat /var/lib/tg-pm-gatekeeper/review.access-token"*) '
                "echo test-access-token; exit 0;; esac\n"
                'echo $$ > "$FAKE_SSH_PID"\n'
                "sleep 1\n",
                encoding="utf-8",
            )
            fake_curl.write_text(
                "#!/bin/sh\n"
                '[ -r "$FAKE_SSH_PID" ] || exit 1\n'
                'pid="$(cat "$FAKE_SSH_PID")"\n'
                'kill -0 "$pid" 2>/dev/null\n',
                encoding="utf-8",
            )
            fake_open.write_text(
                "#!/bin/sh\n"
                'printf "%s" "$1" > "$FAKE_OPENED_URL"\n',
                encoding="utf-8",
            )
            for executable in (fake_ssh, fake_curl, fake_open):
                executable.chmod(0o700)
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{root}:{environment['PATH']}",
                    "FAKE_SSH_PID": str(pid_file),
                    "FAKE_OPENED_URL": str(opened_file),
                }
            )
            result = subprocess.run(
                [str(SCRIPT), "-o", "user@server.example"],
                text=True,
                capture_output=True,
                env=environment,
                check=False,
                timeout=5,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Dashboard opened", result.stdout)
            self.assertEqual(
                opened_file.read_text(encoding="utf-8"),
                "http://127.0.0.1:8765/login?token=test-access-token",
            )

    def test_ssh_target_is_required(self) -> None:
        result = self.run_script()
        self.assertEqual(result.returncode, 2)
        self.assertIn("SSH target is required", result.stderr)

    def test_local_port_is_validated_before_connecting(self) -> None:
        result = self.run_script("-p", "70000", "user@server.example")
        self.assertEqual(result.returncode, 2)
        self.assertIn("1 to 65535", result.stderr)

    def test_remote_socket_must_be_absolute(self) -> None:
        result = self.run_script("-s", "relative/review.sock", "user@server.example")
        self.assertEqual(result.returncode, 2)
        self.assertIn("absolute path", result.stderr)

    def test_interrupt_terminates_the_actual_ssh_process(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pid_file = root / "ssh.pid"
            terminated_file = root / "ssh.terminated"
            fake_ssh = root / "ssh"
            fake_curl = root / "curl"
            fake_ssh.write_text(
                "#!/bin/sh\n"
                'case "$*" in *"cat /var/lib/tg-pm-gatekeeper/review.access-token"*) '
                "echo test-access-token; exit 0;; esac\n"
                'echo $$ > "$FAKE_SSH_PID"\n'
                "trap 'echo yes > \"$FAKE_SSH_TERMINATED\"; exit 0' TERM INT\n"
                "while :; do sleep 0.1; done\n",
                encoding="utf-8",
            )
            fake_curl.write_text(
                "#!/bin/sh\n"
                '[ -r "$FAKE_SSH_PID" ] || exit 1\n'
                'pid="$(cat "$FAKE_SSH_PID")"\n'
                'kill -0 "$pid" 2>/dev/null\n',
                encoding="utf-8",
            )
            fake_ssh.chmod(0o700)
            fake_curl.chmod(0o700)
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{root}:{environment['PATH']}",
                    "FAKE_SSH_PID": str(pid_file),
                    "FAKE_SSH_TERMINATED": str(terminated_file),
                }
            )
            process = subprocess.Popen(
                [str(SCRIPT), "user@server.example"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
            )
            deadline = time.monotonic() + 5
            output_lines: list[str] = []
            while time.monotonic() < deadline:
                line = process.stdout.readline()
                output_lines.append(line)
                if line.startswith("Connected:"):
                    break
            else:
                process.kill()
                self.fail("tunnel helper did not report a connection")

            ssh_pid = int(pid_file.read_text(encoding="ascii"))
            process.send_signal(signal.SIGINT)
            stdout, stderr = process.communicate(timeout=5)
            output = "".join(output_lines) + stdout

            self.assertEqual(process.returncode, 130, stderr)
            self.assertIn("Tunnel closed.", output)
            self.assertTrue(terminated_file.exists())
            with self.assertRaises(ProcessLookupError):
                os.kill(ssh_pid, 0)


if __name__ == "__main__":
    unittest.main()
