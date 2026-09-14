# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DashboardBoundaryTests(unittest.TestCase):
    def test_core_import_does_not_load_dashboard_presentation(self) -> None:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(ROOT / "src")
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import sys; import tg_pm_gatekeeper.telegram_adapter; "
                    "assert 'tg_pm_gatekeeper.dashboard_http' not in sys.modules; "
                    "assert 'tg_pm_gatekeeper.assets' not in sys.modules"
                ),
            ],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_compose_sidecar_has_only_the_runtime_mount(self) -> None:
        compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        dashboard = compose.split("\n  dashboard:\n", 1)[1]
        self.assertIn('profiles: ["dashboard"]', dashboard)
        self.assertIn("network_mode: none", dashboard)
        self.assertIn("read_only: true", dashboard)
        self.assertIn("no-new-privileges:true", dashboard)
        self.assertIn("pids_limit: 32", dashboard)
        self.assertIn("mem_limit: 128m", dashboard)
        self.assertIn("cpus: 0.25", dashboard)
        self.assertIn('restart: "no"', dashboard)
        self.assertEqual(
            dashboard.count(
                "/run/tg-pm-gatekeeper:/run/tg-pm-gatekeeper:rw"
            ),
            1,
        )
        for forbidden in (
            "env_file:",
            "/etc/tg-pm-gatekeeper",
            "/var/lib/tg-pm-gatekeeper",
            "TG_API_",
            "TG_SESSION_",
            "TG_HMAC_",
            "TG_REVIEW_KEY",
            "TG_DENYLIST_",
            "ports:",
        ):
            self.assertNotIn(forbidden, dashboard)

    def test_core_has_no_published_port_and_uses_192_mib_limit(self) -> None:
        gatekeeper = (ROOT / "compose.yaml").read_text(encoding="utf-8").split(
            "\n  dashboard:\n", 1
        )[0]
        self.assertIn("mem_limit: 192m", gatekeeper)
        self.assertNotIn("ports:", gatekeeper)
        self.assertIn("TG_DASHBOARD_RPC_SOCKET_PATH", gatekeeper)

    def test_remote_stop_failure_is_reported(self) -> None:
        helper = (ROOT / "scripts" / "dashboard-remote.sh").read_text(
            encoding="utf-8"
        )
        stop_function = helper.split("stop_dashboard() {", 1)[1].split("}", 1)[0]
        self.assertNotIn("|| true", stop_function)


if __name__ == "__main__":
    unittest.main()
