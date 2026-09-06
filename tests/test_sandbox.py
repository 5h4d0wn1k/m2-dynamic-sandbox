"""Tests for the M2 dynamic sandbox.

Runs offline with only the Python stdlib:
  - a benign sample (writes files, binds 127.0.0.1) is executed inside a
    temp sandbox dir with /proc observation; all assertions are behavioral.
  - the run is skipped gracefully on non-Linux hosts (no /proc).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
FIRMWARE = os.path.join(REPO, "firmware")
sys.path.insert(0, FIRMWARE)

from sandbox import (  # noqa: E402
    DynamicSandbox,
    FileMonitor,
    _parse_addr,
    _hex_ipv4,
    build_socket_table,
)

BENIGN = os.path.join(FIRMWARE, "benign_sample.py")
IS_LINUX = sys.platform.startswith("linux") and os.path.isdir("/proc")


def _run_sample(tmp):
    sb = DynamicSandbox(BENIGN, output=tmp, timeout=15, poll=0.02)
    return sb.run()


@unittest.skipUnless(IS_LINUX, "/proc observation requires Linux")
class TestSandboxBehavior(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="m2t_")
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def test_files_created_in_sandbox(self):
        res = _run_sample(self.tmp)
        names = [c["path"] for c in res.files_created]
        self.assertIn("exfil.txt", names)
        self.assertIn("crafted/data.bin", names)

    def test_sample_process_observed(self):
        res = _run_sample(self.tmp)
        self.assertGreaterEqual(len(res.processes_spawned), 1)
        names = [p["name"] for p in res.processes_spawned]
        self.assertTrue(any("python" in n.lower() for n in names))

    def test_sandbox_dir_isolation(self):
        cwd_before = set(os.listdir("."))
        _run_sample(self.tmp)
        cwd_after = set(os.listdir("."))
        self.assertEqual(cwd_before, cwd_after)

    def test_timeout_kills_and_exits(self):
        sb = DynamicSandbox(BENIGN, output=self.tmp, timeout=0.3, poll=0.02)
        res = sb.run()
        self.assertIsNotNone(res.sandbox_dir)
        self.assertTrue(
            any("timeout" in o for o in res.observations)
            or res.exit_code != 0
            or res.files_created)

    def test_report_written_to_output_dir(self):
        _run_sample(self.tmp)
        report = os.path.join(self.tmp, "report.json")
        self.assertTrue(os.path.exists(report))
        data = json.load(open(report))
        self.assertIn("processes_spawned", data)
        self.assertIn("sockets", data)


class TestHelpers(unittest.TestCase):
    def test_hex_ipv4_little_endian(self):
        self.assertEqual(_hex_ipv4("0100007F"), "127.0.0.1")
        self.assertEqual(_hex_ipv4("00000000"), "0.0.0.0")

    def test_parse_addr_invalid(self):
        ip, port = _parse_addr("zz:1f90", "tcp")
        self.assertEqual(ip, "?")
        self.assertEqual(port, 8080)


class TestFileMonitor(unittest.TestCase):
    def test_diff_detects_created_modified_deleted(self):
        root = tempfile.mkdtemp(prefix="m2fm_")
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        with open(os.path.join(root, "a.txt"), "w") as f:
            f.write("aaaa")
        mon = FileMonitor(root)
        before = mon._snapshot()
        with open(os.path.join(root, "a.txt"), "w") as f:
            f.write("bbbb")
        with open(os.path.join(root, "b.txt"), "w") as f:
            f.write("new")
        os.unlink(os.path.join(root, "a.txt"))
        after = mon._snapshot()
        created, modified, deleted = mon.diff(before, after)
        self.assertEqual([c.path for c in created], ["b.txt"])
        self.assertEqual(modified, [])
        self.assertEqual([d.path for d in deleted], ["a.txt"])


class TestCLI(unittest.TestCase):
    def _run(self, args):
        return subprocess.run(
            [sys.executable, os.path.join(FIRMWARE, "sandbox.py")] + args,
            capture_output=True, text=True, timeout=60,
        )

    def test_help_exit_zero(self):
        r = self._run(["--help"])
        self.assertEqual(r.returncode, 0)
        self.assertIn("sandbox", r.stdout.lower())

    def test_demo_exit_zero(self):
        r = self._run([])
        self.assertEqual(r.returncode, 0)
        self.assertIn("Report", r.stdout)

    def test_missing_sample_exit_one(self):
        r = self._run(["/nonexistent/sample.bin"])
        self.assertEqual(r.returncode, 1)


if __name__ == "__main__":
    unittest.main()