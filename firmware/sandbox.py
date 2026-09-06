#!/usr/bin/env python3
"""
M2 — Dynamic Analysis Sandbox (behavioral, no-root, tmpdir-only)

Runs a NON-DESTRUCTIVE sample inside a throwaway temp directory and observes
its behavior with nothing but the standard library and /proc:

  * spawned processes      -> /proc/<pid>/{stat,cmdline,status} + task children walk
  * created/modified/deleted files -> filesystem snapshot diff of the sandbox dir
  * network binds/connects -> /proc/<pid>/fd socket inodes matched against
                              /proc/net/tcp and /proc/net/tcp6

The sample only ever runs inside `SANDBOX_DIR` (cwd = sandbox dir, HOME/TMP
redirected there). No root, no ptrace, no tcpdump, no external YARA/reg tools.

Run on your own benign fixture, e.g.:

    python3 sandbox.py firmware/benign_sample.py --timeout 8

WARNING: Educational / authorized analysis only. Only run samples you own
or have written authorization to execute.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

try:  # pragma: no cover - import speedup only
    from queue import Queue
except ImportError:  # pragma: no cover
    Queue = None

PROC = "/proc"


# ---------------------------------------------------------------------------
# Observations
# ---------------------------------------------------------------------------


@dataclass
class FileChange:
    path: str
    action: str            # created | modified | deleted
    size: int = 0
    sha256: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class ProcessInfo:
    pid: int
    status: str            # R / S / Z ...
    name: str              # comm
    command_line: str
    parent_pid: int
    cpu_time: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class SocketEvent:
    kind: str              # bind | connect
    protocol: str          # tcp | tcp6
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    pid: int = 0

    def to_dict(self):
        return asdict(self)


@dataclass
class SandboxResult:
    sample_path: str
    sample_sha256: str
    sample_md5: str
    sandbox_dir: str
    start_time: str
    end_time: str
    duration_seconds: float
    exit_code: int
    files_created: list = field(default_factory=list)
    files_modified: list = field(default_factory=list)
    files_deleted: list = field(default_factory=list)
    processes_spawned: list = field(default_factory=list)
    sockets: list = field(default_factory=list)
    observations: list = field(default_factory=list)  # raw poll log

    def to_dict(self):
        d = asdict(self)
        return d


# ---------------------------------------------------------------------------
# Filesystem snapshot/diff
# ---------------------------------------------------------------------------


class FileMonitor:
    def __init__(self, root):
        self.root = os.path.abspath(root)

    def _snapshot(self):
        snap = {}
        for dirpath, _dirs, files in os.walk(self.root):
            for f in files:
                p = os.path.join(dirpath, f)
                try:
                    rel = os.path.relpath(p, self.root)
                    with open(p, "rb") as fh:
                        data = fh.read()
                    snap[rel] = (len(data), hashlib.sha256(data).hexdigest())
                except OSError:
                    pass
        return snap

    def diff(self, before, after):
        created, modified, deleted = [], [], []
        now_suffix = "sample"
        for rel, meta in after.items():
            if rel not in before:
                created.append(FileChange(path=rel, action="created",
                                          size=meta[0], sha256=meta[1]))
            elif before[rel][0] != meta[0] or before[rel][1] != meta[1]:
                modified.append(FileChange(path=rel, action="modified",
                                           size=meta[0], sha256=meta[1]))
        for rel in before:
            if rel not in after:
                deleted.append(FileChange(path=rel, action="deleted",
                                          size=before[rel][0]))
        return created, modified, deleted


# ---------------------------------------------------------------------------
# /proc observation
# ---------------------------------------------------------------------------

def _read_file(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return b""


def _proc_children(pid):
    """Direct children of pid, read from /proc/<pid>/task/*/children."""
    kids = set()
    taskdir = os.path.join(PROC, str(pid), "task")
    try:
        tids = os.listdir(taskdir)
    except OSError:
        return kids
    for tid in tids:
        data = _read_file(os.path.join(taskdir, tid, "children"))
        for tok in data.split():
            try:
                kids.add(int(tok))
            except ValueError:
                pass
    return kids


def _collect_process_tree(root_pid):
    """BFS over /proc children starting at root_pid, return set of pids."""
    seen = {root_pid}
    queue = [root_pid]
    while queue:
        cur = queue.pop(0)
        for c in _proc_children(cur):
            if c not in seen:
                seen.add(c)
                queue.append(c)
    return seen


def _proc_info(pid):
    stat = _read_file(os.path.join(PROC, str(pid), "stat")).decode("utf-8", "replace")
    # comm is in parentheses; parse after last '('
    rp = stat.rfind(")") if stat else -1
    name = ""
    if rp >= 0:
        name = stat[stat.find("(") + 1:rp]
        parts = stat[rp + 1:].split()
        try:
            status = parts[0]
            ppid = int(parts[1])
            utime = int(parts[11])
            stime = int(parts[12])
            cpu = "%.2f+%.2f" % (utime / 100.0, stime / 100.0)
        except (ValueError, IndexError):
            status, ppid, cpu = "?", 0, ""
    else:
        status, ppid, cpu = "?", 0, ""
    cmdline = _read_file(os.path.join(PROC, str(pid), "cmdline")) \
        .replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    return ProcessInfo(pid=pid, status=status, name=name,
                       command_line=cmdline, parent_pid=ppid, cpu_time=cpu)


def _parse_net_tab(data):
    """Parse /proc/net/tcp|tcp6 lines into {inode: entry}."""
    out = {}
    lines = data.decode("utf-8", "replace").splitlines()
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        entry = {
            "sl": parts[0].rstrip(":"),
            "local": parts[1],
            "rem": parts[2],
            "st": parts[3],
            "inode": parts[9],
        }
        out[entry["inode"]] = entry
    return out


def _hex_ipv4(hexstr):
    """'0100007F' (little-endian u32 in /proc/net/tcp) -> '127.0.0.1'."""
    try:
        pairs = [hexstr[i:i + 2] for i in range(0, len(hexstr), 2)]
        raw = bytes(int(p, 16) for p in reversed(pairs))
        return ".".join(str(b) for b in raw[:4])
    except ValueError:
        return "?"


def _hex_ipv6(hexstr):
    raw = bytes.fromhex(hexstr)[:16]
    return ":".join("%02x%02x" % (raw[i], raw[i + 1]) for i in range(0, 16, 2))


def _parse_addr(addr, proto):
    h, port = addr.split(":") if ":" in addr else (addr, "0")
    port = int(port, 16)
    if proto == "tcp":
        return _hex_ipv4(h), port
    return _hex_ipv6(h), port


def build_socket_table():
    """Map socket inode -> (proto, local, rem, state)."""
    table = {}
    for proto in ("tcp", "tcp6"):
        raw = _read_file(os.path.join(PROC, "net", proto))
        if not raw:
            continue
        for inode, e in _parse_net_tab(raw).items():
            loc_ip, loc_port = _parse_addr(e["local"], proto)
            rem_ip, rem_port = _parse_addr(e["rem"], proto)
            st = int(e["st"], 16)
            state = {0xA: "LISTEN", 1: "ESTABLISHED", 2: "SYN_SENT",
                     3: "SYN_RECV", 5: "TIME_WAIT", 6: "CLOSE", 7: "CLOSE_WAIT",
                     0xB: "SYN_SENT2"}.get(st, hex(st))
            table[inode] = {"proto": proto, "local_ip": loc_ip,
                            "local_port": loc_port, "remote_ip": rem_ip,
                            "remote_port": rem_port, "state": state}
    return table


def _pid_socket_inodes(pid):
    """Return list of socket inodes held open by pid (via readlink of fd symlinks)."""
    inodes = []
    fddir = os.path.join(PROC, str(pid), "fd")
    try:
        fds = os.listdir(fddir)
    except OSError:
        return inodes
    for fd in fds:
        try:
            link = os.readlink(os.path.join(fddir, fd))
        except OSError:
            continue
        if link.startswith("socket:[") and link.endswith("]"):
            inodes.append(link[8:-1])
    return inodes


# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------


class DynamicSandbox:
    def __init__(self, sample, output=None, timeout=20, poll=0.05,
                 capture_stdout=True):
        self.sample = os.path.abspath(sample)
        self.timeout = timeout
        self.poll = poll
        self.capture = capture_stdout
        self.output = os.path.abspath(output) if output else None
        self.stop = threading.Event()
        self.observations = []

    def _setup_dir(self):
        if self.output:
            base = self.output
            os.makedirs(base, exist_ok=True)
            self.sandbox_dir = os.path.join(base, "sandbox")
            if os.path.exists(self.sandbox_dir):
                shutil.rmtree(self.sandbox_dir, ignore_errors=True)
            os.makedirs(self.sandbox_dir, exist_ok=True)
        else:
            self.sandbox_dir = tempfile.mkdtemp(prefix="sandbox_")
        return self.sandbox_dir

    def _monitor_loop(self, root_pid):
        self._procs = {}
        self._sockets = []
        self._seen_keys = set()
        seen_sockets = set()
        while not self.stop.is_set() and self.poll > 0:
            table = build_socket_table()
            pids = _collect_process_tree(root_pid)
            for pid in sorted(pids):
                info = _proc_info(pid)
                self._record_proc(info)
                row = {"ts": datetime.now(timezone.utc).isoformat(),
                       "pid": pid, "name": info.name, "status": info.status,
                       "cmdline": info.command_line}
                # socket events
                for inode in _pid_socket_inodes(pid):
                    if inode in table and (pid, inode) not in seen_sockets:
                        seen_sockets.add((pid, inode))
                        e = table[inode]
                        key = (pid, inode, e["local_ip"], e["local_port"],
                               e["remote_ip"], e["remote_port"])
                        kind = ("bind" if e["state"] == "LISTEN"
                                and e["local_ip"] not in ("0.0.0.0", "::")
                                else e["state"].lower())
                        sev = SocketEvent(kind=kind, protocol=e["proto"],
                                          local_ip=e["local_ip"],
                                          local_port=e["local_port"],
                                          remote_ip=e["remote_ip"],
                                          remote_port=e["remote_port"],
                                          pid=pid)
                        if key not in self._seen_keys:
                            self._seen_keys.add(key)
                            self._sockets.append(sev)
                        row.setdefault("sockets", []).append(
                            dict(e, pid=pid, inode=inode))
                self.observations.append(row)
            self.stop.wait(self.poll)
        # final pass after process exits
        if root_pid:
            pids = _collect_process_tree(root_pid)
            for pid in sorted(pids):
                info = _proc_info(pid)
                self._record_proc(info)
                self.observations.append({
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "final": True, "pid": pid, "name": info.name,
                    "status": info.status, "cmdline": info.command_line})

    def _record_proc(self, info):
        """Record a captured ProcessInfo, never clobbering a good capture
        with an unresolved one (e.g. a reaped process read after exit)."""
        if info.parent_pid == 0 and not info.name:
            return
        self._procs[info.pid] = info

    def run(self):
        start = time.time()
        start_iso = datetime.now(timezone.utc).isoformat()
        self._setup_dir()
        # compute sample hashes up front
        with open(self.sample, "rb") as f:
            raw = f.read()
        sha256 = hashlib.sha256(raw).hexdigest()
        md5 = hashlib.md5(raw).hexdigest()

        monitor = FileMonitor(self.sandbox_dir)
        before = monitor._snapshot()

        env = dict(os.environ)
        env["HOME"] = self.sandbox_dir
        env["TMP"] = self.sandbox_dir
        env["TMPDIR"] = self.sandbox_dir
        env["TEMPDIR"] = self.sandbox_dir
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        # Decide how to execute the sample. Executables run directly;
        # .py scripts are executed with the current interpreter.
        cmd = [self.sample]
        if self.sample.endswith(".py") or not os.access(self.sample, os.X_OK):
            cmd = [sys.executable, self.sample]

        stdout_target = subprocess.DEVNULL
        if self.capture:
            stdout_target = open(os.path.join(self.sandbox_dir, "stdout.txt"), "wb")
        proc = subprocess.Popen(
            cmd, cwd=self.sandbox_dir, env=env,
            stdout=stdout_target, stderr=stdout_target)

        root_pid = proc.pid
        worker = threading.Thread(target=self._monitor_loop, args=(root_pid,))
        worker.daemon = True
        worker.start()
        try:
            proc.wait(timeout=self.timeout)
        except subprocess.TimeoutExpired:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                try:
                    proc.kill()
                except OSError:
                    pass
            self.observations.append({"event": "timeout", "pid": root_pid})
        finally:
            self.stop.set()
            if stdout_target is not subprocess.DEVNULL:
                try:
                    stdout_target.close()
                except OSError:
                    pass
        worker.join(timeout=max(self.poll * 2, 0.2))

        after = monitor._snapshot()
        created, modified, deleted = monitor.diff(before, after)

        final_table = build_socket_table()
        final_pids = _collect_process_tree(root_pid)
        for pid in sorted(final_pids):
            try:
                self._record_proc(_proc_info(pid))
            except Exception:
                continue
        for pid in sorted(final_pids):
            for inode in _pid_socket_inodes(pid):
                if inode in final_table:
                    e = final_table[inode]
                    key = (pid, inode, e["local_ip"], e["local_port"],
                           e["remote_ip"], e["remote_port"])
                    if key not in self._seen_keys:
                        self._seen_keys.add(key)
                        kind = ("bind" if e["state"] == "LISTEN"
                                and e["local_ip"] not in ("0.0.0.0", "::")
                                else e["state"].lower())
                        self._sockets.append(SocketEvent(
                            kind=kind, protocol=e["proto"], local_ip=e["local_ip"],
                            local_port=e["local_port"], remote_ip=e["remote_ip"],
                            remote_port=e["remote_port"], pid=pid))
        procs = {pid: info for pid, info in self._procs.items()}
        sockets = list(self._sockets)
        end_iso = datetime.now(timezone.utc).isoformat()

        # cleanup temp dir when no explicit output was requested
        keep_dir = self.sandbox_dir
        cleanup = self.output is None

        result = SandboxResult(
            sample_path=self.sample,
            sample_sha256=sha256,
            sample_md5=md5,
            sandbox_dir=keep_dir,
            start_time=start_iso,
            end_time=end_iso,
            duration_seconds=round(time.time() - start, 3),
            exit_code=proc.returncode if proc.returncode is not None else -1,
            files_created=[c.to_dict() for c in created],
            files_modified=[c.to_dict() for c in modified],
            files_deleted=[c.to_dict() for c in deleted],
            processes_spawned=[p.to_dict() for p in procs.values()],
            sockets=[s.to_dict() for s in sockets],
            observations=self.observations[-2000:],
        )
        if cleanup:
            shutil.rmtree(keep_dir, ignore_errors=True)
        elif self.output:
            write_result(result, os.path.join(self.output, "report.json"))
        return result


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def write_result(result, out_path):
    with open(out_path, "w") as f:
        json.dump(result.to_dict(), f, indent=2)
    return out_path


def print_report(result):
    print("\n" + "=" * 64)
    print("  M2 - Dynamic Analysis Sandbox - Report")
    print("=" * 64)
    print("  Sample:       %s" % result.sample_path)
    print("  SHA256:       %s" % result.sample_sha256)
    print("  Exit code:    %s" % result.exit_code)
    print("  Duration:     %.3fs" % result.duration_seconds)
    print("-" * 64)
    print("  Files created:   %d" % len(result.files_created))
    print("  Files modified:  %d" % len(result.files_modified))
    print("  Files deleted:   %d" % len(result.files_deleted))
    print("  Processes:       %d" % len(result.processes_spawned))
    print("  Sockets:         %d" % len(result.sockets))
    print("-" * 64)
    if result.files_created:
        print("  Created files:")
        for fc in result.files_created[:25]:
            print("    [+] %s (%d bytes)" % (fc["path"], fc["size"]))
    if result.processes_spawned:
        print("  Processes:")
        for p in result.processes_spawned[:25]:
            print("    [%s] pid=%d name=%s %s"
                  % (p["status"], p["pid"], p["name"],
                     (p["command_line"] or "")[:90]))
    if result.sockets:
        print("  Sockets (observed):")
        for s in result.sockets[:40]:
            if s["kind"] == "bind":
                print("    [bind:%s] %s:%d" % (s["protocol"], s["local_ip"],
                                               s["local_port"]))
            else:
                print("    [%s] %s:%d -> %s:%d"
                      % (s["kind"], s["local_ip"], s["local_port"],
                         s["remote_ip"], s["remote_port"]))
    print("=" * 64)


def demo(output=None):
    """Offline demo: build the benign fixture and analyze it."""
    here = os.path.dirname(os.path.abspath(__file__))
    sample = os.path.join(here, "benign_sample.py")
    repo = os.path.dirname(here)
    out = output or os.path.join(repo, "reports", "sandbox")
    sb = DynamicSandbox(sample, output=out, timeout=10, poll=0.05)
    res = sb.run()
    report = os.path.join(out, "report.json")
    write_result(res, report)
    print_report(res)
    print("\nJSON report: %s" % report)
    return res


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="sandbox.py",
        description="M2 - Dynamic Analysis Sandbox (no-root /proc observation)")
    parser.add_argument("sample", nargs="?", default=None,
                        help="Path to the sample to run (or omit for offline demo)")
    parser.add_argument("-o", "--output", default=None,
                        help="Directory to keep the sandbox + report in "
                             "(default: temp dir, cleaned up)")
    parser.add_argument("-t", "--timeout", type=float, default=15.0,
                        help="Execution timeout in seconds (default 15)")
    parser.add_argument("--poll", type=float, default=0.05,
                        help="/proc poll interval in seconds (default 0.05)")
    parser.add_argument("--no-capture", action="store_true",
                        help="Do not capture sample stdout/stderr")
    args = parser.parse_args(argv)

    if not args.sample:
        demo(output=args.output)
        return 0
    if not os.path.exists(args.sample):
        print("Error: sample not found: %s" % args.sample)
        return 1
    sb = DynamicSandbox(args.sample, output=args.output,
                        timeout=args.timeout, poll=args.poll,
                        capture_stdout=not args.no_capture)
    res = sb.run()
    if args.output:
        os.makedirs(args.output, exist_ok=True)
        write_result(res, os.path.join(args.output, "report.json"))
    print_report(res)
    return 0


if __name__ == "__main__":
    sys.exit(main())