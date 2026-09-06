# M2 — Dynamic Analysis Sandbox

A genuine, no-root behavioral sandbox that runs YOUR OWN crafted, non-destructive
sample inside a throwaway temp directory and reports what it did — using nothing
but the Python standard library and the Linux `/proc` filesystem.

## What genuinely works

Real behavioral observation on real Linux hosts (offline, no privileges):

- **Spawned processes** — the sample plus any children it forks are captured by
  walking `/proc/<pid>/task/*/children`, with `pid`, `comm`, state, full
  `/proc/<pid>/cmdline` and CPU time per process.
- **Created / modified / deleted files** — a SHA-256 snapshot diff of the sandbox
  directory before vs after the run. No root, no inotify, no fanotify.
- **Network binds & connects** — socket file-descriptors are resolved via
  `readlink /proc/<pid>/fd/*` to `socket:[inode]` and matched against the real
  kernel tables `/proc/net/tcp` and `/proc/net/tcp6`, yielding protocol, local
  and remote `ip:port` and the connection state. A listener is reported as a
  `bind`, an outbound socket as `connect`/`ESTABLISHED`/`SYN_SENT`, etc.
- **Isolation** — the sample's cwd is the sandbox dir and `HOME`, `TMP`,
  `TMPDIR`, `TEMPDIR` are redirected there. No executable sample leaves the
  temp dir; stdout/stderr are captured into `stdout.txt`.
- **JSON report** — written under the repo's gitignored `reports/` directory
  (or the argparse `-o` directory).

Dependencies: **Python 3 stdlib only** (`subprocess`, `/proc`, `struct`,
`hashlib`, `threading`, `json`, `argparse`). No `yara-python`, no `tcpdump`,
no `reg query`, no root.

## Real fixture shipped

| Fixture | Behavior the sandbox observes |
|---------|-------------------------------|
| `firmware/benign_sample.py` | Writes two files in its cwd and binds a TCP listener on `127.0.0.1` (ephemeral port), then attempts a connection to local discard port `9`. |

The fixture is clearly benign and already annotated as such.

## Usage

```bash
# Help
python3 firmware/sandbox.py --help

# Run the shipped benign fixture (offline demo, exits 0)
python3 firmware/sandbox.py

# Run your own crafted benign sample
python3 firmware/sandbox.py firmware/benign_sample.py -o reports/run1 -t 10

# Keep the sandbox dir + JSON report under reports/
python3 firmware/sandbox.py firmware/benign_sample.py --poll 0.02 -o reports/run2
```

### Offline demo (exits 0)

```bash
python3 firmware/sandbox.py
```

produces the observation report and writes
`reports/sandbox/report.json` (gitignored).

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Behavioural tests run the benign fixture against the live sandbox and assert
files, processes and the `127.0.0.1` bind are observed. On non-Linux hosts the
`/proc` behavioural tests are skipped gracefully; helper tests always run.

## Live Lab Test Plan

1. In an isolated container/VM (no root) run `python3 firmware/sandbox.py`
   the shipped fixture; confirm exit 0 and that the report lists the built
   files, the sample process, and a `bind:tcp` on `127.0.0.1`.
2. Craft your own benign sample (e.g. `python3 -c "open('x','w').write('hi')"`)
   and confirm the created file appears with its SHA-256.
3. Cross-check one observed socket against `ss -tlnp`/`/proc/net/tcp` while the
   sample sleeps; the entries should agree.
4. Only ever run samples you wrote yourself or have explicit written
   authorization to detonate. Never detonate unknown malware outside an
   isolated, throwaway VM.

## Metrics

- Observation sources: `/proc/<pid>/task/*/children`, `/proc/<pid>/stat`,
  `/proc/<pid>/cmdline`, `/proc/<pid>/fd` (readlink), `/proc/net/tcp`,
  `/proc/net/tcp6`; filesystem SHA-256 snapshot diff.
- Test count: 11 stdlib unittest cases (see `tests/`).
- Dependencies: Python 3 stdlib only.
- Offline demo: executes the shipped benign fixture and reports real
  observed process/file/socket behavior.

## IMPORTANT: Read before use.

This tool is for **educational and authorized analysis only**. It executes
files on a real operating system — you MUST only run samples you own or are
explicitly authorized to execute, and you should run it only on systems you own
or within an isolated throwaway lab environment. Executing malware without
authorization may violate computer-crime laws. The repo ships only a clearly
benign test fixture. The author is not responsible for misuse.

## License

MIT — see `LICENSE`.