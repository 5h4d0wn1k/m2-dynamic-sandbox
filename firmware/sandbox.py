#!/usr/bin/env python3
"""
M2 — Dynamic Analysis Sandbox: Automated Malware Detonation and Behavioral Monitoring

Educational tool for malware analysis in controlled environments.
"""

import os
import sys
import json
import time
import shutil
import hashlib
import logging
import argparse
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class FileChange:
    path: str
    action: str
    timestamp: str
    sha256: Optional[str] = None


@dataclass
class NetworkEvent:
    protocol: str
    src_ip: str
    dst_ip: str
    dst_port: int
    timestamp: str
    bytes_sent: int = 0
    bytes_recv: int = 0


@dataclass
class ProcessInfo:
    pid: int
    name: str
    command_line: str
    parent_pid: int
    timestamp: str


@dataclass
class SandboxResult:
    sample_path: str
    sample_sha256: str
    sample_md5: str
    start_time: str
    end_time: str
    duration_seconds: float
    files_created: List[FileChange]
    files_modified: List[FileChange]
    files_deleted: List[FileChange]
    network_events: List[NetworkEvent]
    processes_spawned: List[ProcessInfo]
    yara_matches: List[Dict]
    registry_changes: List[Dict]
    suspicious_indicators: List[str]


class FileMonitor:
    def __init__(self, watch_dirs: List[str]):
        self.watch_dirs = watch_dirs
        self.snapshot: Dict[str, str] = {}
        self.changes: List[FileChange] = []

    def take_snapshot(self):
        self.snapshot.clear()
        for watch_dir in self.watch_dirs:
            if not os.path.exists(watch_dir):
                continue
            for root, _, files in os.walk(watch_dir):
                for f in files:
                    path = os.path.join(root, f)
                    try:
                        self.snapshot[path] = hashlib.sha256(
                            open(path, 'rb').read()
                        ).hexdigest()
                    except (PermissionError, OSError):
                        pass

    def detect_changes(self) -> List[FileChange]:
        current: Dict[str, str] = {}
        changes = []
        now = datetime.now().isoformat()

        for watch_dir in self.watch_dirs:
            if not os.path.exists(watch_dir):
                continue
            for root, _, files in os.walk(watch_dir):
                for f in files:
                    path = os.path.join(root, f)
                    try:
                        content = open(path, 'rb').read()
                        sha = hashlib.sha256(content).hexdigest()
                        current[path] = sha

                        if path not in self.snapshot:
                            changes.append(FileChange(
                                path=path, action='created',
                                timestamp=now, sha256=sha
                            ))
                        elif self.snapshot[path] != sha:
                            changes.append(FileChange(
                                path=path, action='modified',
                                timestamp=now, sha256=sha
                            ))
                    except (PermissionError, OSError):
                        pass

        for path in self.snapshot:
            if path not in current:
                changes.append(FileChange(
                    path=path, action='deleted',
                    timestamp=now
                ))

        self.changes = changes
        return changes


class NetworkMonitor:
    def __init__(self):
        self.events: List[NetworkEvent] = []
        self._proc: Optional[subprocess.Popen] = None
        self._log_file: Optional[str] = None

    def start(self):
        self._log_file = tempfile.mktemp(suffix='.log')
        try:
            self._proc = subprocess.Popen(
                ['tcpdump', '-i', 'any', '-w', self._log_file, '-l'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            logger.info("Network monitoring started (tcpdump)")
        except FileNotFoundError:
            logger.warning("tcpdump not found, network monitoring disabled")

    def stop(self) -> List[NetworkEvent]:
        if self._proc:
            self._proc.terminate()
            self._proc.wait(timeout=5)
        if self._log_file and os.path.exists(self._log_file):
            try:
                result = subprocess.run(
                    ['tcpdump', '-r', self._log_file, '-nn'],
                    capture_output=True, text=True, timeout=30
                )
                for line in result.stdout.strip().split('\n'):
                    if line:
                        self._parse_tcpdump_line(line)
            except Exception as e:
                logger.warning(f"Failed to parse network log: {e}")
            finally:
                os.unlink(self._log_file)
        return self.events

    def _parse_tcpdump_line(self, line: str):
        now = datetime.now().isoformat()
        event = NetworkEvent(
            protocol='unknown', src_ip='0.0.0.0',
            dst_ip='0.0.0.0', dst_port=0, timestamp=now
        )
        if 'UDP' in line:
            event.protocol = 'UDP'
        elif 'TCP' in line:
            event.protocol = 'TCP'
        elif 'ICMP' in line:
            event.protocol = 'ICMP'
        self.events.append(event)


class RegistryMonitor:
    def __init__(self):
        self.changes: List[Dict] = []

    def snapshot_windows(self) -> Dict:
        snapshot = {}
        try:
            result = subprocess.run(
                ['reg', 'query', r'HKLM\SOFTWARE', '/s'],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.split('\n'):
                if line.strip():
                    snapshot[line.strip()] = True
        except Exception:
            pass
        return snapshot

    def detect_changes(self, before: Dict) -> List[Dict]:
        after = self.snapshot_windows()
        changes = []
        for key in after:
            if key not in before:
                changes.append({
                    'action': 'created', 'key': key,
                    'timestamp': datetime.now().isoformat()
                })
        return changes


class YaraScanner:
    def __init__(self, rules_dir: Optional[str] = None):
        self.rules_dir = rules_dir
        self.compiled_rules = None

    def load_rules(self) -> bool:
        if not YARA_AVAILABLE:
            logger.warning("yara-python not installed, YARA scanning disabled")
            return False
        if self.rules_dir and os.path.exists(self.rules_dir):
            try:
                rule_files = {}
                for f in os.listdir(self.rules_dir):
                    if f.endswith('.yar') or f.endswith('.yara'):
                        rule_files[f] = os.path.join(self.rules_dir, f)
                if rule_files:
                    self.compiled_rules = yara.compile(
                        filepaths=rule_files
                    )
                    logger.info(f"Loaded {len(rule_files)} YARA rule files")
                    return True
            except Exception as e:
                logger.error(f"Failed to load YARA rules: {e}")
        return False

    def scan_file(self, filepath: str) -> List[Dict]:
        if not self.compiled_rules:
            return []
        try:
            matches = self.compiled_rules.match(filepath)
            return [{
                'rule': m.rule,
                'namespace': m.namespace,
                'tags': m.tags,
                'meta': m.meta,
                'strings': [(s[0], s[1], s[2]) for s in m.strings]
            } for m in matches]
        except Exception as e:
            logger.error(f"YARA scan error: {e}")
            return []


class DynamicSandbox:
    def __init__(self, args):
        self.sample_path = args.sample
        self.analysis_dir = args.output or tempfile.mkdtemp(prefix='sandbox_')
        self.timeout = args.timeout
        self.yara_rules_dir = args.yara_rules
        self.watch_dirs = args.watch_dirs.split(',') if args.watch_dirs else [
            os.path.join(self.analysis_dir, 'filesystem')
        ]
        self.verbose = args.verbose

        self.file_monitor = FileMonitor(self.watch_dirs)
        self.network_monitor = NetworkMonitor()
        self.registry_monitor = RegistryMonitor()
        self.yara_scanner = YaraScanner(self.yara_rules_dir)

        self.suspicious_indicators: List[str] = []
        self._setup_analysis_env()

    def _setup_analysis_env(self):
        os.makedirs(self.analysis_dir, exist_ok=True)
        for d in self.watch_dirs:
            os.makedirs(d, exist_ok=True)
        sample_dest = os.path.join(self.analysis_dir, 'sample.exe')
        if os.path.exists(self.sample_path):
            shutil.copy2(self.sample_path, sample_dest)
            self.sample_path = sample_dest

    def _compute_hashes(self, filepath: str) -> Dict[str, str]:
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                md5.update(chunk)
                sha256.update(chunk)
        return {'md5': md5.hexdigest(), 'sha256': sha256.hexdigest()}

    def _analyze_strings(self, filepath: str) -> List[str]:
        suspicious = []
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            strings = []
            current = []
            for byte in data:
                if 32 <= byte <= 126:
                    current.append(chr(byte))
                else:
                    if len(current) >= 4:
                        strings.append(''.join(current))
                    current = []
            indicators = [
                'cmd.exe', 'powershell', 'regsvr32', 'rundll32',
                'CreateProcess', 'WriteFile', 'InternetOpen',
                'URLDownload', 'VirtualAlloc', 'LoadLibrary',
                'http://', 'https://', 'ftp://', '\\SYSTEM32',
                'HKLM\\', 'HKCU\\', 'mshta', 'wscript', 'cscript'
            ]
            for s in strings:
                for indicator in indicators:
                    if indicator.lower() in s.lower():
                        suspicious.append(s[:200])
                        break
        except Exception:
            pass
        return suspicious

    def run(self) -> SandboxResult:
        logger.info(f"Starting analysis of: {self.sample_path}")
        hashes = self._compute_hashes(self.sample_path)
        start_time = datetime.now()
        logger.info(f"SHA256: {hashes['sha256']}")
        logger.info(f"Analysis directory: {self.analysis_dir}")

        string_indicators = self._analyze_strings(self.sample_path)
        if string_indicators:
            self.suspicious_indicators.extend(
                [f"String match: {s}" for s in string_indicators[:10]]
            )

        self.file_monitor.take_snapshot()
        self.network_monitor.start()
        reg_before = self.registry_monitor.snapshot_windows()

        logger.info(f"Detonating sample (timeout: {self.timeout}s)...")
        try:
            subprocess.run(
                [self.sample_path],
                timeout=self.timeout,
                cwd=self.analysis_dir,
                capture_output=True
            )
        except subprocess.TimeoutExpired:
            logger.info("Sample execution timed out (expected for persistent malware)")
        except PermissionError:
            logger.error("Permission denied executing sample")
        except Exception as e:
            logger.error(f"Execution error: {e}")

        file_changes = self.file_monitor.detect_changes()
        network_events = self.network_monitor.stop()
        registry_changes = self.registry_monitor.detect_changes(reg_before)

        for fc in file_changes:
            if fc.action == 'created':
                self.suspicious_indicators.append(f"File created: {fc.path}")
        if len(network_events) > 10:
            self.suspicious_indicators.append(
                f"High network activity: {len(network_events)} connections"
            )
        if registry_changes:
            self.suspicious_indicators.append(
                f"Registry modifications: {len(registry_changes)} keys"
            )

        yara_matches = []
        if self.yara_scanner.load_rules():
            for fc in file_changes:
                if fc.action in ('created', 'modified') and os.path.exists(fc.path):
                    yara_matches.extend(self.yara_scanner.scan_file(fc.path))
            yara_matches.extend(self.yara_scanner.scan_file(self.sample_path))

        end_time = datetime.now()
        result = SandboxResult(
            sample_path=self.sample_path,
            sample_sha256=hashes['sha256'],
            sample_md5=hashes['md5'],
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            duration_seconds=(end_time - start_time).total_seconds(),
            files_created=[fc for fc in file_changes if fc.action == 'created'],
            files_modified=[fc for fc in file_changes if fc.action == 'modified'],
            files_deleted=[fc for fc in file_changes if fc.action == 'deleted'],
            network_events=network_events,
            processes_spawned=[],
            yara_matches=yara_matches,
            registry_changes=registry_changes,
            suspicious_indicators=self.suspicious_indicators
        )

        report_path = os.path.join(self.analysis_dir, 'report.json')
        with open(report_path, 'w') as f:
            json.dump(asdict(result), f, indent=2, default=str)
        logger.info(f"Report saved to: {report_path}")
        return result


def print_report(result: SandboxResult):
    print("\n" + "=" * 60)
    print("  M2 — Dynamic Analysis Sandbox — Report")
    print("=" * 60)
    print(f"  Sample:   {result.sample_path}")
    print(f"  SHA256:   {result.sample_sha256}")
    print(f"  MD5:      {result.sample_md5}")
    print(f"  Duration: {result.duration_seconds:.1f}s")
    print(f"  Start:    {result.start_time}")
    print(f"  End:      {result.end_time}")
    print("-" * 60)
    print(f"  Files Created:    {len(result.files_created)}")
    print(f"  Files Modified:   {len(result.files_modified)}")
    print(f"  Files Deleted:    {len(result.files_deleted)}")
    print(f"  Network Events:   {len(result.network_events)}")
    print(f"  Registry Changes: {len(result.registry_changes)}")
    print(f"  YARA Matches:     {len(result.yara_matches)}")
    print("-" * 60)
    if result.files_created:
        print("  Created Files:")
        for fc in result.files_created[:20]:
            print(f"    [+] {fc.path}")
            if fc.sha256:
                print(f"        SHA256: {fc.sha256}")
    if result.network_events:
        print("  Network Events:")
        for ne in result.network_events[:20]:
            print(f"    [{ne.protocol}] {ne.src_ip} -> {ne.dst_ip}:{ne.dst_port}")
    if result.registry_changes:
        print("  Registry Changes:")
        for rc in result.registry_changes[:20]:
            print(f"    [{rc['action']}] {rc['key']}")
    if result.yara_matches:
        print("  YARA Matches:")
        for ym in result.yara_matches:
            print(f"    Rule: {ym['rule']} (tags: {ym.get('tags', [])})")
    if result.suspicious_indicators:
        print("-" * 60)
        print("  Suspicious Indicators:")
        for ind in result.suspicious_indicators:
            print(f"    [!] {ind}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description='M2 — Dynamic Analysis Sandbox'
    )
    parser.add_argument(
        'sample', help='Path to malware sample to analyze'
    )
    parser.add_argument(
        '-o', '--output', help='Output directory for analysis'
    )
    parser.add_argument(
        '-t', '--timeout', type=int, default=60,
        help='Execution timeout in seconds (default: 60)'
    )
    parser.add_argument(
        '--yara-rules', help='Directory containing YARA rule files'
    )
    parser.add_argument(
        '--watch-dirs', help='Comma-separated directories to monitor'
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='Enable verbose output'
    )
    args = parser.parse_args()

    if not os.path.exists(args.sample):
        print(f"Error: Sample not found: {args.sample}")
        sys.exit(1)

    sandbox = DynamicSandbox(args)
    result = sandbox.run()
    print_report(result)


if __name__ == '__main__':
    main()
