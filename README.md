# M2 — Dynamic Analysis Sandbox

Automated malware detonation and behavioral monitoring tool for reverse engineering.

## Overview

This project implements a dynamic analysis sandbox that:
- Detonates malware samples in a controlled environment
- Monitors file system changes (created, modified, deleted files)
- Tracks network connections and traffic
- Monitors Windows registry modifications
- Performs YARA scanning on artifacts
- Extracts suspicious strings and indicators
- Generates comprehensive JSON reports

## Features

- **Automated Detonation**: Execute samples with configurable timeout
- **File Monitoring**: Track filesystem changes in watch directories
- **Network Monitoring**: Capture network connections via tcpdump
- **Registry Monitoring**: Detect Windows registry modifications
- **YARA Scanning**: Scan artifacts with custom YARA rules
- **String Analysis**: Extract suspicious API calls and URLs
- **JSON Reports**: Generate detailed analysis reports
- **Suspicious Indicators**: Auto-detect behavioral red flags

## Installation

```bash
pip install yara-python
```

## Usage

```bash
# Basic analysis
python3 sandbox.py malware_sample.exe

# Custom timeout and output directory
python3 sandbox.py malware_sample.exe -t 120 -o ./analysis_output

# With YARA rules
python3 sandbox.py malware_sample.exe --yara-rules ./rules/

# Verbose mode
python3 sandbox.py malware_sample.exe -v
```

## Example Output

```
============================================================
  M2 — Dynamic Analysis Sandbox — Report
============================================================
  Sample:   ./analysis_output/sample.exe
  SHA256:   a1b2c3d4e5f6...
  MD5:      abc123def456...
  Duration: 60.0s
------------------------------------------------------------
  Files Created:    3
  Files Modified:   1
  Files Deleted:    0
  Network Events:   15
  Registry Changes: 2
  YARA Matches:     1
------------------------------------------------------------
  Created Files:
    [+] C:\Users\user\AppData\temp\dropper.exe
    [+] C:\Windows\Temp\config.dat
  Network Events:
    [TCP] 192.168.1.100 -> 185.234.72.18:443
  Suspicious Indicators:
    [!] File created: C:\Users\user\AppData\temp\dropper.exe
    [!] High network activity: 15 connections
============================================================
```

## Architecture

```
m2-dynamic-sandbox/
├── firmware/
│   ├── sandbox.py          # Main sandbox implementation
│   └── rules/              # YARA rules directory
├── README.md
└── requirements.txt
```

## How It Works

1. **Pre-analysis**: Compute file hashes, snapshot filesystem, start network capture
2. **Detonation**: Execute sample with timeout, capture stdout/stderr
3. **Post-analysis**: Detect file changes, stop network capture, check registry
4. **YARA Scan**: Scan all created/modified files with loaded rules
5. **Report**: Generate JSON report with all findings and indicators

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the system owner before using this tool
- Executing malware on systems without authorization is illegal under federal and state laws
- This tool should ONLY be used on systems you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **State Laws**: Many states have additional computer crime statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Analyzing malware in isolated lab environments
- Authorized malware analysis with written scope
- Academic research in controlled sandboxes
- Security education and training

### Prohibited Use
- Detonating malware on production systems
- Analyzing samples without proper containment
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

## License

MIT
