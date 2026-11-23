# MalScope

**Local Static Malware Analyzer for Windows Portable Executable (PE) Files**

MalScope is a lightweight, local-only malware triage tool developed in Python. It analyses Windows PE files (`.exe`, `.dll`, `.sys`, and `.com`) without executing or detonating them.

The project provides both a Command-Line Interface (CLI) and a local Flask Web UI.

| Item | Details |
|---|---|
| Course | IKB31603 - Ethical Hacking |
| Category | Malware Analysis - Static Analysis |
| Group | GoodGuys |
| Group Members | Muhammad Sufi bin Md Arif, Azim, Hakimi, Azamuddin |

---

## Table of Contents

- [Overview](#overview)
- [Ethical Use and Rules of Engagement](#ethical-use-and-rules-of-engagement)
- [Key Features](#key-features)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [CLI Usage](#cli-usage)
- [Web UI Usage](#web-ui-usage)
- [Output Reports](#output-reports)
- [Safety Guardrails](#safety-and-scope-guardrails)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Overview

MalScope performs static inspection by reading raw file bytes and PE metadata. It can extract:

- MD5 and SHA-256 hashes
- PE import hash (`imphash`)
- PE headers and compile timestamp
- Entry point and machine architecture
- Section names and Shannon entropy
- Embedded URLs and IPv4 indicators
- Imported Windows APIs
- MITRE ATT&CK tactics and technique IDs
- A risk score and final verdict

Supported verdicts are:

| Verdict | Meaning |
|---|---|
| `CLEAN` | No significant suspicious indicators detected |
| `SUSPICIOUS` | One or more indicators require further review |
| `MALICIOUS` | Strong suspicious indicators detected |
| `UNSUPPORTED` | The file is not a valid or supported PE file |

---

## Ethical Use and Rules of Engagement

MalScope is intended only for authorized academic labs and defensive malware analysis.

- Obtain explicit authorization before analysing any file.
- Do not scan or access files outside your authorization scope.
- Static analysis must not replace permission, documentation, or an approved incident-response process.
- The tool never executes target binaries or loads them as runnable code.
- The tool does not upload files or send their hashes and contents to external services.
- The user remains responsible for complying with applicable laws, including Malaysia's Computer Crimes Act 1997 / Act 563.

---

## Key Features

- **Cryptographic Identification**
  - Generates MD5, SHA-256, and PE import hash values.
- **PE Header Analysis**
  - Displays machine architecture, compile timestamp, entry point, and section metadata.
- **Entropy Analysis**
  - Calculates Shannon entropy between `0.0` and `8.0`.
  - Highlights sections with entropy greater than `7.0`, which may indicate packing or encryption.
- **Windows API Detection**
  - Matches imported functions from `rules.json`.
  - Normalizes ANSI `A` and Unicode `W` suffixes before matching.
- **MITRE ATT&CK Mapping**
  - Groups suspicious detections by tactic and technique ID.
- **Network Indicator Extraction**
  - Searches raw bytes for HTTP/HTTPS URLs and IPv4 addresses.
- **Risk Scoring**
  - Produces a score from `0` to `100` with human-readable reasons.
- **Dual Interfaces**
  - Provides terminal output and an offline Flask Web Dashboard.
- **Local Reports**
  - Saves text or JSON reports under `output/`.

---

## Technology Stack

- Python 3.9+
- `pefile` - PE parsing
- Flask - local Web UI
- Werkzeug - secure upload handling
- HTML, CSS, and JavaScript - Web interface

---

## Project Structure

```text
MalScope/
├── main.py                 # CLI entry point
├── requirements.txt        # Python dependencies
├── rules.json              # API detection and ATT&CK rules
├── LICENSE
├── README.md
├── malscope/
│   ├── core.py             # Main analysis and report functions
│   ├── analyzers.py        # Hash, PE, entropy, and IOC analyzers
│   ├── pe_parser.py        # PE structure parsing
│   ├── risk.py             # Risk scoring
│   ├── rules.py            # Rule loading and matching
│   └── guardrails.py       # Authorization and scope checks
├── samples/
│   └── notepad.exe         # Local test sample
├── web/
│   ├── app.py              # Flask server
│   └── templates/
│       ├── index.html
│       └── report.html
└── output/                 # Generated reports
```

---

## Installation

### Requirements

- Python 3.9 or later
- Windows 10 or Windows 11 recommended
- Internet access is required only to clone and install the project dependencies

### 1. Clone the repository

```powershell
git clone https://github.com/msufi00/MalScope.git
cd MalScope
```

### 2. Create a virtual environment

```powershell
python -m venv .venv
```

### 3. Activate the virtual environment

PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Command Prompt:

```bat
.venv\Scripts\activate.bat
```

Linux or macOS:

```bash
source .venv/bin/activate
```

### 4. Install dependencies

```powershell
pip install -r requirements.txt
```

---

## CLI Usage

### Scan the default sample

```powershell
python main.py --file samples/notepad.exe
```

### Generate a JSON report

```powershell
python main.py --file samples/notepad.exe --format json
```

### Perform a dry run

The dry run validates the file path, file size, and allowed directory scope without creating a report.

```powershell
python main.py --file samples/eicar.com --dry-run
```

### Scan from an authorized custom directory

```powershell
python main.py --file D:\TestLab\sample.exe --allow-dir D:\TestLab
```

### CLI options

| Option | Description | Default |
|---|---|---|
| `--file` | Path to the target file | `samples/eicar.com` |
| `--allow-dir` | Authorized directory allowed for scanning; repeatable | `samples/` |
| `--out` | Directory for generated reports | `output` |
| `--format` | Report format: `text` or `json` | `text` |
| `--dry-run` | Validate scope without generating a report | Disabled |
| `--serve` | Launch the local Flask Web UI | Disabled |
| `--port` | Local port for the Web UI | `5000` |

Before a CLI scan begins, the program requires explicit typed legal authorization.

---

## Web UI Usage

### Start the server

```powershell
python main.py --serve
```

Or use a custom local port:

```powershell
python main.py --serve --port 8080
```

Open:

```text
http://127.0.0.1:5000
```

Use the Web UI as follows:

1. Select a file with `.exe`, `.dll`, `.sys`, or `.com` extension.
2. Confirm authorization by ticking the Computer Crimes Act 1997 checkbox.
3. Select **Run Static Analysis**.
4. Review the verdict, file details, entropy results, MITRE ATT&CK findings, and network IOCs.

The Web UI is intentionally restricted to localhost:

- Host: `127.0.0.1`
- Default port: `5000`
- Debug mode: disabled

### Stop the server

Use either:

- Press `Ctrl+C` in the terminal, or
- Select **Stop Server** in the Web UI.

---

## Output Reports

CLI reports are saved locally to the `output/` directory by default.

Example filenames:

```text
malscope_notepad_suspicious_20261123_034441.txt
malscope_notepad_suspicious_20261123_033003.json
```

A report may include:

- File name and size
- Hash values
- PE metadata
- Section entropy
- Suspicious imports
- MITRE ATT&CK mappings
- Embedded network indicators
- Risk score
- Final verdict

Web uploads are copied to a temporary UUID-named file and removed after analysis.

---

## Safety and Scope Guardrails

### Mandatory authorization

- CLI scans require explicit typed consent.
- Web scans require server-side validation of `consent=agree`.

### Directory scope

CLI scans are restricted to `samples/` unless additional directories are passed with `--allow-dir`. Path traversal and out-of-scope paths are rejected.

### File-size limit

Both CLI and Web analysis enforce a maximum file size of 50 MB.

### Upload isolation

Web uploads are:

- Limited to supported PE extensions
- Named with random UUIDs
- Stored temporarily under `output/.tmp_uploads/`
- Deleted after analysis finishes

### Host and request protection

The Web UI validates the `Host` header and blocks cross-origin POST requests to reduce DNS-rebinding and CSRF risks.

### Emergency kill switch

- CLI: press `Ctrl+C`
- Web: select **Stop Server**, or press `Ctrl+C` in the terminal

---

## Limitations

- MalScope does not execute samples and cannot observe runtime behavior.
- Packed or encrypted payloads, such as UPX-compressed files, may not expose their original imports or strings.
- APIs resolved dynamically through `GetProcAddress` or similar runtime methods may be missed.
- The current IOC parser primarily reads ASCII byte sequences and may miss UTF-16LE strings.
- High section entropy is a heuristic, not proof of packing or malware.
- Legitimate Windows binaries may trigger suspicious results. For example, `notepad.exe` may contain common Windows API imports or version strings that match heuristic rules.
- Static results should be verified using dynamic analysis and additional malware-analysis tooling where appropriate.

---

## Troubleshooting

### `ModuleNotFoundError`

Confirm that the virtual environment is active and dependencies are installed:

```powershell
pip install -r requirements.txt
```

### Port 5000 is already in use

Start the Web UI on another port:

```powershell
python main.py --serve --port 8080
```

### File is outside the allowed directory

Add an authorized directory explicitly:

```powershell
python main.py --file D:\TestLab\sample.exe --allow-dir D:\TestLab
```

### Unsupported file

Confirm that the file is a Windows PE file and is not larger than 50 MB.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
