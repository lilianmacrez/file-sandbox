# file-sandbox

An offline static file analyzer for triaging suspicious files.

## Installation

```bash
cargo build --release
```

## Usage

Analyze a file and display the JSON report:

```bash
file-sandbox analyze <file>
```

Save the report to a JSON file:

```bash
file-sandbox analyze <file> --json report.json
```

## Example

```bash
file-sandbox analyze suspicious.exe --json analysis.json
```

## Features

Currently supports:
- Hash calculation (MD5, SHA1, SHA256, BLAKE3) with streaming support

Coming soon:
- String extraction
- IOC detection
- Entropy analysis
- PE/ELF parsing
- YARA scanning
