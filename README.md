# file-sandbox

An offline static file analyzer for triaging suspicious files.

## Installation

```bash
cargo build --release
```

## Usage

After building, you can run the tool using `cargo run --release --`:

Analyze a file and display the JSON report:

```bash
cargo run --release -- analyze <file>
```

Save the report to a JSON file:

```bash
cargo run --release -- analyze <file> --json report.json
```

## Example

```bash
cargo run --release -- analyze suspicious.exe --json analysis.json
```

Alternatively, you can run the binary directly:

```bash
./target/release/file-sandbox-cli.exe analyze <file> --json report.json
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
