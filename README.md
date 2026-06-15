# WebGuardian Desktop

Cross-platform desktop security scanner for PHP projects. Detects malware, backdoors, vulnerabilities, and security misconfigurations in WordPress, Laravel, PrestaShop, and generic PHP applications.

Built with Python and CustomTkinter — runs on Windows and Linux.

## Features

- **🔍 Deep Malware Detection** — eval+base64, gzinflate, obfuscated code, known backdoor filenames
- **⚠️ Dangerous Function Scanner** — exec, system, shell_exec, passthru, popen, proc_open, phpinfo
- **🔐 Sensitive File Detection** — exposed `.env`, backup files (`.bak`, `.old`, `.swp`, `~`), world-writable PHP files
- **📁 Intelligent Directory Walk** — skips `vendor/`, `node_modules/`, `storage/`, `cache/`, `.git/`, hidden dirs, files >10MB
- **🎯 CMS-Specific Checks**:
  - **Laravel** — APP_KEY strength, APP_DEBUG, weak DB passwords, public/.env exposure
  - **WordPress** — WP_DEBUG, default salts, weak DB passwords, PHP files in uploads
  - **PrestaShop** — weak DB passwords, dev mode, install directory still present
  - **Generic** — Git exposure, composer.json integrity, php.ini misconfigurations
- **📊 Real-Time Progress** — progress bar, file counter, timer, current file, findings count
- **🌙 Dark Mode UI** — modern CustomTkinter interface with severity-colored results
- **⚡ Fast** — scans 1000+ files in seconds with filtered directory traversal
- **📦 Standalone Build** — compile to a single `.exe` (Windows) or binary (Linux) with no Python required

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run
python main.py
```

## Usage

1. **Select Directory** — Click "Browse" or type the path to your PHP project
2. **Configure** — Toggle "Check Permissions" on/off
3. **Start Scan** — Click "Start Scan", watch real-time progress
4. **Review Results** — Findings grouped by severity (critical → info), with file paths and line numbers

### From CLI (headless mode)

```python
from webguardian.scanner import Scanner

s = Scanner('/path/to/project')
results = s.run()

print(f"Files scanned: {results['stats']['files_scanned']}")
print(f"Findings: {results['summary']['total']}")
for finding in results['findings']:
    print(f"  [{finding['severity']}] {finding['message']} — {finding['file']}:{finding['line']}")
```

## Project Structure

```
web-guardian-desktop/
├── main.py                          # Entry point
├── requirements.txt                 # Python dependencies
├── build_windows.bat                # Build script → Windows .exe
├── build_linux.sh                   # Build script → Linux binary
├── README.md
├── webguardian/
│   ├── __init__.py
│   ├── app.py                       # CustomTkinter application launcher
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── core.py                  # Scanner engine (file walk, pattern matching)
│   │   ├── signatures.py            # All malware signatures, rules, skip lists
│   │   └── cms.py                   # CMS detectors (Laravel, WordPress, PrestaShop)
│   └── ui/
│       ├── __init__.py
│       └── main_window.py           # Full GUI: config, progress bar, results display
└── assets/
```

## Building Standalone Executable

### Windows

```batch
build_windows.bat
```

Output: `dist/WebGuardian.exe` (single file, no Python required)

### Linux

```bash
chmod +x build_linux.sh
./build_linux.sh
```

Output: `dist/WebGuardian`

Both builds use **PyInstaller** to package everything into a single executable.

## Detection Capabilities

### Malware Signatures (critical severity)

| Pattern | Description |
|---------|-------------|
| `eval(base64_decode(...))` | Obfuscated code execution |
| `eval(gzinflate(...))` | Compressed code execution |
| `preg_replace /e modifier` | Deprecated code execution |
| `create_function()` | Deprecated code execution |
| `base64_decode(≥200 chars)` | Large obfuscated payload |
| `gzinflate(base64_decode(...))` | Nested obfuscation |
| `str_rot13(base64_decode(...))` | Multi-layer obfuscation |
| Hex-encoded strings `\xNN\xNN\xNN` | Obfuscated bytecode |
| `chr(N).chr(N).chr(N)` | Character-by-character string building |
| Variable function callbacks | Dynamic code execution |
| Known backdoor filenames | `shell.php`, `c99.php`, `r57.php`, `b374k.php`, etc. |

### Dangerous Functions (high severity)

`eval()`, `exec()`, `shell_exec()`, `system()`, `passthru()`, `popen()`, `proc_open()`, `pcntl_exec()`, `phpinfo()`

### Suspicious Patterns (high severity)

- Direct callbacks from `$_GET`/`$_POST`/`$_REQUEST`
- Variable variables with superglobals
- `extract($_...)` — variable injection
- `parse_str($_...)` — variable injection
- `move_uploaded_file()` from user input
- `file_put_contents()` / `fwrite()` from user input

### CMS-Specific Checks

**Laravel:** empty APP_KEY, default APP_KEY, short APP_KEY, APP_DEBUG enabled, weak DB passwords, `.env` in `public/`

**WordPress:** WP_DEBUG enabled, default salts, weak DB passwords, PHP files in uploads directory

**PrestaShop:** weak DB passwords, dev mode, install directory exists, exposed configuration files

### Environment & Config Checks

- `.git` directory exposure
- `composer.json` integrity and stability
- `php.ini` / `.user.ini` dangerous settings (display_errors, allow_url_include, expose_php)
- `.env` files in public directories
- Backup files (`.bak`, `.old`, `.swp`, `.orig`, `.save`, etc.)
- World-writable PHP files
- World-readable sensitive files

## Development

### Adding New Signatures

Edit `webguardian/scanner/signatures.py`:

```python
SIGNATURES['malware'].append((r'new_pattern_here', 'Description of the pattern'))
```

### Adding New CMS Detector

1. Create a function in `webguardian/scanner/cms.py`
2. Register it in `detect_cms_type()` and `Scanner.run()` in `core.py`

## Requirements

- Python 3.10+
- Dependencies: `customtkinter`, `Pillow` (installed automatically)

## License

MIT
