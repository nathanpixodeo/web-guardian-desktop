# WebGuardian Desktop — Architecture

## Overview

WebGuardian Desktop is a cross-platform security scanner for PHP projects. It uses a producer-consumer architecture where the scanner engine walks the filesystem in a background thread while the UI displays real-time progress.

## Layers

### 1. Presentation Layer (`webguardian/ui/`)

CustomTkinter-based GUI with three visual sections:
- **Scan config** — path selector, scan button, options
- **Progress panel** — progress bar, file counter, timer, phase label, current file
- **Results panel** — tabbed display with severity-colored findings

### 2. Scanner Engine (`webguardian/scanner/core.py`)

`Scanner` class:
- Takes `root_path` and optional `progress_callback`
- Runs in a separate thread (via `threading.Thread`)
- Walks directory tree with `os.walk()` filtering out `vendor/`, `node_modules/`, `.git/`, etc.
- For each file: runs signature checks → CMS checks → permission checks
- Returns dict with `findings`, `summary`, `stats`

### 3. Signatures (`webguardian/scanner/signatures.py`)

All detection rules in one file:
- `SIGNATURES` — dict of regex patterns grouped by category (`malware`, `dangerous_functions`, `suspicious_variables`, `backdoor_patterns`)
- `BACKUP_FILE_PATTERNS` — regex list for backup file detection
- `KNOWN_BACKDOOR_FILES` — exact filename list
- `SKIP_DIRECTORIES` — set of directory names to exclude
- `SCAN_EXTENSIONS` — file extensions to scan

### 4. CMS Detectors (`webguardian/scanner/cms.py`)

- `detect_cms_type()` — checks for `wp-config.php`, `artisan`, `config/settings.inc.php`
- `check_laravel()` — .env analysis (APP_KEY, APP_DEBUG, DB passwords)
- `check_wordpress()` — wp-config.php analysis (WP_DEBUG, salts, DB passwords)
- `check_prestashop()` — settings.inc.php analysis (DB passwords, dev mode)

## Data Flow

```
User clicks "Start Scan"
  → UI disables button, starts progress bar
  → Creates Scanner(path, callback)
  → Starts scanner.run() in daemon thread
  → UI polls every 500ms for elapsed time
  → Scanner walks filesystem:
      1. Detect CMS type
      2. CMS-specific checks
      3. Git exposure check
      4. Composer integrity check
      5. php.ini config check
      6. Walk files:
         - os.walk with dir filtering
         - For each file: signature scan + permission check
         - Every 50 files: fire progress callback
      7. Aggregate results
  → UI receives completion callback
  → Display results with severity-colored formatting
```

## Key Design Decisions

### Why Python + CustomTkinter instead of PHP web app?
- No web server required — standalone desktop app
- No background process issues on Windows
- Native file dialogs
- Real-time progress without polling
- Cross-platform with single codebase

### Why thread-based instead of async?
- Simpler implementation
- No asyncio complexity
- `os.walk` is blocking anyway
- Progress callback runs on main thread via `after(0, ...)`

## Performance

- Skips `vendor/`, `node_modules/` — 90%+ of files in typical PHP projects
- Skips binary files and files >10MB
- Signature matching uses simple regex (no AST parsing)
- Average scan time: ~350ms for 37 files (web-guardian self-test)

## Extending

### Add new malware signature:
```python
# In signatures.py
SIGNATURES['malware'].append((r'pattern_regex', 'Description'))
```

### Add new CMS detector:
```python
# In cms.py
def check_drupal(path):
    findings = []
    # ... detection logic ...
    return findings

# In core.py Scanner.run()
elif self.cms_type == 'drupal':
    from .cms import check_drupal
    findings = check_drupal(self.root_path)
    # add findings
```

### Add new file check:
```python
# In core.py _scan_file()
# Add at the end before return
if ext == '.twig':
    self._check_twig_templates(file_path, content)
```
