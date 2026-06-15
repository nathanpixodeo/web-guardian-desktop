# WebGuardian Desktop — Changelog

## v1.0.0 (2026-06-15)

### Initial Release

- Cross-platform desktop security scanner (Windows + Linux)
- Malware detection with 20+ signature patterns
- Dangerous function scanner (eval, exec, system, etc.)
- PHP obfuscation detection (base64, gzinflate, hex encoding)
- Known backdoor filename detection
- Suspicous variable and callback detection
- Backup file detection (.bak, .old, .swp, ~, etc.)
- World-writable PHP file detection
- `.git` directory exposure check
- `composer.json` integrity and stability check
- `php.ini` dangerous settings check
- CMS-specific scanners:
  - Laravel: APP_KEY, APP_DEBUG, DB password, .env exposure
  - WordPress: WP_DEBUG, salts, DB password, uploads PHP files
  - PrestaShop: DB password, dev mode, install directory
- CustomTkinter dark mode GUI
- Real-time progress bar with file counter and timer
- Severity-colored results display
- Standalone build support via PyInstaller
