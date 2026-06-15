import os
import re
import time
import stat

from .signatures import (
    SIGNATURES, BACKUP_FILE_PATTERNS, KNOWN_BACKDOOR_FILES,
    SKIP_DIRECTORIES, SCAN_EXTENSIONS,
)
from .cms import detect_cms_type, check_laravel, check_wordpress, check_prestashop


class Scanner:
    def __init__(self, root_path, progress_callback=None):
        self.root_path = os.path.abspath(root_path)
        self.progress_callback = progress_callback
        self.results = {
            'findings': [],
            'stats': {
                'files_scanned': 0,
                'files_skipped': 0,
                'dirs_skipped': 0,
                'elapsed_ms': 0,
            },
            'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0},
            'cms_type': 'unknown',
            'scanned_path': self.root_path,
        }

    def _progress(self, phase, current_file='', n_scanned=0, n_skipped=0):
        if self.progress_callback:
            self.progress_callback({
                'phase': phase,
                'current_file': current_file,
                'files_scanned': n_scanned or self.results['stats']['files_scanned'],
                'files_skipped': n_skipped or self.results['stats']['files_skipped'],
                'findings_count': self.results['summary']['total'],
            })

    def _add_finding(self, severity, message, file_path='', line=0, pattern=''):
        if severity not in ('critical', 'high', 'medium', 'low', 'info'):
            severity = 'info'
        self.results['findings'].append({
            'file': file_path, 'line': line, 'severity': severity,
            'message': message, 'pattern': pattern,
        })
        self.results['summary'][severity] += 1
        self.results['summary']['total'] += 1

    def _should_skip_dir(self, dir_name):
        return dir_name.startswith('.') or dir_name.lower() in SKIP_DIRECTORIES

    def _scan_file(self, file_path):
        ext = os.path.splitext(file_path)[1].lower()
        base = os.path.basename(file_path)

        if base in KNOWN_BACKDOOR_FILES:
            self._add_finding('critical', f'Known backdoor filename: {base}', file_path, pattern='backdoor_filename')
            return

        for pat in BACKUP_FILE_PATTERNS:
            if re.search(pat, base, re.I):
                sev = 'high' if ext in ('.php', '.sql', '.env') else 'medium'
                self._add_finding(sev, f'Backup file found: {base}', file_path, pattern='backup_file')
                return

        if ext in ('.env',):
            self._add_finding('high', f'.env file exposed: {file_path}', file_path, pattern='env_exposed')
            return

        if ext not in SCAN_EXTENSIONS:
            return

        try:
            size = os.path.getsize(file_path)
            if size > 10 * 1024 * 1024:
                return
        except OSError:
            return

        try:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
        except (PermissionError, UnicodeDecodeError):
            return

        lines = content.split('\n')
        for category, patterns in SIGNATURES.items():
            for regex, description in patterns:
                for i, line_text in enumerate(lines, 1):
                    if re.search(regex, line_text):
                        sev = 'critical' if category == 'malware' else 'high'
                        self._add_finding(sev, description, file_path, i, pattern=regex)
                        break

    def _check_permissions(self, file_path):
        try:
            mode = os.stat(file_path).st_mode
            is_world_writable = bool(mode & stat.S_IWOTH)
            is_world_readable = bool(mode & stat.S_IROTH)
            base = os.path.basename(file_path)
            if is_world_writable and base.endswith('.php'):
                self._add_finding('high', f'World-writable PHP file: {base}', file_path, pattern='world_writable')
            if is_world_readable and base in ('.env', 'wp-config.php', 'config.php', 'settings.inc.php'):
                self._add_finding('high', f'World-readable sensitive file: {base}', file_path, pattern='world_readable')
        except OSError:
            pass

    def _check_git_exposure(self):
        git_dir = os.path.join(self.root_path, '.git')
        if os.path.isdir(git_dir):
            self._add_finding('high', '.git directory exposed (repository history accessible)', git_dir, pattern='git_exposure')

    def _check_composer(self):
        composer = os.path.join(self.root_path, 'composer.json')
        if os.path.isfile(composer):
            try:
                import json
                with open(composer, 'r') as f:
                    data = json.load(f)
                if data.get('minimum-stability') and data['minimum-stability'] != 'stable':
                    self._add_finding('medium',
                        f"Composer minimum-stability is '{data['minimum-stability']}'",
                        composer, pattern='unstable_deps')
                if data.get('require-dev'):
                    self._add_finding('low',
                        'Dev dependencies installed (run composer install --no-dev in production)',
                        composer, pattern='dev_deps')
            except (json.JSONDecodeError, PermissionError):
                self._add_finding('medium', 'composer.json is not valid JSON', composer, pattern='invalid_composer')

    def _check_config_files(self):
        for fname in ('php.ini', '.user.ini'):
            ini = os.path.join(self.root_path, fname)
            if os.path.isfile(ini):
                try:
                    with open(ini, 'r') as f:
                        content = f.read()
                    checks = [
                        (r'^display_errors\s*=\s*On', 'display_errors enabled', 'high'),
                        (r'^allow_url_include\s*=\s*On', 'allow_url_include enabled (remote file inclusion risk)', 'critical'),
                        (r'^expose_php\s*=\s*On', 'expose_php enabled (PHP version exposed)', 'medium'),
                    ]
                    for regex, msg, sev in checks:
                        if re.search(regex, content, re.I | re.M):
                            self._add_finding(sev, msg, ini, pattern='php_ini_' + sev)
                except PermissionError:
                    pass

    def run(self):
        start = time.time()
        self._progress('discovering', 'Detecting CMS type...')

        self.results['cms_type'] = detect_cms_type(self.root_path)
        if self.results['cms_type'] == 'wordpress':
            findings = check_wordpress(self.root_path)
            for f in findings:
                self._add_finding(f['severity'], f['message'], f['file'], f['line'])
        elif self.results['cms_type'] == 'laravel':
            findings = check_laravel(self.root_path)
            for f in findings:
                self._add_finding(f['severity'], f['message'], f['file'], f['line'])
        elif self.results['cms_type'] == 'prestashop':
            findings = check_prestashop(self.root_path)
            for f in findings:
                self._add_finding(f['severity'], f['message'], f['file'], f['line'])

        self._check_git_exposure()
        self._check_composer()
        self._check_config_files()

        self._progress('scanning', 'Walking filesystem...')

        for root, dirs, files in os.walk(self.root_path):
            dirs[:] = [d for d in dirs if not self._should_skip_dir(d)]
            self.results['stats']['dirs_skipped'] += sum(1 for d in dirs if d in SKIP_DIRECTORIES or d.startswith('.'))

            for fname in files:
                fpath = os.path.join(root, fname)
                self.results['stats']['files_scanned'] += 1

                if self.results['stats']['files_scanned'] % 50 == 0:
                    self._progress('scanning', fpath)

                self._scan_file(fpath)
                self._check_permissions(fpath)

        self.results['stats']['elapsed_ms'] = int((time.time() - start) * 1000)
        self._progress('completed', 'Scan complete')
        return self.results
