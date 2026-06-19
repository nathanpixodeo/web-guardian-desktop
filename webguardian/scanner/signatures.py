"""Built-in and updateable malware signatures."""

from __future__ import annotations

import json
import re
from pathlib import Path

from webguardian.storage import get_data_dir


SIGNATURES = {
    'malware': [
        (r'eval\s*\(\s*base64_decode\s*\(', 'Obfuscated code execution (eval+base64)'),
        (r'eval\s*\(\s*gzinflate\s*\(', 'Compressed code execution (eval+gzinflate)'),
        (r'eval\s*\(\s*\$\{?\s*[\'"]\s*<\?php', 'PHP code injection via eval'),
        (r'assert\s*\(\s*\$_', 'Dynamic code execution via assert'),
        (r'preg_replace\s*\([\s\S]*?[\'\"\/][e][\'\"\s]', 'Deprecated /e modifier (code execution)'),
        (r'create_function\s*\(', 'Deprecated create_function (code execution)'),
        (r'base64_decode\s*\(\s*[\'\"][A-Za-z0-9+\/=]{200,}', 'Large base64 decode (obfuscated payload)'),
        (r'gzinflate\s*\(\s*base64_decode', 'Nested decompression + decode'),
        (r'gzuncompress\s*\(\s*base64_decode', 'Nested decompression + decode'),
        (r'str_rot13\s*\(\s*base64_decode', 'Obfuscation via rot13 + base64'),
        (r'\$[a-z]\s*=\s*[\'\"][A-Za-z0-9+\/=]{150,}[\'\"]\s*;', 'Long encoded string in short variable'),
        (r'\$[a-z]{1,2}\s*\.=\s*\$[a-z]{1,2}', 'String concatenation obfuscation'),
        (r'\$\w+\s*\(\s*\$\w+\s*\)\s*;', 'Variable function call (possible callback)'),
        (r'\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}', 'Hex-encoded strings'),
        (r'chr\s*\(\s*\d{2,3}\s*\)\s*\.\s*chr', 'Character-by-character string building'),
    ],
    'dangerous_functions': [
        (r'\beval\s*\(', 'Code execution via eval()'),
        (r'\bexec\s*\(', 'System command execution'),
        (r'\bshell_exec\s*\(', 'Shell command execution'),
        (r'\bsystem\s*\(', 'System command execution'),
        (r'\bpassthru\s*\(', 'System command execution'),
        (r'\bpopen\s*\(', 'Process execution'),
        (r'\bproc_open\s*\(', 'Process execution'),
        (r'\bpcntl_exec\s*\(', 'Process execution'),
        (r'\bphpinfo\s*\(\s*\)', 'PHP info exposure'),
    ],
    'suspicious_variables': [
        (r'\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[[^\]]*\]\s*\(', 'Direct callback from user input'),
        (r'\$\{?\s*\$_(?:GET|POST|REQUEST)\s*\[[^\]]*\]\s*\}?\s*\(', 'Variable variable callback from input'),
        (r'\$(?:_|GLOBALS|_\w+)\s*\[[^\]]+\]\s*\{', 'Variable variable with superglobal'),
        (r'extract\s*\(\s*\$_', 'Variable injection via extract()'),
        (r'parse_str\s*\(\s*\$_', 'Variable injection via parse_str()'),
    ],
    'backdoor_patterns': [
        (r'move_uploaded_file\s*\(.*\$_(?:GET|POST|REQUEST)', 'Uploaded file from user input'),
        (r'file_put_contents\s*\(.*\$_(?:GET|POST|REQUEST)', 'Write file from user input'),
        (r'fwrite\s*\(.*\$_(?:GET|POST|REQUEST)', 'Write file from user input'),
        (r'chmod\s*\(.*\d{3,4}\)', 'File permission change'),
    ],
}

BACKUP_FILE_PATTERNS = [
    r'\.bak$', r'\.backup$', r'\.old$', r'\.orig$',
    r'\.swp$', r'~$', r'\.save$', r'\.copy$',
    r'\.php\.old$', r'\.php\.bak$', r'\.php~$',
    r'\.sql\.bak$', r'\.sql\.old$',
    r'\.env\.bak$', r'\.env\.old$', r'\.env\.save$',
]

KNOWN_BACKDOOR_FILES = [
    'shell.php', 'shell.php5', 'cmd.php', 'wso.php',
    'backdoor.php', 'c99.php', 'r57.php', 'b374k.php',
    'webshell.php', 'webadmin.php', 'php_console.php',
    'hacker.php', '1337.php', 'x.php', 'safe.php',
    'adminer.php',
]

SKIP_DIRECTORIES = {
    'vendor', 'node_modules', 'storage', 'cache', 'bower_components',
    '.git', '.svn', '.hg', '.idea', '.vscode', '__pycache__',
    'logs', 'log', 'tmp', 'temp', 'backup', 'backups',
    'compiled', 'dist', 'build', '.next', '.nuxt', 'coverage',
}

SCAN_EXTENSIONS = {
    '.php', '.phtml', '.php3', '.php4', '.php5', '.php7', '.pht', '.inc',
    '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.py', '.sh', '.bash',
    '.html', '.htm', '.htaccess', '.ini', '.conf', '.env', '.suspected',
}


BUNDLED_DATABASE = Path(__file__).resolve().parents[2] / 'assets' / 'signatures.json'


class SignatureDatabase:
    """Loads updateable JSON rules while retaining safe built-in fallbacks."""

    def __init__(self, path: Path | None = None):
        installed = get_data_dir() / 'signatures.json'
        self.path = Path(path) if path else (installed if installed.is_file() else BUNDLED_DATABASE)
        self.version = 'builtin'
        self.build = 0
        self.rules: list[dict] = []
        self.hashes: dict[str, dict] = {}
        self.filenames = set(KNOWN_BACKDOOR_FILES)
        self._load()

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(data, dict):
            return
        self.version = str(data.get('version', self.version))
        self.build = int(data.get('build', self.build))
        for raw in data.get('rules', []):
            if not isinstance(raw, dict) or not raw.get('pattern') or not raw.get('description'):
                continue
            try:
                compiled = re.compile(raw['pattern'], re.IGNORECASE)
            except (re.error, TypeError):
                continue
            extensions = raw.get('extensions', [])
            self.rules.append({
                'id': str(raw.get('id', 'external_rule')),
                'category': str(raw.get('category', 'malware')),
                'severity': str(raw.get('severity', 'high')).lower(),
                'extensions': {str(ext).lower() for ext in extensions},
                'regex': compiled,
                'description': str(raw['description']),
            })
        for raw in data.get('hashes', []):
            digest = str(raw.get('sha256', '')).lower()
            if re.fullmatch(r'[a-f0-9]{64}', digest):
                self.hashes[digest] = raw
        self.filenames.update(str(name).lower() for name in data.get('filenames', []))

    @property
    def pattern_count(self) -> int:
        return sum(len(patterns) for patterns in SIGNATURES.values()) + len(self.rules)

    @property
    def category_count(self) -> int:
        return len(SIGNATURES) + len({rule['category'] for rule in self.rules})

    def rules_for(self, extension: str) -> list[dict]:
        ext = extension.lower()
        return [rule for rule in self.rules if not rule['extensions'] or ext in rule['extensions']]
