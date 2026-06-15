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
    'compiled', 'upload', 'uploads',
}

SCAN_EXTENSIONS = {'.php', '.phtml', '.php3', '.php4', '.php5', '.php7', '.pht', '.suspected'}
