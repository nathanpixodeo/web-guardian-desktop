import re
import os


def detect_cms_type(root_path):
    if os.path.isfile(os.path.join(root_path, 'wp-config.php')):
        return 'wordpress'
    if os.path.isfile(os.path.join(root_path, 'artisan')) and os.path.isdir(os.path.join(root_path, 'app')):
        return 'laravel'
    if os.path.isfile(os.path.join(root_path, 'config', 'settings.inc.php')):
        return 'prestashop'
    return 'generic'


def check_laravel(path):
    findings = []
    env_file = os.path.join(path, '.env')
    if os.path.isfile(env_file):
        try:
            with open(env_file, 'r', errors='ignore') as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    if line.startswith('#') or '=' not in line:
                        continue
                    if re.match(r'^APP_KEY\s*=\s*$', line):
                        findings.append({
                            'file': env_file, 'line': i, 'severity': 'critical',
                            'message': 'APP_KEY is empty',
                        })
                    if re.match(r'^APP_KEY\s*=\s*["\']?base64:[A-Za-z0-9+\/=]{10,20}=["\']?$', line):
                        findings.append({
                            'file': env_file, 'line': i, 'severity': 'high',
                            'message': 'APP_KEY appears too short',
                        })
                    if re.match(r'^APP_KEY\s*=\s*["\']?SomeRandomKey["\']?$', line, re.I):
                        findings.append({
                            'file': env_file, 'line': i, 'severity': 'critical',
                            'message': 'Default APP_KEY detected',
                        })
                    if re.match(r'^APP_DEBUG\s*=\s*true', line, re.I):
                        findings.append({
                            'file': env_file, 'line': i, 'severity': 'high',
                            'message': 'APP_DEBUG is enabled in .env',
                        })
                    if re.match(r'^DB_PASSWORD\s*=\s*["\']?(root|password|123456|secret)?["\']?$', line, re.I):
                        pw = line.split('=', 1)[1].strip().strip('"\'')
                        if pw.lower() in ('', 'root', 'password', '123456', 'secret'):
                            findings.append({
                                'file': env_file, 'line': i, 'severity': 'critical',
                                'message': f'Weak database password: "{pw if pw else "empty"}"',
                            })
        except PermissionError:
            pass

    public_env = os.path.join(path, 'public', '.env')
    if os.path.isfile(public_env):
        findings.append({
            'file': public_env, 'line': 0, 'severity': 'critical',
            'message': '.env exposed in public/ directory',
        })

    return findings


def check_wordpress(path):
    findings = []
    wp_config = os.path.join(path, 'wp-config.php')
    if os.path.isfile(wp_config):
        try:
            with open(wp_config, 'r', errors='ignore') as f:
                content = f.read()
            if re.search(r"define\s*\(\s*['\"]WP_DEBUG['\"]\s*,\s*true\s*\)", content, re.I):
                findings.append({
                    'file': wp_config, 'line': 0, 'severity': 'medium',
                    'message': 'WP_DEBUG is enabled in production',
                })
            if re.search(r"define\s*\(\s*['\"]AUTH_KEY['\"]\s*,\s*['\"]put your unique phrase here['\"]", content, re.I):
                findings.append({
                    'file': wp_config, 'line': 0, 'severity': 'critical',
                    'message': 'Default WordPress salts detected',
                })
            if re.search(r"define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"](root|password)['\"]", content, re.I):
                findings.append({
                    'file': wp_config, 'line': 0, 'severity': 'critical',
                    'message': 'Weak database password in wp-config.php',
                })
        except PermissionError:
            pass

    uploads = os.path.join(path, 'wp-content', 'uploads')
    if os.path.isdir(uploads):
        php_count = 0
        for root, dirs, files in os.walk(uploads):
            for f in files:
                if f.endswith(('.php', '.phtml', '.php5')):
                    php_count += 1
        if php_count:
            findings.append({
                'file': uploads, 'line': 0, 'severity': 'critical',
                'message': f'{php_count} PHP file(s) in wp-content/uploads',
            })

    return findings


def check_prestashop(path):
    findings = []
    settings_file = os.path.join(path, 'config', 'settings.inc.php')
    if os.path.isfile(settings_file):
        try:
            with open(settings_file, 'r', errors='ignore') as f:
                content = f.read()
            m = re.search(r"_DB_PASSWD_\s*=\s*['\"](\S+)['\"]", content)
            if m and m.group(1) in ('', 'root', 'password', '123456'):
                findings.append({
                    'file': settings_file, 'line': 0, 'severity': 'critical',
                    'message': f'Weak PrestaShop DB password: "{m.group(1) or "empty"}"',
                })
            if re.search(r"_PS_MODE_DEV_\s*,\s*true", content, re.I):
                findings.append({
                    'file': settings_file, 'line': 0, 'severity': 'high',
                    'message': 'PrestaShop in dev mode (_PS_MODE_DEV_)',
                })
        except PermissionError:
            pass

    install = os.path.join(path, 'install')
    if os.path.isdir(install):
        findings.append({
            'file': install, 'line': 0, 'severity': 'critical',
            'message': 'Install directory still exists',
        })

    return findings
