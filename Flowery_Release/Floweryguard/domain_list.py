"""Ограниченная загрузка и атомарное обновление списка доменов."""
import os
from pathlib import Path
import shutil
import tempfile
import urllib.parse
import urllib.request

from .certificate_diagnostics import validate_host

COMMUNITY_URL = 'https://raw.githubusercontent.com/KarlMerkel/Floweryguard/main/whitelist.txt'
MAX_BYTES = 1024 * 1024


def fetch_domains(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Для списка нужна HTTPS-ссылка без логина и пароля')
    request = urllib.request.Request(url, headers={'User-Agent': 'Flowery/1.3.0'})
    with urllib.request.urlopen(request, timeout=10.0) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError('Список превышает ограничение 1 МиБ')
    domains = set()
    for line in data.decode('utf-8-sig').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('*.'):
            line = line[2:]
        host = validate_host(line)
        if '.' not in host or ':' in host or host.replace('.', '').isdigit():
            raise ValueError('В списке ожидаются доменные имена')
        domains.add(host)
    if not domains:
        raise ValueError('Загруженный список не содержит доменов')
    return domains


def save_domains(path, domains):
    path = Path(path)
    text = '# Flowery — список доменов\n' + '\n'.join(sorted(domains)) + '\n'
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=str(path.parent),
                                         prefix=path.name + '.', suffix='.tmp', delete=False) as stream:
            temporary = stream.name
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        if path.exists():
            shutil.copy2(path, str(path) + '.bak')
        os.replace(temporary, path)
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)
