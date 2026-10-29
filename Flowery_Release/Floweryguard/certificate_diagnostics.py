"""Проверка TLS без загрузки страницы и без отключения проверки сертификата."""
import argparse
import http.client
import ipaddress
import json
import re
import socket
import ssl
import time


def validate_host(host):
    host = host.strip().rstrip('.')
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    host = host.encode('idna').decode('ascii').lower()
    if (len(host) > 253 or not host or any(
            not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
            for label in host.split('.'))):
        raise ValueError('Укажите только имя сайта, без URL, пути и параметров')
    return host


def parse_proxy(value):
    host, separator, port = value.rpartition(':')
    if not separator or not port.isdigit() or not 0 < int(port) <= 65535:
        raise ValueError('Прокси задаётся как адрес:порт')
    return validate_host(host.strip('[]')), int(port)


def check_certificate(host, port=443, proxy=None, timeout=8.0):
    host = validate_host(host)
    if not 0 < port <= 65535:
        raise ValueError('Порт должен быть от 1 до 65535')
    started = time.monotonic()
    result = {'host': host, 'port': port, 'via': 'proxy' if proxy else 'direct',
              'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    raw = tls = tunnel = None
    try:
        context = ssl.create_default_context()
        if proxy:
            tunnel = http.client.HTTPConnection(proxy[0], proxy[1], timeout=timeout)
            tunnel.set_tunnel(host, port)
            tunnel.connect()
            raw = tunnel.sock
        else:
            raw = socket.create_connection((host, port), timeout=timeout)
        tls = context.wrap_socket(raw, server_hostname=host)
        result.update(status='verified', tls=tls.version(), certificate=tls.getpeercert(),
                      peer=tls.getpeername()[0])
    except ssl.SSLCertVerificationError as error:
        result.update(status='certificate_error', verify_code=error.verify_code,
                      verify_message=error.verify_message)
    except (OSError, http.client.HTTPException) as error:
        result.update(status='connection_error', error=type(error).__name__,
                      errno=getattr(error, 'errno', None))
    finally:
        if tls is not None:
            tls.close()
        elif raw is not None:
            raw.close()
        if tunnel is not None:
            tunnel.close()
    result['elapsed_seconds'] = round(time.monotonic() - started, 3)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('host', help='Имя сайта без URL')
    parser.add_argument('--proxy', help='HTTP-прокси, например 127.0.0.1:8118')
    args = parser.parse_args()
    try:
        result = check_certificate(args.host, proxy=parse_proxy(args.proxy) if args.proxy else None)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['status'] == 'verified' else 1


if __name__ == '__main__':
    raise SystemExit(main())
