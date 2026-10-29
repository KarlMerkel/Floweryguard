"""Отдельное окно живого журнала: только чтение файла, без запуска Flowery."""
import argparse
import codecs
import os
from pathlib import Path
import re
import subprocess
import sys
import time


_window_process = None
_ANSI = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


class LogTail:
    """Читает последние строки и продолжение UTF-8, ограничивая разовый объём."""
    def __init__(self, path, history_lines=200):
        self.stream = open(path, 'rb')
        self.history_lines = history_lines
        self.decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
        self.initial = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stream.close()

    def read_updates(self):
        size = os.fstat(self.stream.fileno()).st_size
        trimmed = False
        if self.initial:
            offset = max(0, size - 65536)
            self.stream.seek(offset)
            trimmed = offset > 0
        elif size < self.stream.tell():
            self.stream.seek(0)
            self.decoder.reset()
        data = self.stream.read(65536)
        if trimmed:
            data = data.partition(b'\n')[2]
        text = self.decoder.decode(data, final=False)
        if self.initial:
            text = ''.join(text.splitlines(keepends=True)[-self.history_lines:])
            self.initial = False
        text = _ANSI.sub('', text)
        return ''.join(c for c in text if c >= ' ' or c in '\n\t')


def open_log_window(path):
    """Немедленно возвращается в меню; повторный выбор не создаёт дубликат."""
    global _window_process
    if _window_process is not None and _window_process.poll() is None:
        return True
    if sys.platform != 'win32':
        return False
    path = str(Path(path).resolve())
    if getattr(sys, 'frozen', False):
        command = [sys.executable, '--log-window', path]
    else:
        command = [sys.executable, '-u', str(Path(__file__).resolve()), path]
    try:
        _window_process = subprocess.Popen(command, creationflags=subprocess.CREATE_NEW_CONSOLE,
                                           close_fds=True)
        return True
    except OSError:
        _window_process = None
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', help='Файл текущей сессии Flowery')
    parser.add_argument('--once', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    print('Flowery — живой журнал')
    print('Закройте это окно или нажмите Ctrl+C. Прокси продолжит работу.')
    print('Файл: ' + args.path, flush=True)
    try:
        with LogTail(args.path) as tail:
            while True:
                text = tail.read_updates()
                if text:
                    print(text, end='', flush=True)
                if args.once:
                    return 0
                time.sleep(.2)
    except KeyboardInterrupt:
        return 0
    except OSError as error:
        print('Не удалось прочитать журнал: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
