"""Модуль централизованного структурированного логирования Flowery (Glue).
Логирует все события и диагностику в отдельный файл сессии в папке Документы пользователя,
не засоряя интерактивную консоль и интерфейс программы.
Формат имени файла: Flowery_v<версия>_<дата_время_запуска>.log
"""

import os
import re
import sys
import logging
import datetime
from typing import Optional

_ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def strip_ansi(text: str) -> str:
    """Удаляет ANSI управляющие последовательности (цветовые коды) из строки."""
    return _ANSI_ESCAPE_RE.sub("", text)


class AnsiStrippingFormatter(logging.Formatter):
    """Форматтер, автоматически удаляющий цветные escape-последовательности перед записью в файл."""
    def format(self, record: logging.LogRecord) -> str:
        orig_msg = record.msg
        if isinstance(orig_msg, str):
            record.msg = strip_ansi(orig_msg)
        res = super().format(record)
        record.msg = orig_msg
        return res


def get_documents_dir() -> str:
    """Возвращает системный путь к папке 'Документы' текущего пользователя Windows."""
    if sys.platform == "win32":
        try:
            import ctypes.wintypes
            buf = ctypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)
            # CSIDL_PERSONAL = 5 (папка My Documents / Документы)
            ctypes.windll.shell32.SHGetFolderPathW(None, 5, None, 0, buf)
            if buf.value and os.path.isdir(buf.value):
                return buf.value
        except Exception as e:
            sys.stderr.write(f"[Logger] Не удалось получить папку Документы через WinAPI: {e}\n")

    # Фолбэки для кроссплатформенности и нестандартных профилей
    home = os.path.expanduser("~")
    docs = os.path.join(home, "Documents")
    if os.path.isdir(docs):
        return docs
    docs_ru = os.path.join(home, "Документы")
    if os.path.isdir(docs_ru):
        return docs_ru
    return home


def get_log_dir() -> str:
    """Возвращает директорию для логов Flowery.
    При наличии переменной окружения FLOWERY_HOME логи пишутся в $FLOWERY_HOME/logs,
    что исключает загрязнение папки Документы пользователя во время тестов (B7).
    """
    flowery_home = os.environ.get("FLOWERY_HOME")
    if flowery_home:
        path = os.path.join(flowery_home, "logs")
        try:
            os.makedirs(path, exist_ok=True)
            return path
        except Exception as e:
            sys.stderr.write(f"[Logger] Не удалось создать директорию логов '{path}': {e}\n")
    doc_dir = get_documents_dir()
    path = os.path.join(doc_dir, "Flowery", "logs")
    try:
        os.makedirs(path, exist_ok=True)
        return path
    except Exception as e:
        sys.stderr.write(f"[Logger] Не удалось создать директорию логов '{path}': {e}\n")
    # Фолбэк на временную папку или локальную
    fallback = os.path.join(os.environ.get("TEMP", os.getcwd()), "Flowery_logs")
    os.makedirs(fallback, exist_ok=True)
    return fallback


def _get_app_version() -> str:
    try:
        try:
            from Floweryguard import __version__
        except ImportError:
            from flowguard import __version__
        return __version__
    except Exception:
        try:
            from Floweryguard import __version__
            return __version__
        except Exception:
            return "1.3.0"


# Единый путь к файлу текущей запущенной сессии: Flowery_v<версия>_<время_запуска>.log
_SESSION_TIMESTAMP = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
_CURRENT_LOG_FILE: Optional[str] = None
_LOGGER: Optional[logging.Logger] = None


def get_current_log_path() -> str:
    """Возвращает полный путь к файлу логов текущей сессии."""
    global _CURRENT_LOG_FILE
    expected_dir = get_log_dir()
    if _CURRENT_LOG_FILE is None or os.path.dirname(_CURRENT_LOG_FILE) != expected_dir:
        _CURRENT_LOG_FILE = os.path.join(
            expected_dir,
            f"Flowery_v{_get_app_version()}_{_SESSION_TIMESTAMP}.log"
        )
    return _CURRENT_LOG_FILE


def open_current_log_file() -> bool:
    """Открывает текущий файл логов в ассоциированном приложении Windows (Блокнот / текстовый редактор)."""
    log_path = get_current_log_path()
    try:
        # Убедимся, что файл создан на диске
        if not os.path.exists(log_path):
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"--- Flowery v{_get_app_version()} Session Started: {_SESSION_TIMESTAMP} ---\n")

        if sys.platform == "win32":
            os.startfile(log_path)
            return True
        else:
            import subprocess
            subprocess.Popen(["xdg-open", log_path])
            return True
    except Exception as e:
        print(f"[!] Не удалось открыть файл логов: {e}")
        return False


def cleanup_old_logs(max_age_days: int = 7) -> int:
    """Удаляет файлы логов старше max_age_days дней. Возвращает количество удалённых."""
    log_dir = get_log_dir()
    removed = 0
    cutoff = datetime.datetime.now().timestamp() - (max_age_days * 86400)
    try:
        for fname in os.listdir(log_dir):
            if fname.startswith("Flowery_v") and fname.endswith(".log"):
                fpath = os.path.join(log_dir, fname)
                try:
                    if os.path.getmtime(fpath) < cutoff:
                        os.remove(fpath)
                        removed += 1
                except Exception as e:
                    sys.stderr.write(f"[Logger] Не удалось удалить старый лог {fpath}: {e}\n")
    except Exception as e:
        sys.stderr.write(f"[Logger] Ошибка при очистке старых логов: {e}\n")
    return removed


def setup_logger(force_reconfigure: bool = False) -> logging.Logger:
    """Настраивает логгер Flowery на запись в отдельный файл сессии в Документах (или FLOWERY_HOME)."""
    global _LOGGER, _CURRENT_LOG_FILE
    expected_dir = get_log_dir()
    logger = logging.getLogger("Flowery")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    # Дедупликация хэндлеров: исключаем повторное добавление FileHandler (B11)
    file_handlers = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
    if file_handlers and not force_reconfigure:
        current_h = file_handlers[0]
        base_dir = os.path.dirname(getattr(current_h, "baseFilename", ""))
        if os.path.normpath(base_dir) == os.path.normpath(expected_dir):
            for extra_h in file_handlers[1:]:
                logger.removeHandler(extra_h)
                try:
                    extra_h.close()
                except Exception:
                    pass
            _LOGGER = logger
            return logger
        else:
            # Директория логов изменилась (например, задан FLOWERY_HOME во время тестов)
            for h in file_handlers:
                logger.removeHandler(h)
                try:
                    h.close()
                except Exception:
                    pass
            _CURRENT_LOG_FILE = None

    log_file = get_current_log_path()

    try:
        cleanup_old_logs(7)
    except Exception as e:
        sys.stderr.write(f"[Logger] Ошибка автоматической ротации логов: {e}\n")

    try:
        handler = logging.FileHandler(log_file, encoding="utf-8", mode="a")
        formatter = AnsiStrippingFormatter(
            "%(asctime)s [%(levelname)s] [%(threadName)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.info(f"=== Flowery v{_get_app_version()} Сессия запущена ({_SESSION_TIMESTAMP}) ===")
        logger.info(f"Файл логов: {log_file}")
        logger.info(f"Python: {sys.version.replace(chr(10), ' ')}")
        logger.info(f"Executable: {sys.executable}")
        logger.info(f"CWD: {os.getcwd()}")
        logger.info(f"Frozen: {getattr(sys, 'frozen', False)}")
        try:
            import platform
            logger.info(f"OS Platform: {platform.platform()} ({sys.platform})")
        except Exception:
            logger.info(f"OS Platform: {sys.platform}")
        logger.info(f"CLI Аргументы: {sys.argv}")
    except Exception as e:
        sys.stderr.write(f"[Logger CRITICAL] Не удалось настроить FileHandler для {log_file}: {e}\n")

    _LOGGER = logger
    return logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Возвращает именованный логгер Flowery."""
    if _LOGGER is None:
        setup_logger()
    if name:
        return logging.getLogger(f"Flowery.{name}")
    return _LOGGER or logging.getLogger("Flowery")


# Глобальный экземпляр логгера для прямого импорта
logger: logging.Logger = get_logger()
