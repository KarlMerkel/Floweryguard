"""Запуск системных команд Windows (netsh, ipconfig) с ограничением времени.

Сетевые команды Windows могут выполняться десятки секунд (например, проверка
DNS-сервера в `netsh ... set dns`). Ни одна команда не должна блокировать запуск
или восстановление настроек без срока.
"""

import subprocess
import sys
from typing import List, Optional

from flowguard.logger import get_logger

logger = get_logger("SysCmd")

DEFAULT_TIMEOUT = 10.0


def run_command(args: List[str], timeout: float = DEFAULT_TIMEOUT,
                capture: bool = False) -> Optional[subprocess.CompletedProcess]:
    """Выполняет команду и возвращает результат.

    None означает, что результат неизвестен: команда не запустилась или превысила
    срок. Вызывающий код должен считать такое изменение неподтверждённым.
    """
    creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    output = subprocess.PIPE if capture else subprocess.DEVNULL
    try:
        return subprocess.run(
            args,
            stdout=output,
            stderr=output,
            creationflags=creationflags,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("Команда превысила срок %.0f с: %s", timeout, " ".join(args))
    except Exception as e:
        logger.error("Ошибка запуска команды %s: %s", " ".join(args), e)
    return None


def succeeded(result: Optional[subprocess.CompletedProcess]) -> bool:
    """True только для завершённой команды с кодом 0."""
    return result is not None and result.returncode == 0
