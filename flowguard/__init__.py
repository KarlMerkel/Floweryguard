"""Flowery (Glue) — DPI bypass tool для мобильного тетеринга."""

__version__ = "1.3.0"
__author__ = "Flowery Team"

import sys

# Регистрируем глобальный алиас Floweryguard -> flowguard
if "Floweryguard" not in sys.modules:
    try:
        import Floweryguard
    except Exception:
        sys.modules["Floweryguard"] = sys.modules[__name__]
