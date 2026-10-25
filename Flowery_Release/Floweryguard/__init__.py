"""Flowery (Glue) — DPI bypass tool для мобильного тетеринга."""

__version__ = "1.3.0"
__author__ = "Flowery Team"

import sys
import importlib
from importlib.abc import MetaPathFinder

# 1. Регистрируем глобальный алиас flowguard -> Floweryguard
if "flowguard" not in sys.modules:
    try:
        import flowguard
    except Exception:
        sys.modules["flowguard"] = sys.modules[__name__]


# 2. MetaPathFinder для динамического разрешения flowguard.<submodule> -> Floweryguard.<submodule>
class FlowguardReleaseAliasFinder(MetaPathFinder):
    @classmethod
    def find_spec(cls, fullname, path=None, target=None):
        if fullname.startswith("flowguard."):
            subname = fullname[len("flowguard."):]
            target_name = f"Floweryguard.{subname}"
            try:
                mod = importlib.import_module(target_name)
                sys.modules[fullname] = mod
                return getattr(mod, "__spec__", None)
            except Exception:
                return None
        return None


if not any(getattr(f, "__name__", "") == "FlowguardReleaseAliasFinder" for f in sys.meta_path):
    sys.meta_path.insert(0, FlowguardReleaseAliasFinder)
