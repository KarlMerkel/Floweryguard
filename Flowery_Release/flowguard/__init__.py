"""Compatibility alias shim for flowguard to Floweryguard (Flowery_Release)."""
import sys
import importlib
import pkgutil
from importlib.abc import MetaPathFinder

import Floweryguard

# 1. Алиас корневого пакета
sys.modules[__name__] = Floweryguard

# 2. Направляем __path__ на Floweryguard
__path__ = list(Floweryguard.__path__)

# 3. Реэкспорт атрибутов
for _attr in dir(Floweryguard):
    if not _attr.startswith("__"):
        globals()[_attr] = getattr(Floweryguard, _attr)


# 4. MetaPathFinder для динамического перехвата любых импортов flowguard.<submodule>
class FlowguardReleaseFinder(MetaPathFinder):
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


if not any(getattr(f, "__name__", "") == "FlowguardReleaseFinder" for f in sys.meta_path):
    sys.meta_path.insert(0, FlowguardReleaseFinder)

# 5. Предзаполнение sys.modules для всех подмодулей Floweryguard
for _mod_info in pkgutil.iter_modules(Floweryguard.__path__):
    _submod_name = _mod_info.name
    try:
        _mod = importlib.import_module(f"Floweryguard.{_submod_name}")
        sys.modules[f"flowguard.{_submod_name}"] = _mod
    except Exception:
        pass
