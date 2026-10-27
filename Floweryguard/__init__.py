"""Compatibility alias shim for Floweryguard -> flowguard (B15).

Гарантирует 100% обратную совместимость для всех существующих тестов и скриптов,
импортирующих Floweryguard или его подмодули.
Каноническим пакетом является flowguard.
"""
import sys
import importlib
import pkgutil
from importlib.abc import MetaPathFinder

import flowguard

# 1. Алиас корневого пакета
sys.modules[__name__] = flowguard

# 2. Направляем __path__ на flowguard
__path__ = list(flowguard.__path__)

# 3. Реэкспорт атрибутов пакета
for _attr in dir(flowguard):
    if not _attr.startswith("__"):
        globals()[_attr] = getattr(flowguard, _attr)


# 4. MetaPathFinder для динамического перехвата любых импортов Floweryguard.<submodule>
class FloweryguardAliasFinder(MetaPathFinder):
    @classmethod
    def find_spec(cls, fullname, path=None, target=None):
        if fullname.startswith("Floweryguard."):
            subname = fullname[len("Floweryguard."):]
            target_name = f"flowguard.{subname}"
            try:
                mod = importlib.import_module(target_name)
                sys.modules[fullname] = mod
                return getattr(mod, "__spec__", None)
            except Exception:
                return None
        return None


if not any(getattr(f, "__name__", "") == "FloweryguardAliasFinder" for f in sys.meta_path):
    sys.meta_path.insert(0, FloweryguardAliasFinder)

# 5. Предзаполнение sys.modules для всех подмодулей flowguard
for _mod_info in pkgutil.iter_modules(flowguard.__path__):
    _submod_name = _mod_info.name
    try:
        _mod = importlib.import_module(f"flowguard.{_submod_name}")
        sys.modules[f"Floweryguard.{_submod_name}"] = _mod
        setattr(flowguard, _submod_name, _mod)
        globals()[_submod_name] = _mod
    except Exception:
        pass
