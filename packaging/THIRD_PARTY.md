# Внешние компоненты

Код Flowery распространяется по MIT (`LICENSE`). Для включённых сторонних компонентов действуют их собственные лицензии. Тексты находятся в `licenses/` двоичного комплекта и `packaging/licenses/` исходного комплекта.

| Компонент | Назначение | Исходники и сведения |
|---|---|---|
| Python 3.11.9 | Интерпретатор внутри автономного EXE | https://www.python.org/downloads/release/python-3119/ |
| PyInstaller 6.22.3 | Загрузчик автономного EXE; лицензия с исключением для создаваемых приложений | https://github.com/pyinstaller/pyinstaller |
| zapret / winws | Обработка UDP и дополнительные пакетные режимы | https://github.com/bol-van/zapret |
| WinDivert | Перехват сетевых пакетов помощником | https://github.com/basil00/WinDivert |
| Cygwin 3.4.10 | Среда выполнения winws | https://cygwin.com/licensing.html и https://cygwin.com/git/newlib-cygwin.git |

Версия winws/WinDivert не устанавливается по метаданным имеющихся бинарников; их точные SHA-256 записаны в `BUILD_INFO.json`. Исходный ZIP Flowery содержит Python-код проекта и используемые бинарные компоненты, а не полный исходный код всех сторонних зависимостей. Для сторонних исходников используйте указанные проекты.

Тексты лицензий получены из `bol-van/zapret:docs/LICENSE.txt`, `basil00/WinDivert:LICENSE`, `mirror/newlib-cygwin:winsup/{COPYING,COPYING.LIB,CYGWIN_LICENSE}`, а также из локальных установок Python/PyInstaller. Ссылки на upstream не подтверждают происхождение конкретной сборки DLL/SYS; перед публичным распространением необходимо сверить версии бинарников и условия их распространения.
