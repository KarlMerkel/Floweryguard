"""Модуль работы с системным треем Windows (System Tray / Background Mode).
Реализован строго на стандартной библиотеке Python через Win32 API (ctypes).
Позволяет сворачивать Flowery в фоновый режим без висящего окна консоли,
показывать контекстное меню, управлять профилями и возвращать окно по клику.
"""

import os
import sys
import ctypes
from ctypes import wintypes
import threading
import time
from typing import Optional, Callable

# Win32 константы
WM_USER = 0x0400
WM_APP = 0x8000
WM_TRAYICON = WM_APP + 1

WM_COMMAND = 0x0111
WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_NULL = 0x0000

WM_LBUTTONUP = 0x0202
WM_LBUTTONDBLCLK = 0x0203
WM_RBUTTONUP = 0x0205

NIM_ADD = 0x00000000
NIM_MODIFY = 0x00000001
NIM_DELETE = 0x00000002
NIM_SETVERSION = 0x00000004

NIF_MESSAGE = 0x00000001
NIF_ICON = 0x00000002
NIF_TIP = 0x00000004
NIF_INFO = 0x00000010

SW_HIDE = 0
SW_NORMAL = 1
SW_SHOW = 5
SW_RESTORE = 9

MF_STRING = 0x00000000
MF_SEPARATOR = 0x00000800
MF_GRAYED = 0x00000001
MF_DISABLED = 0x00000002

TPM_RIGHTBUTTON = 0x0002
TPM_BOTTOMALIGN = 0x0020

ID_TRAY_TITLE = 1001
ID_TRAY_TOGGLE_CONSOLE = 1002
ID_TRAY_PROFILE_INFO = 1003
ID_TRAY_SWITCH_PROFILE = 1004
ID_TRAY_EXIT = 1005
ID_TRAY_OPEN_LOG = 1006

user32 = ctypes.windll.user32 if sys.platform == "win32" else None
shell32 = ctypes.windll.shell32 if sys.platform == "win32" else None
kernel32 = ctypes.windll.kernel32 if sys.platform == "win32" else None


if sys.platform == "win32":
    class NOTIFYICONDATAW(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("hWnd", wintypes.HWND),
            ("uID", wintypes.UINT),
            ("uFlags", wintypes.UINT),
            ("uCallbackMessage", wintypes.UINT),
            ("hIcon", wintypes.HICON),
            ("szTip", wintypes.WCHAR * 128),
            ("dwState", wintypes.DWORD),
            ("dwStateMask", wintypes.DWORD),
            ("szInfo", wintypes.WCHAR * 256),
            ("uTimeoutOrVersion", wintypes.UINT),
            ("szInfoTitle", wintypes.WCHAR * 64),
            ("dwInfoFlags", wintypes.DWORD),
            ("guidItem", ctypes.c_byte * 16),
            ("hBalloonIcon", wintypes.HICON),
        ]

    LRESULT = ctypes.c_long if ctypes.sizeof(ctypes.c_void_p) == 4 else ctypes.c_longlong
    WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

    # 64-bit безопасные сигнатуры User32
    user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user32.DefWindowProcW.restype = LRESULT
    user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user32.PostMessageW.restype = wintypes.BOOL
    user32.PostQuitMessage.argtypes = [ctypes.c_int]
    user32.PostQuitMessage.restype = None

    class WNDCLASSEXW(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.UINT),
            ("style", wintypes.UINT),
            ("lpfnWndProc", WNDPROC),
            ("cbClsExtra", ctypes.c_int),
            ("cbWndExtra", ctypes.c_int),
            ("hInstance", wintypes.HINSTANCE),
            ("hIcon", wintypes.HICON),
            ("hCursor", wintypes.HANDLE),
            ("hbrBackground", wintypes.HANDLE),
            ("lpszMenuName", wintypes.LPCWSTR),
            ("lpszClassName", wintypes.LPCWSTR),
            ("hIconSm", wintypes.HICON),
        ]

    user32.RegisterClassExW.argtypes = [ctypes.POINTER(WNDCLASSEXW)]
    user32.RegisterClassExW.restype = wintypes.ATOM
    user32.CreateWindowExW.argtypes = [
        wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
        wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID
    ]
    user32.CreateWindowExW.restype = wintypes.HWND
    user32.DestroyWindow.argtypes = [wintypes.HWND]
    user32.DestroyWindow.restype = wintypes.BOOL
    user32.LoadImageW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT, ctypes.c_int, ctypes.c_int, wintypes.UINT]
    user32.LoadImageW.restype = wintypes.HANDLE
    user32.LoadIconW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]
    user32.LoadIconW.restype = wintypes.HICON
    user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
    user32.GetMessageW.restype = wintypes.BOOL
    user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
    user32.TranslateMessage.restype = wintypes.BOOL
    user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
    user32.DispatchMessageW.restype = LRESULT
    user32.CreatePopupMenu.argtypes = []
    user32.CreatePopupMenu.restype = wintypes.HMENU
    user32.TrackPopupMenuEx.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_int, ctypes.c_int, wintypes.HWND, wintypes.LPVOID]
    user32.TrackPopupMenuEx.restype = wintypes.BOOL
    user32.AppendMenuW.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_uint64, wintypes.LPCWSTR]
    user32.AppendMenuW.restype = wintypes.BOOL
    user32.DestroyMenu.argtypes = [wintypes.HMENU]
    user32.DestroyMenu.restype = wintypes.BOOL
    user32.SetForegroundWindow.argtypes = [wintypes.HWND]
    user32.SetForegroundWindow.restype = wintypes.BOOL
    user32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
    user32.GetCursorPos.restype = wintypes.BOOL
    user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    user32.ShowWindow.restype = wintypes.BOOL
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.IsWindowVisible.restype = wintypes.BOOL
    user32.RegisterWindowMessageW.argtypes = [wintypes.LPCWSTR]
    user32.RegisterWindowMessageW.restype = wintypes.UINT

    shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]
    shell32.Shell_NotifyIconW.restype = wintypes.BOOL


class FloweryTrayIcon:
    """Управление системным треем и фоновым режимом Flowery на чистом Win32 API."""

    def __init__(
        self,
        app_name: str = "Flowery (Glue)",
        on_exit_callback: Optional[Callable[[], None]] = None,
        get_profile_name_callback: Optional[Callable[[], str]] = None
    ):
        self.app_name = app_name
        self.on_exit_callback = on_exit_callback
        self.get_profile_name_callback = get_profile_name_callback

        self.hwnd = None
        self.h_icon = None
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self._wnd_proc_ref = None
        self._wm_taskbar_created = 0
        self._nid: Optional[NOTIFYICONDATAW] = None

    def start(self, hide_console: bool = False) -> bool:
        """Запускает поток обработки сообщений трея."""
        if sys.platform != "win32" or not user32:
            return False

        if self.is_running:
            return True

        self.is_running = True
        started_event = threading.Event()

        def _tray_worker():
            try:
                self._init_window()
                started_event.set()
                if hide_console:
                    self.hide_console_window()
                self._message_loop()
            except Exception as e:
                try:
                    from Floweryguard.logger import logger
                    logger.error(f"[Tray] Ошибка в потоке трея: {e}")
                except Exception:
                    pass
                started_event.set()
                self.is_running = False

        self._thread = threading.Thread(target=_tray_worker, daemon=True, name="FloweryTrayThread")
        self._thread.start()
        started_event.wait(timeout=2.0)
        return True

    def _init_window(self) -> None:
        """Регистрирует скрытое окно для обработки событий мыши трея."""
        self._wm_taskbar_created = user32.RegisterWindowMessageW("TaskbarCreated")

        def _wnd_proc(hwnd, msg, wparam, lparam):
            try:
                if self._wm_taskbar_created and msg == self._wm_taskbar_created:
                    # Проводник перезапустился — восстанавливаем иконку в трее
                    self._add_tray_icon()
                    return 0
                elif msg == WM_TRAYICON:
                    event = lparam & 0xFFFF
                    if event == WM_RBUTTONUP:
                        self._show_context_menu()
                        return 0
                    elif event == WM_LBUTTONDBLCLK or event == WM_LBUTTONUP:
                        if event == WM_LBUTTONDBLCLK:
                            self.toggle_console_window()
                        return 0
                elif msg == WM_COMMAND:
                    cmd_id = wparam & 0xFFFF
                    if cmd_id == ID_TRAY_TOGGLE_CONSOLE:
                        self.toggle_console_window()
                    elif cmd_id == ID_TRAY_OPEN_LOG:
                        try:
                            from Floweryguard.logger import open_current_log_file
                            open_current_log_file()
                        except Exception:
                            pass
                    elif cmd_id == ID_TRAY_EXIT:
                        self.stop()
                        if self.on_exit_callback:
                            self.on_exit_callback()
                    return 0
                elif msg == WM_DESTROY:
                    user32.PostQuitMessage(0)
                    return 0
                return user32.DefWindowProcW(hwnd, msg, wparam, lparam)
            except Exception:
                try:
                    return user32.DefWindowProcW(hwnd, msg, wparam, lparam)
                except Exception:
                    return 0

        self._wnd_proc_ref = WNDPROC(_wnd_proc)

        class_name = f"FloweryTrayClass_{os.getpid()}"
        h_inst = kernel32.GetModuleHandleW(None)

        # Загрузка фирменной иконки Flowery (icon.ico)
        IMAGE_ICON = 1
        LR_LOADFROMFILE = 0x00000010
        LR_DEFAULTSIZE = 0x00000040
        self.h_icon = None

        base_dirs = [
            getattr(sys, "_MEIPASS", ""),
            os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__)),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..")),
            os.getcwd()
        ]
        for b in base_dirs:
            if b:
                p = os.path.join(b, "icon.ico")
                if os.path.isfile(p):
                    try:
                        self.h_icon = user32.LoadImageW(None, p, IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_DEFAULTSIZE)
                        if self.h_icon:
                            break
                    except Exception:
                        pass

        if not self.h_icon:
            IDI_APPLICATION = 32512
            self.h_icon = user32.LoadIconW(None, IDI_APPLICATION)

        wcex = WNDCLASSEXW()
        wcex.cbSize = ctypes.sizeof(WNDCLASSEXW)
        wcex.lpfnWndProc = self._wnd_proc_ref
        wcex.hInstance = h_inst
        wcex.lpszClassName = class_name
        wcex.hIcon = self.h_icon

        user32.RegisterClassExW(ctypes.byref(wcex))

        self.hwnd = user32.CreateWindowExW(
            0, class_name, "FloweryTrayWindow",
            0, 0, 0, 0, 0, None, None, h_inst, None
        )

        self._add_tray_icon()

    def _add_tray_icon(self) -> None:
        """Добавляет или обновляет иконку в области уведомлений Windows."""
        if not self.hwnd or not shell32:
            return

        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = self.hwnd
        nid.uID = 1
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        nid.uCallbackMessage = WM_TRAYICON
        nid.hIcon = self.h_icon
        nid.szTip = f"{self.app_name} — DPI Bypass Active"
        self._nid = nid

        # Сначала пробуем добавить; если уже была (после краша) — удаляем и добавляем заново
        if not shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid)):
            shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid))
            shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid))

    def _show_context_menu(self) -> None:
        """Отображает контекстное меню при правом клике на иконку."""
        pt = wintypes.POINT()
        user32.GetCursorPos(ctypes.byref(pt))

        h_menu = user32.CreatePopupMenu()

        # Заголовок (неактивный пункт)
        user32.AppendMenuW(h_menu, MF_STRING | MF_DISABLED | MF_GRAYED, ID_TRAY_TITLE, f"{self.app_name} v1.2.0")
        
        # Информация о профиле
        prof_name = self.get_profile_name_callback() if self.get_profile_name_callback else "Активен"
        user32.AppendMenuW(h_menu, MF_STRING | MF_DISABLED, ID_TRAY_PROFILE_INFO, f"Профиль: {prof_name}")
        user32.AppendMenuW(h_menu, MF_SEPARATOR, 0, None)

        # Переключатель консоли и лог-файла
        is_vis = self.is_console_visible()
        console_text = "Скрыть окно консоли" if is_vis else "Показать окно консоли"
        user32.AppendMenuW(h_menu, MF_STRING, ID_TRAY_TOGGLE_CONSOLE, console_text)
        user32.AppendMenuW(h_menu, MF_STRING, ID_TRAY_OPEN_LOG, "Открыть файл логов сессии")
        user32.AppendMenuW(h_menu, MF_SEPARATOR, 0, None)

        # Выход
        user32.AppendMenuW(h_menu, MF_STRING, ID_TRAY_EXIT, "Остановить и выйти")

        user32.SetForegroundWindow(self.hwnd)
        user32.TrackPopupMenuEx(h_menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, pt.x, pt.y, self.hwnd, None)
        user32.PostMessageW(self.hwnd, WM_NULL, 0, 0)
        user32.DestroyMenu(h_menu)

    def _message_loop(self) -> None:
        """Цикл обработки сообщений Windows."""
        msg = wintypes.MSG()
        while self.is_running:
            res = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
            if res <= 0:
                break
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

    def hide_console_window(self) -> None:
        """Скрывает окно консоли."""
        if not kernel32 or not user32:
            return
        h_con = kernel32.GetConsoleWindow()
        if h_con:
            user32.ShowWindow(h_con, SW_HIDE)

    def show_console_window(self) -> None:
        """Отображает окно консоли и делает его активным."""
        if not kernel32 or not user32:
            return
        h_con = kernel32.GetConsoleWindow()
        if h_con:
            user32.ShowWindow(h_con, SW_RESTORE)
            user32.SetForegroundWindow(h_con)

    def is_console_visible(self) -> bool:
        """Проверяет видимость окна консоли."""
        if not kernel32 or not user32:
            return False
        h_con = kernel32.GetConsoleWindow()
        return bool(h_con and user32.IsWindowVisible(h_con))

    def toggle_console_window(self) -> None:
        """Переключает видимость окна консоли (показать/скрыть)."""
        if self.is_console_visible():
            self.hide_console_window()
        else:
            self.show_console_window()

    def update_tooltip(self, text: str) -> None:
        """Обновляет всплывающую подсказку иконки в трее."""
        if not self.hwnd or not shell32:
            return
        try:
            nid = NOTIFYICONDATAW()
            nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
            nid.hWnd = self.hwnd
            nid.uID = 1
            nid.uFlags = NIF_TIP
            nid.szTip = text[:127]
            shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))
        except Exception:
            pass

    def stop(self) -> None:
        """Удаляет иконку из трея и завершает работу."""
        self.is_running = False
        if self.hwnd and shell32:
            try:
                nid = NOTIFYICONDATAW()
                nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
                nid.hWnd = self.hwnd
                nid.uID = 1
                shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid))
            except Exception:
                pass
            try:
                user32.PostMessageW(self.hwnd, WM_DESTROY, 0, 0)
            except Exception:
                pass
