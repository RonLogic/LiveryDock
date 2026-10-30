from __future__ import annotations

import os
from typing import Callable


class WindowsDropTarget:
    """Minimal WM_DROPFILES bridge for Tk windows; silently unavailable elsewhere."""

    def __init__(self, tk_root, callback: Callable[[list[str]], None]):
        self.root = tk_root
        self.callback = callback
        self._old_proc = None
        self._new_proc = None
        self._enabled = False
        self._hwnd = None

    def enable(self) -> bool:
        if os.name != "nt":
            return False
        try:
            import ctypes
            from ctypes import wintypes

            WM_DROPFILES = 0x0233
            GWLP_WNDPROC = -4
            LRESULT = ctypes.c_ssize_t
            WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

            user32 = ctypes.windll.user32
            shell32 = ctypes.windll.shell32
            hwnd = self.root.winfo_id()

            get_window_long = getattr(user32, "GetWindowLongPtrW", user32.GetWindowLongW)
            set_window_long = getattr(user32, "SetWindowLongPtrW", user32.SetWindowLongW)
            get_window_long.argtypes = [wintypes.HWND, ctypes.c_int]
            get_window_long.restype = ctypes.c_void_p
            set_window_long.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]
            set_window_long.restype = ctypes.c_void_p
            user32.CallWindowProcW.argtypes = [ctypes.c_void_p, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
            user32.CallWindowProcW.restype = LRESULT
            shell32.DragQueryFileW.argtypes = [wintypes.HANDLE, wintypes.UINT, wintypes.LPWSTR, wintypes.UINT]
            shell32.DragQueryFileW.restype = wintypes.UINT
            shell32.DragFinish.argtypes = [wintypes.HANDLE]
            shell32.DragFinish.restype = None
            shell32.DragAcceptFiles.argtypes = [wintypes.HWND, wintypes.BOOL]
            shell32.DragAcceptFiles.restype = None

            old_proc = get_window_long(hwnd, GWLP_WNDPROC)
            if not old_proc:
                return False

            def wndproc(h, msg, wparam, lparam):
                if msg == WM_DROPFILES:
                    count = shell32.DragQueryFileW(wparam, 0xFFFFFFFF, None, 0)
                    paths: list[str] = []
                    for index in range(count):
                        length = shell32.DragQueryFileW(wparam, index, None, 0)
                        buffer = ctypes.create_unicode_buffer(length + 1)
                        shell32.DragQueryFileW(wparam, index, buffer, length + 1)
                        paths.append(buffer.value)
                    shell32.DragFinish(wparam)
                    self.root.after(0, lambda p=paths: self.callback(p))
                    return 0
                return user32.CallWindowProcW(old_proc, h, msg, wparam, lparam)

            self._new_proc = WNDPROC(wndproc)
            self._old_proc = old_proc
            self._hwnd = hwnd
            set_window_long(hwnd, GWLP_WNDPROC, ctypes.cast(self._new_proc, ctypes.c_void_p))
            shell32.DragAcceptFiles(hwnd, True)
            self._enabled = True
            return True
        except Exception:
            self._enabled = False
            return False

    def disable(self) -> None:
        if not self._enabled:
            return
        import ctypes
        from ctypes import wintypes
        user32 = ctypes.windll.user32
        setter = getattr(user32, "SetWindowLongPtrW", user32.SetWindowLongW)
        setter.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]
        setter.restype = ctypes.c_void_p
        ctypes.windll.shell32.DragAcceptFiles(self._hwnd, False)
        setter(self._hwnd, -4, self._old_proc)
        self._enabled = False
