#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""打包入口。

双击（无参数）= 打开桌面控制台。
带参数时按 pool.py 的命令行处理，例如：

    freeVPN.exe all         完整扫描一轮
    freeVPN.exe daemon      常驻刷新 + 订阅服务
    freeVPN.exe status      看状态
    freeVPN.exe autostart   设置开机自启
"""
import multiprocessing
import sys


def _hide_console():
    """双击启动 GUI 时把控制台窗口藏起来。

    这里刻意用 --console 打包而不是 --windowed：windowed 模式下 PyInstaller
    会把 sys.stdout 替换成空写入器，GUI 就没法捕获扫描子进程的输出了
    （日志页会一直空白）。所以保留控制台，只在开 GUI 时隐藏它。
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE
    except Exception:
        pass


if __name__ == "__main__":
    multiprocessing.freeze_support()
    if len(sys.argv) == 1:
        sys.argv.append("gui")
        _hide_console()
    import pool
    pool.main()
