#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""打开「更新」页, 真跑一次检查, 截图后自动关闭。"""
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import gui  # noqa: E402

OUT_PNG = Path(r"E:\AI\freeVPN\state\gui-update.png")

root = tk.Tk()
g = gui.PoolGUI(root, 8787)
# 别让"首次自动拉起常驻"在截图时起服务; 但要把队列轮询接回来
try:
    for aid in root.tk.eval("after info").split():
        root.after_cancel(aid)
    root.after(120, g._drain_log)
except Exception:
    pass

g.nb.select(3)                     # 更新页
g.upd_check(silent=True)           # 真查一次
print("已触发检查更新 …")


def shot():
    # 等检查出结果(最多 25 秒)
    for _ in range(100):
        time.sleep(0.25)
        if not g._upd_busy:
            break
    time.sleep(0.8)
    root.update_idletasks()
    import ctypes
    import ctypes.wintypes as wt
    hwnd = ctypes.windll.user32.GetParent(root.winfo_id()) or root.winfo_id()
    r = wt.RECT()
    ctypes.windll.user32.GetWindowRect(hwnd, ctypes.byref(r))
    w, h = r.right - r.left, r.bottom - r.top
    ps = (
        "Add-Type -AssemblyName System.Drawing;"
        f"$b=New-Object System.Drawing.Bitmap({w},{h});"
        "$g=[System.Drawing.Graphics]::FromImage($b);"
        f"$g.CopyFromScreen({r.left},{r.top},0,0,$b.Size);"
        f"$b.Save('{OUT_PNG}',[System.Drawing.Imaging.ImageFormat]::Png);"
        "$g.Dispose();$b.Dispose()"
    )
    subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                   capture_output=True, creationflags=0x08000000)
    print(f"状态: {g.lb_upd_state.cget('text')}")
    print(f"已保存 {OUT_PNG} ({w}x{h})")
    root.quit()


threading.Thread(target=shot, daemon=True).start()
root.mainloop()
