#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""以"按实测延迟排序"的状态打开控制台, 截图后自动关闭 —— 用来确认排序指示器。"""
import json
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import gui  # noqa: E402

OUT_PNG = Path(r"E:\AI\freeVPN\state\gui-sorted.png")

root = tk.Tk()
g = gui.PoolGUI(root, 8787)

# 灌入真实节点
try:
    pool = json.loads((gui.STATE / "pool.json").read_text(encoding="utf-8"))
    g._nodes = pool.get("nodes") or []
except Exception:
    pass
g.sort_by("real")          # 按实测延迟升序
print(f"节点 {len(g._nodes)} 个, 已按「实测延迟」排序")


def shot():
    time.sleep(2.0)
    root.update_idletasks()
    h = root.winfo_id()
    # 拿到顶层窗口(winfo_id 是内层窗口), 用父窗口
    import ctypes
    hwnd = ctypes.windll.user32.GetParent(h) or h
    rect = ctypes.wintypes.RECT() if hasattr(ctypes, "wintypes") else None
    import ctypes.wintypes as wt
    r = wt.RECT()
    ctypes.windll.user32.GetWindowRect(hwnd, ctypes.byref(r))
    w, ht = r.right - r.left, r.bottom - r.top
    ps = (
        "Add-Type -AssemblyName System.Drawing;"
        f"$b=New-Object System.Drawing.Bitmap({w},{ht});"
        "$g=[System.Drawing.Graphics]::FromImage($b);"
        f"$g.CopyFromScreen({r.left},{r.top},0,0,$b.Size);"
        f"$b.Save('{OUT_PNG}',[System.Drawing.Imaging.ImageFormat]::Png);"
        "$g.Dispose();$b.Dispose()"
    )
    subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                   capture_output=True, creationflags=0x08000000)
    print(f"已保存 {OUT_PNG} ({w}x{ht})")
    root.quit()


threading.Thread(target=shot, daemon=True).start()
root.mainloop()
