# -*- coding: utf-8 -*-
"""C0 · 环境侦察: 审计机现状、工具可用性、目标进程状态。

只读, 不做任何改动。
"""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(r"E:\AI\freeVPN")
PY = r"C:\Users\xyw\AppData\Local\Programs\Python\Python313\python.exe"


def sh(cmd, enc="utf-8"):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20,
                           encoding=enc, errors="replace")
        return (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return f"<{type(e).__name__}: {e}>"


print("=" * 70)
print("C0 · 环境侦察")
print("=" * 70)
print(f"python        : {sys.executable}")
print(f"cwd           : {os.getcwd()}")
print(f"OEMCP         : ", end="")
import ctypes
print(ctypes.windll.kernel32.GetOEMCP())
import locale
print(f"locale.getpreferredencoding: {locale.getpreferredencoding(False)}")

print("\n--- 关键工具是否可用 ---")
for tool in ("netstat", "tasklist", "taskkill", "wmic", "icacls"):
    p = sh(["where", tool]).strip().splitlines()
    print(f"  {tool:<10} {'OK  ' + (p[0] if p else '') if p else '**缺失**'}")

print("\n--- 正在跑的 freeVPN / clash 相关进程 (只读) ---")
print(sh(["tasklist", "/FI", "IMAGENAME eq freeVPN.exe", "/FO", "CSV"], enc="gbk").strip())
print(sh(["tasklist", "/FI", "IMAGENAME eq clash-verge.exe", "/FO", "CSV"], enc="gbk").strip())
print(sh(["tasklist", "/FI", "IMAGENAME eq python.exe", "/FO", "CSV"], enc="gbk").strip())

print("\n--- C:\\freeVPN 是否在跑 (不要动它) ---")
cf = Path(r"C:\freeVPN")
print(f"  C:\\freeVPN 存在: {cf.exists()}")
if cf.exists():
    for n in ("freeVPN.exe", "state\\token.txt", "订阅地址.txt"):
        p = cf / n
        print(f"    {n:<20} exists={p.exists()}")

print("\n--- 监听端口快照 (netstat -ano -p TCP, LISTENING) ---")
out = sh(["netstat", "-ano", "-p", "TCP"], enc="gbk")
lis = [ln for ln in out.splitlines() if "LISTENING" in ln]
print(f"  共 {len(lis)} 条 LISTENING")
for ln in lis:
    print("   ", " ".join(ln.split()))

print("\n--- 测试目录 ---")
t = Path(r"E:\AI\_c_test")
t.mkdir(parents=True, exist_ok=True)
print(f"  {t} 已就绪")
