# -*- coding: utf-8 -*-
"""C5 · console_encoding() 的 `f"cp{GetOEMCP()}"` 是否可控 / 会不会产生非法 codec

审计假设: OEM 码页值来自系统, 若能被改坏, 拼出的 "cpXXX" 就是非法 codec,
         所有用 console_encoding() 的 subprocess.run(encoding=...) 都会抛
         LookupError。
本脚本逐条实测这个假设。
"""
import codecs
import ctypes
import os
import subprocess
import sys
import winreg

sys.path.insert(0, r"E:\AI\freeVPN")
import security as sec  # noqa: E402


def banner(t):
    print("\n" + "=" * 72)
    print(t)
    print("=" * 72)


banner("C5-a · 当前值")
cp_now = ctypes.windll.kernel32.GetOEMCP()
print(f"  GetOEMCP()            = {cp_now}")
print(f"  console_encoding()    = {sec.console_encoding()!r}")
print(f"  GetACP()              = {ctypes.windll.kernel32.GetACP()}")
print(f"  GetConsoleOutputCP()  = {ctypes.windll.kernel32.GetConsoleOutputCP()}")

banner("C5-b · 值的来源 (注册表, 只读)")
for hive_name, hive in (("HKLM", winreg.HKEY_LOCAL_MACHINE),):
    for name in ("OEMCP", "ACP"):
        try:
            with winreg.OpenKey(
                    hive,
                    r"SYSTEM\CurrentControlSet\Control\Nls\CodePage") as k:
                v = winreg.QueryValueEx(k, name)[0]
            print(f"  {hive_name}\\...\\Nls\\CodePage\\{name} = {v!r}")
        except OSError as e:
            print(f"  {name}: 读不到 {e}")
print("  → 改这个键需要管理员 (HKLM)。当前进程管理员: "
      f"{bool(ctypes.windll.shell32.IsUserAnAdmin())}")

banner("C5-c · `cp{N}` 的合法性表")
cands = [0, 1, 2, 3, 42, 650, 708, 720, 850, 866, 874, 932, 936, 949, 950,
         1200, 1252, 65001, 99999, 4294967295, -1]
for v in cands:
    name = f"cp{v}"
    try:
        codecs.lookup(name)
        ok = "合法"
    except LookupError:
        ok = "**非法 LookupError**"
    print(f"  {name:<14} {ok}")

banner("C5-d · 代码的兜底路径")
print("  security.py:299-303")
print("    cp = int(GetOEMCP())")
print("    if cp:")
print("        return f'cp{cp}'          # ← 只有 cp==0 被挡掉")
print("    ...fallback: locale.getpreferredencoding(False)")
print(f"  实测 cp=0 时会被 `if cp:` 挡住, 走 fallback; 其它值直接拼进 codec 名。")

banner("C5-e · 模拟非法码页: 哪些调用点会被 LookupError 打穿")
fake = "cp99999"
print(f"  假设 console_encoding() 返回 {fake!r}")
try:
    subprocess.run(["cmd", "/c", "echo hi"], capture_output=True, text=True,
                   encoding=fake, errors="replace", timeout=5)
    print("    subprocess.run(encoding=...) -> 正常")
except LookupError as e:
    print(f"    subprocess.run(encoding=...) -> LookupError: {e}")
print("  调用点是否包了 try/except:")
for fn, guarded in (("port_holders", "有 try 包住整个函数体"),
                    ("client_pids", "有 try"),
                    ("verge_running", "有 try"),
                    ("process_running", "有 try"),
                    ("close_verge 的温和 taskkill (pool.py:2589)", "**没有 try**"),
                    ("close_verge 的强制 taskkill (pool.py:2604)", "**没有 try**")):
    print(f"    {fn:<44} {guarded}")

banner("C5-f · chcp 会不会改 GetOEMCP (子进程里验证)")
r = subprocess.run(
    ["cmd", "/c", "chcp 65001 >nul & "
     f'"{sys.executable}" -c "import ctypes;'
     'print(ctypes.windll.kernel32.GetOEMCP(),'
     'ctypes.windll.kernel32.GetConsoleOutputCP())"'],
    capture_output=True, text=True, encoding="gbk", errors="replace")
print(f"  子进程 (chcp 65001) 输出 GetOEMCP / GetConsoleOutputCP: "
      f"{(r.stdout or '').strip()}")
print(f"  父进程 GetOEMCP = {cp_now}")
print("  → chcp 只改 GetConsoleOutputCP, 不改 GetOEMCP")

print("\n" + "=" * 72)
print("C5 完成")
print("=" * 72)
