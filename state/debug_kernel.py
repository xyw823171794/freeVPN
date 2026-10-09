#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""诊断内核启动: 抓内核真实输出, 对比隔离前后差异。"""
import importlib.util
import subprocess
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

spec = importlib.util.spec_from_file_location("pool", r"E:\AI\freeVPN\pool.py")
pool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pool)
import security as sec  # noqa: E402

CFG = pool.KERNEL_DIR / "config.yaml"
LOG = pool.KERNEL_DIR / "kernel.log"

print("=== 当前内核配置头部 ===")
print("\n".join(CFG.read_text(encoding="utf-8").splitlines()[:14]))
print(f"\npool.SECRET = {pool.SECRET!r}")
print(f"白名单环境变量: {sorted(sec.kernel_env().keys())}")
print(f"creationflags = {hex(sec.kernel_creationflags())}")


def try_launch(label, **kw):
    print(f"\n=== {label} ===")
    with open(LOG, "w", encoding="utf-8", errors="replace") as lf:
        proc = subprocess.Popen(
            [str(pool.MIHOMO), "-d", str(pool.KERNEL_DIR), "-f", str(CFG)],
            stdout=lf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            **kw,
        )
    ok = False
    for _ in range(16):
        if proc.poll() is not None:
            break
        try:
            v = pool._api("/version", 2)
            print(f"  API OK: {v}")
            ok = True
            break
        except Exception:
            time.sleep(0.5)
    if not ok:
        print(f"  API 未就绪 (poll={proc.poll()})")
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=6)
        except subprocess.TimeoutExpired:
            proc.kill()
    time.sleep(0.8)
    tail = LOG.read_text(encoding="utf-8", errors="replace").strip().splitlines()[-12:]
    print("  --- 内核输出 ---")
    for ln in tail:
        print("  " + ln[:150])
    return ok


# A: 完全隔离(当前实现)
try_launch("A) 当前实现: env白名单 + cwd + creationflags + DEVNULL stdin",
           cwd=str(pool.KERNEL_DIR), env=sec.kernel_env(),
           creationflags=sec.kernel_creationflags())

# B: 只加 cwd, 用父进程环境
try_launch("B) 仅 cwd, 继承父进程环境",
           cwd=str(pool.KERNEL_DIR))

# C: 继承环境 + 不设 creationflags
try_launch("C) 继承环境, 无 creationflags")
