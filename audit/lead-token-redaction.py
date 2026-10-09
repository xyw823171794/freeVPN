#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lead 交叉验证: access.log 的令牌脱敏是否覆盖所有投递形式。

令牌有四种投递方式(不同客户端习惯不同):
  1. ?token=xxx
  2. ?t=xxx
  3. Authorization: Bearer xxx
  4. 路径段 /t/<token>/<file>

_log() 里只对 (?|&)(token|t)= 做了脱敏。**路径段那种形式没被覆盖** ——
日志会把整个 URL 原样记下来, 令牌直接落到 access.log。
access.log 的 ACL 是 Authenticated Users:(M), 任何本机用户可读。

这里把四种形式都打一遍, 然后检查日志。
"""
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool  # noqa: E402
import security as sec  # noqa: E402

PY = sys.executable
ROOT = Path(r"E:\AI\freeVPN")
PORT = 8897
LOG = ROOT / "state" / "access.log"
TOKEN = "ZZTESTTOKENZZ_abcdefghijklmnop"

print("=== 起一个测试实例 ===")
p = subprocess.Popen(
    [PY, "-u", str(ROOT / "pool.py"), "serve", "--port", str(PORT)],
    cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    creationflags=sec.hidden_flags())
time.sleep(6)

# 用同一个令牌 —— 从实例自己的 token.txt 读
tok = (ROOT / "state" / "token.txt").read_text(encoding="utf-8").strip()
print(f"  端口 {PORT}, 令牌 {tok[:10]}...")

before = LOG.stat().st_size if LOG.exists() else 0

CASES = [
    ("?token=", f"http://127.0.0.1:{PORT}/sub/pool.yaml?token={tok}"),
    ("?t=", f"http://127.0.0.1:{PORT}/sub/pool.yaml?t={tok}"),
    ("路径段 /t/", f"http://127.0.0.1:{PORT}/t/{tok}/pool.yaml"),
    ("Authorization", f"http://127.0.0.1:{PORT}/sub/pool.yaml"),
]

print("\n=== 依次请求四种形式 ===")
for label, url in CASES:
    req = urllib.request.Request(url)
    if label == "Authorization":
        req.add_header("Authorization", f"Bearer {tok}")
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception as e:
        code = f"{type(e).__name__}"
    print(f"  {label:<16} HTTP {code}")

time.sleep(1)
p.terminate()
try:
    p.wait(timeout=5)
except Exception:
    p.kill()

print("\n=== 新增的日志行 ===")
lines = []
if LOG.exists():
    raw = LOG.read_bytes()
    lines = raw[before:].decode("utf-8", "replace").splitlines()
leak = []
for ln in lines:
    shown = ln[:120]
    bad = tok in ln
    if bad:
        leak.append(ln)
    print(f"  {'[!! 泄露]' if bad else '[OK]    '} {shown}")

print()
if leak:
    print(f"结论: **{len(leak)}/{len(lines)} 行日志含完整令牌**")
    for ln in leak:
        print(f"  泄露形式: {ln.split(chr(9))[3][:90] if chr(9) in ln else ln[:90]}")
    sys.exit(1)
print(f"结论: {len(lines)} 行日志均不含完整令牌")
