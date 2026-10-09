#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 Clash Verge 里的 freeVPN 订阅地址改成"实际在监听的那个"的令牌。

为什么需要这个: 源码版和打包版各有自己的 state/token.txt, 是两个不同的令牌,
却抢同一个 8787 端口。用 A 跑的导入写进客户端的是 A 的令牌; 实际在监听的是 B,
客户端拉订阅就 401, 而且从表面完全看不出原因。
"""
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

VD = Path.home() / "AppData/Roaming/io.github.clash-verge-rev.clash-verge-rev"
IDX = VD / "profiles.yaml"
PORT = 8787

CANDIDATES = [
    Path(r"E:\AI\freeVPN\dist\freeVPN\state\token.txt"),   # 打包版
    Path(r"E:\AI\freeVPN\state\token.txt"),                # 源码版
]


def probe(url: str) -> int:
    try:
        with urllib.request.urlopen(
                urllib.request.Request(url, headers={"User-Agent": "freeVPN"}), timeout=8) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


print("=== 逐个令牌试 127.0.0.1:%d ===" % PORT)
good = None
for f in CANDIDATES:
    if not f.exists():
        print(f"  {f}  (不存在)")
        continue
    tok = f.read_text(encoding="utf-8").strip()
    url = f"http://127.0.0.1:{PORT}/sub/pool.yaml?token={tok}"
    code = probe(url)
    tag = "  <== 在监听的就是它" if code == 200 else ""
    print(f"  {f.parent.parent.name:>8}  {tok[:12]}...  HTTP {code}{tag}")
    if code == 200:
        good = url

if not good:
    print("\n[!] 没有令牌能拉到订阅 —— 先确认常驻在跑、且第一轮扫描已完成")
    sys.exit(1)

print(f"\n=== 把客户端的地址改成能用的那条 ===")
print(f"  {good}")

raw = IDX.read_text(encoding="utf-8")
bak = IDX.with_suffix(".yaml.before-tokenfix.bak")
bak.write_text(raw, encoding="utf-8")
print(f"  已备份: {bak.name}")

new, n = re.subn(
    r"(http://127\.0\.0\.1:%d/sub/pool\.yaml\?token=)[^\s\"']+" % PORT,
    lambda m: m.group(1) + good.split("token=", 1)[1], raw)
IDX.write_text(new, encoding="utf-8")
print(f"  替换了 {n} 处")

print("\n=== 验证 ===")
after = IDX.read_text(encoding="utf-8")
for m in re.finditer(r"http://127\.0\.0\.1:%d/sub/pool\.yaml\?token=\S+" % PORT, after):
    print(f"  HTTP {probe(m.group(0))}  {m.group(0)[:90]}")
