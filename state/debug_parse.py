#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""诊断: 哪些源被解析器漏掉了, 未识别地区长什么样。"""
import importlib.util
import sys
from collections import Counter

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

spec = importlib.util.spec_from_file_location("pool", r"E:\AI\freeVPN\pool.py")
pool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pool)

TARGETS = [
    "https://ghfast.top/https://raw.githubusercontent.com/ripaojiedian/freenode/main/clash",
    "https://ghfast.top/https://raw.githubusercontent.com/Jsnzkpg/Jsnzkpg/Jsnzkpg/Jsnzkpg",
    "https://ghfast.top/https://raw.githubusercontent.com/Peasoft/NoMoreWalls/master/list.txt",
    "https://ghfast.top/https://raw.githubusercontent.com/vxiaov/free_proxies/main/clash/clash.provider.yaml",
]

for u in TARGETS:
    _u, text = pool.fetch_one(u)
    print("=" * 70)
    print(u.split("/")[-2] + "/" + u.split("/")[-1], " 拉取:", "OK" if text else "FAIL")
    if not text:
        continue
    print("  前 260 字符:", repr(text[:260]))
    nodes = pool.parse_any(text)
    print(f"  parse_any -> {len(nodes)}")
    if nodes:
        print("  样例:", {k: v for k, v in list(nodes[0].items())[:8]})
    else:
        print("  [!!] 零解析, 尝试分路诊断")
        print("   clash_yaml ->", len(pool.parse_clash_yaml(text)))
        print("   links      ->", len(pool.parse_links(text)))
        dec = pool.b64_decode(text)
        print("   b64 ok     ->", bool(dec), (len(dec) if dec else 0))

print("\n" + "=" * 70)
print("未识别地区样本 (XX):")
raw, _ = pool.collect(verbose=False)
nodes = pool.dedupe(raw)
xx = [n for n in nodes if n.get("_region") == "XX"]
print(f"XX 共 {len(xx)} / {len(nodes)}")
for n in xx[:25]:
    print(f"   {n['type']:<10} {n['server']:<32} name={n.get('_raw_name')!r}")
print("\n各协议计数:", Counter(n["type"] for n in nodes).most_common())
