#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""核算 L2 负缓存的代价: 被跳过的节点里还有多少能出网。

L2 比 L1 激进(失败 1 次就跳), 所以这个核算更重要。
"""
import random
import sys
import time

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool  # noqa: E402
import security as sec  # noqa: E402

h2 = pool.load_l2_hist()
h1 = pool.load_l1_hist()
print(f"L1 缓存 {len(h1)} 条, L2 缓存 {len(h2)} 条")

raw, _ = pool.collect(verbose=False)
nodes = sec.audit_pool(pool.dedupe(raw))[0]
l1_alive = pool.probe_tcp(nodes, timeout=5.0, concurrency=500, hist=None)
print(f"本轮 L1 存活 {len(l1_alive)}")

cand = pool.diversify(pool.rank(l1_alive), per_subnet=4)[:3000]
now = time.time()
TTL, MINF = 5400, 1
skipped, kept = [], []
for n in cand:
    h = h2.get(n.get("_fp") or "")
    if h and h.get("f", 0) >= MINF and now - h.get("t", 0) < TTL:
        skipped.append(n)
    else:
        kept.append(n)
print(f"L2 会跳过 {len(skipped)}, 会实测 {len(kept)}")
print()

if not skipped:
    print("没有可抽样的跳过节点")
    sys.exit(0)

random.seed(7)
sample = random.sample(skipped, min(300, len(skipped)))
print(f"随机抽 {len(sample)} 个被跳过的节点, 绕过缓存实测一遍 ...")
got = pool.probe_real(sample, timeout_ms=3000, workers=192, chunk=300, hist=None)
rate = len(got) / len(sample) * 100
print(f"  被跳过节点真实可出网率: {len(got)}/{len(sample)} = {rate:.1f}%")

ctrl = random.sample(kept, min(300, len(kept))) if kept else []
if ctrl:
    cgot = pool.probe_real(ctrl, timeout_ms=3000, workers=192, chunk=300, hist=None)
    crate = len(cgot) / len(ctrl) * 100
    print(f"  对照组(未跳过)可出网率: {len(cgot)}/{len(ctrl)} = {crate:.1f}%")
    print()
    if rate < 1:
        print(">>> 跳过的基本都出不去, L2 负缓存几乎零代价")
    elif rate < crate * 0.25:
        print(f">>> 跳过组远低于对照 ({rate:.1f}% vs {crate:.1f}%), 代价可接受")
    else:
        print(f">>> 跳过组偏高 ({rate:.1f}% vs {crate:.1f}%), 该放宽 min_fails")
    print(f"  按跳过 {len(skipped)} 个算, 相当于少发现约 "
          f"{int(len(skipped) * rate / 100)} 个可用节点")
