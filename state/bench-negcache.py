#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""负缓存的代价核算: 被跳过的节点里, 究竟还有多少是活的?

如果存活率接近 0, 这个缓存就是白捡的; 如果有 10% 以上, 就是在丢节点。
"""
import json
import random
import sys

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool  # noqa: E402
import security as sec  # noqa: E402

hist = pool.load_l1_hist()
print(f"负缓存条目 {len(hist)}")

# 复现当轮的候选集
raw, _ = pool.collect(verbose=False)
nodes = sec.audit_pool(pool.dedupe(raw))[0]
print(f"候选 {len(nodes)}")

now = __import__("time").time()
TTL, MINF = 5400, 2
skipped, kept = [], []
for n in nodes:
    h = hist.get(n.get("_fp") or "")
    if h and h.get("f", 0) >= MINF and now - h.get("t", 0) < TTL:
        skipped.append(n)
    else:
        kept.append(n)
print(f"会被跳过 {len(skipped)}   会去探 {len(kept)}")
print()

if not skipped:
    print("没有可抽样的跳过节点")
    sys.exit(0)

random.seed(42)
sample = random.sample(skipped, min(400, len(skipped)))
print(f"从被跳过的节点里随机抽 {len(sample)} 个, 单独探一遍看真实存活率 ...")
alive = pool.probe_tcp(sample, timeout=5.0, concurrency=500, hist=None)
rate = len(alive) / len(sample) * 100
print()
print(f"  被跳过节点的真实存活率: {len(alive)}/{len(sample)} = {rate:.1f}%")
print()
# 对照组: 同一批候选里"没被跳过"的存活率
ctrl = random.sample(kept, min(400, len(kept)))
c_alive = pool.probe_tcp(ctrl, timeout=5.0, concurrency=500, hist=None)
c_rate = len(c_alive) / len(ctrl) * 100
print(f"  对照组(未被跳过)存活率: {len(c_alive)}/{len(ctrl)} = {c_rate:.1f}%")
print()
if rate < 2:
    print(">>> 跳过的基本都是死的, 负缓存几乎零代价")
elif rate < c_rate * 0.25:
    print(f">>> 跳过的存活率远低于对照 ({rate:.1f}% vs {c_rate:.1f}%), 代价可接受")
else:
    print(f">>> 跳过太多活节点了 ({rate:.1f}% vs 对照 {c_rate:.1f}%), TTL 要缩短")
print()
print(f"  按本轮候选 {len(skipped)} 个跳过算, 若存活率 {rate:.1f}%, "
      f"相当于少发现约 {int(len(skipped) * rate / 100)} 个 L1 存活节点")
