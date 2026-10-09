#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""复核 L1 超时: 5.0s vs 3.0s 的存活差到底是超时导致的还是漂移。

之前从 l1.json 的 _tcp 字段算"3s 只损失 0.4%"是错的 ——
_tcp 记的是**两次尝试的最小值**, 会低估首次尝试的耗时。
"""
import json
import sys
import time

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool  # noqa: E402

CAND = pool.STATE / "bench_cands.json"
nodes = json.loads(CAND.read_text(encoding="utf-8"))
if len(nodes) > 4000:
    step = len(nodes) / 4000
    nodes = [nodes[int(i * step)] for i in range(4000)]
print(f"候选 {len(nodes)} 个, 并发固定 500, 交错跑 5.0s / 3.0s")
print()
print(f"  {'顺序':>4} {'超时':>7} {'耗时':>9} {'存活':>7}")
seq = [5.0, 3.0, 5.0, 3.0]
out = []
for i, tmo in enumerate(seq):
    t0 = time.time()
    alive = pool.probe_tcp(nodes, timeout=tmo, concurrency=500)
    dt = time.time() - t0
    out.append((tmo, dt, len(alive)))
    print(f"  {i+1:>4} {tmo:>6.1f}s {dt:>8.1f}s {len(alive):>7}")

a = [n for t, _d, n in out if t == 5.0]
b = [n for t, _d, n in out if t == 3.0]
da = [d for t, d, _n in out if t == 5.0]
db = [d for t, d, _n in out if t == 3.0]
print()
print(f"  5.0s: 存活 {a}  耗时 {[f'{x:.1f}' for x in da]}")
print(f"  3.0s: 存活 {b}  耗时 {[f'{x:.1f}' for x in db]}")
if len(a) == 2 and len(b) == 2:
    ma, mb = sum(a) / 2, sum(b) / 2
    drift = abs(a[0] - a[1]) / max(a)
    loss = (ma - mb) / ma
    print()
    print(f"  同超时两次漂移:   {drift*100:.1f}%")
    print(f"  3.0s 相对 5.0s:   存活少 {loss*100:.1f}%,  耗时省 "
          f"{(sum(da)/2 - sum(db)/2):.1f}s")
    print()
    if loss > 0.05:
        print("  >>> 3.0s 确实丢节点, 不值得换那点时间")
    else:
        print("  >>> 3.0s 的损失在噪声范围内, 可以换")
