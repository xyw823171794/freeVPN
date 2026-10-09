#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""复核: L1 "并发越高存活越少" 到底是并发导致的, 还是节点随时间衰减?

上次是顺序跑的(500→500→1000→1500→1500), 存活数单调下降 —— 这既符合
"并发有害", 也符合"节点在衰减"。交错重复才能分开。
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
print(f"候选 {len(nodes)} 个, 全部 timeout=5.0s, 交错跑 500 / 1500")
print()
print(f"  {'顺序':>4} {'并发':>6} {'耗时':>9} {'存活':>7}")
seq = [500, 1500, 500, 1500]
out = []
for i, conc in enumerate(seq):
    t0 = time.time()
    alive = pool.probe_tcp(nodes, timeout=5.0, concurrency=conc)
    dt = time.time() - t0
    out.append((conc, dt, len(alive)))
    print(f"  {i+1:>4} {conc:>6} {dt:>8.1f}s {len(alive):>7}")

print()
a = [n for c, _t, n in out if c == 500]
b = [n for c, _t, n in out if c == 1500]
print(f"  500  并发的两次: {a}")
print(f"  1500 并发的两次: {b}")
if len(a) == 2 and len(b) == 2:
    drift = abs(a[0] - a[1]) / max(a)
    gap = abs(sum(a) / 2 - sum(b) / 2) / max(sum(a) / 2, 1)
    print()
    print(f"  同并发两次之间的差异: {drift*100:.1f}%  (时间漂移的量级)")
    print(f"  两种并发之间的差异:   {gap*100:.1f}%")
    if drift > gap:
        print("  >>> 差异主要来自时间漂移, 不是并发 —— 提高并发是安全的")
    else:
        print("  >>> 并发本身确实导致存活数下降, 不该再往上加")
