#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""交错重复实验: 分离"并发带来的提升"与"免费节点自身抖动"。

单次跑分不清这两者 —— 同一批节点在不同时刻可用性会变。做法是
A/B 交错重复(48, 192, 48, 192, …), 让时间漂移在两个条件下均摊。
"""
import statistics
import sys
import time

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool  # noqa: E402

N = 400
REPS = 3
WORKERS = (48, 192)

l1 = pool.load_l1()
cand = pool.diversify(pool.rank(l1), per_subnet=4)[:N]
print(f"候选集 {len(cand)} 个, 每种并发跑 {REPS} 轮, 交错进行")
print()

res: dict[int, list[tuple[float, int]]] = {w: [] for w in WORKERS}
for rep in range(REPS):
    for w in WORKERS:
        batch = [dict(n) for n in cand]
        for n in batch:
            n.pop("_real", None)
        t0 = time.time()
        got = pool.probe_real(batch, timeout_ms=3000, workers=w, chunk=N)
        dt = time.time() - t0
        res[w].append((dt, len(got)))
        print(f"  rep{rep+1} 并发 {w:>3}: {dt:>6.1f}s  找到 {len(got):>3} 个")
    print()

print("=" * 62)
print(f"  {'并发':>6} {'耗时(中位)':>12} {'找到(中位)':>12} {'吞吐':>10}")
for w in WORKERS:
    ts = [t for t, _ in res[w]]
    fs = [f for _, f in res[w]]
    mt, mf = statistics.median(ts), statistics.median(fs)
    print(f"  {w:>6} {mt:>11.1f}s {mf:>12.0f} {len(cand)/mt:>8.1f} 个/秒")
print("=" * 62)

t48 = statistics.median([t for t, _ in res[48]])
t192 = statistics.median([t for t, _ in res[192]])
f48 = statistics.median([f for _, f in res[48]])
f192 = statistics.median([f for _, f in res[192]])
print(f"  提速        {t48 / t192:.2f}x")
print(f"  找到节点数  48 并发 {f48:.0f}  ->  192 并发 {f192:.0f}  "
      f"({'不降' if f192 >= f48 * 0.9 else '明显下降, 说明并发过高'})")
