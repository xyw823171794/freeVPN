#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""受控实验: L1 重试修复的效果, 以及 L2 并发能开到多少。

同一批候选、只变一个变量, 避免"改完感觉快了"这种自欺。
"""
import sys
import time

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool  # noqa: E402

l1 = pool.load_l1()
if not l1:
    print("没有 L1 缓存(版本可能已失效), 先跑一次 pool.py all")
    sys.exit(1)
print(f"L1 缓存 {len(l1)} 个存活节点")

# ---- L1 重试修复的效果: 用一小批死节点测 ----
print()
print("=" * 66)
print("L1 · 死节点重试开销")
print("=" * 66)
dead = [{"type": "ss", "server": f"10.255.{i // 250}.{i % 250}", "port": 8388,
         "cipher": "aes-128-gcm", "password": "x", "name": "d"} for i in range(200)]
for tries in (1, 2):
    t0 = time.time()
    alive = pool.probe_tcp(dead, timeout=2.0, concurrency=200, tries=tries)
    dt = time.time() - t0
    print(f"  tries={tries}: {len(dead)} 个死节点耗时 {dt:.1f}s  (存活 {len(alive)})")
print("  期望: tries=2 时超时节点不再重试, 耗时与 tries=1 接近")

# ---- L2 并发 ----
print()
print("=" * 66)
print("L2 · 并发数对吞吐的影响")
print("=" * 66)
cand = pool.diversify(pool.rank(l1), per_subnet=4)[:1200]
print(f"候选集固定为 {len(cand)} 个 (每次实验前重置 _real)")
print()
print(f"  {'并发':>6} {'耗时':>9} {'可用':>6} {'吞吐':>12}")
results = []
for w in (128, 192, 256, 384):
    batch = [dict(n) for n in cand]
    for n in batch:
        n.pop("_real", None)
    t0 = time.time()
    got = pool.probe_real(batch, timeout_ms=3000, workers=w, chunk=1200)
    dt = time.time() - t0
    rate = len(batch) / dt if dt else 0
    results.append((w, dt, len(got), rate))
    print(f"  {w:>6} {dt:>8.1f}s {len(got):>6} {rate:>9.1f} 节点/秒")
    print()

print("结论:")
best = max(results, key=lambda r: r[3])
print(f"  吞吐最高: 并发 {best[0]} -> {best[3]:.1f} 节点/秒 (耗时 {best[1]:.1f}s)")
