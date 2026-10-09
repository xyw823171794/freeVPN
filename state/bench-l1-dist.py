#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""L1 超时该设多少: 看存活节点的实际握手延迟分布。

超时压得太低会误杀慢但可用的节点; 压得不够则死节点拖时间。
分布数据是免费的 —— 就在 l1.json 的 _tcp 字段里。
"""
import sys

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool  # noqa: E402

l1 = pool.load_l1()
vals = sorted(n.get("_tcp") for n in l1 if n.get("_tcp"))
n = len(vals)
print(f"存活节点 {n} 个 (L1 实测握手延迟)")
print()


def pct(p):
    return vals[min(n - 1, int(n * p / 100))]


print("  分位分布:")
for p in (50, 75, 90, 95, 99, 100):
    print(f"    p{p:<3} {pct(p):>8.1f} ms")
print()
print("  各阈值下的存活率 (当前 timeout=5.0s):")
for t in (500, 1000, 1500, 2000, 3000, 4000, 5000):
    keep = sum(1 for v in vals if v <= t)
    print(f"    <={t:>4}ms  {keep:>5}/{n}  {keep/n*100:>5.1f}%")
print()
print("  解读: 如果 2000ms 已经覆盖绝大多数存活节点, 把 timeout 从 5s 压到 2s")
print("        能让死节点少等 3 秒 —— 死节点占六成, 这是可观的时间")
