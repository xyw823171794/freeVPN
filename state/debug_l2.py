#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""诊断 L2 通过率: 看 delay 是快速失败(节点已死)还是超时(网络慢)。"""
import importlib.util
import sys
import time
from collections import Counter

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

spec = importlib.util.spec_from_file_location("pool", r"E:\AI\freeVPN\pool.py")
pool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pool)

l1 = pool.load_l1()
if not l1:
    print("没有 L1 缓存, 先跑一次 pool.py all")
    sys.exit(1)
print(f"L1 缓存: {len(l1)} 个存活节点")

ranked = pool.rank(l1)
print("协议分布:", Counter(n["type"] for n in ranked).most_common())
print("L1 延迟前 5:", [n.get("_tcp") for n in ranked[:5]])

top = ranked[:60]
print(f"\n送内核: {len(top)} 个")
top = pool.prune_bad_nodes(top)
print(f"prune 后: {len(top)} 个")
if not top:
    sys.exit(1)

k = pool.Kernel()
if not k.start(top):
    print("内核起不来")
    sys.exit(1)

names = [f"n{i:05d}" for i in range(len(top))]
ok = 0
fast_fail = 0
slow_fail = 0
t_all = time.time()
for i, nm in enumerate(names[:40]):
    t0 = time.time()
    d = pool._delay(nm, 6000, pool.TEST_URL)
    dt = time.time() - t0
    n = top[i]
    if d:
        ok += 1
        mark = f"OK {d}ms"
    else:
        mark = "FAIL"
        if dt < 3:
            fast_fail += 1
        else:
            slow_fail += 1
    print(f"{i:3d} {n['type']:<9} {n['server']:<30}:{n['port']:<6} "
          f"tcp={n.get('_tcp')!s:<7} {mark:<10} 耗时={dt:4.1f}s")
print(f"\n通过 {ok}/40   快速失败 {fast_fail}   超时失败 {slow_fail}")
print(f"总耗时 {time.time()-t_all:.1f}s")
k.stop()
