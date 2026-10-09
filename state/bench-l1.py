#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""L1 参数寻优: 并发 × 超时。候选集只准备一次, 之后反复用。"""
import sys
import time

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool  # noqa: E402
import security as sec  # noqa: E402

CAND_FILE = pool.STATE / "bench_cands.json"
import json  # noqa: E402

if CAND_FILE.exists():
    nodes = json.loads(CAND_FILE.read_text(encoding="utf-8"))
    print(f"复用候选集 {len(nodes)} 个")
else:
    print("准备候选集(拉源+去重+审计, 约 15 秒)...")
    raw, _st = pool.collect(verbose=False)
    nodes = sec.audit_pool(pool.dedupe(raw))[0]
    # 只存必要字段, 控制体积
    nodes = [{k: v for k, v in n.items() if not k.startswith("_")} for n in nodes]
    CAND_FILE.write_text(json.dumps(nodes, ensure_ascii=False), encoding="utf-8")
    print(f"候选集 {len(nodes)} 个, 已缓存")

# 抽样到 4000 个, 控制实验时长
if len(nodes) > 4000:
    step = len(nodes) / 4000
    nodes = [nodes[int(i * step)] for i in range(4000)]
print(f"本轮实验用 {len(nodes)} 个")
print()
print(f"  {'并发':>6} {'超时':>7} {'耗时':>9} {'存活':>7} {'吞吐':>12}")

for conc, tmo in ((500, 5.0), (500, 3.0), (1000, 3.0), (1500, 3.0), (1500, 2.0)):
    t0 = time.time()
    alive = pool.probe_tcp(nodes, timeout=tmo, concurrency=conc)
    dt = time.time() - t0
    print(f"  {conc:>6} {tmo:>6.1f}s {dt:>8.1f}s {len(alive):>7} "
          f"{len(nodes)/dt:>9.0f} 个/秒")
