#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用**真实节点数据**抓白名单漏掉的必填字段。"""
import subprocess
import sys
from collections import Counter

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool  # noqa: E402
import security as sec  # noqa: E402

l1 = pool.load_l1() or []
print(f"L1 缓存 {len(l1)} 个节点")
part = l1[:250]
k = pool.Kernel()
part = k.prune(part, max_rounds=3)
print(f"prune 后 {len(part)} 个")
if not part:
    # prune 会打印报错, 这里再手工抓一次首轮报错
    k2 = pool.Kernel()
    cfg = k2.write_config(l1[:250])
    r = subprocess.run([str(pool.MIHOMO), "-d", str(pool.KERNEL_DIR), "-f", str(cfg), "-t"],
                       capture_output=True, text=True, timeout=90,
                       encoding="utf-8", errors="replace",
                       cwd=str(pool.KERNEL_DIR), env=sec.kernel_env())
    out = ((r.stdout or "") + (r.stderr or "")).strip()
    print("=== 内核报错 ===")
    for ln in out.splitlines()[-6:]:
        print("  " + ln[:170])
    import re
    m = re.search(r"proxy (\d+):", out)
    if m:
        i = int(m.group(1))
        node = pool.normalize(dict(l1[i]))
        print(f"\n=== 出问题的节点 (index {i}) ===")
        print(f"  原始: { {kk: vv for kk, vv in l1[i].items() if not kk.startswith('_')} }")
        print(f"  normalize 后: {node}")
        print(f"  L1 里同类型节点数: "
              f"{Counter(x.get('type') for x in l1[:250]).most_common()}")
