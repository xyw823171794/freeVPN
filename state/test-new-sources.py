#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""实测候选节点源。

三步都要过, 缺一不可:
  ① 拉得到(不是 404 / 空文件 / HTML 错误页)
  ② 解析得出节点(用 pool 自己的解析器, 保证跟主流程一致)
  ③ 节点不是全死的(抽样 L1 探活, 看存活率)

只做前两步的话, 会挑出一堆"能拉到 5000 个死节点"的源。
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool  # noqa: E402
import security as sec  # noqa: E402

CAND = Path(r"E:\AI\freeVPN\state\candidates_new.txt")
urls = [u.strip() for u in CAND.read_text(encoding="utf-8").splitlines() if u.strip()]
print(f"候选 {len(urls)} 个\n")


def grab(u: str):
    """按主流程的同一套逻辑拉取+解析(含 yaml 炸弹检查与截断)。"""
    _url, text = pool.fetch_one(u, timeout=20)
    if not text:
        return None, "拉不到"
    if sec.yaml_bomb(text):
        return None, "yaml-bomb"
    text = sec.clamp_text(text)
    try:
        nodes = pool.parse_any(text)
    except Exception as e:
        return None, f"解析异常 {type(e).__name__}"
    return nodes, None


print("=== ① 拉取 + ② 解析 ===")
results = []
for i, u in enumerate(urls, 1):
    tag = "/".join(u.split("githubusercontent.com/")[-1].split("/")[:3])
    t0 = time.time()
    nodes, err = grab(u)
    dt = time.time() - t0
    if err or not nodes:
        print(f"  [{i:2}] ✗ {err or '解析出 0 个节点':<22} {tag}")
        results.append((tag, u, 0, dt))
        continue
    print(f"  [{i:2}] ✓ {len(nodes):5} 个节点  {tag}  ({dt:.1f}s)")
    results.append((tag, u, len(nodes), dt))

ok = [(t, u, n, d) for t, u, n, d in results if n > 0]
print(f"\n  能解析出节点的: {len(ok)}/{len(urls)}")

# ---------- ③ 抽样 L1 探活 ----------
print()
print("=== ③ 抽样 L1 探活(每个源最多抽 300 个, 看存活率) ===")
import random
random.seed(7)
scored = []
for tag, u, n, dt in sorted(ok, key=lambda x: -x[2]):
    nodes, err = grab(u)
    if err or not nodes:
        continue
    sample = random.sample(nodes, min(300, len(nodes)))
    # 去重(同源内可能有重复)
    seen, uniq = set(), []
    for x in sample:
        k = f"{x.get('server')}:{x.get('port')}"
        if k not in seen:
            seen.add(k)
            uniq.append(x)
    alive = pool.probe_tcp(uniq, timeout=3.0, concurrency=300, hist=None)
    rate = len(alive) / len(uniq) * 100 if uniq else 0
    scored.append((rate, len(uniq), tag, u, n))
    print(f"  存活 {len(alive):3}/{len(uniq):3} = {rate:5.1f}%   {tag}   (全量 {n})")

scored.sort(reverse=True)
print()
print("=" * 78)
print("按存活率排序")
print("=" * 78)
for rate, tot, tag, u, n in scored:
    flag = "★" if rate >= 10 else (" " if rate >= 3 else "✗")
    print(f"  {flag} {rate:5.1f}%  {tag:<58} 全量 {n}")

print()
print("=== 存活率 >= 3% 的源(建议加入) ===")
add = [u for rate, tot, tag, u, n in scored if rate >= 3]
for u in add:
    print(f"  {u}")
with open(r"E:\AI\freeVPN\state\candidates_ok.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(add) + "\n")
print(f"\n  {len(add)} 个已写入 state/candidates_ok.txt")
