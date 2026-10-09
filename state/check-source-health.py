#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""体检现有 sources.txt 里的每一个源 —— 找出该淘汰的。

新源找不到更好的, 那就反过来看现有的有没有已经死了的。
判据用 L2(真能出网), 不用 L1 —— L1 会被 CDN 假节点骗。
"""
import random
import sys
import time

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool  # noqa: E402
import security as sec  # noqa: E402

SAMPLE = 200
urls = pool.load_sources()
print(f"sources.txt 里 {len(urls)} 个源, 每源抽样 {SAMPLE} 个送 L2\n")

rows = []
for i, url in enumerate(urls, 1):
    short = url.replace("https://raw.githubusercontent.com/", "")
    short = short[:52]
    t0 = time.time()
    try:
        _u, text = pool.fetch_one(url, timeout=25)
    except Exception as e:
        print(f"  [{i:2}] ✗ 拉取异常 {type(e).__name__:<14} {short}")
        rows.append((0.0, 0, 0, short, "拉取异常"))
        continue
    if not text:
        print(f"  [{i:2}] ✗ 拉不到                {short}")
        rows.append((0.0, 0, 0, short, "拉不到"))
        continue
    text = sec.clamp_text(text)
    try:
        nodes = pool.parse_any(text)
    except Exception as e:
        print(f"  [{i:2}] ✗ 解析异常 {type(e).__name__:<14} {short}")
        rows.append((0.0, 0, 0, short, "解析异常"))
        continue
    if not nodes:
        print(f"  [{i:2}] ✗ 0 个节点              {short}")
        rows.append((0.0, 0, 0, short, "空源"))
        continue

    seen, uniq = set(), []
    for n in nodes:
        k = f"{n.get('server')}:{n.get('port')}"
        if k not in seen:
            seen.add(k)
            uniq.append(n)
    random.seed(5)
    sample = random.sample(uniq, min(SAMPLE, len(uniq)))
    got = pool.probe_real(sample, timeout_ms=3000, workers=192,
                          chunk=len(sample), hist=None)
    dt = time.time() - t0
    rate = 100 * len(got) / len(sample)
    per1k = 1000 * len(got) / len(sample)
    rows.append((rate, per1k, len(nodes), short, ""))
    print(f"  [{i:2}] 全量{len(nodes):>5} 唯一{len(uniq):>5} 送测{len(sample):>3} "
          f"可用{len(got):>3}  L2={rate:5.1f}%  每千={per1k:5.1f}  ({dt:.0f}s)  {short}")

rows.sort(reverse=True)
print()
print("=" * 96)
print("按 L2 可用率排序")
print("=" * 96)
keep, prune, weak = [], [], []
for rate, per1k, tot, short, err in rows:
    if err:
        verdict = "✗ 坏源"
        prune.append(short)
    elif rate >= 2:
        verdict = "★ 保留"
        keep.append(short)
    elif rate >= 0.5:
        verdict = "  一般"
        weak.append(short)
    else:
        verdict = "✗ 建议淘汰"
        prune.append(short)
    print(f"  {rate:5.1f}%  每千{per1k:6.1f}  全量{tot:>5}  {verdict:<12} {short}")

print()
print(f"★ 保留 (L2>=2%):    {len(keep)} 个")
print(f"  一般 (0.5-2%):    {len(weak)} 个")
print(f"✗ 建议淘汰 (<0.5%): {len(prune)} 个")
for x in prune:
    print(f"    {x}")
