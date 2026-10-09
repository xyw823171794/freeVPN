#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""对候选源做 L2 实测 —— 这才是"源好不好"的决定性指标。

L1 只说明 TCP 通(CDN IP 也通, 而且通得更快)。
只有把节点塞进内核、真的发一个 HTTP 请求出去, 才知道这个源有没有价值。

输出: 每个源 L2 真实可用率, 以及"每 1000 个候选能捞出几个可用节点"。
后者才是扩池时真正要看的数 —— 一个源给 8000 个节点但只有 3 个能用,
不如一个给 200 个节点里有 20 个能用的。
"""
import random
import sys
import time

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool  # noqa: E402
import security as sec  # noqa: E402

# 候选源(不在现有 sources.txt 里的新源)
CANDIDATES = [
    ("ninjastrikers/nexus-nodes",
     "https://raw.githubusercontent.com/ninjastrikers/nexus-nodes/main/configs/all.txt"),
    ("hamedcode/port-based-vless",
     "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/vless.txt"),
    ("cysk003/freeSub",
     "https://raw.githubusercontent.com/cysk003/freeSub/main/clash.yaml"),
    ("SnapdragonLee/SystemProxy",
     "https://raw.githubusercontent.com/SnapdragonLee/SystemProxy/master/dist/clash_config.yaml"),
    ("wuqb2i4f/xray-toolkit",
     "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri"),
    ("mohamadfg-dev/tg-collector",
     "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/main/category/vless.txt"),
    ("roosterkid/openproxylist",
     "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt"),
    ("Kwinshadow/TGCollector",
     "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/mix.txt"),
    ("Au1rxx/free-vpn-subs",
     "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/stable/clash-0003.yaml"),
]

# 对照: 现有 sources.txt 里的一个源
CONTROL = ("[现有] free18/v2ray c.yaml",
           "https://raw.githubusercontent.com/free18/v2ray/main/c.yaml")

SAMPLE = 300          # 每源抽多少送内核


def l2_rate(nodes: list[dict]) -> tuple[int, int]:
    """跑 L2, 返回 (送测数, 真能出网数)。"""
    if not nodes:
        return 0, 0
    got = pool.probe_real(nodes, timeout_ms=3000, workers=192,
                          chunk=len(nodes), hist=None)
    return len(nodes), len(got)


print(f"每源抽样 {SAMPLE} 个送内核实测 (L2 才是决定性指标)\n")
rows = []
for label, url in CANDIDATES + [CONTROL]:
    t0 = time.time()
    _u, text = pool.fetch_one(url, timeout=25)
    if not text:
        print(f"  {label:<34} 拉不到")
        continue
    text = sec.clamp_text(text)
    nodes = pool.parse_any(text)
    if not nodes:
        print(f"  {label:<34} 解析出 0 个")
        continue

    # 去重(同源内重复很多), 再抽样 —— 否则 4.1x 注水的源会虚高
    seen, uniq = set(), []
    for n in nodes:
        k = f"{n.get('server')}:{n.get('port')}"
        if k not in seen:
            seen.add(k)
            uniq.append(n)
    random.seed(11)
    sample = random.sample(uniq, min(SAMPLE, len(uniq)))

    tested, usable = l2_rate(sample)
    dt = time.time() - t0
    rate = 100 * usable / tested if tested else 0
    per1k = 1000 * usable / tested if tested else 0
    rows.append((rate, per1k, label, len(nodes), len(uniq), tested, usable))
    print(f"  {label:<34} 全量{len(nodes):>5} 唯一{len(uniq):>5}  "
          f"送测{tested:>3} 可用{usable:>3}  L2={rate:5.1f}%  "
          f"每千候选={per1k:5.1f}  ({dt:.0f}s)")

rows.sort(reverse=True)
print()
print("=" * 92)
print("按 L2 可用率排序")
print("=" * 92)
print(f"  {'源':<34} {'L2可用率':>9} {'每千候选':>9}  评价")
for rate, per1k, label, tot, uniq, tested, usable in rows:
    if rate >= 10:
        verdict = "★★ 优质"
    elif rate >= 5:
        verdict = "★  可用"
    elif rate >= 2:
        verdict = "   一般"
    else:
        verdict = "✗  很差"
    print(f"  {label:<34} {rate:8.1f}% {per1k:8.1f}  {verdict}")

print()
good = [label for rate, _p, label, *_ in rows if rate >= 5]
print(f"L2 可用率 >= 5% 的源: {len(good)} 个")
for g in good:
    print(f"  {g}")
