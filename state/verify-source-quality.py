#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证"高存活率"的源是不是 CDN 假节点。

现象: 某些源抽样 L1 存活率 85-97%, 而且 300 个节点 0.1 秒全部响应。
真实代理节点的 TCP 建连中位数在 200ms 以上 —— 0.1s 意味着根本不是远端节点。

判据:
  · 服务器地址是不是 Cloudflare / Fastly / 其他 CDN 网段
  · 端口是不是 80/443/8080/8443 这类 CDN 常用端口
  · 同一 IP 是否被重复用作大量"不同节点"

对照: 已知的真实源(cysk003 / roosterkid / mohamadfg) 存活率 7-28%, 探活耗时 3-12s。
"""
import collections
import ipaddress
import random
import socket
import sys

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool  # noqa: E402
import security as sec  # noqa: E402

SUSPECT = [
    "https://raw.githubusercontent.com/ninjastrikers/nexus-nodes/main/configs/all.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/vless.txt",
    "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri",
]
CONTROL = [
    "https://raw.githubusercontent.com/cysk003/freeSub/main/clash.yaml",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
]

CDN_HINT = {
    "Cloudflare": ["104.16.", "104.17.", "104.18.", "104.19.", "104.2", "172.64.",
                   "172.65.", "172.66.", "172.67.", "172.68.", "172.69.", "172.70.",
                   "172.71.", "162.159.", "188.114.", "190.93.", "197.234.",
                   "198.41.", "103.21.", "103.22.", "103.31.", "141.101.",
                   "108.162.", "131.0.72."],
    "Fastly": ["151.101.", "199.232."],
    "Gcore": ["92.223.", "95.85.6"],
    "Akamai": ["23.32.", "23.33.", "23.34.", "23.35."],
}


def cdn_of(server: str) -> str:
    for name, pres in CDN_HINT.items():
        for p in pres:
            if server.startswith(p):
                return name
    return ""


def analyze(label: str, url: str):
    print(f"\n=== {label}: {url.split('/')[-1]} ===")
    _u, text = pool.fetch_one(url, timeout=25)
    if not text:
        print("  拉不到")
        return
    text = sec.clamp_text(text)
    nodes = pool.parse_any(text)
    if not nodes:
        print("  解析出 0 个节点")
        return

    servers = [n.get("server", "") for n in nodes]
    ports = [str(n.get("port", "")) for n in nodes]
    print(f"  节点总数: {len(nodes)}")
    print(f"  唯一服务器: {len(set(servers))}   (重复度 {len(nodes)/max(1,len(set(servers))):.1f}x)")
    print(f"  唯一 server:port: {len(set(zip(servers, ports)))}")

    cdn = collections.Counter(cdn_of(s) for s in servers)
    cdn.pop("", None)
    if cdn:
        tot = sum(cdn.values())
        print(f"  ** CDN 网段占比: {tot}/{len(servers)} = {100*tot/len(servers):.0f}% **")
        for k, v in cdn.most_common():
            print(f"       {k}: {v}")
    else:
        print("  CDN 网段占比: 0%")

    pc = collections.Counter(ports)
    print(f"  端口 Top5: {pc.most_common(5)}")

    # 抽样探活, 同时记录耗时
    random.seed(3)
    sample = random.sample(nodes, min(200, len(nodes)))
    import time
    t0 = time.time()
    alive = pool.probe_tcp(sample, timeout=3.0, concurrency=300, hist=None)
    dt = time.time() - t0
    print(f"  抽样 {len(sample)} 个: 存活 {len(alive)} ({100*len(alive)/len(sample):.0f}%), "
          f"耗时 {dt:.2f}s")
    if alive:
        tcp = sorted(a.get("_tcp", 9999) for a in alive)
        print(f"  存活节点 TCP 延迟: 中位 {tcp[len(tcp)//2]:.0f}ms  "
              f"最小 {tcp[0]:.0f}ms  最大 {tcp[-1]:.0f}ms")


print("=" * 74)
print("可疑的『高存活率』源")
print("=" * 74)
for i, u in enumerate(SUSPECT):
    analyze(f"可疑 {i+1}", u)

print()
print("=" * 74)
print("对照: 已知的真实源")
print("=" * 74)
for i, u in enumerate(CONTROL):
    analyze(f"对照 {i+1}", u)
