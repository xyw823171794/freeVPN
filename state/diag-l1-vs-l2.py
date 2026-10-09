#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""定位 L1 误杀: 被 L1 判死、但 L2 真能出网的节点。

CHANGELOG「已知未修」里那条: Ruk1ng001 的 200 个节点里 L2 能用 98 个,
但其中 18 个过不了 L1 的 TCP 探测。这里把同一批节点**全量**送 L2(绕过 L1),
再与 L1 结果对比, 并对每个被误杀的节点逐项诊断:

  · server 是域名还是 IP
  · getaddrinfo 解析出几个地址(v4/v6)、耗时多少
  · 每个地址单独直连的结果
  · 把 L1 超时放大到 15s 后能不能连上

跑法: python state/diag-l1-vs-l2.py [样本数]
"""
import asyncio
import ipaddress
import socket
import sys
import time

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool       # noqa: E402
import security as sec  # noqa: E402

SRC = "https://raw.githubusercontent.com/Ruk1ng001/freeSub/main/clash.yaml"


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def diag(n: dict) -> None:
    host, port = n["server"], n["port"]
    kind = "IP " if is_ip(host) else "域名"
    print(f"\n  {str(n.get('name'))[:44]}")
    print(f"    目标 {host}:{port}  [{kind}]  type={n['type']}  L2延迟={n.get('_real')}ms")

    t0 = time.time()
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except Exception as e:
        print(f"    getaddrinfo 失败: {type(e).__name__}: {e}  "
              f"({(time.time()-t0)*1000:.0f}ms)")
        return
    dns_ms = (time.time() - t0) * 1000
    seen = []
    for fam, _t, _p, _c, sa in infos:
        if sa[0] not in [a for _f, a in seen]:
            seen.append((fam, sa[0]))
    tags = ", ".join(f"{'v6' if f == socket.AF_INET6 else 'v4'} {a}" for f, a in seen)
    print(f"    getaddrinfo {dns_ms:.0f}ms -> {len(seen)} 个地址: {tags}")

    for fam, addr in seen:
        t1 = time.time()
        try:
            s = socket.socket(fam, socket.SOCK_STREAM)
            s.settimeout(6.0)
            s.connect((addr, port))
            print(f"      单独直连 {addr:<42} OK    {(time.time()-t1)*1000:.0f}ms")
            s.close()
        except Exception as e:
            print(f"      单独直连 {addr:<42} 失败  {type(e).__name__} "
                  f"{(time.time()-t1)*1000:.0f}ms")

    # 放大超时重测 L1(同一条 asyncio 路径)
    for tmo in (5.0, 15.0):
        t2 = time.time()
        dt, timed_out = asyncio.run(pool._tcp_once(host, port, tmo))
        wall = (time.time() - t2) * 1000
        state = (f"连上 {dt:.0f}ms" if dt is not None
                 else ("超时" if timed_out else "其它失败"))
        print(f"    L1 同路径 timeout={tmo:>4.1f}s -> {state}  (实际耗时 {wall:.0f}ms)")


def main() -> int:
    sample = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    url, text = pool.fetch_one(SRC)
    if not text:
        print("拉源失败")
        return 1
    raw = pool.parse_any(text)
    print(f"源节点 {len(raw)} 个" + (f", 取前 {sample} 个" if sample else " (全量)"))
    nodes = pool.dedupe(raw[:sample] if sample else raw)
    nodes, _audit = sec.audit_pool(nodes)
    print(f"去重 + 审计后 {len(nodes)} 个\n")

    t0 = time.time()
    l1 = pool.probe_tcp([dict(n) for n in nodes], timeout=5.0, concurrency=500, tries=2)
    l1_fp = {n["_fp"] for n in l1}
    print(f"L1 存活 {len(l1)}/{len(nodes)}   ({time.time()-t0:.1f}s)\n")

    t0 = time.time()
    l2 = pool.probe_real([dict(n) for n in nodes], timeout_ms=3000, workers=192)
    l2_fp = {n["_fp"] for n in l2}
    print(f"\nL2 可用 {len(l2)}/{len(nodes)}   ({time.time()-t0:.1f}s)")

    killed = [n for n in nodes if n["_fp"] in l2_fp and n["_fp"] not in l1_fp]
    l1_only = [n for n in nodes if n["_fp"] in l1_fp and n["_fp"] not in l2_fp]
    both = l1_fp & l2_fp
    print()
    print("=" * 78)
    print(f"  L1 存活 {len(l1_fp)}   L2 可用 {len(l2_fp)}   两者都有 {len(both)}")
    print(f"  >>> L1 误杀(L2 可用但 L1 判死): {len(killed)} 个"
          f"   占 L2 可用量的 {100*len(killed)/max(1,len(l2_fp)):.0f}%")
    print(f"  >>> L1 放过但 L2 不可用: {len(l1_only)} 个")
    print("=" * 78)

    # 按协议分组 —— hysteria/tuic 是 QUIC(UDP), 根本不监听 TCP,
    # L1 的 TCP 握手对它们必然失败, 这一列会直接暴露根因
    from collections import defaultdict
    st: dict = defaultdict(lambda: {"n": 0, "l1": 0, "l2": 0, "killed": 0})
    for n in nodes:
        t = str(n.get("type") or "?")
        fp = n["_fp"]
        st[t]["n"] += 1
        st[t]["l1"] += 1 if fp in l1_fp else 0
        st[t]["l2"] += 1 if fp in l2_fp else 0
        st[t]["killed"] += 1 if (fp in l2_fp and fp not in l1_fp) else 0
    print(f"\n  {'协议':<12}{'总数':>6}{'L1存活':>8}{'L2可用':>8}{'被L1误杀':>10}"
          f"{'L1通过率':>10}{'L2可用率':>10}")
    print("  " + "-" * 74)
    for t, v in sorted(st.items(), key=lambda kv: -kv[1]["n"]):
        print(f"  {t:<12}{v['n']:>6}{v['l1']:>8}{v['l2']:>8}{v['killed']:>10}"
              f"{100*v['l1']/max(1,v['n']):>9.0f}%{100*v['l2']/max(1,v['n']):>9.0f}%")

    if killed:
        dom = sum(1 for n in killed if not is_ip(n["server"]))
        print(f"\n被误杀的 {len(killed)} 个里, server 是域名的有 {dom} 个, "
              f"是 IP 的有 {len(killed)-dom} 个")
        print("\n逐项诊断(最多 6 个):")
        for n in killed[:6]:
            diag(n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
