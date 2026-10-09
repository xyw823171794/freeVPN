#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""回归: L1 不能把 QUIC(hysteria/tuic) 节点当死节点筛掉。

这曾是 CHANGELOG 里的「已知未修」: Ruk1ng001 的 200 个节点里 L2 能用 98 个,
其中 18 个过不了 L1 的 TCP 探测, 一度怀疑是 Python 与内核的 DNS 解析路径不同。

实际根因是**协议**: hysteria / hysteria2 / tuic 走 QUIC(UDP), 根本不监听 TCP,
L1 的 TCP 三次握手对它们必然失败。实测把同一批节点全量送 L1 + L2:

    协议         总数   L1存活   L2可用   被L1误杀   L1通过率
    vless        23     17      4        0        74%
    vmess        11      9      3        0        82%
    anytls        9      9      4        0       100%
    ss            8      4      4        0        50%
    trojan        8      6      1        0        75%
    hysteria2    13      2      5        3        15%   ← QUIC
    hysteria      2      0      2        2         0%   ← QUIC
    tuic          2      0      1        1         0%   ← QUIC

修法: QUIC 协议跳过 L1 直接送 L2(见 pool.UDP_TYPES)。

跑法: python state/test-l1-udp.py
"""
from __future__ import annotations

import sys

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool  # noqa: E402

PASS, FAIL = [], []


def check(name: str, ok: bool, detail: str = ""):
    (PASS if ok else FAIL).append(name)
    print(f"  [{'OK ' if ok else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))


# 127.0.0.1:1 会立刻 RST —— 用它当"确定连不上"的目标, 不用等超时
DEAD = ("127.0.0.1", 1)


def node(t: str, name: str) -> dict:
    return {"name": name, "type": t, "server": DEAD[0], "port": DEAD[1]}


def main() -> int:
    print("=" * 74)
    print("  L1 与 QUIC 协议回归")
    print("=" * 74)

    print("\n[1] 协议判定")
    for t in ("hysteria", "hysteria2", "hy2", "tuic", "HYSTERIA2", " Tuic "):
        check(f"is_udp_type({t!r}) 为真", pool.is_udp_type({"type": t}))
    for t in ("vmess", "vless", "trojan", "ss", "ssr", "anytls", "", None):
        check(f"is_udp_type({t!r}) 为假", not pool.is_udp_type({"type": t}))
    check("UDP_TYPES 覆盖 hysteria/hysteria2/tuic",
          {"hysteria", "hysteria2", "tuic"} <= pool.UDP_TYPES)

    print("\n[2] L1: QUIC 放行, TCP 照筛")
    quic = [node("hysteria2", "q1"), node("hysteria", "q2"), node("tuic", "q3")]
    tcp = [node("vmess", "t1"), node("vless", "t2"), node("trojan", "t3")]
    hist: dict = {}
    alive = pool.probe_tcp(quic + tcp, timeout=1.0, concurrency=8, tries=1, hist=hist)
    alive_names = {n["name"] for n in alive}
    check("三个 QUIC 节点全部放行", {"q1", "q2", "q3"} <= alive_names,
          f"放行 {sorted(alive_names)}")
    check("三个 TCP 节点(连不上)全部被筛掉", not ({"t1", "t2", "t3"} & alive_names))
    check("放行的 QUIC 节点带 _l1_skip 标记",
          all(n.get("_l1_skip") == pool.L1_SKIP_UDP for n in alive if n["type"] != "vmess"))
    check("QUIC 节点没有被记进 L1 负缓存",
          all(f"q{i}" not in str(hist) for i in (1, 2, 3)),
          f"负缓存里 {len(hist)} 条")

    print("\n[3] rank: QUIC 节点不能全被排到最后")
    ranked = pool.rank([{"name": "a", "_tcp": 50}, {"name": "b", "_tcp": 100},
                        {"name": "c", "_tcp": 200}, node("hysteria2", "q")])
    order = [n["name"] for n in ranked]
    check("无 _tcp 的节点用中位数占位, 不会掉到最后",
          order.index("q") < order.index("c"), f"排序 {order}")
    check("排序仍是延迟升序", order[0] == "a" and order[-1] == "c", f"排序 {order}")

    print("\n[4] 标记不会漏进产物")
    stripped = pool.strip_private(node("hysteria2", "q") | {"_l1_skip": "udp", "_tcp": 12})
    check("_l1_skip 被 strip_private 过滤", "_l1_skip" not in stripped, str(stripped))

    print("\n" + "=" * 74)
    print(f"  通过 {len(PASS)} / 失败 {len(FAIL)}")
    for f in FAIL:
        print(f"    FAIL: {f}")
    print("=" * 74)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
