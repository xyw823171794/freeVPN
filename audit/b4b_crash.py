# -*- coding: utf-8 -*-
"""
问题 4 补充: 定向定位 fuzz 命中的两类真实缺陷
  (1) parse_vmess 对 JSON 顶层非 dict 的输入抛 AttributeError
  (2) parse_vless/trojan/hysteria2/tuic 对畸形 IPv6 netloc 抛 ValueError
并确认这些异常在正常入口 (parse_links / parse_any / collect) 是否被兜住。
"""
import base64
import sys

sys.path.insert(0, r"E:\AI\freeVPN")
import pool

print("=" * 78)
print("### 4.5a parse_vmess 的 AttributeError (JSON 顶层不是 object)")
print("=" * 78)
for payload in (b"[]", b"123", b'"str"', b"null", b"true", b'{"add":"1.2.3.4"}'):
    link = "vmess://" + base64.b64encode(payload).decode()
    try:
        r = pool.parse_vmess(link)
        print(f"  {payload!r:22} -> {r}")
    except Exception as e:
        print(f"  {payload!r:22} -> *** {type(e).__name__}: {e} ***")
    try:
        r = pool.parse_links(link + "\n")
        print(f"     经 parse_links -> {r}")
    except Exception as e:
        print(f"     经 parse_links -> *** {type(e).__name__}: {e} ***")
    try:
        r = pool.parse_any(link + "\n")
        print(f"     经 parse_any   -> {r}")
    except Exception as e:
        print(f"     经 parse_any   -> *** {type(e).__name__}: {e} ***")
    print()

print("=" * 78)
print("### 4.5b 畸形 IPv6 netloc 的 ValueError")
print("=" * 78)
for link in ("vless://u@[::1:443",
             "vless://u@[::1]:443",
             "trojan://p@[abc]:443",
             "hysteria2://p@[:::1]:443",
             "tuic://u:p@[1:2:3]:443"):
    for fn in (pool.parse_vless, pool.parse_trojan, pool.parse_hysteria2, pool.parse_tuic):
        try:
            fn(link)
        except Exception as e:
            print(f"  {fn.__name__:16} {link:28} -> {type(e).__name__}: {e}")
            break
    try:
        r = pool.parse_any(link + "\n")
        print(f"  parse_any        {link:28} -> {len(r)} 节点 (异常已被 parse_links 兜住)")
    except Exception as e:
        print(f"  parse_any        {link:28} -> *** {type(e).__name__}: {e} ***")
