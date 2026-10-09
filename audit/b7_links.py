# -*- coding: utf-8 -*-
"""
问题 7 验证: proxy_to_link 生成的链接能否被注入 (名字里的 # & 换行 是否破坏链接结构,
进而污染客户端解析的通用订阅)。
"""
import base64
import sys

sys.path.insert(0, r"E:\AI\freeVPN")
import pool
import security as sec

UUID = "11111111-2222-3333-4444-555555555555"

EVIL_NAMES = [
    "普通名字",
    "带#井号",
    "带&和号",
    "带?问号",
    "带%百分号",
    "带/斜杠",
    "带\\反斜杠",
    "带 空格 和\t制表",
    "带\n换行\r回车",
    "带\u2028行分隔符",
    "带:冒号@at",
    "很长的名字" * 40,
    "☠️💀🏴‍☠️ emoji",
    "</script><script>alert(1)</script>",
    "a\r\nX-Injected: 1",
]


def mk(t: str, name: str, **kw) -> dict:
    base = {"name": name, "type": t, "server": "1.2.3.4", "port": 443}
    if t in ("vmess", "vless"):
        base["uuid"] = UUID
        base["alterId"] = 0
        base["cipher"] = "auto"
        base["tls"] = True
    if t == "trojan":
        base["password"] = "pw"
        base["tls"] = True
    if t == "ss":
        base["cipher"] = "aes-128-gcm"
        base["password"] = "pw"
    if t in ("hysteria2",):
        base["password"] = "pw"
    if t == "tuic":
        base["uuid"] = UUID
        base["password"] = "pw"
    base.update(kw)
    return base


print("=" * 78)
print("### 7.1 名字里的危险字符是否被转义")
print("=" * 78)
print(f"  {'名字(repr)':<34}{'类型':<10}{'生成的链接':<60}")
for t in ("vmess", "vless", "trojan", "ss", "hysteria2", "tuic"):
    for nm in EVIL_NAMES:
        n = pool.normalize(mk(t, nm))
        if not n:
            print(f"  {nm!r:<34}{t:<10}<normalize 丢弃>")
            continue
        link = pool.proxy_to_link(n)
        raw_newline = "\n" in link or "\r" in link or "\u2028" in link
        flag = "  <<< 链接里出现裸换行!" if raw_newline else ""
        print(f"  {nm!r:<34}{t:<10}{link[:78]}{flag}")
    print()

print("=" * 78)
print("### 7.2 生成的链接能否原样解析回来 (往返一致性)")
print("=" * 78)
for t in ("vmess", "vless", "trojan", "ss", "hysteria2", "tuic"):
    for nm in EVIL_NAMES:
        n = pool.normalize(mk(t, nm))
        if not n:
            continue
        link = pool.proxy_to_link(n)
        fn = pool.PARSERS.get(t)
        try:
            back = fn(link) if fn else None
        except Exception as e:
            print(f"  {t:9} {nm!r:<28} 回解析抛 {type(e).__name__}: {e}")
            continue
        if back is None:
            print(f"  {t:9} {nm!r:<28} 回解析得到 None (链接不可解析)")
            continue
        same = (str(back.get("server")) == "1.2.3.4"
                and str(back.get("port")) == "443")
        if not same:
            print(f"  {t:9} {nm!r:<28} *** server/port 被改写: "
                  f"{back.get('server')}:{back.get('port')} ***")
        elif back.get("name") != n["name"]:
            print(f"  {t:9} {nm!r:<28} name 往返不一致: {back.get('name')!r} "
                  f"!= {n['name']!r}")
print("  (只打印异常/被改写/不一致的条目; 无输出=全部一致)")

print()
print("=" * 78)
print("### 7.3 通用订阅 (build_b64) 结构是否被污染")
print("=" * 78)
nodes = []
for t in ("vmess", "vless", "trojan", "ss", "hysteria2", "tuic"):
    for nm in EVIL_NAMES:
        n = pool.normalize(mk(t, nm))
        if n:
            nodes.append(n)
b64 = pool.build_b64(nodes)
dec = base64.b64decode(b64).decode("utf-8")
lines = dec.split("\n")
print(f"  节点数={len(nodes)}  解码后行数={len(lines)}  "
      f"{'一致' if len(lines) == len(nodes) else '*** 不一致: 有节点塞进了裸换行 ***'}")
bad = [l for l in lines if not pool.LINK_RE.match(l)]
print(f"  不以已知协议开头的行: {len(bad)}")
for l in bad[:5]:
    print("   ", l[:120])

print()
print("=" * 78)
print("### 7.4 server / uuid / password 字段能否注入链接结构")
print("=" * 78)
INJ = [
    ("server", "1.2.3.4#evil"),
    ("server", "1.2.3.4?x=1"),
    ("server", "1.2.3.4@evil.com"),
    ("server", "evil.com/path"),
    ("server", "1.2.3.4\nMATCH,DIRECT"),
    ("server", "1.2.3.4 "),
    ("server", "a" * 300),
    ("uuid", "u@evil.com"),
    ("uuid", "u#frag"),
    ("uuid", "u?q=1"),
    ("uuid", "u\nnewline"),
    ("password", "p@evil.com"),
    ("password", "p#frag"),
    ("password", "p\nX"),
]
for field, val in INJ:
    p = mk("vless", "n")
    p[field] = val
    n = pool.normalize(dict(p))
    if not n:
        print(f"  vless {field:9} = {val!r:<26} -> normalize 丢弃 (已挡)")
        continue
    link = pool.proxy_to_link(n)
    print(f"  vless {field:9} = {val!r:<26} -> 存活, 链接: {link[:90]}")

for field, val in INJ:
    p = mk("tuic", "n")
    p[field] = val
    n = pool.normalize(dict(p))
    if not n:
        print(f"  tuic  {field:9} = {val!r:<26} -> normalize 丢弃 (已挡)")
        continue
    link = pool.proxy_to_link(n)
    print(f"  tuic  {field:9} = {val!r:<26} -> 存活, 链接: {link[:90]}")

print()
print("=" * 78)
print("### 7.5 urlsplit 对含 @ / [ 的 netloc 的行为 (解析歧义)")
print("=" * 78)
import urllib.parse
for u in ("tuic://a@b:pw@1.2.3.4:443",
          "vless://a@b@1.2.3.4:443",
          "vless://u@[::1]:443",
          "vless://u@[::1:443",
          "ss://YWJj@1.2.3.4:8388#x"):
    try:
        p = pool._url_parts(u)
        print(f"  {u:34} -> scheme={p[0]} user={p[1]!r} pw={p[2]!r} host={p[3]!r} port={p[4]}")
    except Exception as e:
        print(f"  {u:34} -> {type(e).__name__}: {e}")
