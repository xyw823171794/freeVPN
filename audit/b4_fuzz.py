# -*- coding: utf-8 -*-
"""
问题 4 验证: 解析器健壮性 —— 畸形/截断输入是否抛未捕获异常、死循环、吃满内存;
以及正则 ReDoS、深嵌套递归爆栈。
"""
import json
import random
import string
import sys
import time
import traceback

sys.path.insert(0, r"E:\AI\freeVPN")
import pool
import security as sec

random.seed(20260930)


def timed(fn, *a, **kw):
    t0 = time.perf_counter()
    try:
        r = fn(*a, **kw)
        return time.perf_counter() - t0, r, None
    except Exception as e:
        return time.perf_counter() - t0, None, f"{type(e).__name__}: {e}"


print("=" * 78)
print("### 4.1 畸形输入 fuzz: parse_any 是否抛未捕获异常 / 卡死")
print("=" * 78)
CORPUS = [
    "", " ", "\n" * 100,
    "vmess://", "vmess://!!!!", "vmess://" + "A" * 5000,
    "vmess://" + "eyJhZGQiOiIxLjIuMy40In0",  # 缺字段的合法 b64
    "vless://", "vless://@", "vless://u@", "vless://u@h", "vless://u@h:",
    "vless://u@h:99999", "vless://u@h:0", "vless://u@h:-1", "vless://u@h:443?a=b%",
    "trojan://", "trojan://p@", "trojan://p@h:443#%00%0a%0d",
    "ss://", "ss://@", "ss://#", "ss://YWVzLTEyOC1nY206cHc@1.2.3.4:8388",
    "ss://" + "=" * 300, "ss://AAAA@", "ss://aaaa@b:", "ss://aaaa@:80",
    "ss://" + "A" * 4000 + "@1.2.3.4:8388#x",
    "hysteria2://", "hysteria2://@", "hysteria2://p@h:443?obfs=",
    "tuic://", "tuic://u@", "tuic://u:p@h:443",
    "proxies:", "proxies: []", "proxies:\n  - ", "proxies:\n  - {",
    "proxies:\n  - name: x\n    server: 1.2.3.4\n    port: 443",
    "proxies:\n" + "  - server: a\n    port: 1\n" * 300,
    "\x00\x01\x02\xff\xfe", "a" * 100000,
    "-" * 10000, ":" * 10000, "#" * 10000,
    "proxies:\n" + "\t" * 5000 + "- server: a\n    port: 1",
    "{\"a\": " * 400 + "1" + "}" * 400,
    "[" * 400 + "]" * 400,
    "a: &x [*x]", "a: &x\n  b: *x\n" * 3,
]
bad = 0
for i, txt in enumerate(CORPUS):
    dt, r, err = timed(pool.parse_any, txt)
    flag = ""
    if err:
        flag = "  <== 未捕获异常"
        bad += 1
    if dt > 1.0:
        flag += f"  <== 慢 {dt:.2f}s"
    if err or dt > 1.0:
        print(f"  #{i:02d} len={len(txt):7} t={dt:7.3f}s {flag}  {err or ''}")
        print(f"       输入前 60 字符: {txt[:60]!r}")
print(f"  -> 共 {len(CORPUS)} 条, 抛异常 {bad} 条, 无异常超 1s 的条目见上")

print()
print("=" * 78)
print("### 4.2 随机 fuzz: parse_links / parse_clash_yaml / _mini_yaml_proxies")
print("=" * 78)
ALPHABET = string.printable + "中文#@:?&=/%[]{}" + "\u2028\u0085"
fails = []
for i in range(4000):
    n = random.randint(0, 400)
    s = "".join(random.choice(ALPHABET) for _ in range(n))
    for fn in (pool.parse_links, pool.parse_any, pool.parse_clash_yaml,
               pool._mini_yaml_proxies, pool.b64_fix, pool.clean_name,
               pool.detect_region):
        try:
            fn(s)
        except Exception as e:
            fails.append((fn.__name__, type(e).__name__, str(e)[:90], s[:70]))
    for fn in (pool.parse_vmess, pool.parse_vless, pool.parse_trojan, pool.parse_ss,
               pool.parse_hysteria2, pool.parse_tuic):
        for pre in ("vmess://", "vless://", "trojan://", "ss://",
                    "hysteria2://", "tuic://"):
            try:
                fn(pre + s)
            except Exception as e:
                fails.append((fn.__name__, type(e).__name__, str(e)[:90], (pre + s)[:70]))
print(f"  随机用例 4000 × 多解析器 -> 未捕获异常 {len(fails)} 条")
from collections import Counter
print("  按函数统计:", dict(Counter(f[0] for f in fails)))
print("  按异常类型:", dict(Counter(f[1] for f in fails)))
for f in fails[:5]:
    print("   ", f)
print("  注意: 上表是**直接**调用解析器的结果; 经 parse_links/parse_any 的路径见 4.2b")
print()
print("  --- 4.2b 走正常入口 (parse_links / parse_any) 是否兜住 ---")
fails2 = []
for i in range(4000):
    n = random.randint(0, 400)
    s = "".join(random.choice(ALPHABET) for _ in range(n))
    for fn in (pool.parse_links, pool.parse_any):
        try:
            fn(s)
        except Exception as e:
            fails2.append((fn.__name__, type(e).__name__, str(e)[:80], s[:60]))
print(f"  parse_links / parse_any 直接入口: 未捕获异常 {len(fails2)} 条")
for f in fails2[:8]:
    print("   ", f)

print()
print("=" * 78)
print("### 4.3 正则 ReDoS 实测 (AD_PAT 里 \\s* + 可选组 + \\s* 的组合)")
print("=" * 78)
print("  AD_PAT =", pool.AD_PAT.pattern[:100])
print("  输入形如 '|' + ' '×N + '!'")
prev = None
for n in (500, 1000, 1500, 2000, 4000):
    s = "|" + " " * n + "!"
    dt, _, err = timed(pool.AD_PAT.sub, " ", s)
    ratio = f"  (比上一档放大 {dt/prev:.1f}×)" if prev else ""
    print(f"  AD_PAT.sub   N={n:5} 耗时={dt:9.3f}s{ratio}{err or ''}")
    prev = dt
print("  -> 输入 4000 字节即可让单次 clean_name 卡 2 分钟; 长度每翻倍耗时约 ×8 (O(n³))")
print()
print("  端到端: normalize() 一个名字含大量空格的节点")
for n in (1000, 2000):
    node = {"name": "|" + " " * n + "!", "type": "ss", "server": "1.2.3.4",
            "port": 8388, "cipher": "aes-128-gcm", "password": "pw"}
    dt, _, err = timed(pool.normalize, node)
    print(f"  normalize  名字长度={n:5} 耗时={dt:9.3f}s {err or ''}")
print()
for n in (2000, 8000, 32000, 128000):
    s = "登录" * n
    dt, _, err = timed(sec._LURE_RE.search, s)
    print(f"  _LURE_RE.search  '登录'×{n:<7} 耗时={dt:8.3f}s {err or ''}")
for n in (1000, 5000, 20000, 100000):
    s = "a" * n + "!"
    dt2, _, err2 = timed(pool.bad_host, s)
    print(f"  bad_host 长度={n:<7} 耗时={dt2:8.3f}s {err2 or ''}")
for n in (10000, 100000, 1000000):
    s = ("a: &x\n  b: *x\n" * (n // 10))
    dt, _, err = timed(sec.yaml_bomb, s)
    print(f"  yaml_bomb 长度={len(s):<9} 耗时={dt:8.3f}s {err or ''}")
print()
print("  长名字对 detect_region 的影响:")
for n in (1000, 20000, 100000):
    s = "x" * n
    dt, _, err = timed(pool.detect_region, s)
    print(f"  detect_region 长度={n:<7} 耗时={dt:8.3f}s {err or ''}")

print()
print("=" * 78)
print("### 4.4 深嵌套 -> 递归爆栈 (scrub / _yaml_lines 都是递归实现)")
print("=" * 78)


def deep_dict(depth: int) -> dict:
    d: dict = {}
    cur = d
    for i in range(depth):
        cur["k"] = {}
        cur = cur["k"]
    return d


for depth in (200, 600, 1000, 3000, 20000):
    node = {"name": "x", "type": "ss", "server": "1.2.3.4", "port": 443,
            "cipher": "aes-128-gcm", "password": "pw", "deep": deep_dict(depth)}
    dt, r, err = timed(pool.scrub, node)
    print(f"  scrub 深度={depth:<6} 耗时={dt:6.3f}s {err or 'ok'}")
    dt, r, err = timed(pool.normalize, dict(node))
    print(f"  normalize 深度={depth:<6} 耗时={dt:6.3f}s {err or 'ok'}")
    dt, r, err = timed(pool._dump_yaml, {"proxies": [node]})
    print(f"  _dump_yaml 深度={depth:<6} 耗时={dt:6.3f}s {err or 'ok'}")
    dt, r, err = timed(pool.build_clash, [node])
    print(f"  build_clash 深度={depth:<6} 耗时={dt:6.3f}s {err or 'ok'}")
    print()
