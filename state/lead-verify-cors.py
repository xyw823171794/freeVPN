#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lead 补验 A-01 的关键一环: 带 Origin 时 mihomo 是否回 CORS 放行。

这一环决定 A-01 是"本机任意进程可利用"还是"浏览器里任意网页可利用" ——
差别很大。没有 CORS 放行, 浏览器的 preflight 会挡掉带 Authorization 的 PATCH。
"""
import json
import sys
import urllib.error
import urllib.request

sys.path.insert(0, r"E:\AI\freeVPN")
import pool  # noqa: E402

nodes = [{"type": "ss", "server": "1.2.3.4", "port": 8388,
          "cipher": "aes-128-gcm", "password": "x", "name": "t"}]
pool._write_kernel_config(nodes)
k = pool.Kernel()
if not k.start(nodes):
    print("内核起不来")
    sys.exit(1)

CTRL = f"http://127.0.0.1:{pool.CTRL_PORT}"
ORIGIN = "http://evil.example"


def probe(label, method, path, headers):
    req = urllib.request.Request(CTRL + path, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            h = dict(r.getheaders())
            code = r.status
    except urllib.error.HTTPError as e:
        h = dict(e.headers)
        code = e.code
    except Exception as e:
        print(f"  {label}: 连接异常 {type(e).__name__}")
        return {}
    acao = h.get("Access-Control-Allow-Origin")
    acah = h.get("Access-Control-Allow-Headers")
    acam = h.get("Access-Control-Allow-Methods")
    print(f"  {label}")
    print(f"     HTTP {code}")
    print(f"     Access-Control-Allow-Origin  = {acao!r}")
    print(f"     Access-Control-Allow-Headers = {acah!r}")
    print(f"     Access-Control-Allow-Methods = {acam!r}")
    return h


print("=" * 66)
print("带 Origin 的简单请求 (GET)")
print("=" * 66)
probe("GET /configs  +Origin", "GET", "/configs",
      {"Origin": ORIGIN, "Authorization": f"Bearer {pool.SECRET}"})

print()
print("=" * 66)
print("preflight OPTIONS (浏览器发 PATCH 前必发)")
print("=" * 66)
probe("OPTIONS /configs +Origin +请求方法PATCH", "OPTIONS", "/configs",
      {"Origin": ORIGIN,
       "Access-Control-Request-Method": "PATCH",
       "Access-Control-Request-Headers": "authorization,content-type"})

print()
print("=" * 66)
print("判定")
print("=" * 66)
req = urllib.request.Request(CTRL + "/configs", method="OPTIONS",
                             headers={"Origin": ORIGIN,
                                      "Access-Control-Request-Method": "PATCH",
                                      "Access-Control-Request-Headers": "authorization"})
try:
    with urllib.request.urlopen(req, timeout=8) as r:
        acao = dict(r.getheaders()).get("Access-Control-Allow-Origin")
except urllib.error.HTTPError as e:
    acao = dict(e.headers).get("Access-Control-Allow-Origin")
except Exception:
    acao = None

if acao in ("*", ORIGIN):
    print(f"  >>> 浏览器可利用: preflight 放行 (ACAO={acao!r})")
    print("      任意网页可带 Authorization: Bearer freevpn 打 PATCH /configs")
else:
    print(f"  >>> 浏览器不可利用: preflight 未放行 (ACAO={acao!r})")
    print("      但本机任意进程仍可直接调 API —— 密钥硬编码这条依然成立")

k.stop()
