#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A5b · 内核 API 到底能读出什么: /proxies 与 /configs 的响应内容。

用于核实 A-01 里"任意网页能读到全部节点凭据"这一断言。
只打印字段结构, 凭据值做掩码。
"""
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(r"E:\AI\freeVPN")
sys.path.insert(0, str(ROOT))
import pool          # noqa: E402
import security as sec  # noqa: E402

TMP = ROOT / "audit" / "_tmp"
KDIR = TMP / "kernel"
KDIR.mkdir(parents=True, exist_ok=True)
pool.KERNEL_DIR = KDIR

NODES = [
    {"type": "ss", "server": "1.1.1.1", "port": 8388,
     "cipher": "aes-128-gcm", "password": "SECRET-PASSWORD-A"},
    {"type": "vmess", "server": "2.2.2.2", "port": 443, "uuid": "deadbeef-1111-2222-3333-444455556666",
     "alterId": 0, "cipher": "auto", "tls": True, "servername": "example.com"},
]
CFG = pool._write_kernel_config(NODES)
print(f"配置: {CFG}")

proc = subprocess.Popen([str(pool.MIHOMO), "-d", str(KDIR), "-f", str(CFG)],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        stdin=subprocess.DEVNULL, cwd=str(KDIR),
                        env=sec.kernel_env(), creationflags=sec.kernel_creationflags())
try:
    for _ in range(40):
        if proc.poll() is not None:
            print("内核退出"); sys.exit(1)
        try:
            pool._api("/version", timeout=2)
            break
        except Exception:
            time.sleep(0.5)

    def mask(o):
        if isinstance(o, dict):
            return {k: ("***" if k.lower() in ("password", "uuid", "secret", "psk",
                                               "private-key", "token") else mask(v))
                    for k, v in o.items()}
        if isinstance(o, list):
            return [mask(x) for x in o]
        return o

    print("\n=== GET /proxies (字段结构) ===")
    p = pool._api("/proxies")
    for name, v in list(p.get("proxies", {}).items()):
        print(f"  {name}: {json.dumps(mask(v), ensure_ascii=False)[:220]}")

    print("\n=== GET /configs (字段结构) ===")
    c = pool._api("/configs")
    print(f"  顶层键: {sorted(c.keys())}")
    proxies = c.get("proxies") or []
    print(f"  /configs 里 proxies 条数: {len(proxies)}")
    for item in proxies:
        print(f"    {json.dumps(mask(item), ensure_ascii=False)}")
    print(f"  /configs 里有没有 password 明文: "
          f"{'SECRET-PASSWORD-A' in json.dumps(c, ensure_ascii=False)}")
    print(f"  /configs 里有没有 uuid 明文: "
          f"{'deadbeef-1111-2222-3333-444455556666' in json.dumps(c, ensure_ascii=False)}")

    print("\n=== 其它可读端点 (避开 /traffic /memory /logs 这三个流式端点) ===")
    for ep in ("/version", "/configs", "/proxies", "/rules", "/connections"):
        try:
            d = pool._api(ep, timeout=3)
            keys = sorted(d.keys())[:8] if isinstance(d, dict) else type(d).__name__
            print(f"  {ep:<14} -> OK  {keys}")
        except Exception as e:
            print(f"  {ep:<14} -> {type(e).__name__}")
    print("  (/traffic /memory /logs 是 chunked 流式端点, 未测以免挂住)")

    print("\n=== 写端点: PUT /configs 是否可改配置 ===")
    import urllib.request
    body = json.dumps({"mode": "global"}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{pool.CTRL_PORT}/configs",
                                 data=body, method="PATCH",
                                 headers={"Authorization": f"Bearer {pool.SECRET}",
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            print(f"  PATCH /configs {{'mode':'global'}} -> HTTP {r.status}")
    except Exception as e:
        print(f"  PATCH /configs -> {getattr(e, 'code', type(e).__name__)}")
    print(f"  改完之后 GET /configs mode = {pool._api('/configs').get('mode')!r}")

    print("\n=== 写端点: 能不能把代理端口暴露到局域网 ===")

    def patch(obj):
        req = urllib.request.Request(f"http://127.0.0.1:{pool.CTRL_PORT}/configs",
                                     data=json.dumps(obj).encode(), method="PATCH",
                                     headers={"Authorization": f"Bearer {pool.SECRET}",
                                              "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status
        except Exception as e:
            return getattr(e, "code", type(e).__name__)

    def listen_ports(pid):
        r = subprocess.run(["netstat", "-ano"], capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
        out = set()
        for line in (r.stdout or "").splitlines():
            p = line.split()
            if len(p) >= 5 and p[0] == "TCP" and p[-1] == str(pid):
                out.add(p[1])
        return sorted(out)

    print(f"  改之前监听: {listen_ports(proc.pid)}")
    st = patch({"allow-lan": True, "bind-address": "0.0.0.0"})
    time.sleep(1.5)
    print(f"  PATCH {{'allow-lan': true, 'bind-address': '0.0.0.0'}} -> HTTP {st}")
    print(f"  改之后监听: {listen_ports(proc.pid)}")
    c2 = pool._api("/configs")
    print(f"  /configs 里 allow-lan={c2.get('allow-lan')!r}  bind-address={c2.get('bind-address')!r}")
    print(f"  >>> {'代理端口已被暴露到所有接口 (0.0.0.0)' if any(a.startswith('0.0.0.0') for a in listen_ports(proc.pid)) else '仍只绑回环'}")
    patch({"allow-lan": False})
finally:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=6)
        except subprocess.TimeoutExpired:
            proc.kill()
