#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lead 交叉验证 audit-server 的两条关键结论, 不采信报告原文。

A-01: 内核控制端口密钥是否真的硬编码 + API 是否真的回 CORS *
A-04: 非 ASCII 令牌是否真的抛 TypeError
"""
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, r"E:\AI\freeVPN")
import pool  # noqa: E402
import security as sec  # noqa: E402

FAIL = []


def check(label, got, want):
    ok = got == want
    if not ok:
        FAIL.append(label)
    print(f"  [{'确认' if ok else '不符'}] {label}: {got!r} (期望 {want!r})")
    return ok


print("=" * 64)
print("A-04 · 非 ASCII 令牌")
print("=" * 64)
try:
    r = sec.token_ok("中文令牌", "abcdef")
    print(f"  token_ok('中文令牌', 'abcdef') -> {r}  没有抛异常")
    FAIL.append("A-04 未复现")
except TypeError as e:
    print(f"  token_ok('中文令牌', 'abcdef') -> TypeError: {e}")
    print("  >>> A-04 确认: 会抛未捕获异常")
except Exception as e:
    print(f"  其它异常 {type(e).__name__}: {e}")

print()
print("=" * 64)
print("A-01 · 内核控制端口")
print("=" * 64)

# 1) 密钥是否硬编码
print(f"  pool.SECRET 常量 = {pool.SECRET!r}")
check("SECRET 是硬编码的 'freevpn'", pool.SECRET, "freevpn")

# 2) 生成的配置里 secret 是不是这个硬编码值
nodes = [{"type": "ss", "server": "1.2.3.4", "port": 8388,
          "cipher": "aes-128-gcm", "password": "x", "name": "t"}]
cfgpath = pool._write_kernel_config(nodes)
import yaml  # noqa: E402
cfg = yaml.safe_load(cfgpath.read_text(encoding="utf-8"))
print(f"  生成的配置里 secret = {cfg.get('secret')!r}")
print(f"  生成的配置里 external-controller = {cfg.get('external-controller')!r}")
check("配置里的 secret 就是硬编码值", cfg.get("secret"), "freevpn")

# 3) 真启动内核, 测 API 与 CORS
print()
print("  启动内核实测 ...")
k = pool.Kernel()
if not k.start(nodes):
    print("  [!] 内核起不来, 跳过实测")
    sys.exit(1)

CTRL = f"http://127.0.0.1:{pool.CTRL_PORT}"
try:
    # 3a) 带正确 secret
    req = urllib.request.Request(CTRL + "/configs",
                                 headers={"Authorization": f"Bearer {pool.SECRET}"})
    with urllib.request.urlopen(req, timeout=8) as r:
        hdrs = dict(r.getheaders())
        body = json.loads(r.read())
    check("用硬编码密钥能读 /configs", r.status, 200)
    acao = hdrs.get("Access-Control-Allow-Origin")
    check("mihomo 回 Access-Control-Allow-Origin: *", acao, "*")
    print(f"     /configs 里 allow-lan = {body.get('allow-lan')!r}, "
          f"bind-address = {body.get('bind-address')!r}")

    # 3b) 错误密钥应当被拒
    try:
        req = urllib.request.Request(CTRL + "/configs",
                                     headers={"Authorization": "Bearer wrong"})
        urllib.request.urlopen(req, timeout=8)
        check("错误密钥被拒", "放行了", "401")
    except urllib.error.HTTPError as e:
        check("错误密钥被拒", e.code, 401)

    # 3c) 能不能真的改配置(这就是 A-01 的核心危害)
    payload = json.dumps({"allow-lan": True, "bind-address": "0.0.0.0"}).encode()
    req = urllib.request.Request(CTRL + "/configs", data=payload, method="PATCH",
                                 headers={"Authorization": f"Bearer {pool.SECRET}",
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    print(f"  PATCH /configs {{allow-lan:true, bind-address:0.0.0.0}} -> HTTP {code}")

    # 3d) 看监听地址是否真的被改成 0.0.0.0
    time.sleep(1.5)
    out = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         f"Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
         f"Where-Object {{ $_.OwningProcess -eq {k.proc.pid} }} | "
         f"Select-Object -ExpandProperty LocalAddress | Sort-Object -Unique"],
        capture_output=True, text=True, timeout=30).stdout
    addrs = [a.strip() for a in out.splitlines() if a.strip()]
    print(f"  内核当前监听地址: {addrs}")
    if any(a in ("0.0.0.0", "::") for a in addrs):
        print("  >>> A-01 确认: 代理端口被改到 0.0.0.0, harden 的 allow-lan=false 被推翻")
    else:
        print("  >>> 监听地址未变, A-01 的写操作未复现")
        FAIL.append("A-01 写操作未复现")
finally:
    k.stop()

print()
print("=" * 64)
if FAIL:
    print(f"有 {len(FAIL)} 项未按报告复现: {FAIL}")
else:
    print("全部按报告复现")
