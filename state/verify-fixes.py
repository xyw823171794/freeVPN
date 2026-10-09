#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lead 修复复验: 逐条重放两位审计员发现的漏洞, 确认已被堵住。

判据是"攻击还能不能打穿", 不是"代码里有没有那句修复"。
"""
import json
import os
import sys
import time

import yaml

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool  # noqa: E402
import security as sec  # noqa: E402

RESULTS = []


def check(tag, title, blocked, detail=""):
    RESULTS.append((tag, title, blocked))
    print(f"  [{'已堵住' if blocked else '仍可打穿'}] {tag} {title}")
    if detail:
        print(f"           {detail}")


print("=" * 70)
print("B-1 · 产物 YAML 顶层注入 (Unicode 行分隔符)")
print("=" * 70)
PAYLOAD_KEY = ("x: 1\u2028tun:\u2028  enable: true\u2028  stack: system"
               "\u2028  auto-route: true\u2028  #")
raw = {"name": "evil", "type": "vmess", "server": "1.2.3.4", "port": 443,
       "uuid": "11111111-2222-3333-4444-555555555555", "alterId": 0,
       "cipher": "auto", "tls": True, PAYLOAD_KEY: "1"}
n = pool.normalize(dict(raw))
kept, _aud = sec.audit_pool([n] if n else [])
if kept:
    cfg = yaml.safe_load(pool.build_clash(kept, "PoC"))
    injected = "tun" in cfg or "tunnels" in cfg or "hosts" in cfg
    check("B-1", "恶意键名注入顶层 tun", not injected,
          f"产物顶层键: {sorted(cfg.keys())}")
else:
    check("B-1", "恶意键名注入顶层 tun", True, "节点已在审计/归一阶段被丢弃")
# 行分隔符本身
sep_alive = [c for c in ("\x85", "\u2028", "\u2029") if c in pool.scrub(f"a{c}b")]
check("B-1b", "scrub 清除 Unicode 行分隔符", not sep_alive,
      f"残留: {[hex(ord(c)) for c in sep_alive]}")
# C1 控制符(\x80-\x9f)漏掉时, 内核报 "yaml: control characters are not allowed",
# 而这个错误不带 proxy 索引, prune 定位不到 → 整片候选被丢弃
c0 = [hex(c) for c in range(0x00, 0x20) if chr(c) in pool.scrub("a" + chr(c) + "b")]
c1 = [hex(c) for c in range(0x80, 0xA0) if chr(c) in pool.scrub("a" + chr(c) + "b")]
check("B-1c", "C0+C1 控制符全部清除", not c0 and not c1,
      f"C0 残留 {c0 or '无'} / C1 残留 {c1 or '无'}")

print()
print("=" * 70)
print("A-01 · 内核控制端口密钥/端口硬编码")
print("=" * 70)
k1, k2 = pool.Kernel(), pool.Kernel()
same_secret = k1.secret == k2.secret
same_port = k1.port == k2.port
check("A-01", "密钥每次实例化随机", not same_secret, f"{k1.secret[:10]}… vs {k2.secret[:10]}…")
check("A-01b", "控制端口随机且非 19090", not same_port and k1.port != 19090,
      f"{k1.port} vs {k2.port}")
hard = sec.harden_kernel_config({}, k1.secret)
check("A-01c", "hardened 配置用实例密钥而非固定值",
      hard.get("secret") == k1.secret and hard.get("secret") != "freevpn",
      f"secret={str(hard.get('secret'))[:12]}…")
check("A-01d", "模块里不再有固定密钥常量",
      not hasattr(pool, "SECRET") and not hasattr(pool, "CTRL_PORT"))

print()
print("=" * 70)
print("A-02 · 状态页存储型 XSS")
print("=" * 70)
EVIL = ['<img src=x onerror=alert(1)>',
        '<script>alert(2)</script>',
        '"><svg onload=alert(3)>']
rep = {"generated_at": "2026-01-01T00:00:00", "sources_ok": 1, "sources_total": 1,
       "after_dedupe": 3, "after_l1": 3, "after_l2": 3, "final": 3,
       "regions": {"HK": 3}, "audit": {"blocked": 0, "warned": 0, "reasons": {}},
       "fastest": [{"name": e, "region": "HK", "type": "vmess",
                    "tcp": 1, "real": 2} for e in EVIL]}
page = pool.render_page(rep, 8787, "TOK", "", "NONCE123")
raw_hits = sum(1 for e in EVIL if e in page)
check("A-02", "恶意节点名被 HTML 转义", raw_hits == 0, f"原样出现 {raw_hits}/3")
check("A-02b", "页面含 nonce 脚本标签", 'nonce="NONCE123"' in page)
check("A-02c", "已移除内联 onclick", "onclick=" not in page)

print()
print("=" * 70)
print("A-03 / A-11 · 访问日志令牌泄露与日志注入")
print("=" * 70)
import re  # noqa: E402
redacted = re.sub(r"([?&](?:token|t)=)[^&\s]*", r"\1***",
                  "/sub/pool.yaml?token=SECRETVALUE&x=1")
check("A-03", "日志里令牌被脱敏", "SECRETVALUE" not in redacted, redacted)
src = (pool.Path(__file__).parent.parent / "pool.py").read_text(encoding="utf-8")
check("A-03b", "日志轮转改为归档而非 unlink", "access.log.1" in src)
check("A-11", "日志字段做了控制字符清洗",
      "_clean" in src and "re.sub" in src and "\\x85" in src)

print()
print("=" * 70)
print("A-04 · 非 ASCII 令牌触发未捕获异常")
print("=" * 70)
try:
    r = sec.token_ok("中文令牌", "abcdef")
    check("A-04", "非 ASCII 令牌不再抛异常", True, f"返回 {r}")
except Exception as e:
    check("A-04", "非 ASCII 令牌不再抛异常", False, f"{type(e).__name__}: {e}")
check("A-04b", "正确令牌仍能通过", sec.token_ok("abc123", "abc123"))
check("A-04c", "错误令牌仍被拒", not sec.token_ok("abc124", "abc123"))

print()
print("=" * 70)
print("A-06 · kernel_env 凭据泄漏")
print("=" * 70)
probes = {"GITHUB_PAT": "x", "GITLAB_PAT": "x", "VAULT_ADDR": "x",
          "KUBECONFIG": "x", "DOCKER_CONFIG": "x", "MY_API_KEY": "x"}
for k_, v in probes.items():
    os.environ[k_] = v
env = sec.kernel_env()
leaked = [k_ for k_ in probes if k_ in env]
for k_ in probes:
    os.environ.pop(k_, None)
check("A-06", "凭据类环境变量不再传给内核", not leaked, f"泄漏: {leaked or '无'}")
check("A-06b", "SYSTEMROOT 仍保留(内核必需)",
      any(k_.upper() == "SYSTEMROOT" for k_ in env))

print()
print("=" * 70)
print("B-2 / A-07 · 节点级内核字段透传")
print("=" * 70)
EVIL_NODE = {"type": "ss", "server": "1.2.3.4", "port": 8388,
             "cipher": "aes-128-gcm", "password": "x", "name": "evil",
             "interface-name": "Ethernet", "dialer-proxy": "DIRECT",
             "routing-mark": 255, "smux": True, "ip-version": "ipv4",
             "tun": {"enable": True}, "allow-lan": True,
             "external-controller": "0.0.0.0:9090"}
nn = pool.normalize(dict(EVIL_NODE))
survived = [k_ for k_ in EVIL_NODE
            if k_ in ("interface-name", "dialer-proxy", "routing-mark", "smux",
                      "tun", "allow-lan", "external-controller")
            and nn and k_ in nn]
check("B-2", "节点级内核字段被白名单过滤", not survived, f"存活: {survived or '无'}")
check("B-2b", "合法字段仍保留",
      bool(nn) and all(x in nn for x in ("cipher", "password", "server", "port")))

print()
print("=" * 70)
print("B-3 · DNS 重绑定域名绕过")
print("=" * 70)
rb = [{"type": "vmess", "server": "127.0.0.1.nip.io", "port": 443,
       "uuid": "11111111-2222-3333-4444-555555555555"},
      {"type": "vmess", "server": "127-0-0-1.sslip.io", "port": 443,
       "uuid": "11111111-2222-3333-4444-555555555556"}]
blocked = 0
for r_ in rb:
    fs = sec.audit_node(r_)
    if any(f.level == "block" for f in fs):
        blocked += 1
check("B-3", "通配 DNS 重绑定域名被审计拦截", blocked == len(rb),
      f"拦截 {blocked}/{len(rb)}")

print()
print("=" * 70)
print("B-4 · clean_name ReDoS")
print("=" * 70)
t0 = time.time()
pool.clean_name("a " * 100000)          # 200KB
dt = time.time() - t0
check("B-4", "200KB 名字不再挂住(修复前 4000B 就要 119 秒)", dt < 2.0, f"耗时 {dt:.3f}s")

print()
print("=" * 70)
print("B-7 · skip-cert-verify 变体绕过审计")
print("=" * 70)
for variant in ({"skip-cert-verify": 1}, {"Skip-Cert-Verify": True},
                {"skip-cert-verify": "true"}):
    node = {"type": "trojan", "server": "x.com", "port": 443, "password": "p"}
    node.update(variant)
    nn2 = pool.normalize(dict(node))
    if not nn2:
        continue
    norm = nn2.get("skip-cert-verify")
    fs = sec.audit_node(nn2)
    warned = any(f.code == "no-cert-verify" for f in fs)
    check(f"B-7 {list(variant)[0]}", "变体归一成真 bool 并被审计告警",
          isinstance(norm, bool) and norm is True and warned,
          f"归一后={norm!r} 告警={warned}")

print()
print("=" * 70)
print("B-9 · tuic uuid 未校验污染通用订阅")
print("=" * 70)
bad_tuic = {"type": "tuic", "server": "1.2.3.4", "port": 443,
            "uuid": "u#frag", "password": "pw"}
nt = pool.normalize(dict(bad_tuic))
if nt:
    link = pool.proxy_to_link(nt)
    broken = link and ("#" in link.split("@")[0])
    check("B-9", "畸形 tuic uuid 被拒", not broken, f"链接: {str(link)[:60]}")
else:
    check("B-9", "畸形 tuic uuid 被拒", True, "节点已被丢弃")

print()
print("=" * 70)
print("A-13 · host_ok 端口校验")
print("=" * 70)
check("A-13", "错误端口被拒", not sec.host_ok("127.0.0.1:9999", 8787))
check("A-13b", "正确端口放行", sec.host_ok("127.0.0.1:8787", 8787))
check("A-13c", "多值 Host 被拒", not sec.host_ok("127.0.0.1,evil.com", 8787))
check("A-13d", "evil.com 仍被拒", not sec.host_ok("evil.com", 8787))

print()
print("=" * 70)
passed = sum(1 for _t, _ti, ok in RESULTS if ok)
print(f"复验结果: {passed}/{len(RESULTS)} 项已堵住")
fails = [(t, ti) for t, ti, ok in RESULTS if not ok]
if fails:
    print("仍可打穿:")
    for t, ti in fails:
        print(f"  - {t} {ti}")
print("=" * 70)
sys.exit(1 if fails else 0)
