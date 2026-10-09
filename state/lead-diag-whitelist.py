#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""诊断: 白名单/引号化改动后内核为什么拒绝配置。"""
import subprocess
import sys

import yaml

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool  # noqa: E402

SAMPLES = [
    {"type": "vmess", "server": "1.2.3.4", "port": 443,
     "uuid": "11111111-2222-3333-4444-555555555555", "alterId": 0,
     "cipher": "auto", "tls": True, "servername": "a.com", "network": "ws",
     "ws-opts": {"path": "/x", "headers": {"Host": "a.com"}}, "udp": True},
    {"type": "vless", "server": "1.2.3.5", "port": 443,
     "uuid": "11111111-2222-3333-4444-555555555556", "tls": True,
     "servername": "b.com", "network": "tcp", "flow": "xtls-rprx-vision"},
    {"type": "trojan", "server": "1.2.3.6", "port": 443, "password": "pw",
     "sni": "c.com", "udp": True},
    {"type": "ss", "server": "1.2.3.7", "port": 8388,
     "cipher": "aes-128-gcm", "password": "pw2", "udp": True},
    {"type": "hysteria2", "server": "1.2.3.8", "port": 443, "password": "pw3",
     "sni": "d.com", "skip-cert-verify": True},
]

norm = []
for s in SAMPLES:
    n = pool.normalize(dict(s))
    if n:
        norm.append(n)
        print(f"  {s['type']:<10} -> {sorted(k for k in n if not k.startswith('_'))}")
    else:
        print(f"  {s['type']:<10} -> 被丢弃")

print()
k = pool.Kernel()
cfgpath = k.write_config(norm)
text = cfgpath.read_text(encoding="utf-8")
print("=== 生成的 YAML 片段 (proxies 段) ===")
lines = text.splitlines()
try:
    i = lines.index('"proxies":')
except ValueError:
    i = lines.index("proxies:")
print("\n".join(lines[i:i + 16]))
print()
print("=== PyYAML 能否反解 ===")
try:
    d = yaml.safe_load(text)
    print(f"  OK, 顶层键: {sorted(d.keys())}")
    print(f"  proxies[0] 键: {sorted(d['proxies'][0])}")
except Exception as e:
    print(f"  失败: {e}")
print()
print("=== mihomo -t 的真实报错 ===")
r = subprocess.run([str(pool.MIHOMO), "-d", str(pool.KERNEL_DIR), "-f", str(cfgpath), "-t"],
                   capture_output=True, text=True, timeout=90,
                   encoding="utf-8", errors="replace")
out = ((r.stdout or "") + (r.stderr or "")).strip()
for ln in out.splitlines()[-12:]:
    print("  " + ln[:150])
print(f"  退出码 {r.returncode}")
