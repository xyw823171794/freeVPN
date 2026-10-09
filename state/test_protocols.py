#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""回归测试: 字段白名单不能把协议必需字段过滤掉。

背景: 加了按协议类型的白名单之后, 键名归一把小写化做过头 —— `alterId` 变成
`alterid`, 内核直接拒绝: "proxy 0: '' has unset fields: alterId"。整轮 L2
几乎每片都失败。这个测试就是为那次回归加的。

判据: 每种协议都给一份**字段齐全**的节点, 走完整 normalize 之后交给
`mihomo -t`, 必须全部通过。
"""
import subprocess
import sys

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool  # noqa: E402

SAMPLES = [
    ("vmess", {"type": "vmess", "server": "1.2.3.4", "port": 443,
               "uuid": "11111111-2222-3333-4444-555555555555", "alterId": 64,
               "cipher": "auto", "tls": True, "servername": "a.com",
               "network": "ws", "ws-opts": {"path": "/x", "headers": {"Host": "a.com"}},
               "udp": True, "skip-cert-verify": True}),
    ("vmess-grpc", {"type": "vmess", "server": "1.2.3.4", "port": 443,
                    "uuid": "11111111-2222-3333-4444-555555555556", "alterId": 0,
                    "cipher": "auto", "tls": True, "servername": "a.com",
                    "network": "grpc", "grpc-opts": {"grpc-service-name": "gs"}}),
    ("vless-reality", {"type": "vless", "server": "1.2.3.5", "port": 443,
                       "uuid": "11111111-2222-3333-4444-555555555557",
                       "tls": True, "servername": "b.com", "network": "tcp",
                       "flow": "xtls-rprx-vision", "client-fingerprint": "chrome",
                       # REALITY 的 public-key 必须是合法 X25519 公钥(base64url, 43 字符),
                       # 随手写个短串内核会报 "invalid REALITY public key"
                       "reality-opts": {"public-key":
                                        "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4QcvW3vCc",
                                        "short-id": "ab"}}),
    ("vless-ws", {"type": "vless", "server": "1.2.3.5", "port": 80,
                  "uuid": "11111111-2222-3333-4444-555555555558",
                  "network": "ws", "ws-opts": {"path": "/y", "headers": {"Host": "b.com"}}}),
    ("trojan", {"type": "trojan", "server": "1.2.3.6", "port": 443,
                "password": "pw", "sni": "c.com", "udp": True,
                "alpn": ["h2", "http/1.1"], "skip-cert-verify": True}),
    ("trojan-ws", {"type": "trojan", "server": "1.2.3.6", "port": 443,
                   "password": "pw", "network": "ws",
                   "ws-opts": {"path": "/z", "headers": {"Host": "c.com"}}}),
    ("ss", {"type": "ss", "server": "1.2.3.7", "port": 8388,
            "cipher": "aes-128-gcm", "password": "pw2", "udp": True}),
    ("ss-plugin", {"type": "ss", "server": "1.2.3.7", "port": 8389,
                   "cipher": "aes-256-cfb", "password": "pw3",
                   "plugin": "obfs", "plugin-opts": {"mode": "http", "host": "d.com"}}),
    ("hysteria2", {"type": "hysteria2", "server": "1.2.3.8", "port": 443,
                   "password": "pw4", "sni": "e.com", "skip-cert-verify": True,
                   "obfs": "salamander", "obfs-password": "op"}),
    ("tuic", {"type": "tuic", "server": "1.2.3.9", "port": 443,
              "uuid": "11111111-2222-3333-4444-555555555559", "password": "pw5",
              "sni": "f.com", "alpn": ["h3"], "congestion-controller": "bbr",
              "udp-relay-mode": "native", "skip-cert-verify": True}),
]

norm, labels = [], []
for label, s in SAMPLES:
    n = pool.normalize(dict(s))
    if not n:
        print(f"  [丢弃] {label:<14} —— normalize 没通过")
        continue
    kept = sorted(k for k in n if not k.startswith("_"))
    print(f"  [保留] {label:<14} {kept}")
    norm.append(n)
    labels.append(label)

print()
k = pool.Kernel()
cfgpath = k.write_config(norm)
r = subprocess.run([str(pool.MIHOMO), "-d", str(pool.KERNEL_DIR), "-f", str(cfgpath), "-t"],
                   capture_output=True, text=True, timeout=90,
                   encoding="utf-8", errors="replace",
                   cwd=str(pool.KERNEL_DIR), env=__import__("security").kernel_env())
out = ((r.stdout or "") + (r.stderr or "")).strip()
print("=== mihomo -t ===")
for ln in out.splitlines()[-6:]:
    print("  " + ln[:160])

ok = r.returncode == 0 and len(norm) == len(SAMPLES)
print()
if ok:
    print(f"PASS {len(norm)}/{len(SAMPLES)} 种协议配置全部被内核接受")
else:
    print(f"FAIL 内核拒绝 (退出码 {r.returncode}), 保留 {len(norm)}/{len(SAMPLES)}")
sys.exit(0 if ok else 1)
