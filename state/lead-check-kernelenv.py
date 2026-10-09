#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证 security.py 改动后内核仍能正常启动(白名单环境变量的回归测试)。"""
import sys

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import pool  # noqa: E402
import security as sec  # noqa: E402

env = sec.kernel_env()
print(f"  白名单后环境变量数: {len(env)}")
print(f"  SYSTEMROOT 保留:    {any(k.upper() == 'SYSTEMROOT' for k in env)}")
print(f"  PATH 保留:          {any(k.upper() == 'PATH' for k in env)}")
leak = [k for k in env
        if any(w in k.upper() for w in ("KEY", "TOKEN", "SECRET", "PASSWORD",
                                        "AUTH", "PAT", "VAULT", "KUBE", "DOCKER"))]
print(f"  凭据类泄漏:         {leak if leak else '无'}")

nodes = [{"type": "ss", "server": "1.2.3.4", "port": 8388,
          "cipher": "aes-128-gcm", "password": "x", "name": "t"}]
k = pool.Kernel()
ok = k.start(nodes)
print(f"  内核启动:           {ok}")
if ok:
    print("  >>> 白名单没有踩到 SYSTEMROOT 那个坑, 内核控制端口正常")
    k.stop()
else:
    print("  >>> 内核起不来 —— 白名单漏了必需变量")
sys.exit(0 if ok else 1)
