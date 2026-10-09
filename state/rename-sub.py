#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把订阅产物的文件名从 pool.* 统一成 freevpn.*，与产品名一致。

现状不一致：客户端里的条目叫 `freeVPN`、深链 `name=freeVPN`，
但 URL 路径是 `/sub/pool.yaml` —— 客户端按 URL 末段推名字的地方会显示 "pool"。

同时**保留 `pool.*` 作为兼容别名**：已经导入过的客户端订阅地址是
`/sub/pool.yaml?...`，直接改名会让它们 404。
"""
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
P = Path(r"E:\AI\freeVPN\pool.py")
s = P.read_text(encoding="utf-8")
orig = s

REPS = [
    # 1) 产物文件名
    ('(OUT / "pool.yaml").write_text(build_clash(nodes, f"{ver.__title__} · 全量"), encoding="utf-8")',
     '(OUT / "freevpn.yaml").write_text(build_clash(nodes, f"{ver.__title__} · 全量"), encoding="utf-8")'),
    ('(OUT / "pool.txt").write_text(build_b64(nodes), encoding="utf-8")',
     '(OUT / "freevpn.txt").write_text(build_b64(nodes), encoding="utf-8")'),
    ('(OUT / "pool.yaml").read_text(encoding="utf-8"), encoding="utf-8")',
     '(OUT / "freevpn.yaml").read_text(encoding="utf-8"), encoding="utf-8")'),
    # 2) URL
    ('/sub/pool.yaml?token={args.port}', '/sub/freevpn.yaml?token={args.port}'),
    ('/sub/pool.yaml?token={token}', '/sub/freevpn.yaml?token={token}'),
    ('/sub/pool.txt?token={token}', '/sub/freevpn.txt?token={token}'),
    # 3) 注释里的示例
    ('· 路径段 /t/<token>/pool.yaml     (正则只管 query)',
     '· 路径段 /t/<token>/freevpn.yaml  (正则只管 query)'),
    ('· /sub/pool.yaml;token=<token>    (只认 ? 和 &)',
     '· /sub/freevpn.yaml;token=<token> (只认 ? 和 &)'),
    ('fn = path[1:]  # 兼容 /pool.yaml 这种不带 /sub/ 的写法',
     'fn = path[1:]  # 兼容 /freevpn.yaml 这种不带 /sub/ 的写法'),
    ('# freeVPN.exe / bin/mihomo.exe(会被执行), 或改 out/pool.yaml(订阅本身)',
     '# freeVPN.exe / bin/mihomo.exe(会被执行), 或改 out/freevpn.yaml(订阅本身)'),
]

for a, b in REPS:
    n = s.count(a)
    if n == 0:
        print(f"  [未命中] {a[:60]}")
    else:
        s = s.replace(a, b)
        print(f"  [改 {n} 处] {a[:60]}")

# 4) _resolve_sub 加兼容别名
old = '''            if not fn or "/" in fn or "\\\\" in fn or ".." in fn or fn.startswith("."):
                return None
            base = OUT.resolve()
            stem = fn.rsplit(".", 1)[0] if "." in fn else fn'''
new = '''            if not fn or "/" in fn or "\\\\" in fn or ".." in fn or fn.startswith("."):
                return None
            base = OUT.resolve()
            stem = fn.rsplit(".", 1)[0] if "." in fn else fn
            # 兼容旧名字: 产物从 pool.* 改成了 freevpn.*, 但已经导入过的客户端
            # 地址还是 /sub/pool.yaml —— 不改名映射的话它们会 404。
            if stem.lower() == "pool":
                stem = "freevpn"'''
if old in s:
    s = s.replace(old, new)
    print("  [改] _resolve_sub 加了 pool -> freevpn 的兼容映射")
else:
    print("  [!!] _resolve_sub 段没匹配上")

P.write_text(s, encoding="utf-8")
print(f"\n  {len(orig)} -> {len(s)} 字节")
print()
print("=== 残留检查 ===")
left = [m.group(0) for m in re.finditer(r"pool\.(yaml|txt)", s)]
print(f"  pool.yaml/pool.txt 残留: {len(left)} 处 {left}")
