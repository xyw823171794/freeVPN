#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""回归测试: 节点名绝不能和地区分组名相同。

内核遇到 ProxyGroup 里出现与自己同名的成员会直接报
"loop is detected in ProxyGroup" 并拒绝加载整份配置 —— 池子全部产物作废。
触发条件: 节点原始名清洗后恰好等于地区名(如 "德国"), 命名兜底就撞上了分组名。
"""
import importlib.util
import sys

import yaml

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

spec = importlib.util.spec_from_file_location("pool", r"E:\AI\freeVPN\pool.py")
pool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pool)

# 极端用例: 名字清洗后正好等于地区名, 逼出撞名
RAW = [
    {"type": "vmess", "server": "1.2.3.4", "port": 443,
     "uuid": "a1b2c3d4-1111-2222-3333-444455556666", "name": "德国"},
    {"type": "vmess", "server": "1.2.3.5", "port": 443,
     "uuid": "a1b2c3d4-1111-2222-3333-444455556667", "name": "德国"},
    {"type": "vmess", "server": "1.2.3.6", "port": 443,
     "uuid": "a1b2c3d4-1111-2222-3333-444455556668", "name": "德国 节点"},
    {"type": "trojan", "server": "9.9.9.9", "port": 443, "password": "p", "name": "香港"},
    {"type": "trojan", "server": "9.9.9.10", "port": 443, "password": "p", "name": "香港"},
    {"type": "trojan", "server": "9.9.9.11", "port": 443, "password": "p", "name": "vmess"},
    {"type": "trojan", "server": "9.9.9.12", "port": 443, "password": "p", "name": ""},
]

nodes = []
for r in RAW:
    n = pool.normalize(dict(r))
    if n:
        nodes.append(n)

print(f"normalize 后 {len(nodes)} 个节点")
cfg = yaml.safe_load(pool.build_clash(nodes))
proxies = cfg["proxies"]
groups = cfg["proxy-groups"]

proxy_names = [p["name"] for p in proxies]
group_names = [g["name"] for g in groups]
print(f"节点名 ({len(proxy_names)}):")
for n in proxy_names:
    print(f"   {n}")
print(f"分组名 ({len(group_names)}):")
for g in group_names:
    print(f"   {g}")

print()
ok = True

# ① 节点名与分组名不得相交
bad = set(proxy_names) & set(group_names)
if bad:
    print(f"FAIL 节点名与分组名撞车: {bad}")
    ok = False
else:
    print("PASS 节点名与分组名无冲突")

# ② 节点名不得重复
dup = {n for n in proxy_names if proxy_names.count(n) > 1}
if dup:
    print(f"FAIL 节点名重复: {dup}")
    ok = False
else:
    print("PASS 节点名唯一")

# ③ 分组里引用的成员必须真实存在
#    注意 known 要同时包含节点名和分组名 —— 分组可以嵌套引用其它分组
known = set(proxy_names) | set(group_names) | {"DIRECT", "REJECT", "GLOBAL", "PASS"}
for g in groups:
    missing = [m for m in (g.get("proxies") or []) if m not in known]
    if missing:
        print(f"FAIL 分组 {g['name']} 引用了不存在的成员: {missing}")
        ok = False
if ok:
    print("PASS 所有分组引用的成员都存在")

sys.exit(0 if ok else 1)
