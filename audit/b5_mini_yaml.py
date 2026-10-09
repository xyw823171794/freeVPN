# -*- coding: utf-8 -*-
"""
问题 5 验证: _mini_yaml_proxies (PyYAML 缺失时的降级路径) 与 safe_load 的解析歧义。
做法: 同一段文本分别喂两条路径, 逐条比对产出的节点字典;
      再拿真实产物 out/pool.yaml 做对照。
"""
import json
import pathlib
import sys

sys.path.insert(0, r"E:\AI\freeVPN")
import pool
import security as sec

ROOT = pathlib.Path(r"E:\AI\freeVPN")

CASES = {
    "A 常规块式": (
        "proxies:\n"
        "  - name: a\n    type: vmess\n    server: 1.2.3.4\n    port: 443\n"
        "    uuid: 11111111-2222-3333-4444-555555555555\n"
    ),
    "B 流式 {..}": (
        "proxies:\n"
        "  - {name: a, type: vmess, server: 1.2.3.4, port: 443, "
        "uuid: 11111111-2222-3333-4444-555555555555}\n"
    ),
    "C 缩进 0 的列表项": (
        "proxies:\n"
        "- name: a\n  type: vmess\n  server: 1.2.3.4\n  port: 443\n"
        "  uuid: 11111111-2222-3333-4444-555555555555\n"
    ),
    "D proxies 嵌在别的键下": (
        "proxy-providers:\n"
        "  proxies:\n"
        "    - name: a\n      type: vmess\n      server: 9.9.9.9\n      port: 443\n"
        "      uuid: 11111111-2222-3333-4444-555555555555\n"
    ),
    "E 别名/锚点复用": (
        "proxies:\n"
        "  - &tpl\n    name: a\n    type: vmess\n    server: 1.2.3.4\n    port: 443\n"
        "    uuid: 11111111-2222-3333-4444-555555555555\n"
    ),
    "F 布尔/数字类型歧义": (
        "proxies:\n"
        "  - name: a\n    type: vmess\n    server: 1.2.3.4\n    port: 443\n"
        "    uuid: 11111111-2222-3333-4444-555555555555\n"
        "    tls: yes\n    alterId: 0x10\n    skip-cert-verify: on\n"
    ),
    "G 没有 port 字段": (
        "proxies:\n"
        "  - name: a\n    type: vmess\n    server: 1.2.3.4\n"
        "    uuid: 11111111-2222-3333-4444-555555555555\n"
    ),
    "H 多行标量 name": (
        "proxies:\n"
        "  - name: >\n      line1\n      line2\n    type: vmess\n    server: 1.2.3.4\n"
        "    port: 443\n    uuid: 11111111-2222-3333-4444-555555555555\n"
    ),
    "I 中文/emoji 键值": (
        "proxies:\n"
        "  - name: 香港节点①\n    type: vmess\n    server: 1.2.3.4\n    port: 443\n"
        "    uuid: 11111111-2222-3333-4444-555555555555\n    note: 备注🇭🇰\n"
    ),
    "J 缩进不齐的列表项": (
        "proxies:\n"
        "  - name: a\n    type: vmess\n    server: 1.2.3.4\n    port: 443\n"
        "    uuid: 11111111-2222-3333-4444-555555555555\n"
        "   - name: b\n     type: vmess\n     server: 5.6.7.8\n     port: 443\n"
        "     uuid: 22222222-2222-3333-4444-555555555555\n"
    ),
}


def both(text: str):
    real = pool._yaml
    a = pool.parse_clash_yaml(text)          # PyYAML 路径
    pool._yaml = None
    b = pool._mini_yaml_proxies(text)        # 降级路径
    pool._yaml = real
    return a, b


def audit_verdict(nodes):
    if not nodes:
        return "-"
    kept, rep = sec.audit_pool([dict(x) for x in nodes])
    return f"放行{len(kept)}/拦截{rep.blocked}"


print("=" * 78)
print("### 5.1 safe_load 路径 vs _mini_yaml_proxies 路径 逐例比对")
print("=" * 78)
for label, text in CASES.items():
    a, b = both(text)
    same = json.dumps(a, sort_keys=True, ensure_ascii=False) == \
        json.dumps(b, sort_keys=True, ensure_ascii=False)
    print(f"  {label:24} safe_load={len(a)} 节点  mini={len(b)} 节点  "
          f"{'一致' if same else '*** 分歧 ***'}")
    if not same:
        print(f"      safe_load: {json.dumps(a, ensure_ascii=False)[:220]}")
        print(f"      mini     : {json.dumps(b, ensure_ascii=False)[:220]}")
    print(f"      审计裁决(两条路径各自): safe_load={audit_verdict(a)}  "
          f"mini={audit_verdict(b)}")

print()
print("=" * 78)
print("### 5.2 真实产物 out/pool.yaml 走两条路径")
print("=" * 78)
real_text = (ROOT / "out" / "pool.yaml").read_text(encoding="utf-8")
a, b = both(real_text)
print(f"  safe_load={len(a)} 节点   mini={len(b)} 节点")
if a and b:
    ka = set(a[0].keys())
    kb = set(b[0].keys())
    print(f"  首节点键差异: 只在 safe_load={sorted(ka - kb)}  只在 mini={sorted(kb - ka)}")
    print(f"  safe_load 首节点: {json.dumps(a[0], ensure_ascii=False)[:300]}")
    print(f"  mini      首节点: {json.dumps(b[0], ensure_ascii=False)[:300]}")
if a and b:
    servers_a = sorted(str(x.get('server')) for x in a)
    servers_b = sorted(str(x.get('server')) for x in b)
    print(f"  server 集合一致: {servers_a == servers_b}")
    if servers_a != servers_b:
        print(f"    只在 safe_load: {sorted(set(servers_a) - set(servers_b))[:10]}")
        print(f"    只在 mini     : {sorted(set(servers_b) - set(servers_a))[:10]}")

print()
print("=" * 78)
print("### 5.3 降级路径能否造出「审计看不到」的节点? (结论验证)")
print("=" * 78)
# 关键点: 审计和产物用的是同一个 dict, 不存在"审计看到 A、内核拿到 B"
evil = ("proxies:\n"
        "  - name: a\n    type: vmess\n    server: 127.0.0.1\n    port: 443\n"
        "    uuid: 11111111-2222-3333-4444-555555555555\n")
for tag, parser in (("safe_load", lambda t: pool.parse_clash_yaml(t)),
                    ("mini", lambda t: pool._mini_yaml_proxies(t))):
    nodes = [pool.normalize(x) for x in parser(evil)]
    nodes = [n for n in nodes if n]
    kept, rep = sec.audit_pool(nodes)
    out = pool.build_clash(kept, "t") if kept else ""
    print(f"  {tag:10} 解析={len(nodes)} 审计放行={len(kept)} 拦截={rep.blocked} "
          f"产物含该 server: {'127.0.0.1' in out}")
print("  -> 两条路径产出的都是同一个 dict, 审计与产物不可能看到不同内容;")
print("     降级路径的差异只影响「哪几个节点被解析出来」, 不构成审计绕过。")
