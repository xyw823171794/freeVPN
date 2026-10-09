# -*- coding: utf-8 -*-
"""
问题 4 补充 2: 端到端证明 —— 一个源就能让整轮刷新崩溃。
链路: 恶意源文本 -> parse_any (PyYAML 深嵌套 RecursionError -> 降级到 _mini_yaml_proxies)
      -> 造出 1500 层嵌套的节点 dict -> dedupe -> normalize -> scrub 递归爆栈
      -> run_cycle 里 dedupe() 没有 try/except -> 进程带 traceback 退出。
"""
import sys
import time

sys.path.insert(0, r"E:\AI\freeVPN")
import pool
import security as sec

DEPTH = 1500
lines = ["proxies:", "  - name: deep", "    type: ss", "    server: 1.2.3.4",
         "    port: 8388", "    cipher: aes-128-gcm", "    password: pw"]
ind = 4
for i in range(DEPTH):
    lines.append(" " * ind + f"k{i}:")
    ind += 1
src = "\n".join(lines) + "\n"
print(f"恶意源体积: {len(src)/1024:.1f} KB, 缩进层数: {DEPTH}")
print(f"yaml_bomb 判定: {sec.yaml_bomb(src)} (False = 放行)")
print(f"clamp_text 后长度不变: {len(sec.clamp_text(src)) == len(src)}")
print()

t0 = time.perf_counter()
nodes = pool.parse_any(src)
print(f"parse_any 成功返回 {len(nodes)} 个节点, 耗时 {time.perf_counter()-t0:.2f}s")
print(f"  (PyYAML safe_load 先因 RecursionError 失败, 落到 _mini_yaml_proxies)")
d = 0
cur = nodes[0]
while isinstance(cur, dict) and cur:
    nxt = list(cur.values())[-1]
    if not isinstance(nxt, dict):
        break
    cur = nxt
    d += 1
print(f"  节点 dict 嵌套深度 ≈ {d}")

print()
print("--- 接下来调用 run_cycle 里用的 dedupe() ---")
try:
    t0 = time.perf_counter()
    out = pool.dedupe(nodes)
    print(f"dedupe 返回 {len(out)} 个节点 ({time.perf_counter()-t0:.2f}s)")
except Exception as e:
    print(f"*** dedupe 抛出 {type(e).__name__}: {e}")
    print("    run_cycle() 里 `nodes = dedupe(raw)` 没有 try/except,")
    print("    main() 里 `run_cycle(args)` 也没有 —— 进程会带 traceback 退出。")
    import traceback
    tb = traceback.format_exc().splitlines()
    for ln in tb[-14:]:
        print("      " + ln)

print()
print("--- 对照: 若节点嵌套浅于 ~600 层 ---")
for depth in (100, 500, 900, 1100):
    ls = ["proxies:", "  - name: d", "    type: ss", "    server: 1.2.3.4",
          "    port: 8388", "    cipher: aes-128-gcm", "    password: pw"]
    j = 4
    for i in range(depth):
        ls.append(" " * j + f"k{i}:")
        j += 1
    s = "\n".join(ls) + "\n"
    try:
        ns = pool.dedupe(pool.parse_any(s))
        print(f"  深度={depth:<5} 源={len(s):<6}字节 -> dedupe 正常, 产出 {len(ns)} 节点")
    except Exception as e:
        print(f"  深度={depth:<5} 源={len(s):<6}字节 -> {type(e).__name__}: {e}")
