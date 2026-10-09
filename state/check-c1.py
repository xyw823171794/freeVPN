#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证 C1 控制符修复: 这批字符漏掉时整片配置会被内核拒掉。"""
import subprocess
import sys

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool  # noqa: E402
import security as sec  # noqa: E402

print("=== scrub 对各类控制符的清除情况 ===")
c0 = [hex(c) for c in range(0x00, 0x20) if chr(c) in pool.scrub("a" + chr(c) + "b")]
c1 = [hex(c) for c in range(0x80, 0xA0) if chr(c) in pool.scrub("a" + chr(c) + "b")]
sp = [hex(ord(c)) for c in "\u2028\u2029" if c in pool.scrub("a" + c + "b")]
print(f"  C0 控制符未清:   {c0 or '无'}")
print(f"  C1 控制符未清:   {c1 or '无'}")
print(f"  Unicode 行分隔符未清: {sp or '无'}")

print()
print("=== 用真实数据验证: 600 个节点的配置能否被内核接受 ===")
l1 = pool.load_l1()
cand = pool.diversify(pool.rank(l1), per_subnet=4)[:600]
k = pool.Kernel()
cfg = k.write_config(cand)
r = subprocess.run([str(pool.MIHOMO), "-d", str(pool.KERNEL_DIR), "-f", str(cfg), "-t"],
                   capture_output=True, text=True, timeout=120,
                   encoding="utf-8", errors="replace",
                   cwd=str(pool.KERNEL_DIR), env=sec.kernel_env())
out = ((r.stdout or "") + (r.stderr or "")).strip()
errs = [ln for ln in out.splitlines() if "level=error" in ln]
print(f"  600 个节点: 退出码 {r.returncode}")
for ln in errs[-3:]:
    print("    " + ln[:150])
if r.returncode == 0:
    print("  PASS 配置被接受")
else:
    print("  FAIL 仍被拒")
sys.exit(0 if r.returncode == 0 else 1)
