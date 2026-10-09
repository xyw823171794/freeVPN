#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 state/ 下脚本里的旧路径和旧名字统一到 freeVPN。

目录已经从 freeVPN 改名成 freeVPN，这些脚本里的绝对路径和引用都得跟上，
否则回归脚本全部失效。
"""
import re
import sys
from pathlib import Path

ROOT = Path(r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

REPS = [
    (r"E:\AI\freeVPN", r"E:\AI\freeVPN"),
    ("freeVPN", "freeVPN"),
    ("freeVPN", "freeVPN"),
    ("freeVPN", "freeVPN"),
    ("freevpn", "freevpn"),
    ("freeVPN", "freeVPN"),
]

# rename.py 自己是替换表，不能改
SKIP = {"rename.py"}

changed = 0
for f in sorted(ROOT.rglob("*")):
    if not f.is_file():
        continue
    if any(p in {"bin", "dist", "build", "__pycache__", ".git"} for p in f.parts):
        continue
    if f.name in SKIP or f.suffix.lower() not in {".py", ".ps1", ".bat", ".json", ".md", ".txt"}:
        continue
    try:
        s = f.read_text(encoding="utf-8")
    except Exception:
        continue
    orig = s
    for a, b in REPS:
        s = s.replace(a, b)
    if s != orig:
        f.write_text(s, encoding="utf-8")
        changed += 1
        print(f"  改 {f.relative_to(ROOT)}")

print(f"\n  共 {changed} 个文件")
print()
print("=== 残留检查 ===")
left = 0
for f in sorted(ROOT.rglob("*")):
    if not f.is_file():
        continue
    if any(p in {"bin", "dist", "build", "__pycache__", ".git"} for p in f.parts):
        continue
    if f.name in SKIP or f.suffix.lower() not in {".py", ".ps1", ".bat", ".json", ".md", ".txt"}:
        continue
    try:
        s = f.read_text(encoding="utf-8")
    except Exception:
        continue
    for m in re.finditer(r"freeVPN|freeVPN|freeVPN|freevpn|freeVPN", s):
        print(f"  [残留] {f.relative_to(ROOT)}:{s[:m.start()].count(chr(10))+1}  {m.group(0)}")
        left += 1
print(f"  残留 {left} 处" if left else "  没有残留（rename.py 除外）")
