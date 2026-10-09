#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把项目里写死的旧名字统一换成 freeVPN。

刻意做成脚本而不是手改一堆 sed: 换名字最容易漏, 漏一处就是"某个地方还叫旧名"。
脚本跑完会列出所有文件的残留, 一眼能看出有没有漏。
"""
import re
import sys
from pathlib import Path

ROOT = Path(r"E:\AI\vpn-pool")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# (旧, 新) —— 按长到短排, 避免 "VPN Pool" 被 "VPN P" 之类的规则先吃掉
REPS = [
    ("VPNPool", "freeVPN"),          # exe 名 / 任务名 / vbs 名
    ("VPN Pool", "freeVPN"),         # 界面标题
    ("VPN 池", "freeVPN"),            # 中文名
    ("vpnpool", "freevpn"),          # 备份文件名后缀 / 旧密钥常量
    ("vpn-pool", "freeVPN"),         # 项目目录名
]

# 不动的: 二进制、缓存、构建产物、历史日志
SKIP_DIRS = {"bin", "dist", "build", "__pycache__", "state", "out", ".git"}
SKIP_FILES = {"sources.txt"}

TEXT_EXT = {".py", ".md", ".bat", ".json", ".txt", ".spec"}


def main() -> int:
    dry = "--apply" not in sys.argv
    changed = []
    for f in sorted(ROOT.rglob("*")):
        if not f.is_file():
            continue
        if any(part in SKIP_DIRS for part in f.parts):
            continue
        if f.name in SKIP_FILES or f.suffix.lower() not in TEXT_EXT:
            continue
        try:
            s = f.read_text(encoding="utf-8")
        except Exception:
            try:
                s = f.read_text(encoding="gbk")
            except Exception:
                continue
        orig = s
        hits = {}
        for a, b in REPS:
            n = s.count(a)
            if n:
                hits[a] = n
                s = s.replace(a, b)
        if s != orig:
            rel = f.relative_to(ROOT)
            changed.append((rel, hits))
            if not dry:
                f.write_text(s, encoding="utf-8")

    print("模式:", "试跑(加 --apply 才真改)" if dry else "已写入")
    print()
    for rel, hits in changed:
        detail = ", ".join(f"{k}×{v}" for k, v in hits.items())
        print(f"  {rel}   {detail}")
    print(f"\n  共 {len(changed)} 个文件")

    if not dry:
        print()
        print("=== 改完后的残留检查 ===")
        left = 0
        for f in sorted(ROOT.rglob("*")):
            if not f.is_file() or any(p in SKIP_DIRS for p in f.parts):
                continue
            if f.name in SKIP_FILES or f.suffix.lower() not in TEXT_EXT:
                continue
            try:
                s = f.read_text(encoding="utf-8")
            except Exception:
                continue
            for m in re.finditer(r"VPNPool|VPN Pool|VPN 池|vpnpool|vpn-pool", s):
                line = s[:m.start()].count("\n") + 1
                print(f"  [残留] {f.relative_to(ROOT)}:{line}  {m.group(0)}")
                left += 1
        print(f"  残留 {left} 处" if left else "  没有残留")
    return 0


if __name__ == "__main__":
    sys.exit(main())
