# -*- coding: utf-8 -*-
"""C3-a · 只读: 摸清 clash* 协议处理器的注册表现状 (实验前的基线 + 还原依据)"""
import json
import sys
import winreg
from pathlib import Path

SCHEMES = ("clash", "clash-verge", "mihomo", "flclash")
HIVES = (("HKCU", winreg.HKEY_CURRENT_USER), ("HKLM", winreg.HKEY_LOCAL_MACHINE))

snap = {}
print("=" * 72)
print("C3-a · clash* 协议处理器注册表现状")
print("=" * 72)
for scheme in SCHEMES:
    for hname, hive in HIVES:
        path = rf"Software\Classes\{scheme}\shell\open\command"
        key = f"{hname}\\{path}"
        try:
            with winreg.OpenKey(hive, path) as k:
                val, typ = winreg.QueryValueEx(k, "")
            snap[key] = {"exists": True, "value": val, "type": typ}
            print(f"  [有] {key}\n        {val!r}  (type={typ})")
        except FileNotFoundError:
            snap[key] = {"exists": False}
            print(f"  [无] {key}")
        except OSError as e:
            snap[key] = {"exists": False, "err": str(e)}
            print(f"  [错] {key}  {e}")

# 整个 scheme 键是否存在的更粗快照（还原时要决定删哪个键）
print("\n--- scheme 根键是否存在 ---")
for scheme in SCHEMES:
    for hname, hive in HIVES:
        try:
            with winreg.OpenKey(hive, rf"Software\Classes\{scheme}"):
                print(f"  [有] {hname}\\Software\\Classes\\{scheme}")
        except OSError:
            print(f"  [无] {hname}\\Software\\Classes\\{scheme}")

out = Path(r"E:\AI\_c_test\reg_snapshot.json")
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(snap, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"\n快照已存: {out}")

sys.path.insert(0, r"E:\AI\freeVPN")
import pool  # noqa: E402
print("\n--- pool.detect_clients() 当前看到的 ---")
for scheme, cmd in pool.detect_clients():
    print(f"  {scheme:<14} -> {cmd}")
print(f"\n--- pool.verge_exe() 当前返回 ---\n  {pool.verge_exe()!r}")
