#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""d8 · 新增的目录级 ACL 收紧 (harden_dir_perms) 会不会把文件权限清空。

背景: 审计过程中发现 `C:\\freeVPN\\state` 的 ACL 被改成
    SYSTEM:(OI)(CI)(F) + xyw:(OI)(CI)(F)
而它下面的 daemon.log / gui.log / daemon.pid 变成 **icacls 输出为空**、
`Get-Content` 报 Access denied —— 也就是 DACL 里一个 ACE 都没有。

security.py 新加的这段就是这么写的:
    icacls <root> /inheritance:r
          /grant:r <user>:(OI)(CI)F
          /grant:r SYSTEM:(OI)(CI)F
          /T /C /Q

怀疑点: (OI)(CI) 是**容器继承标志**, 只对目录有意义。对文件下这条 grant
时 icacls 不会给文件加 ACE, 于是 /inheritance:r 把文件原有的继承 ACE 全切掉
之后, 文件就变成"零 ACE" —— 谁都读不了, 包括程序自己。

本脚本在 %TEMP% 下造一棵同样的目录树复现, 不碰 C:\\freeVPN。
用法: python audit/d8_acl_harden.py
"""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(r"E:\AI\freeVPN")
sys.path.insert(0, str(ROOT))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import security as sec  # noqa: E402

WORK = Path(tempfile.mkdtemp(prefix="freevpn_d8_"))
TREE = WORK / "state"
(TREE / "sub").mkdir(parents=True)
(TREE / "daemon.log").write_text("token=SECRET\n", encoding="utf-8")
(TREE / "gui.log").write_text("token=SECRET\n", encoding="utf-8")
(TREE / "sub" / "deep.txt").write_text("deep\n", encoding="utf-8")

print("=" * 78)
print("d8 · harden_dir_perms 的实际效果")
print("=" * 78)
print(f"实验目录: {WORK}\n")


def show(p: Path) -> list[str]:
    r = subprocess.run(["icacls", str(p)], capture_output=True, text=True,
                       encoding=sec.console_encoding(), errors="replace",
                       timeout=30, creationflags=sec.hidden_flags())
    aces = [x.strip() for x in (r.stdout or "").splitlines() if ":(" in x]
    return aces


def readable(p: Path) -> bool:
    try:
        p.read_bytes()
        return True
    except Exception:
        return False


print("### 收紧之前\n")
for p in (TREE, TREE / "daemon.log", TREE / "sub"):
    print(f"  {p.relative_to(WORK)}")
    for a in show(p):
        print(f"      {a}")
    if p.is_file():
        print(f"      可读: {readable(p)}")

print("\n### 执行 security.harden_dir_perms(目录)\n")
user = os.environ.get("USERNAME", "")
print(f"  icacls {TREE} /inheritance:r /grant:r {user}:(OI)(CI)F "
      f"/grant:r SYSTEM:(OI)(CI)F /T /C /Q")
# 直接调新函数; 名字不确定就退回等价命令
fn = (getattr(sec, "harden_install_dir", None)
      or getattr(sec, "harden_dir_perms", None)
      or getattr(sec, "tighten_dir_perms", None))
if fn:
    ok = fn(TREE)
    print(f"  调用 {fn.__name__}() -> {ok}")
else:
    print("  (security 里没有该函数, 用等价命令)")
    r = subprocess.run(["icacls", str(TREE), "/inheritance:r",
                        "/grant:r", f"{user}:(OI)(CI)F",
                        "/grant:r", "SYSTEM:(OI)(CI)F",
                        "/T", "/C", "/Q"],
                       capture_output=True, text=True,
                       encoding=sec.console_encoding(), errors="replace",
                       timeout=120, creationflags=sec.hidden_flags())
    print(f"  returncode={r.returncode}")

print("\n### 收紧之后\n")
empty = []
for p in (TREE, TREE / "daemon.log", TREE / "gui.log",
          TREE / "sub", TREE / "sub" / "deep.txt"):
    aces = show(p)
    r = readable(p) if p.is_file() else None
    print(f"  {p.relative_to(WORK)}")
    if aces:
        for a in aces:
            print(f"      {a}")
    else:
        print("      **icacls 输出为空 —— DACL 里没有任何 ACE**")
        empty.append(str(p.relative_to(WORK)))
    if r is not None:
        print(f"      可读: {r}")
        if not r:
            empty.append(f"{p.relative_to(WORK)} (不可读)")

print("\n### 结论\n")
print(f"  变成空 DACL 的对象: {len(set(empty))} 个")
for x in sorted(set(empty)):
    print(f"    {x}")
print()
print("  目录本身拿到了 ACE (grant 生效), 但**文件没有** ——")
print("  因为 (OI)(CI) 是容器继承标志, 对文件下 grant 不会产生 ACE,")
print("  而 /inheritance:r 已经把文件原有的继承 ACE 全切掉了。")
print("  净效果: 文件从'任何本机用户可读改'变成'**谁都读不了**',")
print("  包括 freeVPN 自己 —— 重启后 load_or_create_token() 读 token.txt 会失败。")

shutil.rmtree(WORK, ignore_errors=True)
print(f"\n(实验目录已清理: {WORK})")
raise SystemExit(0)
