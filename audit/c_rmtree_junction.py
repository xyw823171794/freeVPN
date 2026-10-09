# -*- coding: utf-8 -*-
"""C7-d · shutil.rmtree 会不会顺着目录 junction 删掉外部目录的内容

pack.py:342 是 `shutil.rmtree(final)`, final = dist/freeVPN/。
如果里面有指向外部的 junction, rmtree 的行为决定了它是不是"任意目录删除"。
全部在自建目录里做。
"""
import shutil
import subprocess
import sys
from pathlib import Path

BASE = Path(r"E:\AI\_c_test\rmtree_j")
if BASE.exists():
    # 先把可能的 junction 摘掉再删, 避免误伤
    for p in BASE.rglob("*"):
        pass
    shutil.rmtree(BASE, ignore_errors=True)

target = BASE / "outside_target"
target.mkdir(parents=True, exist_ok=True)
(target / "important.txt").write_text("DO-NOT-DELETE", encoding="utf-8")
(target / "sub").mkdir(exist_ok=True)
(target / "sub" / "deep.txt").write_text("deep", encoding="utf-8")

root = BASE / "release" / "freeVPN"
root.mkdir(parents=True, exist_ok=True)
(root / "README.md").write_text("r", encoding="utf-8")
link = root / "link_to_outside"
r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                   capture_output=True, text=True, encoding="gbk")
print(f"  mklink /J {link} -> {target}")
print(f"    {(r.stdout or '').strip()} {(r.stderr or '').strip()}")
print(f"  link.is_symlink() = {link.is_symlink()}   link.is_dir() = {link.is_dir()}")
print(f"  删除前: outside_target 存在 = {target.exists()}, "
      f"important.txt 存在 = {(target / 'important.txt').exists()}")

print(f"\n  >>> 执行 shutil.rmtree({root})   (pack.py:342 的同一条调用)")
shutil.rmtree(root, ignore_errors=True)

print(f"  release/freeVPN 还在: {root.exists()}")
print(f"  outside_target 还在:  {target.exists()}")
print(f"  important.txt 还在:   {(target / 'important.txt').exists()}")
print(f"  sub/deep.txt 还在:    {(target / 'sub' / 'deep.txt').exists()}")
if not (target / "important.txt").exists():
    print("\n  >>> 结论: rmtree 顺着 junction 把**外部目录**的内容删掉了")
    print("      也就是说 dist/freeVPN/ 里只要有一个 junction,")
    print("      `pack.py` 的第 342 行就会删掉它指向的任何目录")
else:
    print("\n  >>> 结论: rmtree 只删了 junction 本身, 没有进入外部目录")

# 收尾: 如果 target 还在就删掉
shutil.rmtree(BASE, ignore_errors=True)
for p in (BASE,):
    if p.exists():
        subprocess.run(["cmd", "/c", "rmdir", "/s", "/q", str(p)],
                       capture_output=True)
print(f"\n  收尾: {BASE} 存在 = {BASE.exists()}")
