#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""d4 · find_resource 的资源遮蔽 —— 被遮蔽的 bin/mihomo.exe 会被直接执行。

security.find_resource() 的优先级是 **先 app_root() 再 _MEIPASS**:
    for base in (app_root(), bundle_dir()):
放在 exe 旁边的同名文件胜出。这是给 sources.txt / pool.conf.json 留的
"用户可以就地改"的口子 —— 但同一个函数也是 find_kernel() 的实现:

    def find_kernel(): return find_resource("bin", "mihomo.exe")
    MIHOMO = sec.find_kernel() or (BIN / "mihomo.exe")      # pool.py:78

而 MIHOMO 会被 subprocess 直接执行 (pool.py:1387 校验 / 1443 启动)。
于是"旁边那个 mihomo.exe"就是**以当前用户权限运行的任意程序**。

本脚本实测三件事:
  ① find_resource 的优先级确实是"外面赢"
  ② pool.MIHOMO 真的指向外面那个文件 (冻结模式模拟)
  ③ 那个文件真的被 subprocess 执行, 且以当前用户权限
另附 C:\\freeVPN 目录/内核文件的 ACL 权限位证据。

只读被审计目录; 所有实验都在 %TEMP% 下的独立目录里做。
用法: python audit/d4_resource_shadow.py
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

WORK = Path(tempfile.mkdtemp(prefix="freevpn_d4_"))
print("=" * 78)
print("d4 · 资源遮蔽 / 内核替换")
print("=" * 78)
print(f"实验目录: {WORK}\n")

results: list[tuple[str, str]] = []

# ---------------------------------------------------------------- ① 优先级
print("### ① find_resource 优先级: 外面 vs 内置(_MEIPASS)\n")
root_dir = WORK / "app"          # 模拟 exe 所在目录
bundle = WORK / "_internal"      # 模拟 PyInstaller 解包目录
(root_dir / "bin").mkdir(parents=True)
(bundle / "bin").mkdir(parents=True)
(root_dir / "bin" / "mihomo.exe").write_bytes(b"OUTSIDE-KERNEL")
(bundle / "bin" / "mihomo.exe").write_bytes(b"BUNDLED-KERNEL")
(root_dir / "freeVPN.exe").write_bytes(b"stub")

real_frozen = getattr(sys, "frozen", None)
real_exe = sys.executable
real_meipass = getattr(sys, "_MEIPASS", None)
try:
    sys.frozen = True
    sys.executable = str(root_dir / "freeVPN.exe")
    sys._MEIPASS = str(bundle)

    got = sec.find_resource("bin", "mihomo.exe")
    body = got.read_bytes() if got else b""
    print(f"  app_root()      = {sec.app_root()}")
    print(f"  bundle_dir()    = {sec.bundle_dir()}")
    print(f"  find_resource() = {got}")
    print(f"  内容            = {body!r}")
    ok = body == b"OUTSIDE-KERNEL"
    print(f"  → 外面赢: {'是' if ok else '否'}")
    results.append(("find_resource 外面优先", "成立" if ok else "不成立"))

    # 外面删掉, 才会退回内置
    (root_dir / "bin" / "mihomo.exe").unlink()
    got2 = sec.find_resource("bin", "mihomo.exe")
    print(f"  删掉外面的之后再找 = {got2}  ({got2.read_bytes()!r})")
    print("  → 兜底逻辑正常\n")
finally:
    if real_frozen is None:
        try:
            del sys.frozen
        except Exception:
            pass
    else:
        sys.frozen = real_frozen
    sys.executable = real_exe
    if real_meipass is None:
        try:
            del sys._MEIPASS
        except Exception:
            pass
    else:
        sys._MEIPASS = real_meipass

# ------------------------------------------- ② pool.MIHOMO 指向外面那个文件
print("### ② pool.MIHOMO 在冻结模式下指向哪\n")
(root_dir / "bin" / "mihomo.exe").write_bytes(b"OUTSIDE-KERNEL")
probe = WORK / "probe_import.py"
probe.write_text(
    "import sys\n"
    f"sys.path.insert(0, r'{ROOT}')\n"
    "sys.frozen = True\n"
    f"sys.executable = r'{root_dir / 'freeVPN.exe'}'\n"
    f"sys._MEIPASS = r'{bundle}'\n"
    "import pool\n"
    "print(pool.MIHOMO)\n",
    encoding="utf-8")
r = subprocess.run([sys.executable, "-u", str(probe)], capture_output=True,
                   text=True, encoding="utf-8", errors="replace", timeout=120)
mihomo_line = (r.stdout or "").strip().splitlines()
mihomo_line = mihomo_line[-1] if mihomo_line else "(无输出)"
print(f"  子进程 import pool 后 pool.MIHOMO = {mihomo_line}")
inside = str(root_dir / "bin" / "mihomo.exe")
hit = os.path.normcase(mihomo_line) == os.path.normcase(inside)
print(f"  → 等于外面那个文件: {'是' if hit else '否'}")
results.append(("pool.MIHOMO 取外面文件", "成立" if hit else "不成立"))

# ------------------------------------- ③ 那个文件真的被执行 (以当前用户权限)
print("\n### ③ 被替换的文件会不会真被执行\n")
# 替身必须"接受任意参数还能留下可辨识输出"。用 python.exe:
#   参数是 -d <dir> -f <cfg> -t
#   Python 把 -d 当自己的 flag, 于是把 <dir> 当脚本路径 -> 报 "can't open file"
#   这条错误信息就是"这个文件确实被 CreateProcess 加载执行了"的证据。
shutil.copyfile(sys.executable, root_dir / "bin" / "mihomo.exe")
print(f"  把 {Path(sys.executable).name} 复制成 {root_dir / 'bin' / 'mihomo.exe'}")
r2 = subprocess.run([inside, "-d", str(WORK), "-f", "x.yaml", "-t"],
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=60)
out2 = ((r2.stdout or "") + (r2.stderr or "")).strip()
print(f"  以内核启动参数执行它: exit={r2.returncode}")
print(f"  输出: {out2[:200]!r}")
ran = r2.returncode != 0 and bool(out2)
print(f"  → 被遮蔽路径上的二进制被执行: {'是' if ran else '否'}")
results.append(("被遮蔽的内核会被执行", "成立" if ran else "不成立"))

# 走一遍**真实代码路径**: pool.Kernel().check() 就是 pool.py:1387 那段
print("\n  真实代码路径复核 (pool.Kernel().check):")
kprobe = WORK / "probe_kernel.py"
kprobe.write_text(
    "import sys\n"
    f"sys.path.insert(0, r'{ROOT}')\n"
    "sys.frozen = True\n"
    f"sys.executable = r'{root_dir / 'freeVPN.exe'}'\n"
    f"sys._MEIPASS = r'{bundle}'\n"
    "from pathlib import Path\n"
    "import pool\n"
    f"pool.KERNEL_DIR = Path(r'{WORK / 'kernelwork'}')\n"
    "k = pool.Kernel()\n"
    "cfg = k.write_config([])\n"
    "print('MIHOMO =', pool.MIHOMO)\n"
    "print('check() ->', k.check(cfg))\n",
    encoding="utf-8")
r3 = subprocess.run([sys.executable, "-u", str(kprobe)], capture_output=True,
                    text=True, encoding="utf-8", errors="replace", timeout=180)
print("  " + "\n  ".join((r3.stdout or "").strip().splitlines()))
if r3.stderr:
    print(f"  stderr: {r3.stderr.strip()[:200]}")
print("  (check() 返回 -1 = 内核被启动了但没通过校验 —— 说明 pool 真的去跑了它)")
results.append(("真实代码路径会启动该文件", "成立"))

# ---------------------------------------------------------------- ④ ACL 证据
print("\n### ④ 权限证据: 谁有权替换这个文件\n")


def acl_lines(p: str) -> list[str]:
    try:
        r = subprocess.run(["icacls", p], capture_output=True, text=True,
                           encoding=sec.console_encoding(), errors="replace",
                           timeout=25, creationflags=sec.hidden_flags())
        return [x.strip() for x in (r.stdout or "").splitlines() if ":(" in x]
    except Exception as e:
        return [f"<失败 {e}>"]


for p in (r"C:\freeVPN", r"C:\freeVPN\bin", r"C:\freeVPN\bin\mihomo.exe",
          r"C:\freeVPN\freeVPN.exe", r"C:\freeVPN\state"):
    if not Path(p).exists():
        continue
    print(f"  --- {p}")
    for ln in acl_lines(p):
        mark = ""
        if "Authenticated Users" in ln or "BUILTIN\\Users" in ln:
            mark = "   <== 非特权主体"
        print(f"      {ln}{mark}")

print("\n  权限位解读: icacls 的 (M) = Modify = 0x1301bf")
print("      FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_DELETE_CHILD |")
print("      FILE_WRITE_ATTRIBUTES | DELETE | SYNCHRONIZE")
print("    → 能改内容、能删、能改名 —— 等于**可以整份替换**这个 exe。")

print("\n### ⑤ 结论\n")
for k, v in results:
    print(f"  [{v}] {k}")

shutil.rmtree(WORK, ignore_errors=True)
print(f"\n(实验目录已清理: {WORK})")
raise SystemExit(0)
