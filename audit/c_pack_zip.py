# -*- coding: utf-8 -*-
"""C7/C8 · pack.py 的打包边界

  C8-a 实跑 pack.running_instances(): 它把**别的目录**里的 freeVPN.exe 也算成
       "正在运行的实例"
  C8-b 用同名的诱饵进程验证 `taskkill /F /IM <name> /T` 的全局按名语义
  C7-a 逐行复现 pack.py:375-385 的 zip 白名单, 检查硬链接/大小写变体绕过
  C7-b 目录 junction 是否被 Path.rglob 跟随 (决定能不能整目录穿越)
  C7-c 逐行复现 pack.py:325-360 的发布/回滚逻辑, 构造 move 失败场景

不调用 pack.main() —— 那会真的跑 PyInstaller 并搬动 dist/ 里的运行数据。
"""
import json
import os
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

sys.path.insert(0, r"E:\AI\freeVPN")
import pack  # noqa: E402
import version as ver  # noqa: E402

SIM = Path(r"E:\AI\_c_test\packsim")
TMP = Path(r"E:\AI\_c_test")
APP = ver.__app_name__


def banner(t):
    print("\n" + "=" * 72)
    print(t)
    print("=" * 72)


# ---------------------------------------------------------------------------
banner("C8-a · 实跑 pack.running_instances()")
pids = pack.running_instances()
print(f"  pack.running_instances() = {pids}")
for pid in pids:
    r = subprocess.run(
        ["wmic", "process", "where", f"ProcessId={pid}",
         "get", "Name,ExecutablePath,CommandLine", "/value"],
        capture_output=True, text=True, encoding="gbk", errors="replace")
    for ln in (r.stdout or "").splitlines():
        if ln.strip():
            print(f"    {ln.strip()}")
print(f"  APP 名 = {APP}.exe")
print("  >>> 这些进程里包含 C:\\freeVPN 里那份正在服务订阅的生产实例。")
print("      pack.py 只按**进程名**判断, 不区分路径 —— 它会把别的目录里的实例")
print("      当成'锁着本目录 dist/ 的自己人'。")

# ---------------------------------------------------------------------------
banner("C8-b · 用同名诱饵验证 `taskkill /F /IM <name> /T` 的全局语义")
BAIT = "c_test_bait"
baitdir = TMP / "bait"
baitdir.mkdir(parents=True, exist_ok=True)
bait1 = baitdir / f"{BAIT}.exe"
shutil.copy2(r"C:\Windows\System32\cmd.exe", bait1)
other = TMP / "bait2"
other.mkdir(parents=True, exist_ok=True)
bait2 = other / f"{BAIT}.exe"
shutil.copy2(r"C:\Windows\System32\cmd.exe", bait2)
p1 = subprocess.Popen([str(bait1)], stdin=subprocess.PIPE,
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
p2 = subprocess.Popen([str(bait2)], stdin=subprocess.PIPE,
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1.2)
print(f"  在**两个不同目录**各起一个 {BAIT}.exe: PID {p1.pid} ({bait1.parent})"
      f" / PID {p2.pid} ({bait2.parent})")
r = subprocess.run(["taskkill", "/F", "/IM", f"{BAIT}.exe", "/T"],
                   capture_output=True, text=True, encoding="gbk",
                   errors="replace")
print(f"  taskkill /F /IM {BAIT}.exe /T  rc={r.returncode}")
for ln in (r.stdout or "").splitlines():
    print(f"    {ln.strip()}")
time.sleep(0.8)
print(f"  杀之后: p1 活={p1.poll() is None}   p2 活={p2.poll() is None}")
for p in (p1, p2):
    if p.poll() is None:
        p.kill()
print("  >>> /IM 是按**进程名全局**匹配, 跨目录、跨会话。")
print("      pack.py:119 用的就是这个形式 (freeVPN.exe), 因此 `pack.py --kill`")
print("      会把 C:\\freeVPN 里那份生产实例一并结束。")

# ---------------------------------------------------------------------------
banner("C7-a · 复现 pack.py:375-385 的 zip 白名单")
final = SIM / "dist" / APP
if SIM.exists():
    shutil.rmtree(SIM, ignore_errors=True)
(final / "state").mkdir(parents=True, exist_ok=True)
(final / "out").mkdir(parents=True, exist_ok=True)
(final / "_internal").mkdir(parents=True, exist_ok=True)
(final / "State").mkdir(parents=True, exist_ok=True)
(final / f"{APP}.exe").write_bytes(b"MZ fake")
(final / "README.md").write_text("readme", encoding="utf-8")
(final / "_internal" / "base_library.zip").write_bytes(b"PK fake")
TOKEN = "SUPER-SECRET-SUBSCRIPTION-TOKEN-1234567890"
(final / "state" / "token.txt").write_text(TOKEN, encoding="utf-8")
(final / "state" / "access.log").write_text("GET /sub?token=" + TOKEN,
                                            encoding="utf-8")
(final / "out" / "pool.yaml").write_text("proxies: []", encoding="utf-8")
(final / "订阅地址.txt").write_text("http://127.0.0.1:8787/?token=" + TOKEN,
                                    encoding="utf-8")

# 攻击者预置 1: 指向 state/token.txt 的硬链接 (无需管理员)
os.link(str(final / "state" / "token.txt"), str(final / "leak_hardlink.txt"))
# 攻击者预置 2: 大小写变体目录 (Windows 文件系统不区分大小写, Python 字符串区分)
(final / "State" / "token_upper.txt").write_text(TOKEN, encoding="utf-8")

print(f"  合成发布目录 {final}")
for f in sorted(final.rglob("*")):
    if f.is_file():
        print(f"    {f.relative_to(final)}")

skip_top = {"state", "out", "订阅地址.txt"}          # pack.py:375
zpath = SIM / f"{APP}-sim.zip"
n = 0
with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
    for f in sorted(final.rglob("*")):              # pack.py:378
        if not f.is_file():
            continue
        rel = f.relative_to(final)
        if rel.parts[0] in skip_top or "__pycache__" in rel.parts:   # pack.py:382
            continue
        z.write(f, str(Path(APP) / rel))            # pack.py:384
        n += 1

print(f"\n  打出 zip: {zpath.name}  ({n} 个文件)")
names = zipfile.ZipFile(zpath).namelist()
for nm in sorted(names):
    print(f"    {nm}")

banned = [nm for nm in names
          if any(seg in ("state", "out") for seg in Path(nm).parts[1:])
          or Path(nm).name == "订阅地址.txt"]
print(f"\n  白名单目标是否泄漏: {banned or '（state/out/订阅地址.txt 本身没进去）'}")

z = zipfile.ZipFile(zpath)
leak = [nm for nm in names if "leak_hardlink" in nm]
if leak:
    content = z.read(leak[0]).decode("utf-8", "replace")
    print(f"\n  >>> 硬链接绕过: {leak[0]} 被打进 zip, 内容是令牌明文")
    print(f"      {content!r}")
    print(f"      与 state/token.txt 相同: {content == TOKEN}")
upper = [nm for nm in names if "token_upper" in nm]
print(f"  >>> 大小写变体绕过 (State 与 state 同时存在时): {bool(upper)}  {upper}")
print("      —— 注意: 上面这一步其实**测不出来**, 因为 Windows 不区分大小写,")
print("         `final/'State'` 与 `final/'state'` 指向同一个目录。")
print("         真正要问的是: 目录名本身是 'State' 时白名单还管不管用。")

# 单独构造: 发布目录里只有一个名叫 State 的目录
final_u = SIM / "distU" / APP
if final_u.exists():
    shutil.rmtree(final_u, ignore_errors=True)
(final_u / "State").mkdir(parents=True, exist_ok=True)
(final_u / "State" / "token.txt").write_text(TOKEN, encoding="utf-8")
(final_u / "README.md").write_text("r", encoding="utf-8")
zpath_u = SIM / f"{APP}-simU.zip"
with zipfile.ZipFile(zpath_u, "w", zipfile.ZIP_DEFLATED) as z:
    for f in sorted(final_u.rglob("*")):
        if not f.is_file():
            continue
        rel = f.relative_to(final_u)
        if rel.parts[0] in skip_top or "__pycache__" in rel.parts:
            continue
        z.write(f, str(Path(APP) / rel))
names_u = zipfile.ZipFile(zpath_u).namelist()
print(f"  目录名叫 'State' 时 zip 内容: {sorted(names_u)}")
print(f"  >>> 白名单被大小写绕过: "
      f"{any('token.txt' in n for n in names_u)}  "
      "(`rel.parts[0] in skip_top` 是大小写敏感的字符串比较)")

# ---------------------------------------------------------------------------
banner("C7-b · Path.rglob 是否跟随目录 junction (mklink /J, 无需管理员)")
outside = TMP / "outside_secret"
outside.mkdir(parents=True, exist_ok=True)
(outside / "token.txt").write_text("OUTSIDE-SECRET-TOKEN", encoding="utf-8")
(outside / "sub").mkdir(exist_ok=True)
(outside / "sub" / "x.yaml").write_text("a: 1", encoding="utf-8")
jl = final / "mylink"
if jl.exists():
    subprocess.run(["cmd", "/c", "rmdir", str(jl)], capture_output=True)
r = subprocess.run(["cmd", "/c", "mklink", "/J", str(jl), str(outside)],
                   capture_output=True, text=True, encoding="gbk",
                   errors="replace")
print(f"  mklink /J {jl} -> {outside}")
print(f"    rc={r.returncode}  {(r.stdout or '').strip()} {(r.stderr or '').strip()}")
print(f"    jl.is_symlink() = {jl.is_symlink()}   jl.is_dir() = {jl.is_dir()}")
print(f"    os.path.islink  = {os.path.islink(str(jl))}")
print("  rglob 看到的:")
for f in sorted(final.rglob("*")):
    print(f"    {f.relative_to(final)}   is_file={f.is_file()}")
followed = [f for f in final.rglob("*") if "outside_secret" in str(f)
            or f.relative_to(final).parts[0] == "mylink"]
print(f"  >>> rglob 是否穿过 junction: {bool(followed)}  {[str(x.relative_to(final)) for x in followed]}")

# 用同一套白名单逻辑再打一次, 看外部目录会不会整包进 zip
zpath2 = SIM / f"{APP}-sim2.zip"
with zipfile.ZipFile(zpath2, "w", zipfile.ZIP_DEFLATED) as z:
    for f in sorted(final.rglob("*")):
        if not f.is_file():
            continue
        rel = f.relative_to(final)
        if rel.parts[0] in skip_top or "__pycache__" in rel.parts:
            continue
        z.write(f, str(Path(APP) / rel))
names2 = zipfile.ZipFile(zpath2).namelist()
link_names = [n for n in names2 if "/mylink/" in n.replace("\\", "/")]
print(f"  第二次 zip 全部条目 ({len(names2)} 个): {sorted(names2)}")
print(f"  >>> junction 目标目录里的文件被打进 zip: {link_names}")
for n in link_names:
    print(f"      {n} = "
          f"{zipfile.ZipFile(zpath2).read(n).decode('utf-8', 'replace')!r}")

banner("C7-b2 · junction 指向自身祖先会不会让 rglob 无限递归")
loop = final / "loop"
if loop.exists():
    subprocess.run(["cmd", "/c", "rmdir", str(loop)], capture_output=True)
subprocess.run(["cmd", "/c", "mklink", "/J", str(loop), str(final)],
               capture_output=True, text=True, encoding="gbk")
probe = TMP / "loop_probe.py"
probe.write_text(
    "import sys\n"
    "from pathlib import Path\n"
    f"root = Path(r'{final}')\n"
    "n = 0\n"
    "for f in root.rglob('*'):\n"
    "    n += 1\n"
    "    if n > 300000:\n"
    "        print('LIMIT', n)\n"
    "        break\n"
    "else:\n"
    "    print('DONE', n)\n", encoding="utf-8")
try:
    r = subprocess.run([sys.executable, str(probe)], capture_output=True,
                       text=True, timeout=25, encoding="utf-8",
                       errors="replace")
    print(f"  rglob 遍历结果: {(r.stdout or '').strip()} "
          f"{(r.stderr or '').strip()[:200]}")
except subprocess.TimeoutExpired:
    print("  >>> 25 秒内没跑完 —— rglob 跟随 junction 时**没有环检测**")
print("  (pack.py:378 的 final.rglob('*') 会走同一段逻辑)")

# ---------------------------------------------------------------------------
banner("C7-c · 复现 pack.py:325-360 的发布/回滚, 构造 move 失败")
sim2 = SIM / "dist2"
if sim2.exists():
    shutil.rmtree(sim2, ignore_errors=True)
dist2 = sim2 / "dist"
final2 = dist2 / APP
(final2 / "state").mkdir(parents=True, exist_ok=True)
(final2 / "state" / "token.txt").write_text("KEEP-ME", encoding="utf-8")
outdir2 = sim2 / "stage" / APP          # 故意**不存在**, 模拟组装产物丢失
print(f"  final  = {final2}  (含 state/token.txt = 'KEEP-ME')")
print(f"  outdir = {outdir2}  exists={outdir2.exists()}")

keep_names = ["state", "out", "订阅地址.txt"]        # pack.py:329
saved = []
if final2.exists():
    for sub in keep_names:
        src = final2 / sub
        if not src.exists():
            continue
        tmp = dist2 / f".keep_{APP}_{sub.replace('.', '_')}"
        if tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True) if tmp.is_dir() else tmp.unlink()
        shutil.move(str(src), str(tmp))
        saved.append((tmp, sub))
    try:
        shutil.rmtree(final2)
    except PermissionError:
        print("  PermissionError 分支: 会回滚 (本次没触发)")
print(f"  搬走后: saved={[(str(t), s) for t, s in saved]}")
print(f"          final 还存在: {final2.exists()}")
print(f"  下一步 shutil.move(outdir, final) 因为 outdir 不存在会抛异常:")
try:
    shutil.move(str(outdir2), str(final2))
except Exception as e:
    print(f"    !! {type(e).__name__}: {e}")
    print("    pack.py:353 这里**没有 try/except** —— 异常直接冒泡, 脚本中断")
print(f"\n  结果: final 存在 = {final2.exists()}")
print(f"        用户数据位置 = {[str(t) for t, _ in saved]}")
print(f"        dist2 下的残留:")
for f in sorted(dist2.iterdir()):
    print(f"          {f.name}  (dir={f.is_dir()})")
print("  >>> 用户的 state/out/订阅地址.txt 被移进 dist/.keep_* 隐藏目录后, "
      "发布失败不会回滚")
print("      (回滚代码只写在 PermissionError 分支里, 见 pack.py:343-349)")

# 收尾
for d in (SIM, outside, baitdir, other):
    shutil.rmtree(d, ignore_errors=True)

print("\n" + "=" * 72)
print("C7/C8 完成")
print("=" * 72)
