#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一键打包: 出免 Python 环境的独立可执行文件。

    python pack.py                打包（默认单文件版）
    python pack.py --zip          顺便压成 zip
    python pack.py --zip --kill   有实例在跑时先结束它
    python pack.py --onedir       出目录版（启动快，但必须整目录一起拷）

默认 **单文件版**：内核、源清单、配置全部打进一个 exe，走到哪都能双击运行。

为什么不默认用目录版：目录版一旦只拿 exe 不带 `_internal/`，启动就报
    [PYI-xxxxx:ERROR] Failed to load Python DLL
双击时这个错误一闪而过，用户看到的就是"启动不了"。而在压缩包里直接双击
exe 正好会踩这个坑（Windows 只解压那一个文件）。

产物：
    dist/freeVPN/            打包输出（zip 的根目录）
    dist/freeVPN-v1.0.0-win64.zip

**不会进包的东西**（故意的）：
    state/token.txt     订阅访问令牌 —— 那是密钥
    state/*.log         访问日志里出现过令牌
    state/l1_hist.json  负缓存，属于本机运行痕迹
    out/                生成的订阅产物
    audit/              安全审计报告与 PoC
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import version as ver  # noqa: E402

DIST = ROOT / "dist"
# PyInstaller 先往这里写, 最后一步才整体换到 dist/。
# 直接往 dist/ 写的话, 构建期间那个目录是空的/半成品 —— 谁在这时候双击
# 里面的 exe 都会"启动不了", 而那个窗口有十几秒。
STAGE = ROOT / "build" / "dist"
BUILD = ROOT / "build"
APP = ver.__app_name__
NO_WINDOW = 0x08000000 if sys and hasattr(sys, "platform") and sys.platform == "win32" else 0

# 打进 exe 的资源（源路径 -> 包内相对路径）。放在外面的同名文件优先，
# 所以这些既是默认值，也是"用户没放配置文件时"的兜底。
BUNDLED = [
    (ROOT / "bin" / "mihomo.exe", "bin/mihomo.exe"),
    (ROOT / "sources.txt", "sources.txt"),
    (ROOT / "pool.conf.json", "pool.conf.json"),
    # 第⑤层分流规则的数据源(国内 IP 段 / 国内域名后缀)。打进 exe 只是兜底,
    # 用户放一份在外面就能覆盖 —— 见 security.find_resource。
    (ROOT / "cn_cidr.txt", "cn_cidr.txt"),
    (ROOT / "cn_domains.txt", "cn_domains.txt"),
]

# 放在 exe 旁边、供用户编辑或阅读的
SIDECARS = [
    (ROOT / "sources.txt", "sources.txt"),
    (ROOT / "pool.conf.json", "pool.conf.json"),
    (ROOT / "cn_cidr.txt", "cn_cidr.txt"),
    (ROOT / "cn_domains.txt", "cn_domains.txt"),
    (ROOT / "README.md", "README.md"),
    (ROOT / "CHANGELOG.md", "CHANGELOG.md"),
]

# 明显用不到的重型模块，排掉能让产物小一截、启动也快
EXCLUDES = [
    "numpy", "pandas", "matplotlib", "scipy", "PIL", "lxml",
    "openpyxl", "docx", "pptx", "XlsxWriter", "pytest", "setuptools",
    "pip", "tkinter.test", "test", "unittest",
]


def run(cmd: list) -> int:
    print("$ " + " ".join(str(c) for c in cmd))
    return subprocess.call([str(c) for c in cmd], cwd=str(ROOT))


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def tree_size(p: Path) -> tuple[int, int]:
    total = files = 0
    for f in p.rglob("*"):
        if f.is_file():
            total += f.stat().st_size
            files += 1
    return total, files


def running_instances() -> list[int]:
    """**本次构建目录里**正在跑的 freeVPN.exe 的 PID。

    它们会锁住 dist/ 里的文件，构建到 COLLECT 阶段就 PermissionError。
    注意 PyInstaller 的 exe 是"引导器 + 子进程"结构，只关窗口不一定全退。

    **必须按可执行文件路径筛，不能只按进程名。** `taskkill /IM <name>` 是
    按名字**全局**匹配的 —— 跨目录、跨会话。实测：本机同时存在源码版和
    打包版（或新旧两份安装）时，按名字判断会把**别的目录里正在服务订阅的
    生产实例**也算进来，`--kill` 一并结束，订阅直接中断。
    这里用 wmic 拿 ExecutablePath，只认落在本次构建目录下的那些。
    """
    want_exe = (DIST / APP / f"{APP}.exe")
    try:
        want = str(want_exe.resolve()).lower()
    except Exception:
        want = str(want_exe).lower()
    try:
        r = subprocess.run(
            ["wmic", "process", "where", f"name='{APP}.exe'",
             "get", "ProcessId,ExecutablePath", "/format:csv"],
            capture_output=True, text=True, timeout=25,
            encoding="utf-8", errors="replace", creationflags=NO_WINDOW)
    except Exception:
        return []
    mine = []
    for line in (r.stdout or "").splitlines():
        line = line.strip()
        if not line or "," not in line:
            continue
        cols = [c.strip() for c in line.split(",")]
        pid = next((c for c in reversed(cols) if c.isdigit()), "")
        path = next((c for c in cols
                     if c.lower().endswith(f"{APP}.exe".lower())), "")
        # 拿不到路径时保守跳过 —— 宁可让用户手动关，也不要误杀别的实例
        if pid and path and path.lower() == want:
            mine.append(int(pid))
    return mine


def kill_instances():
    """只结束**本次构建目录**里的实例（按 PID，不按进程名）。"""
    for pid in running_instances():
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                       capture_output=True, creationflags=NO_WINDOW)


def main() -> int:
    ap = argparse.ArgumentParser(description="打包 freeVPN为独立可执行文件")
    ap.add_argument("--zip", action="store_true", help="额外压成 zip")
    ap.add_argument("--keep", action="store_true", help="保留上次的 build 缓存")
    ap.add_argument("--kill", action="store_true",
                    help="先结束正在运行的 freeVPN.exe (它锁着 dist/)")
    ap.add_argument("--onefile", action="store_true",
                    help="出单文件版(一个 exe 走天下, 但每次启动都要往临时目录解压 85MB)")
    ap.add_argument("--onedir", action="store_true",
                    help="出目录版(默认, 启动快; 但必须整个目录一起拷)")
    args = ap.parse_args()

    print("=" * 66)
    print(f"  打包 {ver.__title__} v{ver.__version__}  ({ver.__release_date__})")
    print("=" * 66)

    # 预检: 有实例在跑就直接说清楚, 别等构建到一半抛 PermissionError
    pids = running_instances()
    if pids:
        if args.kill:
            print(f"[*] 结束 {len(pids)} 个正在运行的 {APP}.exe: {pids}")
            kill_instances()
            time.sleep(2)
        else:
            print(f"[!] 有 {len(pids)} 个 {APP}.exe 正在运行 (PID {pids})")
            print("    它锁着 dist/ 里的文件, 直接构建会在 COLLECT 阶段报")
            print("    PermissionError: [WinError 5] 拒绝访问。")
            print("    先关掉控制台窗口, 或者加 --kill 让打包脚本替你结束它。")
            return 1

    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("[!] 没装 PyInstaller。装一下:")
        print("    python -m pip install pyinstaller")
        return 1

    if not (ROOT / "bin" / "mihomo.exe").exists():
        print("[!] 缺 bin/mihomo.exe —— 没有它 L2 内核实测跑不了, 池子质量会大幅下降")
        print("    下载: https://github.com/MetaCubeX/mihomo/releases")
        return 1

    if not args.keep:
        # 只清构建缓存和暂存区 —— 不动 dist/。
        # dist/ 是用户正在用的目录, 构建中途删掉它正是"启动不了"的来源。
        for d in (STAGE, BUILD / APP):
            if d.exists():
                print(f"[*] 清理 {d}")
                shutil.rmtree(d, ignore_errors=True)
    STAGE.mkdir(parents=True, exist_ok=True)

    # ---------------- 1) PyInstaller ----------------
    # 默认目录版: 启动快、不依赖临时目录可写。
    #
    # 单文件版(--onefile)每次启动都要把 85MB 解压到 %TEMP%, 而那个目录
    # 未必可写 —— 实测在受限环境下 bootloader 直接报
    # "Could not create temporary directory!" 然后退出, 双击时一闪而过。
    # 很多杀软也会拦"往临时目录写 exe"。所以单文件版做成可选项。
    #
    # 目录版的代价是必须整目录一起拷: 只拿 exe 不带 _internal/ 会报
    # "Failed to load Python DLL"。这个用 启动.bat 做前置检查兜住。
    onefile = args.onefile and not args.onedir
    mode = "单文件版" if onefile else "目录版"
    print()
    print(f"--- 1/3 PyInstaller 构建（{mode}）---")
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--onefile" if onefile else "--onedir",
        "--console",   # 不能用 --windowed: 那会把 sys.stdout 换成空写入器,
                       # GUI 就抓不到扫描子进程的输出, 日志页会一直空白
        "--name", APP,
        "--hidden-import", "security",
        "--hidden-import", "gui",
        "--hidden-import", "version",
        "--distpath", str(STAGE),
        "--workpath", str(BUILD),
        "--specpath", str(BUILD),
    ]
    # 只有单文件版需要把资源打进 exe（它没有"旁边"可言）。
    # 目录版走外面的 bin/ 与同级配置文件，再打一份进去等于把 58MB 内核装两遍。
    if onefile:
        for src, rel in BUNDLED:
            if not src.exists():
                print(f"    [跳过] {rel}（源文件不存在）")
                continue
            cmd += ["--add-data" if src.suffix != ".exe" else "--add-binary",
                    f"{src};{Path(rel).parent.as_posix()}"]
    for m in EXCLUDES:
        cmd += ["--exclude-module", m]
    cmd.append(str(ROOT / "launcher.py"))

    t0 = time.time()
    if run(cmd) != 0:
        print("[!] PyInstaller 构建失败")
        return 1
    print(f"    构建耗时 {time.time()-t0:.0f}s")

    # ---------------- 2) 组装发布目录 ----------------
    # 在暂存区里组装好, 最后整体换到 dist/ —— dist/ 只在最后几秒不可用
    print()
    print("--- 2/3 组装发布目录 ---")
    outdir = STAGE / APP
    if onefile:
        raw_exe = STAGE / f"{APP}.exe"
        if not raw_exe.exists():
            print(f"[!] 没找到 {raw_exe}")
            return 1
        outdir.mkdir(parents=True, exist_ok=True)
        shutil.move(str(raw_exe), str(outdir / f"{APP}.exe"))

    exe = outdir / f"{APP}.exe"
    if not exe.exists():
        print(f"[!] 发布目录里没有 {exe}")
        return 1
    print(f"    {APP}.exe  ({human(exe.stat().st_size)})")

    # 目录版的内核在 _internal 之外，单文件版已经打进去了 —— 都补一份在外面,
    # 方便用户想换内核版本时直接替换（find_resource 会优先用外面的）
    if not onefile:
        dst = outdir / "bin" / "mihomo.exe"
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "bin" / "mihomo.exe", dst)
        print(f"    bin/mihomo.exe  ({human(dst.stat().st_size)})")

    for src, rel in SIDECARS:
        if not src.exists():
            continue
        dst = outdir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        print(f"    {rel}  ({human(dst.stat().st_size)})")

    # ---------------- 3) 说明与版本标记 ----------------
    # 目录版必须整目录一起拷。只拿 exe 时 bootloader 会在 Python 起来之前
    # 就报 "Failed to load Python DLL" 然后秒退 —— 双击时一闪而过, 用户看到
    # 的就是"启动不了"。这个 bat 做前置检查, 把那种情况变成一句人话。
    if not onefile:
        # 这个 bat 里必须显示中文, 所以不能走"纯 ASCII"那条路。
        # 正确做法是**用 GBK 编码写、并且不要 chcp 65001** ——
        # cmd 按控制台默认码页(中文系统是 936)逐字节读批处理文件,
        # 文件是 GBK 字节、码页也是 GBK, 才对得上。
        # 反过来(UTF-8 文件 + chcp 65001)会让字节对齐错位, 中文变乱码甚至语法错误。
        (outdir / "启动.bat").write_text(
            "@echo off\r\n"
            "cd /d \"%~dp0\"\r\n"
            "if not exist \"_internal\" (\r\n"
            "    echo.\r\n"
            "    echo   [x] 缺少 _internal 文件夹\r\n"
            "    echo.\r\n"
            "    echo   freeVPN.exe 不能单独运行，它依赖同目录的 _internal 文件夹。\r\n"
            "    echo   请把整个文件夹一起拷走；如果是从压缩包里直接双击的，先解压。\r\n"
            "    echo.\r\n"
            "    pause\r\n"
            "    exit /b 1\r\n"
            ")\r\n"
            "start \"\" \"%~dp0freeVPN.exe\"\r\n"
            "exit /b 0\r\n",
            encoding="gbk", errors="replace")
        print("    启动.bat  (带 _internal 前置检查, GBK 编码)")

    (outdir / "使用说明.txt").write_text(
        f"{ver.__title__} v{ver.__version__} —— 免安装版\r\n"
        "========================================\r\n"
        "\r\n"
        "【重要】不要只拿 freeVPN.exe 一个文件！\r\n"
        "  它依赖同目录的 _internal 文件夹。单独拿走 exe 会启动不了，\r\n"
        "  而且报错一闪而过。请把整个文件夹一起拷走。\r\n"
        "  从压缩包里直接双击 exe 也会这样 —— 先解压再用。\r\n"
        "\r\n"
        "1. 双击 freeVPN.exe，打开控制台\r\n"
        "2. 点「启动常驻」—— 之后池子会自己刷新，不用再管\r\n"
        "3. 点「一键导入到客户端」，把它加进 Clash Verge / 小火箭\r\n"
        "\r\n"
        "想开机自动跑：点「设置开机自启」。\r\n"
        "\r\n"
        "命令行也能用（在地址栏输入 cmd 回车，然后）：\r\n"
        "    freeVPN.exe --version   看版本\r\n"
        "    freeVPN.exe status      看状态\r\n"
        "    freeVPN.exe all         手动完整扫描一轮\r\n"
        "    freeVPN.exe autostart   设置开机自启\r\n"
        "\r\n"
        "注意：\r\n"
        "  · 首次运行会在本目录生成 state\\ 和 out\\，别删\r\n"
        "  · state\\token.txt 是订阅访问令牌，等于订阅权限，别外发\r\n"
        "  · sources.txt / pool.conf.json 可以就地改，改完重启常驻生效\r\n"
        "  · 免费节点持有者能看到你的明文目标域名，别在上面登网银、主邮箱\r\n",
        encoding="utf-8")
    (outdir / "VERSION").write_text(
        f"{APP} {ver.__version__}\n"
        f"release {ver.__release_date__}\n"
        f"built   {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"mode    {'onefile' if onefile else 'onedir'}\n",
        encoding="utf-8")
    print("    使用说明.txt / VERSION")

    # ---------------- 结果 ----------------
    # 暂存区已经组装完毕, 现在才动 dist/ —— 这一步是秒级的
    print()
    print("--- 3/3 发布 ---")
    final = DIST / APP

    # **保住运行数据**: state/(令牌、缓存、负缓存) 和 out/(订阅产物)。
    # 直接 rmtree 会把用户的 state/token.txt 删掉 —— 那等于换了订阅密钥,
    # 客户端里已经填好的订阅地址立刻 401, 而用户只是重打了一次包,
    # 完全不可能想到是这个原因。
    keep_names = ["state", "out", "订阅地址.txt"]
    saved: list[tuple[Path, str]] = []
    if final.exists():
        for sub in keep_names:
            src = final / sub
            if not src.exists():
                continue
            tmp = DIST / f".keep_{APP}_{sub.replace('.', '_')}"
            if tmp.exists():
                shutil.rmtree(tmp, ignore_errors=True) if tmp.is_dir() else tmp.unlink()
            shutil.move(str(src), str(tmp))
            saved.append((tmp, sub))
        try:
            shutil.rmtree(final)
        except PermissionError:
            print(f"[!] 删不掉 {final} —— 有程序正在用它。")
            print("    关掉控制台窗口, 或者加 --kill 重跑。")
            for tmp, sub in saved:              # 别把用户的数据落在临时目录里
                back = final / sub
                if not back.exists():
                    shutil.move(str(tmp), str(back))
            print(f"    新构建留在 {outdir}，可以手动替换。")
            return 1
    DIST.mkdir(parents=True, exist_ok=True)
    shutil.move(str(outdir), str(final))
    print(f"    已发布到 {final}")
    for tmp, sub in saved:
        dst = final / sub
        if dst.exists():
            shutil.rmtree(dst, ignore_errors=True) if dst.is_dir() else dst.unlink()
        shutil.move(str(tmp), str(dst))
        print(f"    保留运行数据: {sub}")

    size, files = tree_size(final)
    print(f"    体积   {human(size)}  ({files} 个文件)")

    zpath = None
    if args.zip:
        print()
        print("--- 压缩 ---")
        # 不能用 shutil.make_archive 直接压 final/ —— 里面现在有**运行数据**:
        # state/token.txt 是订阅密钥、out/ 是产物、订阅地址.txt 也带令牌。
        # 那些属于这台机器, 不该跟着发布包发给别人。所以按白名单挑文件打。
        zpath = DIST / f"{APP}-v{ver.__version__}-win64.zip"
        if zpath.exists():
            zpath.unlink()
        skip_top = {"state", "out", "订阅地址.txt"}
        n = 0
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
            for f in sorted(final.rglob("*")):
                if not f.is_file():
                    continue
                rel = f.relative_to(final)
                if rel.parts[0] in skip_top or "__pycache__" in rel.parts:
                    continue
                z.write(f, str(Path(APP) / rel))
                n += 1
        print(f"    压缩   {zpath.name}  ({human(zpath.stat().st_size)}, {n} 个文件)")

    print()
    print("=" * 66)
    print(f"  完成：{ver.__title__} v{ver.__version__}（{mode}）")
    print(f"  把 {final.name}/ 整个拷给别人，双击 {APP}.exe 即可，不需要装 Python。")
    if not onefile:
        print("  目录版：必须整目录一起拷 —— 只拿 exe 会报 Failed to load Python DLL。")
    print("=" * 66)
    return 0


if __name__ == "__main__":
    sys.exit(main())
