#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""freeVPN · 在线更新 —— 从项目的 GitHub 仓库拉最新版本。

设计取舍(每一条都是为了让**更新通道本身**不能变成后门):

  · **更新源写死**。`REPO` 是常量, 不接受命令行传 URL —— 一个能改更新源的
    更新器就是一个远程代码执行入口, 比不更新危险得多。
  · **只下载, 不自动执行**。Windows 上程序没法覆盖正在运行的自己; 而且
    "下载即执行"本来也是最糟的更新设计。解压完生成一个替换脚本, 由用户跑。
  · **解压防路径穿越**。更新包同样是外部输入, zip slip 一样能写到程序目录外面。
  · **版本只升不降**, 并校验包内版本号与远程一致 —— 防降级, 也防"挂羊头卖狗肉"。
  · 包里的 `state/` `out/` `bin/` `订阅地址.txt` 一律不覆盖: 那是用户的运行数据,
    尤其 `out/` 里是节点凭证、`订阅地址.txt` 里是令牌。
"""
from __future__ import annotations

import json
import os
import re
import shutil
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

import security as sec
import version as ver

# 更新源。改这里等于换一个信任根, 别做成可配置的。
REPO = "xyw823171794/freeVPN"
BRANCH = "main"
API = f"https://api.github.com/repos/{REPO}"
RAW = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}"
SRC_ZIP = f"https://github.com/{REPO}/archive/refs/heads/{BRANCH}.zip"

UA = f"freeVPN-updater/{ver.__version__}"
TIMEOUT = 30
MAX_PACKAGE_BYTES = 200 * 1024 * 1024

# 更新包里**不允许**覆盖的顶层项 —— 全是用户的运行数据
PROTECTED_TOP = {"state", "out", "bin", ".git"}
PROTECTED_FILES = {"订阅地址.txt"}


def update_dir() -> Path:
    return sec.app_root() / "state" / "update"


# --------------------------------------------------------------------------
# 版本
# --------------------------------------------------------------------------
def ver_tuple(s: str) -> tuple:
    """'v1.4.10' -> (1, 4, 10)。非数字段当 0, 保证不会抛异常。"""
    parts = re.findall(r"\d+", str(s or ""))
    return tuple(int(p) for p in parts[:3]) + (0,) * (3 - len(parts[:3]))


def is_newer(remote: str, local: str = None) -> bool:
    return ver_tuple(remote) > ver_tuple(local or ver.__version__)


# --------------------------------------------------------------------------
# 取远端信息
# --------------------------------------------------------------------------
def _get(url: str, timeout: int = TIMEOUT) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                               "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _get_json(url: str):
    try:
        return json.loads(_get(url).decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        if e.code in (403, 404):
            return None          # 无 release / 触发限流, 交给上层回退
        raise
    except Exception:
        return None


def remote_info() -> dict:
    """远端最新版本。

    两条通道, 按可靠性排:
      ① GitHub Release —— 能拿到**打包好的 win64 zip**(带 exe), 是首选
      ② main 分支 —— 仓库还没发 release 时的回退, 只能拿源码 zip
    返回 {version, kind, url, notes, size} —— 拿不到就 version 为空。
    """
    rel = _get_json(f"{API}/releases/latest")
    if isinstance(rel, dict) and rel.get("tag_name"):
        tag = str(rel["tag_name"])
        assets = rel.get("assets") or []
        # 优先挑名字里带 win64 的打包产物; 没有就用源码包
        pick = next((a for a in assets if "win64" in str(a.get("name", "")).lower()
                     and str(a.get("name", "")).lower().endswith(".zip")), None)
        if pick is None:
            pick = next((a for a in assets
                         if str(a.get("name", "")).lower().endswith(".zip")), None)
        return {
            "version": tag.lstrip("vV"),
            "tag": tag,
            "kind": "release" if pick else "release-source",
            "url": (pick or {}).get("browser_download_url") or SRC_ZIP,
            "size": int((pick or {}).get("size") or 0),
            "notes": (rel.get("body") or "").strip()[:2000],
            "published": rel.get("published_at") or "",
        }

    # 回退: 直接读 main 分支的 version.py —— 只下几 KB, 比拉整包再比版本划算
    try:
        txt = _get(f"{RAW}/version.py", timeout=15).decode("utf-8", "replace")
    except Exception:
        txt = ""
    m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', txt)
    if not m:
        return {"version": "", "kind": "none", "url": "", "size": 0, "notes": "",
                "published": ""}
    return {"version": m.group(1), "tag": "", "kind": "source",
            "url": SRC_ZIP, "size": 0, "notes": "", "published": ""}


# --------------------------------------------------------------------------
# 下载 / 解压
# --------------------------------------------------------------------------
def download(url: str, dest: Path, quiet: bool = False) -> Path:
    """下载到 dest。带体积上限与进度输出。"""
    if not url.lower().startswith("https://"):
        raise ValueError(f"更新包必须是 https: {url}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    tmp = dest.with_suffix(dest.suffix + ".part")
    got = 0
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r, open(tmp, "wb") as fh:
        total = int(r.headers.get("Content-Length") or 0)
        while True:
            chunk = r.read(262144)
            if not chunk:
                break
            got += len(chunk)
            if got > MAX_PACKAGE_BYTES:
                fh.close()
                tmp.unlink(missing_ok=True)
                raise ValueError(f"更新包超过 {MAX_PACKAGE_BYTES // 1048576}MB, 已中止")
            fh.write(chunk)
            if not quiet and total:
                pct = got * 100 // total
                print(f"\r    下载 {got // 1024 // 1024}MB / {total // 1024 // 1024}MB"
                      f"  {pct}%", end="", flush=True)
    if not quiet:
        print()
    os.replace(tmp, dest)
    return dest


def _safe_plan(zf: zipfile.ZipFile, dest: Path) -> list[tuple[zipfile.ZipInfo, Path]]:
    """把 zip 里的成员映射到目标路径, 任何越界一律拒绝。

    更新包也是外部输入。`../../x` / 绝对路径 / `C:` 盘符都是经典 zip slip,
    解压出来能写到程序目录外面 —— 一个"在线更新"就能覆盖任意文件。
    """
    dest = dest.resolve()
    plan = []
    for info in zf.infolist():
        name = info.filename.replace("\\", "/")
        if name.endswith("/"):
            continue
        if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
            raise ValueError(f"更新包含绝对路径: {name}")
        parts = [p for p in name.split("/") if p not in ("", ".")]
        if any(p == ".." for p in parts):
            raise ValueError(f"更新包含路径穿越: {name}")
        target = (dest / Path(*parts)).resolve()
        if dest != target and dest not in target.parents:
            raise ValueError(f"更新成员越出目标目录: {name}")
        plan.append((info, target))
    return plan


def extract_package(zip_path: Path, dest: Path) -> tuple[Path, int]:
    """解压到 dest, 跳过受保护的顶层项。返回 (包根目录, 写入文件数)。

    zip 通常带一层 `<repo>-<ref>/` 前缀, 这里剥掉它, 让包根直接是程序目录。
    """
    with zipfile.ZipFile(zip_path) as zf:
        plan = _safe_plan(zf, dest)
        if not plan:
            raise ValueError("更新包是空的")
        # 剥掉公共的一层前缀
        roots = {str(Path(*[p for p in i.filename.replace("\\", "/").split("/") if p][:1]))
                 for i, _ in plan}
        prefix = roots.pop() if len(roots) == 1 else None
        written = 0
        for info, target in plan:
            rel = target.relative_to(dest.resolve())
            parts = rel.parts
            if prefix and parts and parts[0] == prefix:
                parts = parts[1:]
            if not parts:
                continue
            if parts[0] in PROTECTED_TOP or str(Path(*parts)) in PROTECTED_FILES:
                continue
            out = dest / Path(*parts)
            out.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(out, "wb") as dst:
                shutil.copyfileobj(src, dst)
            written += 1
    return dest, written


def package_version(root: Path) -> str:
    """从解压出来的包里读版本号。"""
    v = root / "VERSION"
    if v.exists():
        for line in v.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip().startswith("freeVPN"):
                return line.split()[-1].strip()
    p = root / "version.py"
    if p.exists():
        m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']',
                      p.read_text(encoding="utf-8", errors="replace"))
        if m:
            return m.group(1)
    return ""


# --------------------------------------------------------------------------
# 应用
# --------------------------------------------------------------------------
APPLY_BAT = r"""@echo off
REM freeVPN update applier -- generated by pool.py update
REM Pure ASCII on purpose: cmd.exe reads .bat in the console code page,
REM and non-ASCII bytes shift the parser and break the script.
setlocal
set "SRC=%~dp0payload"
set "DST=%~dp0..\.."
echo.
echo   freeVPN updater
echo   from: %SRC%
echo   to  : %DST%
echo.
echo   Waiting for the running freeVPN to exit (close its window / stop the daemon).
:wait
tasklist /FI "IMAGENAME eq freeVPN.exe" 2>nul | find /I "freeVPN.exe" >nul
if not errorlevel 1 (
  timeout /t 2 /nobreak >nul
  goto wait
)
echo   Copying files ...
robocopy "%SRC%" "%DST%" /E /NFL /NDL /NJH /NJS /NP >nul
if errorlevel 8 (
  echo   [X] robocopy failed with code %ERRORLEVEL%
  pause
  exit /b 1
)
echo   [OK] files replaced. Your state\ out\ bin\ and 订阅地址.txt were left alone.
echo.
if exist "%DST%\freeVPN.exe" (
  echo   Starting freeVPN ...
  start "" "%DST%\freeVPN.exe"
) else (
  echo   Source tree updated. Run: python pool.py all
)
echo.
pause
"""


def write_apply_script(stage_root: Path) -> Path:
    bat = stage_root.parent / "apply-update.bat"
    # newline 用 CRLF —— cmd.exe 对纯 LF 的 .bat 在部分版本上会读错行
    bat.write_bytes(APPLY_BAT.replace("\n", "\r\n").encode("ascii"))
    return bat


def run(check_only: bool = False, force: bool = False, quiet: bool = False) -> int:
    """检查并（可选）下载新版。返回进程退出码。"""
    print(f"[*] 本地版本 {ver.__version__}  ({ver.__release_date__})")
    print(f"[*] 更新源   https://github.com/{REPO}")
    try:
        info = remote_info()
    except Exception as e:
        print(f"[!] 查不到远端版本: {type(e).__name__}: {e}")
        print("    (仓库还没有 release 也没关系 —— 会回退到 main 分支)")
        return 2

    rv = info.get("version") or ""
    if not rv:
        print("[!] 远端没有可识别的版本号。")
        print("    仓库建好后至少要有一个 release/tag, 或者 main 分支上有 version.py。")
        return 2

    kind = {"release": "GitHub Release(含打包的 exe)",
            "release-source": "GitHub Release(只有源码包)",
            "source": "main 分支源码"}.get(info.get("kind"), info.get("kind"))
    print(f"[*] 远端版本 {rv}  来源: {kind}")
    if info.get("published"):
        print(f"    发布于 {info['published']}")
    if info.get("notes"):
        print("    --- 更新说明 ---")
        for ln in info["notes"].splitlines()[:12]:
            print(f"    {ln}")

    if not is_newer(rv, ver.__version__) and not force:
        print("\n[=] 已经是最新版本, 无需更新。")
        return 0

    if check_only:
        print(f"\n[+] 有新版本: {ver.__version__} -> {rv}")
        print("    跑 `python pool.py update` 下载并生成替换脚本。")
        return 0

    stage_root = update_dir() / rv
    if stage_root.exists():
        shutil.rmtree(stage_root, ignore_errors=True)
    stage_root.mkdir(parents=True, exist_ok=True)

    pkg = stage_root / f"freeVPN-{rv}.zip"
    print(f"\n[*] 下载 {info['url'][:100]}")
    download(info["url"], pkg, quiet=quiet)
    print(f"    已保存 {pkg.stat().st_size // 1024} KB")

    payload = stage_root / "payload"
    payload.mkdir(parents=True, exist_ok=True)
    root, n = extract_package(pkg, payload)
    print(f"    解压 {n} 个文件 -> {root}")

    pv = package_version(root)
    if pv and ver_tuple(pv) != ver_tuple(rv):
        print(f"[!] 包内版本 {pv} 与远端声明 {rv} 不一致 —— 拒绝, 已删掉解压结果")
        shutil.rmtree(stage_root, ignore_errors=True)
        return 3
    print(f"    包内版本校验通过: {pv or '(未标注)'}")

    bat = write_apply_script(stage_root)
    print("\n" + "=" * 72)
    print(f"  更新已下载并解压到: {stage_root}")
    print(f"  替换脚本:           {bat}")
    print()
    print("  接下来(程序无法覆盖正在运行的自己, 所以必须由你点一下):")
    print(f"    1. 关掉 freeVPN(窗口 / daemon 都退干净)")
    print(f"    2. 双击 {bat.name}")
    print("    3. 它会 robocopy 覆盖程序文件, 然后自动启动新版本")
    print()
    print("  state\\ out\\ bin\\ 订阅地址.txt 都不会被覆盖。")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(check_only="--check" in sys.argv, force="--force" in sys.argv))
