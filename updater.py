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
import socket
import subprocess
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

import security as sec
import version as ver

# 更新源。改这里等于换一个信任根, 别做成可配置的。
#
# 仓库名曾经是 `github.com-xyw823171794-freeVPN` —— 建仓库时把整个 URL
# 填进了"仓库名"框留下的。在 Settings → Rename 改成 `freeVPN` 之后这里跟着改,
# 两边必须一致, 否则 update 会去一个不存在的地方拉包。
REPO = "xyw823171794/freeVPN"
BRANCH = "main"
API = f"https://api.github.com/repos/{REPO}"
RAW = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}"
SRC_ZIP = f"https://github.com/{REPO}/archive/refs/heads/{BRANCH}.zip"
# Release 附件的**固定下载路径** —— 不需要 API, 知道 tag 和文件名就能下。
# 这条路径是绕开 API 限流的关键, 见 remote_info() 的说明。
DL = f"https://github.com/{REPO}/releases/download"
APP_NAME = "freeVPN"

UA = f"freeVPN-updater/{ver.__version__}"
TIMEOUT = 30          # 下载用: urlopen 的 timeout 是单次读超时, 大包要留够
API_TIMEOUT = 10      # 版本查询用 —— 超过 10 秒基本就是被掐了, 早点告诉用户
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
# 本机常见代理端口。国内直连 GitHub 经常被掐(TCP 能连、TLS 握手被打断), 而
# 同一时刻走本机代理正常。双击运行的 exe 没有 HTTPS_PROXY 环境变量, 所以直连
# 失败时自动借一下本机代理 —— 只连回环, 不做任何外部探测。
PROXY_CANDIDATES = ("http://127.0.0.1:7897", "http://127.0.0.1:7890",
                    "http://127.0.0.1:10809", "http://127.0.0.1:10808",
                    "http://127.0.0.1:2080", "http://127.0.0.1:1080")


def local_proxy() -> str | None:
    """本机开着的常见代理端口(毫秒级探测, 不通就跳过)。"""
    env = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if env:
        return env            # 用户显式指定了, 优先用
    for p in PROXY_CANDIDATES:
        try:
            port = int(p.rsplit(":", 1)[1])
        except ValueError:
            continue
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return p
        except OSError:
            continue
    return None


def _open_via(proxy: str, req, timeout: int):
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    return opener.open(req, timeout=timeout)


def _get(url: str, timeout: int = API_TIMEOUT) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                               "Accept": "application/vnd.github+json"})
    # 本机有代理就**先走代理**: 国内直连 GitHub 基本都要靠它, 先直连等于白等
    # 一个 10 秒超时。代理不通再退回直连。
    p = local_proxy()
    if p:
        try:
            with _open_via(p, req, min(timeout, 8)) as r:
                return r.read()
        except urllib.error.HTTPError:
            raise          # 服务器有响应 —— 网络是通的, 换路没意义
        except Exception as e:
            print(f"[*] 本机代理 {p} 走不通({type(e).__name__}), 改直连")
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


def _version_from_raw() -> str:
    """从 main 分支的 version.py 读版本号。

    只下几 KB, 而且**不受 API 限流影响** —— 匿名 API 是 60 次/小时, 在国内
    共享出口 IP 上极容易打满。
    """
    try:
        txt = _get(f"{RAW}/version.py", timeout=API_TIMEOUT).decode("utf-8", "replace")
    except Exception:
        return ""
    m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', txt)
    return m.group(1) if m else ""


def _exists(url: str) -> bool:
    """HEAD 探测远端文件在不在(release 下载链接支持 HEAD, 不用下整包)。"""
    try:
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": UA})
        p = local_proxy()
        if p:
            with _open_via(p, req, API_TIMEOUT):
                return True
        with urllib.request.urlopen(req, timeout=API_TIMEOUT):
            return True
    except Exception:
        return False


def remote_info() -> dict:
    """远端最新版本。

    三条通道, 按可靠性排:

      ① **GitHub Release API** —— 能同时拿到附件列表和更新说明, 首选。
      ② **main 的 version.py + 拼固定下载 URL** —— API 不可用时的主力。
         GitHub 的 release 附件路径是固定的:
             https://github.com/<repo>/releases/download/<tag>/<file>
         知道 tag 和文件名就能下, **不需要 API**。
         这一步很关键: 匿名 API 限流(60 次/小时)在国内共享出口 IP 上极常见,
         如果这时只会回退到"源码 zip", exe 用户就拿不到带 exe 的包 —— 实测踩过
         (Release 明明发了, 界面却显示"来源: main 分支源码")。
      ③ **源码 zip** —— 连附件都没有时兜底。

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

    # ② API 不可用(限流/被墙) —— 拿版本号, 拼 Release 的固定下载 URL
    ver = _version_from_raw()
    if not ver:
        return {"version": "", "kind": "none", "url": "", "size": 0, "notes": "",
                "published": ""}
    tag = f"v{ver}"
    for name in (f"{APP_NAME}-{tag}-win64.zip", f"{APP_NAME}-{ver}-win64.zip"):
        url = f"{DL}/{tag}/{name}"
        if _exists(url):
            return {"version": ver, "tag": tag, "kind": "release",
                    "url": url, "size": 0, "notes": "", "published": ""}
    # ③ 连附件都没探测到 —— 源码包兜底
    return {"version": ver, "tag": tag, "kind": "source",
            "url": SRC_ZIP, "size": 0, "notes": "", "published": ""}


# --------------------------------------------------------------------------
# 下载 / 解压
# --------------------------------------------------------------------------
def download(url: str, dest: Path, quiet: bool = False, on_progress=None) -> Path:
    """下载到 dest。带体积上限、进度回调、**断点续传**。

    续传是刚需不是锦上添花: 国内拉 GitHub Release 常年只有几十 KB/s, 33MB 的包
    要十几分钟, 中途断一次就得从头再来 —— 实测踩过(10 分钟下到 23MB 被打断)。

    on_progress(got, total) 给 GUI 用 —— 有回调时不再往 stdout 打进度。
    """
    if not url.lower().startswith("https://"):
        raise ValueError(f"更新包必须是 https: {url}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")

    # 断点续传: 半截文件还在就带 Range 接着下
    start = tmp.stat().st_size if tmp.exists() else 0
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    if start:
        req.add_header("Range", f"bytes={start}-")
    p = local_proxy()          # 有代理就先走代理, 见 _get 的说明
    try:
        resp = (_open_via(p, req, TIMEOUT) if p
                else urllib.request.urlopen(req, timeout=TIMEOUT))
    except urllib.error.HTTPError:
        raise                      # 服务器有响应, 网络是通的
    except Exception as e:
        if not p:
            raise
        print(f"[*] 本机代理 {p} 走不通({type(e).__name__}), 改直连")
        resp = urllib.request.urlopen(req, timeout=TIMEOUT)

    # 206 = 服务器接受了 Range, 可以接着写; 200 = 不支持, 从头来
    partial = start > 0 and getattr(resp, "status", 200) == 206
    if start and not partial:
        print("[*] 服务器不支持断点续传, 从头下载")
        start = 0
    elif start:
        print(f"[*] 续传: 已有 {start // 1048576}MB, 接着下")

    got = start
    t0 = time.time()
    with resp as r, open(tmp, "ab" if partial else "wb") as fh:
        total = int(r.headers.get("Content-Length") or 0) + (start if partial else 0)
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
            if on_progress is not None:
                try:
                    on_progress(got, total)
                except Exception:
                    pass
            elif not quiet:
                el = max(0.001, time.time() - t0)
                spd = got / el / 1024          # KB/s
                done = f"{got // 1048576}MB"
                allmb = f"{total // 1048576}MB" if total else "?"
                pct = f"  {got * 100 // total}%" if total else ""
                print(f"\r    下载 {done} / {allmb}{pct}  ({spd:.0f} KB/s)",
                      end="", flush=True)
    if not quiet and on_progress is None:
        el = max(0.001, time.time() - t0)
        print(f"\n    完成 {got // 1048576}MB, 平均 {got / el / 1024:.0f} KB/s")
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
REM
REM Pure ASCII on purpose: cmd.exe reads .bat in the console code page, and
REM non-ASCII bytes shift the parser and break the script.
REM
REM This runs **silently** (no console window when the app launches it) and
REM logs everything to apply.log next to this file -- so a failed update is
REM still diagnosable, without bothering the user with a black window.
setlocal
for %%I in ("%~dp0..\..") do set "DST=%%~fI"
set "SRC=%~dp0__PAYLOAD__\payload"
set "LOG=%~dp0apply.log"

echo [%DATE% %TIME%] update start >> "%LOG%"
echo [%DATE% %TIME%] from %SRC% >> "%LOG%"
echo [%DATE% %TIME%] to   %DST% >> "%LOG%"

REM Wait for THIS folder's freeVPN to exit. Match the full executable path,
REM NOT the image name: tasklist /IM is a global match, so a second freeVPN
REM install (say a daemon serving C:\freeVPN) would keep this loop spinning.
echo [%DATE% %TIME%] waiting for freeVPN to exit >> "%LOG%"
:wait
set "RUNNING="
for /f "delims=" %%P in ('wmic process where "name='freeVPN.exe'" get ExecutablePath 2^>nul ^| find /I "%DST%\freeVPN.exe"') do set "RUNNING=1"
if defined RUNNING (
  ping -n 2 127.0.0.1 >nul
  goto wait
)

echo [%DATE% %TIME%] copying files >> "%LOG%"
robocopy "%SRC%" "%DST%" /E /NFL /NDL /NJH /NJS /NP >> "%LOG%" 2>&1
if errorlevel 8 (
  echo [%DATE% %TIME%] WARN robocopy exit %ERRORLEVEL% >> "%LOG%"
)

REM The payload never contains state\ out\ bin\ or the subscription-address
REM file, so the user's data cannot be touched by this copy.

REM Bring the resident service back up. It had to be killed so the exe could be
REM replaced; without this the subscription stays dark until the user notices.
REM No --port here on purpose: daemon reads pool.conf.json like everything else.
echo [%DATE% %TIME%] restarting resident service >> "%LOG%"
start "" "%DST%\freeVPN.exe" daemon --log "%DST%\state\daemon.log"

echo [%DATE% %TIME%] starting GUI >> "%LOG%"
if exist "%DST%\freeVPN.exe" (
  start "" "%DST%\freeVPN.exe"
) else (
  echo [%DATE% %TIME%] no freeVPN.exe here (source tree update?) >> "%LOG%"
)
echo [%DATE% %TIME%] done >> "%LOG%"
exit /b 0
"""


def stop_resident(root: Path | None = None) -> int:
    """停掉本目录下的 freeVPN.exe（常驻 / 控制台）。返回结束的进程数。

    **为什么必须做**：替换脚本要等**所有**同目录的 freeVPN.exe 退出才能覆盖 exe，
    而 daemon 是常驻的 —— 不停它，脚本会永远卡在 "waiting for freeVPN to exit"。
    实测踩过：一键更新跑完就卡在那儿，版本一个字节都没换。

    按**可执行文件路径**筛，不按进程名 —— 本机可能还装着另一份 freeVPN
    （比如源码版），按名字会误杀。也不会杀调用者自己。
    """
    base = Path(root) if root else sec.app_root()
    exe = str((base / "freeVPN.exe")).lower()
    me = os.getpid()
    killed = 0
    try:
        r = subprocess.run(
            ["wmic", "process", "where", "name='freeVPN.exe'",
             "get", "ProcessId,ExecutablePath", "/format:csv"],
            capture_output=True, text=True, timeout=20,
            encoding=sec.console_encoding(), errors="replace",
            creationflags=sec.hidden_flags())
        for line in (r.stdout or "").splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 3:
                continue
            pid_s, path = parts[-1], parts[-2]
            if not pid_s.isdigit() or path.lower() != exe:
                continue
            pid = int(pid_s)
            if pid == me:
                continue          # 别把自己杀了
            subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                           capture_output=True, timeout=15,
                           creationflags=sec.hidden_flags())
            killed += 1
    except Exception:
        pass
    return killed


def launch_apply(bat: Path) -> bool:
    """分离启动替换脚本。**调用方启动成功后应当立刻退出自己。**

    必须分离(`DETACHED_PROCESS` + 新进程组): 脚本要等本进程退出才能覆盖 exe,
    当普通子进程启动的话父进程一退它就被一起带走了。

    静默(CREATE_NO_WINDOW): 用户要的是"点一下, 程序自己关掉再打开", 不是
    一个黑窗口。进度和失败原因都写进 apply.log。
    """
    try:
        if os.name == "nt":
            DETACHED_PROCESS = 0x00000008
            CREATE_NEW_PROCESS_GROUP = 0x00000200
            CREATE_NO_WINDOW = 0x08000000
            flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
            subprocess.Popen(
                ["cmd", "/c", str(bat)], cwd=str(bat.parent),
                creationflags=flags, close_fds=True,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
        else:
            subprocess.Popen(
                ["/bin/sh", str(bat)], cwd=str(bat.parent),
                start_new_session=True, close_fds=True,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
        return True
    except Exception as e:
        print(f"[!] 启动替换脚本失败: {type(e).__name__}: {e}")
        return False


def write_apply_script(stage_root: Path) -> Path:
    """生成替换脚本, 放在 `state/update/` 下(与版本目录同级), 方便用户找。

    payload 的真实位置是 `state/update/<版本>/payload` —— **比脚本低一层**。
    第一版按 `%~dp0payload` 写, 少了一层版本目录, robocopy 直接报 16
    (隔离演练抓到的)。所以版本目录名在生成时烘进脚本里。
    """
    name = stage_root.name
    if not re.fullmatch(r"[A-Za-z0-9._\-]+", name):
        raise ValueError(f"版本目录名含不安全字符: {name!r}")
    bat = stage_root.parent / "apply-update.bat"
    # newline 用 CRLF —— cmd.exe 对纯 LF 的 .bat 在部分版本上会读错行。
    #
    # 内容必须是**纯 ASCII**: cmd.exe 按控制台代码页逐字节解析批处理, UTF-8 的中文
    # 会被当成 GBK 读, 解析器在词中间断开(README 里为这个坑专门写过一段)。
    # 这里显式校验而不是靠 encode 抛异常 —— 上一版模板里混进了中文, 直到用户
    # 点下去才炸。
    text = APPLY_BAT.replace("__PAYLOAD__", name).replace("\n", "\r\n")
    try:
        data = text.encode("ascii")
    except UnicodeEncodeError as e:
        bad = e.object[e.start:e.end]
        raise ValueError(f"apply 脚本混进了非 ASCII 字符 {bad!r} —— .bat 必须纯 ASCII") from e
    bat.write_bytes(data)
    return bat


def proxy_hint() -> None:
    """直连 GitHub 不通时的提示。

    国内直连 github.com 经常被掐: 实测 TCP 能连上、TLS/SSH 握手阶段被打断
    (`Connection was reset` / `kex_exchange_identification` 超时), 而同一时刻
    走本机代理就正常。urllib 认 HTTPS_PROXY 环境变量, 不用改代码也不用改配置。
    """
    cur = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    print()
    if cur:
        print(f"    当前 HTTPS_PROXY={cur} —— 如果它本身不通, 换一个再试")
        return
    print("    如果直连 GitHub 不稳(国内常见, 表现为 reset / 握手超时), 借本机代理:")
    print('      PowerShell:  $env:HTTPS_PROXY="http://127.0.0.1:7897"')
    print('      cmd:         set HTTPS_PROXY=http://127.0.0.1:7897')
    print("    端口按你代理软件里实际的监听端口改。")


def run(check_only: bool = False, force: bool = False, quiet: bool = False,
        apply_now: bool = False) -> int:
    """检查并（可选）下载新版。返回进程退出码。

    apply_now=True 走"傻瓜式": 下载解压完**自己启动替换脚本并退出**,
    由脚本接手覆盖文件 + 拉起新版本。
    """
    print(f"[*] 本地版本 {ver.__version__}  ({ver.__release_date__})")
    print(f"[*] 更新源   https://github.com/{REPO}")
    try:
        info = remote_info()
    except Exception as e:
        print(f"[!] 查不到远端版本: {type(e).__name__}: {e}")
        proxy_hint()
        return 2

    rv = info.get("version") or ""
    if not rv:
        print("[!] 远端没有可识别的版本号 —— 网络不通, 或者仓库确实还没有 release/tag。")
        proxy_hint()
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
    payload = stage_root / "payload"
    if payload.is_dir() and any(payload.iterdir()) and not force:
        # 这一版已经下过了 —— 别重复下 33MB(国内可能要十几分钟)。
        # 典型场景: 上次替换被打断/卡住, 重来时不该从头再下一遍。
        print(f"\n[*] v{rv} 已经下载过了, 直接用 {payload}")
        print("    （想强制重下加 --force）")
        root = payload
        n = sum(1 for f in payload.rglob("*") if f.is_file())
    else:
        if stage_root.exists():
            shutil.rmtree(stage_root, ignore_errors=True)
        stage_root.mkdir(parents=True, exist_ok=True)
        pkg = stage_root / f"freeVPN-{rv}.zip"
        print(f"\n[*] 下载 {info['url'][:100]}")
        download(info["url"], pkg, quiet=quiet)
        print(f"    已保存 {pkg.stat().st_size // 1024} KB")
        payload.mkdir(parents=True, exist_ok=True)
        root, n = extract_package(pkg, payload)
        print(f"    解压 {n} 个文件 -> {root}")

    pv = package_version(root)
    if pv and ver_tuple(pv) != ver_tuple(rv):
        print(f"[!] 包内版本 {pv} 与远端声明 {rv} 不一致 —— 拒绝, 已删掉解压结果")
        shutil.rmtree(stage_root, ignore_errors=True)
        return 3
    print(f"    包内版本校验通过: {pv or '(未标注)'}")

    # 打包版拿到的是源码包 —— 里面的代码在 exe 里已经编译过, 替换源码对 exe 没用。
    # 必须说清楚, 否则用户会以为"更新完了", 而程序本体还是旧的。
    if sec.is_frozen() and info.get("kind") in ("source", "release-source"):
        print()
        print("[!] 你是打包版(freeVPN.exe), 而远端只有**源码包**:")
        print("    · cn_cidr.txt / cn_domains.txt / sources.txt / pool.conf.json 会更新")
        print("    · freeVPN.exe 本身不会变(源码包里没有它)")
        print("    要让程序本体也能在线更新, 仓库需要一个带 win64 zip 的 Release。")

    bat = write_apply_script(stage_root)

    if apply_now:
        # 先把常驻/控制台停掉 —— 替换脚本要等**所有**同目录的 freeVPN.exe 退出
        # 才动手, 而 daemon 是常驻的, 不停它脚本会一直等下去(实测卡死, 版本没换)。
        # 它们都会被脚本重新拉起来, 用户无感。
        n = stop_resident()
        if n:
            print(f"[*] 已停掉同目录的 freeVPN 进程 {n} 个（脚本稍后会拉回来）")
            time.sleep(1.5)          # 等文件句柄释放干净
        # 傻瓜式那条路: 启动分离的替换脚本, 自己立刻退出 —— 脚本会等本进程
        # 退出后覆盖文件, 再把新版本拉起来。用户看到的就是"程序自己重启了"。
        print("\n[*] 一键更新: 启动替换脚本, 本程序马上退出")
        if launch_apply(bat):
            print("    脚本会等本进程退出后覆盖文件, 然后自动启动新版本。")
            print(f"    （失败原因写在 {bat.parent / 'apply.log'}）")
            return 0
        print(f"[!] 没能启动替换脚本 —— 请手动双击它:\n    {bat}")
        return 4

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
    print()
    print("  嫌麻烦的话: python pool.py update --apply —— 下完自己退出并重启。")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(check_only="--check" in sys.argv, force="--force" in sys.argv,
                 apply_now="--apply" in sys.argv))
