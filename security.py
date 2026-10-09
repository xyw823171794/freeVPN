#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
freeVPN · 安全模块
===================

本项目的根本风险不是"节点慢"，而是**节点配置来自完全不可信的公开源**。
免费订阅由匿名第三方维护，里面可以塞任意字段、任意服务器地址、任意命名。

信任边界与对应防线：

    公开订阅源（完全不可信）
        │  ① 输入隔离  Untrusted —— 响应限长、拦 YAML 炸弹、解析资源上限
        ▼
    解析后的节点（不可信数据）
        │  ② 节点审计  Audit     —— 拦内网指向、关闭证书校验、敏感端口、诱导命名
        ▼
    池子产物（半可信）
        │  ③ 进程隔离  Sandbox   —— 内核受限启动：环境变量白名单、禁 tun、
        │                           禁 GEO 下载、独立工作目录、输出重定向
        │  ④ 访问控制  Gate      —— 订阅服务 token、Host 校验防 DNS rebinding、
        │                           CORS 收紧、路径穿越防护
        ▼
    客户端（用户侧）
        └  ⑤ 分流规则  Rules     —— 银行/支付/政务/内网/云元数据永不进代理

**本项目不声称能让免费节点变安全。** 节点持有者始终能看到你的明文目标域名。
上面每一层都只做一件事：缩小可控风险面，把"不可控"限制在你能接受的范围内。
真正敏感的流量不该出现在免费节点上 —— 规则层是最后一道，不是唯一一道。
"""
from __future__ import annotations

import codecs
import ipaddress
import locale
import os
import re
import secrets
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ==========================================================================
# ① 输入隔离 —— 订阅源是不可信输入
# ==========================================================================
MAX_RESPONSE_BYTES = 8 * 1024 * 1024  # 单源响应硬上限, 防内存炸弹
MAX_PARSE_CHARS = 4 * 1024 * 1024     # 送进 YAML/正则解析的最大字符数

# YAML 锚点/别名炸弹(Billion Laughs): safe_load 也会被指数展开打爆
_ANCHOR_RE = re.compile(r"&\w+\s*$", re.M)
_ALIAS_RE = re.compile(r"^\s*\*\w+", re.M)


def yaml_bomb(text: str, limit: int = 80) -> bool:
    """检测 YAML 锚点/别名炸弹。命中则整源丢弃。"""
    if len(text) > MAX_PARSE_CHARS:
        return True
    return (len(_ANCHOR_RE.findall(text)) > limit
            or len(_ALIAS_RE.findall(text)) > limit)


def clamp_text(text: str, limit: int = MAX_PARSE_CHARS) -> str:
    return text[:limit] if len(text) > limit else text


# 必须剥掉的行分隔符: 除了 ASCII 控制符, 还有 Unicode 的 U+0085 / U+2028 / U+2029。
#
# 这三种字符不会被 [\x00-\x1f\x7f] 命中, 但 YAML 读取端把它们当换行。后果是
# 它们可以藏在"键名"里, 让键名在序列化时断成两行, 从而把任意顶层键
# (tun / tunnels / hosts / sniffer) 注入产物 —— 实测能绕过 harden_kernel_config
# 的 pop("tun"), 内核启动时真的去建 TUN 设备。
LINE_SEP_CHARS = "\x85\u2028\u2029"
LINE_SEP_RE = re.compile("[\x85\u2028\u2029]")


def has_line_sep(s: str) -> bool:
    return bool(LINE_SEP_RE.search(s or ""))


# ==========================================================================
# ② 节点审计 —— 出站前扫描每个节点
# ==========================================================================
# 这些端口出现在"代理节点"上极不寻常, 通常意味着源在拿你当跳板探内网
SENSITIVE_PORTS = {
    22, 23, 25, 53, 110, 135, 137, 139, 143, 445, 465, 587, 993, 995,
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017,
}

# 诱导性命名: 伪装成银行/支付/登录页的节点, 用来骗你在上面提交凭证
_LURE_RE = re.compile(
    r"(网银|银行|支付|支付宝|微信支付|登录|登陆|密码|验证码|实名|"
    r"bank|paypal|alipay|login|signin|verify|password|credential|"
    r"免费机场|官方|客服|退款|领取|福利)",
    re.I,
)

# 内网/保留域名后缀: 节点指向这些地址等于把你导进内网
_INTERNAL_SUFFIX = (".local", ".lan", ".internal", ".localhost", ".home.arpa",
                    ".in-addr.arpa", ".corp", ".intranet", ".test", ".example")

# 通配 DNS 服务: 域名里嵌的 IP 会被解析出来, 所以 `127.0.0.1.nip.io` 这类
# 写法能骗过"服务器是不是字面量内网地址"的检查, 实际连的是回环。
# 实测这类域名零告警通过审计, 内核解析后真的连上了本机监听端口。
_REBIND_SUFFIX = (
    ".nip.io", ".sslip.io", ".xip.io", ".local.gd", ".lvh.me", ".vcap.me",
    ".traefik.me", ".localtest.me", ".lacolhost.com", ".rebind.network",
    ".1u.ms", ".v.gg", ".insanelab.com", ".localtest.dev",
)

# 非标准端口 + 无加密, 明文传输风险
TLS_PORTS = {443, 8443, 2053, 2083, 2087, 2096, 4443, 9443, 8843}


@dataclass
class Finding:
    level: str    # "block" = 直接丢弃, "warn" = 保留但记账
    code: str
    detail: str


@dataclass
class AuditReport:
    scanned: int = 0
    blocked: int = 0
    warned: int = 0
    reasons: dict[str, int] = field(default_factory=dict)

    def note(self, f: Finding):
        self.reasons[f.code] = self.reasons.get(f.code, 0) + 1

    def as_dict(self) -> dict:
        return {
            "scanned": self.scanned,
            "blocked": self.blocked,
            "warned": self.warned,
            "reasons": dict(sorted(self.reasons.items(), key=lambda kv: -kv[1])),
        }


def _host_kind(host: str) -> tuple[str, object | None]:
    h = (host or "").strip().strip("[]").lower()
    try:
        return "ip", ipaddress.ip_address(h)
    except ValueError:
        return "name", None


def audit_node(p: dict) -> list[Finding]:
    """审计单个节点。返回的 Finding 里只要有一条 block, 该节点就不该进池子。"""
    out: list[Finding] = []
    kind, ip = _host_kind(p.get("server", ""))

    # --- 服务器地址 ---
    if kind == "ip":
        if ip.is_loopback:
            out.append(Finding("block", "loopback", f"服务器是回环地址 {ip}"))
        elif ip.is_private:
            out.append(Finding("block", "private-ip", f"服务器是内网地址 {ip}"))
        elif ip.is_link_local:
            out.append(Finding("block", "link-local", f"服务器是链路本地地址 {ip}"))
        elif ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            out.append(Finding("block", "reserved-ip", f"服务器是保留地址 {ip}"))
    else:
        name = str(p.get("server", "")).lower()
        if any(name.endswith(s) for s in _INTERNAL_SUFFIX):
            out.append(Finding("block", "internal-domain", f"服务器指向内网域名 {name}"))
        if not re.fullmatch(r"[a-z0-9]([a-z0-9\-._]*[a-z0-9])?", name):
            out.append(Finding("block", "bad-hostname", f"服务器名含非法字符: {name!r}"))

    # --- 敏感端口 ---
    port = p.get("port")
    if isinstance(port, int) and port in SENSITIVE_PORTS:
        out.append(Finding("block", "sensitive-port",
                           f"{p.get('type')} 节点落在敏感端口 {port}"))

    # --- TLS 校验被关闭: 中间人可以透明劫持 ---
    if p.get("skip-cert-verify") is True:
        out.append(Finding("warn", "no-cert-verify",
                           f"{p.get('server')}:{port} 关闭了证书校验"))

    # --- 无加密 + 非标准端口 ---
    if p.get("type") in ("vmess", "vless", "trojan") and not p.get("tls"):
        if isinstance(port, int) and port not in TLS_PORTS:
            out.append(Finding("warn", "plaintext",
                               f"{p.get('type')} 明文传输于非标准端口 {port}"))

    # --- 诱导性命名 ---
    nm = str(p.get("_raw_name") or p.get("name") or "")
    m = _LURE_RE.search(nm)
    if m:
        out.append(Finding("warn", "lure-name", f"节点名疑似诱导: {m.group(0)}"))

    # --- 键名/值里藏行分隔符: 这是往产物顶层注入键的手段 ---
    for k in p.keys():
        if has_line_sep(str(k)):
            out.append(Finding("block", "line-sep-in-key",
                               f"字段名里含 Unicode 行分隔符, 可用于 YAML 顶层注入: {k!r:.60}"))
            break

    # --- 通配 DNS 域名: 可解析到回环/内网, 绕过地址字面量检查 ---
    server = str(p.get("server", "")).lower()
    for wild in _REBIND_SUFFIX:
        if server.endswith(wild):
            out.append(Finding("block", "rebind-domain",
                               f"服务器用通配 DNS 域名 {server}, 可解析到内网/回环"))
            break

    # --- 伪装成知名服务 ---
    for brand in ("google", "cloudflare", "microsoft", "apple", "amazon"):
        if brand in server and kind == "ip":
            out.append(Finding("warn", "brand-spoof",
                               f"IP 节点伪装 {brand} 域名"))
            break

    return out


def audit_pool(nodes: list[dict]) -> tuple[list[dict], AuditReport]:
    """全池审计。返回 (通过审计的节点, 报告)。"""
    rep = AuditReport()
    keep: list[dict] = []
    for n in nodes:
        rep.scanned += 1
        findings = audit_node(n)
        blocked = [f for f in findings if f.level == "block"]
        for f in findings:
            rep.note(f)
        if blocked:
            rep.blocked += 1
            continue
        if findings:
            rep.warned += 1
        n["_findings"] = [{"level": f.level, "code": f.code} for f in findings]
        keep.append(n)
    return keep, rep


# ==========================================================================
# ③ 进程隔离 —— 内核加载的是不可信配置, 必须限制它能做什么
# ==========================================================================
# 内核只需要这些系统变量就能正常起来。
#
# 必须是白名单, 不能是关键词黑名单: 黑名单只挡得住名字里含 KEY/TOKEN/SECRET 的
# 变量, 而 GITHUB_PAT / GITLAB_PAT / VAULT_ADDR / KUBECONFIG / DOCKER_CONFIG
# 都不含这些词 —— 实测全部泄漏进内核进程。内核加载的是完全不可信的公开订阅
# 配置, 它能看到的环境面必须收窄到最小。
#
# 键名比较统一转大写: Windows 上 os.environ 的键是大写的, 写成 "SystemRoot"
# 会匹配不上, 漏掉 SYSTEMROOT 会让内核静默不监听控制端口(实测踩过这个坑)。
_KEEP_ENV = {
    "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "PATH", "PATHEXT", "COMSPEC",
    "TEMP", "TMP", "TMPDIR", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER", "OS", "LANG",
    "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA",
    "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)", "COMMONPROGRAMFILES",
}


def kernel_env() -> dict[str, str]:
    """内核进程环境: 只保留系统必需项, 其余(含一切凭据与代理设置)一律不传。

    顺带也摘掉了 *_PROXY —— 内核按配置自己出站, 继承来的代理设置会让它的
    直连测试走错路, 测出来的延迟全是假的。
    """
    return {k: v for k, v in os.environ.items() if k.upper() in _KEEP_ENV}


def kernel_creationflags() -> int:
    """Windows: 不弹控制台窗口, 不让内核共享父进程控制台。"""
    if os.name == "nt":
        return 0x08000000 | 0x00000200  # CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
    return 0


def hidden_flags() -> int:
    """起**普通**子进程时用的标志: 不给它分配新控制台。

    从 GUI(pythonw) 或无控制台的计划任务里起控制台程序时, 不设这个标志
    Windows 就会分配一个新控制台 —— 屏幕上闪一个黑窗。实测踩过:
    控制台每 2 秒跑一次 wmic 查进程, 于是每 2 秒闪一下。
    所有 subprocess 调用都该带上它。
    """
    return 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW


def console_encoding() -> str:
    """Windows 控制台程序(tasklist / taskkill / netstat / icacls)输出的编码。

    它们按**控制台码页**输出(中文系统是 GBK), 不是 UTF-8。
    硬按 UTF-8 解会得到一串乱码 —— 实测进程名会变成
    `??..?e?????p????..?`, 用户看到的占用者提示完全没法读。

    取 OEM 码页而不是 ANSI 码页: 控制台程序用的是前者。
    """
    if os.name != "nt":
        return "utf-8"
    try:
        import ctypes
        cp = int(ctypes.windll.kernel32.GetOEMCP())
        if cp:
            name = f"cp{cp}"
            # 必须验证 codec 名合法。GetOEMCP 从注册表读
            # (HKLM\...\Nls\CodePage\OEMCP), 值被改成非法数字时
            # 所有调用点都会抛 LookupError —— 而且那不是 OSError,
            # 不会被各处的 except OSError 兜住, 表现为莫名其妙的崩溃。
            codecs.lookup(name)
            return name
    except Exception:
        pass
    try:
        return locale.getpreferredencoding(False) or "utf-8"
    except Exception:
        return "utf-8"


def _probe_write(d: Path) -> bool:
    """往目录里写一个**随机名**探针文件, 成功返回 True。

    名字必须随机: 原来用 f".wtest-{os.getpid()}" —— pid 可预测, 而 Windows 上
    os.link 不需要管理员权限。本机攻击者可以预置一个指向任意文件的硬链接,
    我们 write_text 就把那个文件覆盖成 "x" 了。
    """
    name = f".wtest-{secrets.token_hex(8)}"
    t = d / name
    try:
        if t.exists() or t.is_symlink():
            return False
        t.write_text("x", encoding="utf-8")
        t.unlink(missing_ok=True)
        return True
    except Exception:
        return False


def write_confined() -> str:
    """本程序是不是被限制只能写自己附近? 返回原因描述, 没被限制返回空串。

    有些环境会**按路径**限制可执行文件的写入范围(agent 工作区、受管目录):
    放在里面的程序只能写工作区内部, 写 %TEMP% / %APPDATA% 一律拒绝。
    表现是"导入客户端失败"、"开机自启设不了"这类莫名其妙的问题。

    判据: 连系统临时目录都写不了, 而自己所在目录能写 —— 那就是被按路径关起来了。
    """
    import tempfile
    own = app_root()
    own_ok = _probe_write(own)
    # 必须直接读 TEMP 环境变量, 不能用 tempfile.gettempdir():
    # 那个函数在 TEMP 不可写时会**回退到当前目录**, 而当前目录往往就是
    # 程序自己那儿(可写) —— 于是检测永远"通过", 等于没检测。
    raw = os.environ.get("TEMP") or os.environ.get("TMP") or ""
    d = Path(raw) if raw else Path(tempfile.gettempdir())
    if _probe_write(d):
        return ""
    if own_ok:
        return (f"本程序所在目录（{own}）能写，但系统临时目录写不了。\n"
                "这种限制是按**路径**生效的 —— 放在该位置的程序只能写它附近。")
    return ""


def process_running(exe: str) -> bool:
    """某个 exe 名有没有在跑。走 tasklist 且隐藏窗口, 不会闪控制台。"""
    try:
        r = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {exe}", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=15,
            encoding=console_encoding(), errors="replace",
            creationflags=hidden_flags())
        return exe.lower() in (r.stdout or "").lower()
    except Exception:
        return False


_STILL_ACTIVE = 259


def pid_alive(pid: int) -> bool:
    """进程是否还活着 —— 走 Win32 API, 不起子进程（也就不会闪窗）。"""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    try:
        if os.name != "nt":
            os.kill(pid, 0)
            return True
        import ctypes
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
        if not h:
            return False
        try:
            code = ctypes.c_ulong()
            ok = k32.GetExitCodeProcess(h, ctypes.byref(code))
            return bool(ok) and code.value == _STILL_ACTIVE
        finally:
            k32.CloseHandle(h)
    except Exception:
        return False


def kernel_preexec():
    """POSIX: 给内核进程加资源上限, 降权到 nobody。Windows 返回 None。"""
    if os.name == "nt":
        return None

    def _limit():
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_NOFILE, (4096, 4096))
            resource.setrlimit(resource.RLIMIT_NPROC, (512, 512))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except Exception:
            pass
        try:
            import pwd
            if os.getuid() == 0:
                nb = pwd.getpwnam("nobody")
                os.setgid(nb.pw_gid)
                os.setuid(nb.pw_uid)
        except Exception:
            pass
    return _limit


def harden_kernel_config(cfg: dict, secret: str | None = None) -> dict:
    """对内核配置做安全收口。就地修改并返回。"""
    # 不监听局域网, 不暴露控制端口, 不读进程信息
    cfg["allow-lan"] = False
    cfg.pop("bind-address", None)
    cfg["find-process-mode"] = "off"
    cfg["ipv6"] = False
    cfg["log-level"] = "silent"
    # 关闭 tun: 它会改系统路由表并需要管理员权限
    cfg.pop("tun", None)
    # 内核不该为了跑起来去外网拉数据(GEOIP/GEOSITE/MMDB)。
    # 规则层完全不使用 GEO 规则, 所以关掉自动更新就够了 ——
    # 注意别去动 geox-url, 空串会让内核直接拒绝整份配置。
    cfg["geo-auto-update"] = False
    cfg.pop("external-ui", None)
    # 控制端口只绑回环, 且必须带密钥
    cfg["external-controller"] = "127.0.0.1:19090"
    cfg["secret"] = secret or secrets.token_urlsafe(18)
    # DNS 不监听对外端口, 不用需要 MMDB 的 fallback-filter
    dns = cfg.setdefault("dns", {})
    dns.pop("listen", None)
    dns.pop("fallback-filter", None)
    return cfg


# ==========================================================================
# ④ 访问控制 —— 订阅服务是本机的一个 HTTP 端口, 不能谁都能读
# ==========================================================================
_ALLOWED_HOSTS = ("127.0.0.1", "localhost", "[::1]", "::1")


def app_root() -> Path:
    """程序根目录。

    打包成 exe 之后 `__file__` 指向 PyInstaller 的临时解包目录, 拿它当根目录
    会导致 bin/mihomo.exe、state/、out/ 全部找不到。冻结环境下必须用
    **exe 自己所在的目录**。
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def self_cmd() -> list[str]:
    """重新调起自己的命令前缀（起扫描子进程 / 写自启脚本时用）。

    源码运行时是 `python -u pool.py`, 打包后就是 exe 自己。
    """
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, "-u", str(app_root() / "pool.py")]


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def bundle_dir() -> Path | None:
    """PyInstaller 打包进 exe 的资源目录（--onefile 时是临时解包目录）。"""
    p = getattr(sys, "_MEIPASS", None)
    return Path(p) if p else None


def find_resource(*rel: str) -> Path | None:
    """按优先级找一个资源文件。

    先看程序根目录（源码模式 / 目录版 / 用户自己放的同名文件），
    再看 exe 内置的资源（--onefile 打包进去的）。用户放在外面的优先，
    这样 sources.txt 这类配置仍然可以就地编辑。
    """
    for base in (app_root(), bundle_dir()):
        if not base:
            continue
        p = base.joinpath(*rel)
        if p.exists():
            return p
    return None


def find_kernel() -> Path | None:
    """定位 mihomo 内核。

    单文件版把内核打进了 exe（在 bundle 目录里），目录版和源码模式则是
    旁边的 bin/ 目录。两处都找，优先外面的 —— 用户想换内核版本直接替换即可。
    """
    return find_resource("bin", "mihomo.exe")


def harden_install_dir(root: Path) -> bool:
    """把安装目录的 ACL 收紧到「当前用户 + SYSTEM」。

    为什么要做: 从压缩包解压到 `C:\\freeVPN` 这类位置时，目录继承的是
    `Authenticated Users:(M)` —— **本机任何登录用户都能改**。后果:

      · 替换 `freeVPN.exe`      → 受害者下次启动即以自己身份执行攻击者的程序
      · 替换 `bin/mihomo.exe`   → 每次 L2 实测都会执行它(外面优先, 见 find_resource)
      · 改 `out/pool.yaml`      → 往受害者的 VPN 客户端注入任意代理节点
      · 改 `state/` 下任何文件

    逐**文件**收紧没用(以前只对 token.txt 和 订阅地址.txt 做了)——
    新产生的文件、以及同一目录下的其它文件仍然是宽松的。要对**目录**做。

    返回是否成功。失败不致命(可能没有改 ACL 的权限), 但要能告诉用户。

    **不要加 `/T`。** `(OI)(CI)` 是容器专用标志, 对文件无效 ——
    实测 `icacls <dir> /inheritance:r /grant:r "user:(OI)(CI)F" /T` 会让
    所有**文件**在失去继承 ACE 之后又拿不到新的 ACE, DACL 变成**空**的,
    结果谁都读不了(连本程序的 exe 都启动不了), 而且 icacls 还报
    "Successfully processed N files"。只对根目录设继承标志, 子项自动继承。
    """
    if os.name != "nt":
        return False
    try:
        root = Path(root)
        if not root.exists():
            return False
        user = os.environ.get("USERNAME") or ""
        if not user:
            return False
        # 只处理根目录: /inheritance:r 去掉继承来的宽松 ACE,
        # /grant:r 加上收紧后的 ACE 并带 (OI)(CI) 让它往下继承。
        r = subprocess.run(
            ["icacls", str(root),
             "/inheritance:r",
             "/grant:r", f"{user}:(OI)(CI)F",
             "/grant:r", "SYSTEM:(OI)(CI)F"],
            capture_output=True, text=True, timeout=120,
            encoding=console_encoding(), errors="replace",
            creationflags=hidden_flags())
        if r.returncode != 0:
            return False
        # 复查: 子项真的继承到了吗? 拿不到就说明加固没生效, 别报成功。
        # 挑根目录里第一个存在的文件来查。
        probe = next((p for p in sorted(root.iterdir()) if p.is_file()), None)
        if probe is None:
            return True
        chk = subprocess.run(["icacls", str(probe)],
                             capture_output=True, text=True, timeout=30,
                             encoding=console_encoding(), errors="replace",
                             creationflags=hidden_flags())
        out = (chk.stdout or "").lower()
        # 空 DACL 或仍有宽松主体 -> 判定失败
        if not out.strip() or "authenticated users" in out or "builtin\\users" in out:
            return False
        return True
    except Exception:
        return False


def dir_is_loose(root: Path) -> bool:
    """目录是否对本机其他用户可写(需要收紧)。"""
    if os.name != "nt":
        return False
    try:
        r = subprocess.run(["icacls", str(root)],
                           capture_output=True, text=True, timeout=30,
                           encoding=console_encoding(), errors="replace",
                           creationflags=hidden_flags())
        out = r.stdout or ""
        # Authenticated Users:(M/W) 或 Users:(M/W) 都算宽松
        for line in out.splitlines():
            low = line.lower()
            if "authenticated users" in low or "builtin\\users" in low:
                if ":(m)" in low or ":(w)" in low or "(m)" in low or "(w)" in low:
                    return True
        return False
    except Exception:
        return False


def tighten_file_perms(path) -> bool:
    """把文件权限收紧到"仅当前用户 + SYSTEM"。

    `os.chmod(path, 0o600)` 在 Windows 上只映射到只读位, **完全不动 ACL** ——
    实测 token.txt 的 ACL 是 `Authenticated Users:(M)` / `Users:(RX)`,
    也就是本机任何用户都能读走令牌。必须显式用 icacls 改。
    """
    try:
        if os.name == "nt":
            user = os.environ.get("USERNAME") or ""
            if not user:
                return False
            r = subprocess.run(
                ["icacls", str(path), "/inheritance:r",
                 "/grant:r", f"{user}:F", "/grant:r", "SYSTEM:F"],
                capture_output=True, text=True, timeout=20,
                encoding=console_encoding(), errors="replace",
                creationflags=hidden_flags())
            return r.returncode == 0
        os.chmod(path, 0o600)
        return True
    except Exception:
        return False


def token_file() -> Path:
    """令牌文件位置。

    必须用 app_root() 而不是 `__file__`：打包成 exe 之后 `__file__` 指向
    PyInstaller 的解包目录，令牌会被写进 `_internal/state/`，而控制台和
    订阅地址读的是 exe 旁边的 `state/` —— 结果就是"服务明明在跑，订阅地址
    却是空的"，客户端怎么都拉不到。
    """
    return app_root() / "state" / "token.txt"


def load_or_create_token() -> str:
    """订阅服务访问令牌。首次生成后持久化, 客户端订阅地址里带上它。"""
    tf = token_file()
    if tf.exists():
        t = tf.read_text(encoding="utf-8").strip()
        if len(t) >= 16:
            # 每次启动都重新收紧一次 ACL —— 老版本创建的令牌文件权限是松的
            # (chmod 在 Windows 上不动 ACL), 只在创建时收紧就永远修不到它
            tighten_file_perms(tf)
            return t
    tok = secrets.token_urlsafe(24)
    tf.parent.mkdir(parents=True, exist_ok=True)
    tf.write_text(tok + "\n", encoding="utf-8")
    tighten_file_perms(tf)
    return tok


def token_ok(provided: str | None, expected: str) -> bool:
    """恒定时间比较。

    必须比较 bytes 而不是 str —— `secrets.compare_digest` 对含非 ASCII 的 str
    会直接抛 TypeError("comparing strings with non-ASCII characters is not
    supported")。攻击者只要发 `?token=中文` 就能让请求线程抛未捕获异常:
    客户端收到的是连接断开而不是 401(会误报"订阅不可用"), 而且异常发生在
    写访问日志之前, 这类探测完全不留痕。实测过。
    """
    if not provided:
        return False
    try:
        return secrets.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))
    except (TypeError, UnicodeError):
        return False


def host_ok(host_header: str | None, port: int) -> bool:
    """校验 Host 头, 挡 DNS rebinding。

    恶意网页可以把某个域名解析到 127.0.0.1, 然后让你的浏览器去读本机订阅服务。
    只认 localhost 系 Host 头即可断掉这条路。
    """
    if not host_header:
        return False
    h = host_header.strip().lower()
    if "," in h:
        return False          # 多值 Host 一律拒绝, 不做"取第一个"的猜测
    if h.startswith("["):     # IPv6 字面量
        return h in (f"[::1]:{port}", "[::1]")
    host, sep, p = h.rpartition(":")
    if not sep:               # 没带端口
        host, p = h, None
    if host not in _ALLOWED_HOSTS:
        return False
    # 端口必须一致(不匹配说明前面挂了别的东西, 别静默放行)
    return p is None or p == str(port)


# ==========================================================================
# ⑤ 分流规则 —— 有些流量永远不该出现在免费节点上
# ==========================================================================
# 内网 / 回环 / 保留段: 直连, 且不解析 DNS
_PRIVATE_RULES = [
    "IP-CIDR,0.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
    "IP-CIDR,192.0.0.0/24,DIRECT,no-resolve",
    "IP-CIDR,192.0.2.0/24,DIRECT,no-resolve",
    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
    "IP-CIDR,198.18.0.0/15,DIRECT,no-resolve",
    "IP-CIDR,198.51.100.0/24,DIRECT,no-resolve",
    "IP-CIDR,203.0.113.0/24,DIRECT,no-resolve",
    "IP-CIDR,224.0.0.0/4,DIRECT,no-resolve",
    "IP-CIDR,240.0.0.0/4,DIRECT,no-resolve",
    "IP-CIDR,255.255.255.255/32,REJECT,no-resolve",
    "IP-CIDR6,::1/128,DIRECT,no-resolve",
    "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
    "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
    "IP-CIDR6,ff00::/8,DIRECT,no-resolve",
    "IP-CIDR6,2001:db8::/32,DIRECT,no-resolve",
]

# 云元数据端点: 拒绝。免费节点上的恶意配置常拿它做 SSRF 偷云凭证。
# 四家主要厂商的端点都要覆盖 —— 只挡 AWS 那条等于没挡。
_METADATA_RULES = [
    "IP-CIDR,169.254.169.254/32,REJECT,no-resolve",
    "IP-CIDR,100.100.100.200/32,REJECT,no-resolve",      # 阿里云
    "DOMAIN-SUFFIX,metadata.google.internal,REJECT",
    "DOMAIN,metadata.goog,REJECT",
    "DOMAIN-SUFFIX,metadata.azure.com,REJECT",
    "DOMAIN-SUFFIX,metadata.tencentyun.com,REJECT",
    "DOMAIN-SUFFIX,metadata.aliyun.com,REJECT",
    "DOMAIN-SUFFIX,metadata.azure.net,REJECT",
    "DOMAIN,metadata.azure.com,REJECT",
]

# 本地网络设备/管理面
_LOCAL_RULES = [
    "DOMAIN-SUFFIX,local,DIRECT",
    "DOMAIN-SUFFIX,lan,DIRECT",
    "DOMAIN-SUFFIX,internal,DIRECT",
    "DOMAIN-SUFFIX,localhost,DIRECT",
]

# 银行 / 支付 / 政务 / 身份 —— 这些走免费节点等于把凭证递给陌生人
_SENSITIVE_DOMAINS = [
    # 银行
    "icbc.com.cn", "ccb.com", "abchina.com", "boc.cn", "bankcomm.com",
    "cmbchina.com", "spdb.com.cn", "cib.com.cn", "cgbchina.com.cn",
    "hxb.com.cn", "cebbank.com", "psbc.com", "pingan.com", "bankofbeijing.com.cn",
    "nbcb.com.cn", "95588.com", "95533.com", "95599.cn",
    "cmbc.com.cn", "citicbank.com", "bankofshanghai.com", "jsbchina.com",
    "webank.com", "czbank.com", "hzbank.com.cn", "bankofjiangsu.com",
    "srcb.com", "gdb.com.cn", "bankofchina.com", "bocsh.com",
    # 支付 / 清算
    "alipay.com", "alipayobjects.com", "tenpay.com", "unionpay.com",
    "unionpayintl.com", "95516.com", "pay.qq.com", "weixin.qq.com",
    "wechat.com", "wx.qq.com",
    # 政务 / 税务 / 社保
    "gov.cn", "12306.cn", "chinatax.gov.cn", "mps.gov.cn", "12333.cn",
    "12345.gov.cn", "chinaport.gov.cn", "mohrss.gov.cn",
    # 二次验证 / 密码管理(国内可直连的部分)
    "passport.baidu.com", "id.qq.com", "passport.weibo.com",
]

_SENSITIVE_RULES = [f"DOMAIN-SUFFIX,{d},DIRECT" for d in _SENSITIVE_DOMAINS]


# --------------------------------------------------------------------------
# 国内流量 —— 默认直连, 永不进免费节点
# --------------------------------------------------------------------------
# 为什么必须有这一段: 产物规则的兜底是 `MATCH,🚀 节点选择`。在它缺席时,
# **所有**没命中上面那份清单的流量(含全部国内站点)都会进免费节点 ——
# 节点持有者能看到你访问了哪些国内服务, 国内站点还会因为境外 IP 触发风控
# (异地登录、验证码、风控拦截)。这是"节点没有屏蔽国内连接"的根因。
#
# 为什么内联 CIDR/域名, 而不是 `GEOIP,CN` / `GEOSITE,cn`: 那两条要客户端
# 本地有 MMDB/dat 文件, 缺失时内核**直接拒绝整份配置**(实测 90 秒超时后
# "test failed"), 整个订阅会失效 —— 这个失败模式比"产物大 230 KB"严重得多。
# 代价只是产物变大, 换"一定加载得起来"。
#
# 数据文件(都在程序根目录, 可直接编辑, 改完下一轮扫描即生效):
#   cn_cidr.txt     中国大陆 IP 段, 由 state/gen-cn-rules.py 从 APNIC 生成
#   cn_domains.txt  中国大陆域名后缀, 手工维护
CN_MODES = ("direct", "reject", "off")
CN_MODE = "direct"     # direct=国内直连 | reject=国内直接掐断 | off=不生成规则
# IP 规则要不要解析域名后再判定(即不带 no-resolve)。
# True: 国内长尾域名(不在 cn_domains.txt 里)也能靠解析出的国内 IP 命中直连 ——
#       代价是未命中的连接会多一次真实 DNS 查询(mihomo 有缓存)。
# False: 只匹配本来就是 IP 的连接, 不触发任何解析。
CN_RESOLVE = True
CN_IPV6 = False        # 产物 ipv6: false, IPv6 段默认不下发


def _read_list_resource(name: str) -> list[str]:
    """读「每行一条」的数据文件, 跳过注释与空行。找不到返回空表。"""
    p = find_resource(name)
    if not p:
        return []
    try:
        out = []
        for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
            ln = ln.split("#", 1)[0].strip()
            if ln:
                out.append(ln)
        return out
    except Exception:
        return []


_CN_CACHE: dict[str, list[str]] = {}


def cn_networks(version: int = 4) -> list[str]:
    """cn_cidr.txt 里指定版本的网段。文件里的条目一律过一遍 ipaddress 校验 ——
    用户手改坏了不该把畸形规则下发到客户端。"""
    key = f"v{version}"
    if key not in _CN_CACHE:
        nets = []
        for ln in _read_list_resource("cn_cidr.txt"):
            try:
                n = ipaddress.ip_network(ln, strict=False)
            except ValueError:
                continue
            if n.version == version:
                nets.append(str(n))
        _CN_CACHE[key] = nets
    return _CN_CACHE[key]


def cn_domains() -> list[str]:
    """cn_domains.txt 里的域名后缀, 一律小写并去前导点。"""
    if "dom" not in _CN_CACHE:
        out = []
        for ln in _read_list_resource("cn_domains.txt"):
            d = ln.lower().lstrip(".")
            if re.fullmatch(r"[a-z0-9][a-z0-9.\-]{0,252}", d):
                out.append(d)
        _CN_CACHE["dom"] = out
    return _CN_CACHE["dom"]


def _cn_action(mode: str | None) -> tuple[str, str]:
    """(生效模式, 动作)。不认识的模式一律退回默认并说明。"""
    m = str(mode if mode is not None else CN_MODE).strip().lower()
    if m not in CN_MODES:
        print(f"[!] cn_mode={m!r} 不认识(可用: {'/'.join(CN_MODES)}), 按 direct 处理")
        m = "direct"
    return m, ("REJECT" if m == "reject" else "DIRECT")


def cn_domain_rules(mode: str | None = None) -> list[str]:
    m, act = _cn_action(mode)
    if m == "off":
        return []
    return [f"DOMAIN-SUFFIX,{d},{act}" for d in cn_domains()]


def cn_ip_rules(mode: str | None = None, resolve: bool | None = None,
                ipv6: bool | None = None) -> list[str]:
    m, act = _cn_action(mode)
    if m == "off":
        return []
    res = CN_RESOLVE if resolve is None else bool(resolve)
    v6 = CN_IPV6 if ipv6 is None else bool(ipv6)
    tail = "" if res else ",no-resolve"
    rules = [f"IP-CIDR,{n},{act}{tail}" for n in cn_networks(4)]
    if v6:
        rules += [f"IP-CIDR6,{n},{act}{tail}" for n in cn_networks(6)]
    return rules


def cn_rules(mode: str | None = None, resolve: bool | None = None,
             ipv6: bool | None = None) -> list[str]:
    return (cn_domain_rules(mode)
            + cn_ip_rules(mode, resolve, ipv6))


def build_security_rules(cn_mode: str | None = None, cn_resolve: bool | None = None,
                         cn_ipv6: bool | None = None) -> list[str]:
    """第⑤层的完整规则表。顺序即优先级:

        云元数据拒绝 > 敏感站点直连 > 国内域名直连 > 内网直连 > 国内 IP 直连
        > 本地域名直连 > (产物再补一条 MATCH 走代理)

    敏感站点必须排在国内规则**前面** —— 银行/政务也在 cn_domains 的覆盖范围里,
    排后面会被 cn_mode=reject 一并掐掉。
    """
    return (_METADATA_RULES
            + _SENSITIVE_RULES
            + cn_domain_rules(cn_mode)
            + _PRIVATE_RULES
            + cn_ip_rules(cn_mode, cn_resolve, cn_ipv6)
            + _LOCAL_RULES)


def configure_cn(mode=None, resolve=None, ipv6=None) -> str:
    """按 pool.conf.json 覆盖国内分流设置并重建规则表。返回生效模式。

    数据文件缺失要显式说出来 —— 静默降级成"国内流量全走节点"正是要修的那个
    问题, 不能让它悄悄发生。
    """
    global CN_MODE, CN_RESOLVE, CN_IPV6, SECURITY_RULES
    if mode is not None:
        CN_MODE = _cn_action(mode)[0]
    if resolve is not None:
        CN_RESOLVE = bool(resolve)
    if ipv6 is not None:
        CN_IPV6 = bool(ipv6)
    SECURITY_RULES = build_security_rules()
    if CN_MODE != "off":
        if not cn_networks(4):
            print("[!] 找不到/读不出 cn_cidr.txt —— 国内 IP 直连规则为空, "
                  "国内流量会进节点。跑 python state/gen-cn-rules.py 生成。")
        if not cn_domains():
            print("[!] 找不到/读不出 cn_domains.txt —— 国内域名直连规则为空。")
    return CN_MODE


def cn_summary() -> str:
    """给控制台/产物头注释用的一行说明。"""
    if CN_MODE == "off":
        return "国内分流: 关闭"
    n4, n6 = len(cn_networks(4)), len(cn_networks(6))
    v6 = f" + IPv6 {n6} 段" if CN_IPV6 else ""
    return (f"国内分流: {CN_MODE} ({len(cn_domains())} 域名 + IPv4 {n4} 段{v6}, "
            f"{'解析后判定' if CN_RESOLVE else '仅真实 IP'})")


# 顺序即优先级: 元数据拒绝 > 敏感直连 > 国内域名 > 内网直连 > 国内 IP > 本地
SECURITY_RULES: list[str] = build_security_rules()


def summarize(rep: AuditReport) -> str:
    """给控制台/状态页用的一行摘要。"""
    if not rep.scanned:
        return "未审计"
    top = list(rep.reasons.items())[:4]
    detail = ", ".join(f"{k}×{v}" for k, v in top) if top else "无异常"
    return (f"审计 {rep.scanned} 个: 拦截 {rep.blocked}, 告警 {rep.warned} ({detail})")


if __name__ == "__main__":
    print("freeVPN 安全模块自检")
    print(f"  分流规则      {len(SECURITY_RULES)} 条")
    print(f"  {cn_summary()}")
    print(f"  敏感域名      {len(_SENSITIVE_DOMAINS)} 个")
    print(f"  敏感端口      {len(SENSITIVE_PORTS)} 个")
    print(f"  响应上限      {MAX_RESPONSE_BYTES // 1024 // 1024} MB")
    tok = load_or_create_token()
    print(f"  服务令牌      {tok[:8]}... (已写入 state/token.txt)")
    probes = [
        {"type": "vmess", "server": "127.0.0.53", "port": 80},
        {"type": "ss", "server": "192.168.1.10", "port": 8388},
        {"type": "vmess", "server": "1.2.3.4", "port": 22},
        {"type": "trojan", "server": "x.com", "port": 443, "skip-cert-verify": True},
        {"type": "vmess", "server": "evil.local", "port": 443},
        {"type": "vmess", "server": "1.2.3.4", "port": 443, "_raw_name": "网银登录专用"},
        {"type": "vless", "server": "8.8.8.8", "port": 443, "tls": True},
    ]
    for p in probes:
        fs = audit_node(p)
        tag = "BLOCK" if any(f.level == "block" for f in fs) else ("WARN" if fs else "PASS")
        why = "; ".join(f"{f.code}:{f.detail}" for f in fs) or "干净"
        print(f"  [{tag:<5}] {p['server']:<16} {p['port']:<6} {why}")
