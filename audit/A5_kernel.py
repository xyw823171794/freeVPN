#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A5 · 内核进程隔离与 harden 绕过。

测三件事:
  ① kernel_env() 到底剔除干净没有 (对真实 os.environ 做扫描)
  ② 不可信节点字段能不能绕过 harden_kernel_config
  ③ 内核真的启动后, 控制端口 / mixed-port 绑在哪、硬编码 secret 能不能直接用

内核工作目录重定向到 audit/_tmp/kernel, 不碰生产的 state/kernel/config.yaml。
用法: python audit/A5_kernel.py
"""
import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(r"E:\AI\freeVPN")
sys.path.insert(0, str(ROOT))
import pool          # noqa: E402
import security as sec  # noqa: E402

TMP = ROOT / "audit" / "_tmp"
KDIR = TMP / "kernel"
KDIR.mkdir(parents=True, exist_ok=True)
pool.KERNEL_DIR = KDIR           # 不污染 state/kernel

# 审计模块真正想拦的那类名字; 比 _SENSITIVE_ENV_RE 更宽, 用来找漏网之鱼
WIDE = re.compile(r"(KEY|TOKEN|SECRET|PASS|CRED|AUTH|COOKIE|SESSION|PRIVATE|"
                  r"CERT|SIGN|BEARER|API|PAT|ACCOUNT|PROXY)", re.I)


def pid_ports(pid: int) -> list[tuple[str, int]]:
    r = subprocess.run(["netstat", "-ano"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    out = []
    for line in (r.stdout or "").splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[-1] == str(pid) and parts[0] == "TCP":
            local = parts[1]
            addr, _, port = local.rpartition(":")
            out.append((addr, int(port)))
    return out


def main():
    print("=" * 72)
    print("① kernel_env(): 父进程环境变量被剔除得够不够")
    print("=" * 72)
    keep = sec.kernel_env()
    dropped = sorted(set(os.environ) - set(keep))
    print(f"  父进程变量 {len(os.environ)} 个, 传给内核 {len(keep)} 个, 剔除 {len(dropped)} 个")
    print(f"  剔除样例: {dropped[:8]}")
    leak = sorted(k for k in keep if WIDE.search(k))
    print(f"  仍会传进内核的「看起来像密钥/凭据」的变量 ({len(leak)} 个):")
    for k in leak:
        print(f"    - {k}  (值长度 {len(os.environ.get(k, ''))}, 内容不打印)")
    if not leak:
        print("    (无)")
    # 反向: 剔除清单里有没有误伤系统必需项
    must = [k for k in ("SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP", "USERPROFILE",
                        "APPDATA", "LOCALAPPDATA", "NUMBER_OF_PROCESSORS", "COMSPEC")
            if k in os.environ]
    missing = [k for k in must if k not in keep]
    print(f"  系统必需项检查: 缺失 {missing or '无'}")

    print()
    print("  --- 黑名单缺口: 注入几个「不含关键词」的敏感变量名, 看是否被剔除 ---")
    probes = {
        "GITHUB_PAT": "ghp_FAKEVALUE",          # PAT 不在 _SENSITIVE_ENV_RE 里
        "GITLAB_PAT": "glpat-FAKEVALUE",
        "SSH_AUTH_SOCK": r"\\.\pipe\openssh-ssh-agent",  # 泄漏 = 内核能用你的 SSH 密钥
        "VAULT_ADDR": "https://vault.internal",
        "MY_API": "FAKEVALUE",
        "NPM_TOKEN": "npm_FAKEVALUE",           # 含 TOKEN, 应被剔除
        "AWS_SECRET_ACCESS_KEY": "FAKEVALUE",   # 含 SECRET, 应被剔除
        "KUBECONFIG": r"C:\Users\me\.kube\config",
    }
    saved = {k: os.environ.get(k) for k in probes}
    os.environ.update(probes)
    kept = sec.kernel_env()
    for k, v in probes.items():
        mark = "!! 泄漏进内核" if k in kept else "已剔除"
        print(f"    {k:<24} {mark}")
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v

    print()
    print("=" * 72)
    print("② 不可信节点字段能否绕过 harden_kernel_config")
    print("=" * 72)
    # 全部字段都是「通过审计后」仍然可能残留的东西: audit_node 只拦 server/port/名字,
    # 不碰这些内核选项
    evil = {
        "type": "ss", "server": "8.8.8.8", "port": 8388,
        "cipher": "aes-128-gcm", "password": "pw",
        "name": "evil-node",
        "interface-name": "Ethernet",          # 指定出站网卡
        "dialer-proxy": "DIRECT",              # 指定拨号链
        "routing-mark": 1234,                  # 绕过系统分流
        "tun": {"enable": True, "stack": "gvisor"},   # 顶层 tun 的仿冒
        "bind-address": "0.0.0.0",
        "allow-lan": True,
        "external-controller": "0.0.0.0:9090",
        "secret": "",
        "ipv6": True,
        "skip-cert-verify": True,
        "udp": True,
        "smux": {"enabled": True, "protocol": "h2mux"},
    }
    benign = {"type": "ss", "server": "1.1.1.1", "port": 8388,
              "cipher": "aes-128-gcm", "password": "pw"}
    cfg_path = pool._write_kernel_config([evil, benign])
    text = cfg_path.read_text(encoding="utf-8")
    print(f"  生成配置: {cfg_path}  ({len(text)} 字节)")
    keep_top = [k for k in ("allow-lan", "external-controller", "secret", "ipv6",
                            "find-process-mode", "log-level", "geo-auto-update", "tun")
                if re.search(rf"^{k}:", text, re.M)]
    print(f"  顶层保留的键: {keep_top}")
    for key in ("allow-lan", "external-controller", "secret", "ipv6", "log-level"):
        m = re.search(rf"^{key}:\s*(.*)$", text, re.M)
        print(f"    {key:<22} = {m.group(1) if m else '(已被删除)'}")
    print(f"  顶层是否还有 tun: {'tun:' in text}")
    import yaml
    top = yaml.safe_load(text) or {}
    print(f"  解析后的顶层键: {sorted(top.keys())}")
    print(f"  顶层 tun 存在: {'tun' in top}   顶层 bind-address 存在: {'bind-address' in top}")
    print("  恶意节点里这些字段是否原样进了 proxies:")
    for f in ("interface-name", "dialer-proxy", "routing-mark", "bind-address",
              "allow-lan", "external-controller", "tun", "skip-cert-verify"):
        print(f"    {f:<22} {'保留' if f in text else '未出现'}")
    # 名字是否被换成索引
    print(f"  节点名是否被改写: {'evil-node' not in text} (evil-node 不应出现)")

    print()
    print("  mihomo -t 校验:", end=" ")
    bad = pool._kernel_check(cfg_path)
    print("通过" if bad is None else f"被拒 (坏节点索引 {bad})")

    print()
    print("=" * 72)
    print("③ 真启动内核: 监听地址 + 硬编码 secret")
    print("=" * 72)
    if not pool.MIHOMO.exists():
        print("  未找到 bin/mihomo.exe, 跳过")
        return
    proc = subprocess.Popen(
        [str(pool.MIHOMO), "-d", str(KDIR), "-f", str(cfg_path)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL, cwd=str(KDIR),
        env=sec.kernel_env(), creationflags=sec.kernel_creationflags())
    try:
        ready = False
        for _ in range(40):
            if proc.poll() is not None:
                print(f"  内核退出 (exit {proc.returncode})")
                return
            try:
                pool._api("/version", timeout=2)
                ready = True
                break
            except Exception:
                time.sleep(0.5)
        print(f"  内核就绪: {ready}  pid={proc.pid}")
        ports = pid_ports(proc.pid)
        print(f"  内核监听: {sorted(set(ports))}")
        for addr, port in sorted(set(ports)):
            kind = "回环" if addr.startswith("127.") else ("全接口" if addr == "0.0.0.0" else addr)
            print(f"    {addr}:{port}  -> {kind}")

        print()
        print("  --- 控制端口鉴权 ---")
        import urllib.request
        def try_api(secret):
            req = urllib.request.Request(
                f"http://127.0.0.1:{pool.CTRL_PORT}/proxies",
                headers={"Authorization": f"Bearer {secret}"})
            try:
                with urllib.request.urlopen(req, timeout=4) as r:
                    return r.status
            except Exception as e:
                return getattr(e, "code", type(e).__name__)
        print(f"    pool.py 里写死的 SECRET = {pool.SECRET!r}")
        print(f"    用 SECRET 调 /proxies        -> {try_api(pool.SECRET)}")
        print(f"    用错误 secret 调 /proxies    -> {try_api('wrong-secret-12345')}")
        print(f"    用空 secret 调 /proxies      -> {try_api('')}")

        print()
        print("  --- 控制端口的浏览器可达性 (CORS / preflight) ---")
        def hdrs(url, method="GET", extra=None):
            req = urllib.request.Request(url, method=method, headers=extra or {})
            try:
                with urllib.request.urlopen(req, timeout=4) as r:
                    return r.status, dict(r.headers)
            except Exception as e:
                h = getattr(e, "headers", None)
                return getattr(e, "code", type(e).__name__), (dict(h) if h else {})
        st, hs = hdrs(f"http://127.0.0.1:{pool.CTRL_PORT}/version",
                      extra={"Origin": "http://evil.com",
                             "Authorization": f"Bearer {pool.SECRET}"})
        print(f"    带 Origin 的 GET  -> {st}")
        print(f"      Access-Control-Allow-Origin: {hs.get('Access-Control-Allow-Origin', '(无)')}")
        st2, hs2 = hdrs(f"http://127.0.0.1:{pool.CTRL_PORT}/proxies", method="OPTIONS",
                        extra={"Origin": "http://evil.com",
                               "Access-Control-Request-Method": "GET",
                               "Access-Control-Request-Headers": "authorization"})
        print(f"    preflight OPTIONS -> {st2}  "
              f"ACAO={hs2.get('Access-Control-Allow-Origin', '(无)')} "
              f"ACAH={hs2.get('Access-Control-Allow-Headers', '(无)')}")
        st3, _ = hdrs(f"http://127.0.0.1:{pool.CTRL_PORT}/proxies", method="GET")
        print(f"    不带 Origin/不带 secret 的 GET /proxies -> {st3}")

        print()
        print("  --- 恶意节点字段是否被内核接受 ---")
        d = pool._api("/proxies")
        names = [n for n in d.get("proxies", {}) if n.startswith("n")]
        print(f"    内核识别节点: {names}")
        for n in names:
            p = pool._api(f"/proxies/{urllib.parse.quote(n, safe='')}")
            print(f"    {n}: type={p.get('type')} udp={p.get('udp')} "
                  f"smux={bool(p.get('smux'))} history={bool(p.get('history'))}")

        print()
        print("  --- 内核 API 能不能被拿去打本机服务 (SSRF) ---")
        import urllib.parse as up
        q = up.urlencode({"timeout": 2000, "url": f"http://127.0.0.1:{pool.CTRL_PORT}/version"})
        try:
            r = pool._api(f"/proxies/{up.quote(names[0], safe='')}/delay?{q}", timeout=6)
            print(f"    让内核去请求 127.0.0.1:{pool.CTRL_PORT}: {r}")
        except Exception as e:
            print(f"    让内核去请求 127.0.0.1:{pool.CTRL_PORT}: {type(e).__name__}: {e}")
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=6)
            except subprocess.TimeoutExpired:
                proc.kill()
        print("\n  内核已停止")


if __name__ == "__main__":
    import urllib.parse  # noqa: F401  (③ 里用到)
    main()
