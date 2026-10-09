# -*- coding: utf-8 -*-
"""
问题 1 验证: 能否构造恶意节点绕过 audit_node / bad_server / normalize 进入最终产物。
逐条试: 非 IP 形式的内网、skip-cert-verify 变体写法、敏感端口等价写法、DNS 重绑定式域名。
"""
import sys

sys.path.insert(0, r"E:\AI\freeVPN")
import pool
import security as sec

UUID = "11111111-2222-3333-4444-555555555555"


def verdict(p: dict) -> str:
    """返回 normalize + audit 的最终裁决。"""
    n = pool.normalize(dict(p))
    if n is None:
        return "DROPPED-normalize"
    fs = sec.audit_node(n)
    blocked = [f for f in fs if f.level == "block"]
    if blocked:
        return "BLOCKED-" + ",".join(f.code for f in blocked)
    warns = ",".join(f.code for f in fs)
    return f"PASS(进入产物)" + (f" warn={warns}" if warns else "")


def base(server: str, port=443, **kw) -> dict:
    p = {"name": "t", "type": "vmess", "server": server, "port": port,
         "uuid": UUID, "alterId": 0, "cipher": "auto", "tls": True}
    p.update(kw)
    return p


def section(title: str, cases: list[tuple[str, dict]]):
    print("=" * 78)
    print(f"### {title}")
    print("=" * 78)
    for label, p in cases:
        try:
            v = verdict(p)
        except Exception as e:
            v = f"EXCEPTION {type(e).__name__}: {e}"
        print(f"  {label:38} server={p.get('server')!r:34} -> {v}")
    print()


if __name__ == "__main__":
    print("security.py:", sec.__file__)
    print()

    section("1.1 回环地址的各种写法 (目标是让节点连到本机)", [
        ("点分四段", base("127.0.0.1")),
        ("127.1 简写", base("127.1")),
        ("127.0.1 简写", base("127.0.1")),
        ("0x7f000001 十六进制", base("0x7f000001")),
        ("2130706433 十进制", base("2130706433")),
        ("017700000001 八进制", base("017700000001")),
        ("127.0.0.1. (尾点)", base("127.0.0.1.")),
        ("[::1] 方括号", base("[::1]")),
        ("::1 裸写", base("::1")),
        ("[0:0:0:0:0:0:0:1]", base("[0:0:0:0:0:0:0:1]")),
        ("[::ffff:127.0.0.1] v4映射", base("[::ffff:127.0.0.1]")),
        ("::ffff:7f00:1 十六进制映射", base("::ffff:7f00:1")),
        ("localhost", base("localhost")),
        ("localhost. (尾点)", base("localhost.")),
        ("LOCALHOST 大写", base("LOCALHOST")),
        ("127.0.0.1.nip.io 重绑定域名", base("127.0.0.1.nip.io")),
        ("127-0-0-1.sslip.io 重绑定域名", base("127-0-0-1.sslip.io")),
        ("localtest.me 重绑定域名", base("localtest.me")),
        ("0.0.0.0", base("0.0.0.0")),
        ("0", base("0")),
        ("[::]", base("[::]")),
    ])

    section("1.2 内网/保留段的各种写法", [
        ("10.0.0.1", base("10.0.0.1")),
        ("10.1 简写", base("10.1")),
        ("0x0a000001", base("0x0a000001")),
        ("167772161 十进制", base("167772161")),
        ("192.168.1.1", base("192.168.1.1")),
        ("172.16.0.1", base("172.16.0.1")),
        ("169.254.169.254 云元数据", base("169.254.169.254")),
        ("100.64.0.1 CGNAT", base("100.64.0.1")),
        ("100.100.100.200 阿里元数据", base("100.100.100.200")),
        ("[fd00::1]", base("[fd00::1]")),
        ("[fe80::1]", base("[fe80::1]")),
        ("224.0.0.1 组播", base("224.0.0.1")),
        ("240.0.0.1 保留", base("240.0.0.1")),
        ("[::ffff:10.0.0.1]", base("[::ffff:10.0.0.1]")),
        ("192.168.1.1.nip.io", base("192.168.1.1.nip.io")),
        ("10.0.0.1.sslip.io", base("10-0-0-1.sslip.io")),
        ("evil.local", base("evil.local")),
        ("evil.local. 尾点", base("evil.local.")),
        ("evil.internal", base("evil.internal")),
        ("evil.home.arpa", base("evil.home.arpa")),
        ("evil.localdomain (未列后缀)", base("evil.localdomain")),
        ("router 单标签主机名", base("router")),
        ("nas 单标签主机名", base("nas")),
        ("[fd00::1].nip.io 变体", base("x.fd00.nip.io")),
    ])

    section("1.3 敏感端口的等价写法", [
        ("22 int", base("1.2.3.4", 22)),
        ("'22' 字符串", base("1.2.3.4", "22")),
        ("22.0 浮点", base("1.2.3.4", 22.0)),
        ("0x16 十六进制串", base("1.2.3.4", "0x16")),
        ("022 八进制串", base("1.2.3.4", "022")),
        ("'22 ' 带空格", base("1.2.3.4", " 22 ")),
        ("True (bool 子类 int)", base("1.2.3.4", True)),
        ("3306 int", base("1.2.3.4", 3306)),
        ("'3306' 字符串", base("1.2.3.4", "3306")),
    ])

    section("1.4 skip-cert-verify 的变体写法 (audit 只认 `is True`)", [
        ("True 布尔", base("1.2.3.4", 443, **{"skip-cert-verify": True})),
        ("'true' 字符串", base("1.2.3.4", 443, **{"skip-cert-verify": "true"})),
        ("'True' 字符串", base("1.2.3.4", 443, **{"skip-cert-verify": "True"})),
        ("1 整数", base("1.2.3.4", 443, **{"skip-cert-verify": 1})),
        ("'1' 字符串", base("1.2.3.4", 443, **{"skip-cert-verify": "1"})),
        ("'y' 字符串", base("1.2.3.4", 443, **{"skip-cert-verify": "y"})),
        ("'on' 字符串", base("1.2.3.4", 443, **{"skip-cert-verify": "on"})),
        ("Skip-Cert-Verify 键名变体", base("1.2.3.4", 443, **{"Skip-Cert-Verify": True})),
        ("skip_cert_verify 下划线变体", base("1.2.3.4", 443, **{"skip_cert_verify": True})),
        ("skip-cert-verify 带尾空格键", base("1.2.3.4", 443, **{"skip-cert-verify ": True})),
        ("不设置(对照)", base("1.2.3.4", 443)),
    ])

    print("=" * 78)
    print("### 1.5 audit_node 内部判定函数直查")
    print("=" * 78)
    for h in ("127.0.0.1", "127.1", "2130706433", "0x7f000001", "[::ffff:127.0.0.1]",
              "localhost.", "127.0.0.1.nip.io", "localtest.me", "router", "nas",
              "evil.localdomain", "1.2.3.4"):
        kind, ip = sec._host_kind(h)
        print(f"  _host_kind({h!r:26}) = {kind:5} {ip!r:28} "
              f"bad_server={pool.bad_server(h)!s:5} bad_host={pool.bad_host(h)}")

    print()
    print("=" * 78)
    print("### 1.6 通过审计的域名实际解析到哪 (DNS 重绑定验证)")
    print("=" * 78)
    import socket
    for h in ("127.0.0.1.nip.io", "127-0-0-1.sslip.io", "localtest.me",
              "10-0-0-1.sslip.io", "1.2.3.4.nip.io", "evil.localdomain"):
        try:
            infos = socket.getaddrinfo(h, 443, proto=socket.IPPROTO_TCP)
            addrs = sorted({i[4][0] for i in infos})
        except Exception as e:
            addrs = [f"<{type(e).__name__}: {e}>"]
        print(f"  {h:26} bad_server={pool.bad_server(h)!s:5} -> {addrs}")

