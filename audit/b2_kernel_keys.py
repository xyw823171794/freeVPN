# -*- coding: utf-8 -*-
"""
问题 2 验证: 节点字段里有没有会被内核执行的键没被过滤掉?
normalize 只白名单剔除 ("id","aid","ps","add","scy","v","host","path","tls_sni") 7 个键,
其余全量透传 -> 攻击者可以在 Clash YAML 源里给节点塞任意内核选项。
本脚本: (1) 证明透传; (2) 用 mihomo -t 证明内核接受; (3) 用真实拨号证明 dialer-proxy 生效;
        (4) 证明 skip-cert-verify 的变体写法能骗过 audit_node 而内核照收。
"""
import pathlib
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, r"E:\AI\freeVPN")
import pool
import security as sec

ROOT = pathlib.Path(r"E:\AI\freeVPN")
WORK = ROOT / "audit" / "_miwork4"
WORK.mkdir(parents=True, exist_ok=True)
UUID = "11111111-2222-3333-4444-555555555555"

DANGEROUS = {
    # build_clash 里永远存在这个分组名 -> 攻击者可以照抄它做 dialer-proxy 目标
    "dialer-proxy": "🚀 节点选择",
    "interface-name": "以太网",
    "routing-mark": 255,
    "ip-version": "ipv6",
    "smux": {"enabled": True, "protocol": "h2mux", "max-connections": 1},
    "brutal-opts": {"enabled": True, "up": "100 Mbps", "down": "100 Mbps"},
    "tfo": True,
    "mptcp": True,
    "packet-encoding": "packetaddr",
    "udp-over-tcp": True,
    "subname": "x",
    "client-fingerprint": "chrome",
    "fingerprint": "chrome",
    "server-cert-fingerprint-sha256": "00" * 32,
    "reality-opts": {"public-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                     "short-id": "0123abcd"},
    "ws-opts": {"path": "/", "headers": {"Host": "a.b"}, "max-early-data": 2048,
                "early-data-header-name": "Sec-WebSocket-Protocol"},
}


def run_mihomo_t(cfg_text: str, tag: str):
    p = WORK / f"t_{tag}.yaml"
    p.write_text(cfg_text, encoding="utf-8")
    r = subprocess.run([str(ROOT / "bin" / "mihomo.exe"), "-d", str(WORK), "-f", str(p), "-t"],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", cwd=str(WORK), timeout=120)
    out = ((r.stdout or "") + (r.stderr or "")).strip()
    errs = [ln for ln in out.splitlines() if "level=error" in ln or "fatal" in ln
            or "failed" in ln]
    return r.returncode, (errs[:2] or out.splitlines()[-1:])


def one_node_cfg(proxy: dict, extra: str = "") -> str:
    return (f"mixed-port: 17888\nallow-lan: false\nmode: rule\nlog-level: warning\n"
            f"proxies:\n" + "".join(f"  - {k}: {v}\n" for k, v in proxy.items()) +
            f"proxy-groups:\n  - name: G\n    type: select\n    proxies: [p]\n"
            f"rules:\n  - MATCH,G\n" + extra)


def sec1_passthrough():
    print("=" * 78)
    print("### 2.1 危险键能否穿过 parse_clash_yaml -> normalize -> audit_pool -> 产物")
    print("=" * 78)
    lines = ["proxies:",
             '  - name: "evil"', "    type: vmess", "    server: 1.2.3.4", "    port: 443",
             f"    uuid: {UUID}", "    alterId: 0", "    cipher: auto", "    tls: true"]
    for k, v in DANGEROUS.items():
        if isinstance(v, dict):
            lines.append(f"    {k}:")
            for kk, vv in v.items():
                lines.append(f"      {kk}: {vv}")
        elif isinstance(v, bool):
            lines.append(f"    {k}: {'true' if v else 'false'}")
        else:
            lines.append(f"    {k}: {v}")
    src = "\n".join(lines) + "\n"

    raw = pool.parse_any(src)
    nodes = pool.dedupe(raw)
    kept, rep = sec.audit_pool(nodes)
    print(f"  parse_any={len(raw)} normalize 后={len(nodes)} 审计放行={len(kept)} "
          f"拦截={rep.blocked} 告警={rep.warned}")
    if not kept:
        print("  !! 全部被拦, 透传链中断")
        return
    out = pool.build_clash(kept, "POC")
    print("  产物 proxies[0] 里存活的键:")
    print("   ", sorted(k for k in kept[0] if not k.startswith("_")))
    (ROOT / "audit" / "_poc_keys.yaml").write_text(out, encoding="utf-8")
    rc, msg = run_mihomo_t(out, "keys")
    print(f"  mihomo -t 退出码 {rc}  -> 内核{'接受' if rc == 0 else '拒绝'}")
    for m in msg:
        print("     ", m.strip()[:200])
    print()


def sec2_dialer_proxy():
    print("=" * 78)
    print("### 2.2 dialer-proxy 是否真被内核执行 (真实拨号观察)")
    print("=" * 78)
    seen: list[str] = []
    port = 19555

    def listener():
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(8)
        s.settimeout(25)
        try:
            while True:
                c, addr = s.accept()
                try:
                    d = c.recv(256)
                except Exception:
                    d = b""
                seen.append(d.split(b"\r\n")[0].decode("latin1", "replace"))
                c.close()
        except Exception:
            pass
        s.close()

    threading.Thread(target=listener, daemon=True).start()
    time.sleep(0.6)

    # inner: 服务器地址是个黑洞; 但带 dialer-proxy: outer
    # outer: 指向本机监听 -> 若内核执行 dialer-proxy, 会先连本机并发出 CONNECT inner
    cfg = (f"mixed-port: 17905\nallow-lan: false\nmode: rule\nlog-level: info\n"
           "proxies:\n"
           "  - name: inner\n    type: ss\n    server: 198.51.100.7\n    port: 8080\n"
           "    cipher: aes-128-gcm\n    password: pw\n    dialer-proxy: outer\n"
           f"  - name: outer\n    type: http\n    server: 127.0.0.1\n    port: {port}\n"
           "proxy-groups:\n  - name: G\n    type: select\n    proxies: [inner]\n"
           "rules:\n  - MATCH,G\n")
    p = WORK / "dialer.yaml"
    p.write_text(cfg, encoding="utf-8")
    logf = WORK / "dialer.log"
    with open(logf, "wb") as fh:
        proc = subprocess.Popen([str(ROOT / "bin" / "mihomo.exe"), "-d", str(WORK), "-f", str(p)],
                                stdout=fh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                cwd=str(WORK), creationflags=0x08000000)
        time.sleep(3.5)
        try:
            c = socket.create_connection(("127.0.0.1", 17905), timeout=5)
            c.sendall(b"GET http://example.invalid/ HTTP/1.1\r\nHost: example.invalid\r\n"
                      b"Proxy-Connection: close\r\n\r\n")
            try:
                c.recv(64)
            except Exception:
                pass
            c.close()
        except Exception as e:
            print(f"  (mixed-port 请求异常 {e})")
        time.sleep(3.0)
        proc.kill()
        proc.wait(timeout=10)
    print(f"  本机 {port} 端口收到的代理请求: {seen if seen else '无'}")
    if seen:
        print("  => 内核执行了节点里的 dialer-proxy: 出站先经过攻击者指定的另一个节点")
    log = logf.read_text(encoding="utf-8", errors="replace")
    for ln in log.splitlines():
        if "dial" in ln.lower() or "198.51.100.7" in ln:
            print("     log:", ln.strip()[:220])
    print()


def sec3_skipcert():
    print("=" * 78)
    print("### 2.3 skip-cert-verify 变体: audit 是否漏报 / 内核是否照收")
    print("=" * 78)
    variants = [
        ("布尔 true", "    skip-cert-verify: true\n"),
        ("字符串 'true'", '    skip-cert-verify: "true"\n'),
        ("字符串 '1'", '    skip-cert-verify: "1"\n'),
        ("字符串 'y'", '    skip-cert-verify: "y"\n'),
        ("字符串 'yes'", '    skip-cert-verify: "yes"\n'),
        ("字符串 'on'", '    skip-cert-verify: "on"\n'),
        ("整数 1", "    skip-cert-verify: 1\n"),
        ("裸 yes (YAML1.1 布尔)", "    skip-cert-verify: yes\n"),
        ("裸 on", "    skip-cert-verify: on\n"),
        ("键名 Skip-Cert-Verify", "    Skip-Cert-Verify: true\n"),
        ("键名 SKIP-CERT-VERIFY + 'abc'", '    SKIP-CERT-VERIFY: "abc"\n'),
        ("非法值 'abc' (对照)", '    skip-cert-verify: "abc"\n'),
        ("不设置 (对照)", ""),
    ]
    for label, frag in variants:
        src = ('proxies:\n  - name: "x"\n    type: trojan\n    server: 1.2.3.4\n'
               '    port: 443\n    password: pw\n' + frag)
        raw = pool.parse_any(src)
        nodes = pool.dedupe(raw)
        kept, rep = sec.audit_pool(nodes)
        warns = [f.code for f in sec.audit_node(kept[0])] if kept else ["<被丢弃>"]
        rc, msg = run_mihomo_t(src, "scv")
        print(f"  {label:28} audit告警={str(warns):18} "
              f"mihomo -t={'接受' if rc == 0 else '拒绝'}")
        if rc != 0:
            print(f"      -> {msg[0].strip()[:180]}")
    print()


if __name__ == "__main__":
    sec1_passthrough()
    sec2_dialer_proxy()
    sec3_skipcert()
