# -*- coding: utf-8 -*-
"""
问题 1 续: 通过审计的"主机名"形式内网地址, 内核到底会不会当成 IP 解析?
做法: 本机起监听 -> mihomo 配置一个 server=127.1 / 2130706433 / 0x7f000001 的 http 代理
      -> 通过 mihomo 的 mixed-port 发一次请求 -> 看本机监听是否收到连接。
收到连接 = 内核把这些写法解析成了回环地址 = bad_server 被绕过且真实可用。
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
WORK = ROOT / "audit" / "_miwork2"
WORK.mkdir(parents=True, exist_ok=True)
MIXED = 17901
TARGET_PORT = 19443
hits: list[str] = []


def listener():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", TARGET_PORT))
    s.listen(8)
    s.settimeout(30)
    try:
        while True:
            c, addr = s.accept()
            try:
                data = c.recv(256)
            except Exception:
                data = b""
            hits.append(f"{addr[0]} -> {data[:80]!r}")
            c.close()
    except Exception:
        pass
    finally:
        s.close()


def try_server(server: str):
    """返回 (audit 裁决, 内核是否把流量送到本机监听, hits, dial 日志)。"""
    node = {"name": "t", "type": "ss", "server": server, "port": TARGET_PORT,
            "cipher": "aes-128-gcm", "password": "pw"}
    n = pool.normalize(dict(node))
    audit = "DROPPED-normalize" if n is None else (
        "BLOCKED" if any(f.level == "block" for f in sec.audit_node(n)) else "PASS")
    if n is None:
        return audit, "未进产物, 无法测", [], []

    cfg = WORK / "c.yaml"
    cfg.write_text(pool._dump_yaml({
        "mixed-port": MIXED, "allow-lan": False, "mode": "rule", "log-level": "info",
        "proxies": [{"name": "p", "type": "ss", "server": server, "port": TARGET_PORT,
                     "cipher": "aes-128-gcm", "password": "pw"}],
        "proxy-groups": [{"name": "G", "type": "select", "proxies": ["p"]}],
        "rules": ["MATCH,G"],
    }), encoding="utf-8")

    hits.clear()
    logf = WORK / "run.log"
    with open(logf, "wb") as fh:
        proc = subprocess.Popen([str(ROOT / "bin" / "mihomo.exe"), "-d", str(WORK),
                                 "-f", str(cfg)],
                                stdout=fh, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, cwd=str(WORK),
                                creationflags=0x08000000)
        time.sleep(3.5)
        try:
            c = socket.create_connection(("127.0.0.1", MIXED), timeout=4)
            c.sendall(b"GET http://example.invalid/ HTTP/1.1\r\nHost: example.invalid\r\n"
                      b"Proxy-Connection: close\r\n\r\n")
            c.settimeout(4)
            try:
                c.recv(128)
            except Exception:
                pass
            c.close()
        except Exception as e:
            hits.append(f"<mixed-port 连接失败 {e}>")
        time.sleep(2.0)
        proc.kill()
        proc.wait(timeout=10)
    log = logf.read_text(encoding="utf-8", errors="replace")
    dial = [ln.strip() for ln in log.splitlines()
            if any(w in ln.lower() for w in ("dial ", "lookup", "no such host",
                                             "refused", "resolv", "dns"))]
    real_hits = [h for h in hits if not h.startswith("<")]
    return audit, ("命中本机监听" if real_hits else "未命中"), hits, dial[:3]


if __name__ == "__main__":
    t = threading.Thread(target=listener, daemon=True)
    t.start()
    time.sleep(0.6)
    print(f"本机监听 127.0.0.1:{TARGET_PORT}, mihomo mixed-port {MIXED}")
    print()
    for srv in ("127.1", "127.0.1", "2130706433", "0x7f000001", "017700000001",
                "10.1", "167772161", "router", "127.0.0.1.nip.io",
                "127.0.0.1", "1.2.3.4"):
        try:
            audit, res, h, dial = try_server(srv)
        except Exception as e:
            print(f"  {srv:20} EXCEPTION {type(e).__name__}: {e}")
            continue
        print(f"  {srv:20} audit={audit:18} 内核行为={res}")
        for x in h:
            print(f"      hit: {x}")
        for x in dial:
            print(f"      log: {x}")
