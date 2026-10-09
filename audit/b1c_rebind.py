# -*- coding: utf-8 -*-
"""
问题 1 续 2: DNS 重绑定型内网地址的完整链路证明。
audit_node / bad_server 只按"字符串是不是 IP 字面量"判定;
凡是域名一律放行 —— 包括 127.0.0.1.nip.io 这种公开通配 DNS。
本脚本证明: 该节点通过审计 + 进入产物 + 内核真的连到本机回环端口。
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
WORK = ROOT / "audit" / "_miwork3"
WORK.mkdir(parents=True, exist_ok=True)
MIXED = 17903
TARGET_PORT = 19445
stop = threading.Event()
hits: list[str] = []


def listener():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", TARGET_PORT))
    s.listen(16)
    s.settimeout(1.0)
    while not stop.is_set():
        try:
            c, addr = s.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            data = c.recv(128)
        except Exception:
            data = b""
        hits.append(f"来自 {addr[0]}:{addr[1]} 的入站连接, 前 32 字节 = {data[:32]!r}")
        c.close()
    s.close()


def run(server: str):
    node = {"name": "t", "type": "ss", "server": server, "port": TARGET_PORT,
            "cipher": "aes-128-gcm", "password": "pw"}
    n = pool.normalize(dict(node))
    if n is None:
        print(f"  {server:22} normalize 丢弃 —— 无法利用")
        return
    fs = sec.audit_node(n)
    blocked = [f for f in fs if f.level == "block"]
    print(f"  {server:22} audit: block={[f.code for f in blocked]} "
          f"warn={[f.code for f in fs if f.level != 'block']}")

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
                                 "-f", str(cfg)], stdout=fh, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, cwd=str(WORK),
                                creationflags=0x08000000)
        time.sleep(3.5)
        try:
            c = socket.create_connection(("127.0.0.1", MIXED), timeout=5)
            c.sendall(b"GET http://example.invalid/ HTTP/1.1\r\nHost: example.invalid\r\n"
                      b"Proxy-Connection: close\r\n\r\n")
            try:
                c.recv(64)
            except Exception:
                pass
            c.close()
        except Exception as e:
            print(f"      (mixed-port 请求异常 {e})")
        time.sleep(3.0)
        proc.kill()
        proc.wait(timeout=10)
    print(f"      -> 本机 {TARGET_PORT} 端口收到入站连接: {len(hits)} 次")
    for h in hits:
        print(f"         {h}")
    log = logf.read_text(encoding="utf-8", errors="replace")
    for ln in log.splitlines():
        if "dial tcp" in ln or "resolve failed" in ln:
            print(f"         log: {ln.strip()[:230]}")
            break
    print()


if __name__ == "__main__":
    threading.Thread(target=listener, daemon=True).start()
    time.sleep(0.8)
    print(f"本机监听 127.0.0.1:{TARGET_PORT}; mihomo mixed-port {MIXED}")
    print()
    for srv in ("127.0.0.1.nip.io", "127-0-0-1.sslip.io", "localtest.me"):
        run(srv)
    stop.set()
