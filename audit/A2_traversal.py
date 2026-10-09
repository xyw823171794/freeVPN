#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A2 · 路径穿越矩阵 + 原始报文级绕过(多重 Host 头 / 请求行注入)。

HTTP 层探测走 curl.exe (--path-as-is, 否则 curl 会自己把 .. 规范化掉);
curl 做不到的(多重 Host 头)用裸 socket 直接发请求行。

用法: python audit/A2_traversal.py
"""
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(r"E:\AI\freeVPN")
sys.path.insert(0, str(ROOT))
import pool          # noqa: E402
import security as sec  # noqa: E402

PORT = 8790
BASE = f"http://127.0.0.1:{PORT}"
TOKEN = sec.load_or_create_token()
CURL = r"C:\Windows\System32\curl.exe"
TMP = ROOT / "audit" / "_tmp"
TMP.mkdir(parents=True, exist_ok=True)
pool.ADDR_FILE = TMP / "addr.txt"
OUTFILE = TMP / "body.bin"

# 必须读到的敏感文件 —— 任何一个内容出现在响应里就是越界
SENSITIVE = {
    "state/token.txt": TOKEN,
    "pool.py": "def make_handler",
    "security.py": "_SENSITIVE_ENV_RE",
    "sources.txt": None,
}


def curl(args, timeout=8):
    if OUTFILE.exists():
        OUTFILE.unlink()
    cmd = [CURL, "-s", "-o", str(OUTFILE), "-w", "%{http_code}",
           "--max-time", str(timeout), "--path-as-is"] + args
    r = subprocess.run(cmd, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    body = OUTFILE.read_bytes() if OUTFILE.exists() else b""
    return (r.stdout or "").strip(), body, (r.stderr or "").strip()


def raw(req: bytes, timeout=6) -> bytes:
    s = socket.create_connection(("127.0.0.1", PORT), timeout=timeout)
    s.sendall(req)
    buf = b""
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            buf += c
            if len(buf) > 400000:
                break
    except Exception:
        pass
    s.close()
    return buf


PAYLOADS = [
    "/sub/../state/token.txt",
    "/sub/..%2fstate%2ftoken.txt",
    "/sub/..%2Fstate%2Ftoken.txt",
    "/sub/..%5cstate%5ctoken.txt",
    "/sub/%2e%2e%2fstate%2ftoken.txt",
    "/sub/%2e%2e/state/token.txt",
    "/sub/%252e%252e%252fstate%252ftoken.txt",
    "/sub/%252e%252e%252fstate%252ftoken.txt",
    "/sub/....//state/token.txt",
    "/sub/..;/state/token.txt",
    "/sub/..%00/state/token.txt",
    "/sub/./../state/token.txt",
    "/sub/../pool.py",
    "/sub/..%2f..%2fpool.py",
    "/sub/../../pool.py",
    "/sub/..%5c..%5cpool.py",
    "/sub/%2e%2e%5csecurity.py",
    "/../state/token.txt",
    "/%2e%2e%2fstate%2ftoken.txt",
    "/..%2fstate%2ftoken.txt",
    "/%2e%2e/state/token.txt",
    "/..%252fstate%252ftoken.txt",
    "/sub/C:pool.yaml",
    "/sub/C:%5cWindows%5cwin.ini",
    "/sub/%5c%5c127.0.0.1%5cc$%5cWindows%5cwin.ini",
    "/sub/\\\\127.0.0.1\\c$\\Windows\\win.ini",
    "/sub/pool.yaml::$DATA",
    "/sub/pool.yaml:secret",
    "/sub/pool.yaml::$INDEX_ALLOCATION",
    "/sub/pool.yaml.",
    "/sub/pool.yaml%20",
    "/sub/pool.yaml...",
    "/sub/POOL~1.YAM",
    "/sub/POOL~1",
    "/sub/CON",
    "/sub/NUL",
    "/sub/PRN",
    "/sub/AUX",
    "/sub/COM1",
    "/sub/LPT1",
    "/sub/NUL.yaml",
    "/sub/token.txt",
    "/sub/../state/access.log",
    "/sub/..%2fstate%2faccess.log",
    "/sub/%2e%2e%2fstate%2faccess.log",
    "/sub/../security.py",
    "/sub/../pool.py%00.yaml",
    "/sub/pool.yaml%00",
    "/sub/%00pool.yaml",
    "/sub/.hidden",
    "/sub/.%2e/pool.yaml",
    "/sub/..%09/pool.yaml",
]


def judge(body: bytes):
    """返回命中的敏感标记列表。"""
    hits = []
    txt = body.decode("utf-8", "replace")
    for path, marker in SENSITIVE.items():
        if marker and marker in txt:
            hits.append(path)
    if "def make_handler" in txt or "class PoolServer" in txt:
        hits.append("pool.py")
    if "compare_digest" in txt or "_SENSITIVE_ENV_RE" in txt:
        hits.append("security.py")
    return hits


def main():
    print(f"令牌: {TOKEN}")
    srv = pool.serve(PORT, block=False)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.8)
    print(f"服务实例: http://127.0.0.1:{PORT}\n")

    print("--- ① curl.exe 穿越矩阵 (--path-as-is) ---")
    leak = []
    for p in PAYLOADS:
        code, body, err = curl([f"{BASE}{p}?token={TOKEN}"])
        if not code:
            code = "000(断连)"
        hits = judge(body)
        tag = "LEAK" if hits else "  - "
        if hits:
            leak.append((p, hits))
        print(f"  [{tag}] {p:<48} -> {code:<10} {len(body)}B {err[:60]}")
    print(f"\n  curl 侧越界命中: {len(leak)}")

    print("\n--- ② 裸 socket: 多重 Host 头 ---")
    probes = [
        ("Host: evil.com 在前, 127.0.0.1 在后",
         f"GET /sub/pool.yaml?token={TOKEN} HTTP/1.1\r\nHost: evil.com\r\nHost: 127.0.0.1:{PORT}\r\nConnection: close\r\n\r\n"),
        ("Host: 127.0.0.1 在前, evil.com 在后",
         f"GET /sub/pool.yaml?token={TOKEN} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nHost: evil.com\r\nConnection: close\r\n\r\n"),
        ("Host 尾随逗号 + 合法值",
         f"GET /sub/pool.yaml?token={TOKEN} HTTP/1.1\r\nHost: 127.0.0.1:{PORT},evil.com\r\nConnection: close\r\n\r\n"),
        ("无 Host 头 (HTTP/1.0)",
         f"GET /sub/pool.yaml?token={TOKEN} HTTP/1.0\r\n\r\n"),
        ("绝对 URI 请求行 + 合法 Host",
         f"GET http://evil.com/sub/pool.yaml?token={TOKEN} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nConnection: close\r\n\r\n"),
        ("绝对 URI 请求行 + 无 Host",
         f"GET http://127.0.0.1:{PORT}/sub/pool.yaml?token={TOKEN} HTTP/1.1\r\nConnection: close\r\n\r\n"),
        ("请求行带 CR 折叠",
         f"GET /sub/pool.yaml?token={TOKEN} HTTP/1.1\r\nHost: evil.com\r\n Host: 127.0.0.1:{PORT}\r\nConnection: close\r\n\r\n"),
        ("超长 Host 头 (70000 字节)",
         f"GET /sub/pool.yaml?token={TOKEN} HTTP/1.1\r\nHost: {'a' * 70000}\r\nConnection: close\r\n\r\n"),
        ("请求行超长 (70000 字节 URL)",
         f"GET /{'a' * 70000}?token={TOKEN} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nConnection: close\r\n\r\n"),
        ("重复 Content-Length (走私)",
         f"POST /sub/pool.yaml?token={TOKEN} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nContent-Length: 0\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"),
        ("Transfer-Encoding: chunked 走私",
         f"POST / HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\nConnection: close\r\n\r\n0\r\n\r\nGET /sub/pool.yaml?token={TOKEN} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n\r\n"),
    ]
    for label, req in probes:
        t0 = time.time()
        resp = raw(req.encode("utf-8", "replace"))
        dt = time.time() - t0
        first = resp.split(b"\r\n", 1)[0].decode("latin-1") if resp else "(无响应)"
        hits = judge(resp)
        n_resp = resp.count(b"HTTP/1.")
        print(f"  {label:<38} -> {first[:34]:<34} {len(resp):>7}B "
              f"HTTP段={n_resp} {dt:.2f}s {'LEAK:' + str(hits) if hits else ''}")

    print(f"\n=== 越界命中合计 {len(leak)} 条 ===")
    for p, h in leak:
        print(f"    {p} -> {h}")
    srv.shutdown()


if __name__ == "__main__":
    main()
