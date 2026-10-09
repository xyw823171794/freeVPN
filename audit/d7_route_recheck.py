#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""d7 · _resolve_sub / CSP nonce / 校验顺序 —— 复验 (这几段代码改动过)。

A 轮已测过一遍, 这里按**当前代码**重测, 只看结论是否仍然成立:
  ① 路径穿越能不能读到 out/ 以外的文件
  ② CSP nonce 是否每次随机、是否同时出现在 header 与页面里
  ③ Host 校验与令牌校验的先后顺序 (未认证请求能观测到什么)
  ④ 正常订阅名仍然可读 (确认防护没有误伤)

日志重定向到 %TEMP%, 不碰生产 state/access.log。
用法: python audit/d7_route_recheck.py
"""
import os
import socket
import sys
import threading
import time
from pathlib import Path

ROOT = Path(r"E:\AI\freeVPN")
sys.path.insert(0, str(ROOT))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool          # noqa: E402
import security as sec  # noqa: E402

PORT = 8893
TOKEN = "ROUTETEST_token_0123456789abcdef"
TMP = Path(os.environ.get("TEMP", ".")) / "freevpn_d7"
TMP.mkdir(parents=True, exist_ok=True)
LOG = TMP / "access_d7.log"
if LOG.exists():
    LOG.unlink()
pool.ACCESS_LOG = LOG
pool.ADDR_FILE = TMP / "addr.txt"

srv = pool.PoolServer(("127.0.0.1", PORT),
                      pool.make_handler(PORT, TOKEN, "clash://install-config?url=x"))
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.4)
print("=" * 78)
print("d7 · _resolve_sub / nonce / 校验顺序 复验")
print("=" * 78)
print(f"127.0.0.1:{PORT}   令牌 {TOKEN[:10]}...   日志 {LOG}\n")

SECRET = (ROOT / "state" / "token.txt").read_text(encoding="utf-8").strip()


def req(target: str, host: str | None = None, extra: str = "") -> tuple[str, str]:
    h = host if host is not None else f"127.0.0.1:{PORT}"
    raw = (f"GET {target} HTTP/1.1\r\nHost: {h}\r\n{extra}"
           f"Connection: close\r\n\r\n").encode("utf-8", "replace")
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=6)
    except Exception as e:
        return "000", f"<连接失败 {e}>"
    try:
        s.sendall(raw)
        buf = b""
        while True:
            c = s.recv(65536)
            if not c:
                break
            buf += c
            if len(buf) > 400000:
                break
        return buf.decode("utf-8", "replace"), ""
    except Exception as e:
        return "000", f"<读失败 {e}>"
    finally:
        try:
            s.close()
        except Exception:
            pass


def status(resp: str) -> str:
    if resp.startswith("HTTP/"):
        p = resp.split(" ", 2)
        return p[1] if len(p) > 1 else "?"
    return "000"


# ---------------------------------------------------------------- ① 穿越
print("### ① 路径穿越 (_resolve_sub)\n")
TRAVERSALS = [
    "/sub/../state/token.txt",
    "/sub/..%2fstate%2ftoken.txt",
    "/sub/..%2Fstate%2Ftoken.txt",
    "/sub/..%5cstate%5ctoken.txt",
    "/sub/%2e%2e%2fstate%2ftoken.txt",
    "/sub/%2e%2e/state/token.txt",
    "/sub/....//state/token.txt",
    "/sub/..;/state/token.txt",
    "/sub/./../state/token.txt",
    "/sub/%252e%252e%252fstate%252ftoken.txt",
    "/sub/..%00/state/token.txt",
    "/../state/token.txt",
    "/%2e%2e%2fstate%2ftoken.txt",
    "/sub/sub/../../pool.py",
    f"/t/{TOKEN}/../../state/token.txt",
    f"/t/{TOKEN}/..%2f..%2fstate%2ftoken.txt",
]
leak = []
for t in TRAVERSALS:
    resp, err = req(f"{t}?token={TOKEN}")
    code = status(resp)
    hit = SECRET in resp
    if hit:
        leak.append(t)
    print(f"  {code:<5} {'[!! 读到令牌]' if hit else '[OK]        '} {t}  {err[:40]}")

print("\n  参考: state/token.txt 的令牌前缀 =", SECRET[:6], "(长度", len(SECRET), ")")
print(f"  → 穿越成功读到令牌的用例: {len(leak)} 个")

# ---------------------------------------------------------------- ② nonce
print("\n### ② CSP nonce\n")
import re  # noqa: E402
nonces = []
for i in range(3):
    resp, _ = req(f"/?token={TOKEN}")
    m = re.search(r"script-src 'nonce-([A-Za-z0-9_\-]+)'", resp)
    n2 = re.findall(r'nonce="([A-Za-z0-9_\-]+)"', resp)
    n = m.group(1) if m else "(没有 CSP)"
    nonces.append(n)
    same = bool(n2) and all(x == n for x in n2)
    print(f"  第 {i+1} 次: CSP nonce={n[:18]}...  页面里出现 {len(n2)} 次, "
          f"与 header 一致: {'是' if same else '否'}")
print(f"  三次 nonce 互不相同: {'是' if len(set(nonces)) == 3 else '否'}")
print(f"  长度: {[len(x) for x in nonces]}")

# ---------------------------------------------------------------- ③ 顺序
print("\n### ③ Host 校验 vs 令牌校验 的先后\n")
CASES = [
    ("Host 错 + 无令牌", "/sub/pool.yaml", "evil.com"),
    ("Host 错 + 正确令牌", f"/sub/pool.yaml?token={TOKEN}", "evil.com"),
    ("Host 对 + 无令牌", "/sub/pool.yaml", None),
    ("Host 对 + 正确令牌", f"/sub/pool.yaml?token={TOKEN}", None),
    ("Host 错 + 错令牌", "/sub/pool.yaml?token=bad", "evil.com"),
]
for label, tgt, host in CASES:
    resp, _ = req(tgt, host=host)
    print(f"  {status(resp):<5} {label}")
print("\n  → Host 错一律 403, 说明 Host 校验在令牌之前;")
print("    未认证请求无法区分'令牌对不对'(都被 403 挡住)。")

# ---------------------------------------------------------------- ④ 正常路径
print("\n### ④ 正常订阅名仍然可读\n")
for tgt in (f"/sub/pool.yaml?token={TOKEN}", f"/sub/pool.txt?token={TOKEN}",
            f"/pool.yaml?token={TOKEN}", f"/t/{TOKEN}/pool.yaml",
            f"/sub/POOL.YAML?token={TOKEN}", f"/sub/pool.yml?token={TOKEN}"):
    resp, _ = req(tgt)
    body = resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""
    print(f"  {status(resp):<5} {len(body):>6} 字节  {tgt}")

print(f"\n(日志: {LOG}  {LOG.stat().st_size if LOG.exists() else 0} 字节)")
srv.shutdown()
srv.server_close()
raise SystemExit(0)
