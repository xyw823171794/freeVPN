#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A1 · 访问控制矩阵 —— token / Host / 请求形式绕过。

方法: 自起一个实例(端口 8789, 不动 8787 的生产实例), 所有 HTTP 请求一律走
curl.exe。PowerShell 的 Invoke-WebRequest 连接池默认只有 2, 会给出假超时。

用法: python audit/A1_gate.py
"""
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(r"E:\AI\freeVPN")
sys.path.insert(0, str(ROOT))
import pool          # noqa: E402
import security as sec  # noqa: E402

PORT = 8789
BASE = f"http://127.0.0.1:{PORT}"
TOKEN = sec.load_or_create_token()
CURL = r"C:\Windows\System32\curl.exe"
TMP = ROOT / "audit" / "_tmp"
TMP.mkdir(parents=True, exist_ok=True)

# 只把"纯地址提示文件"重定向到临时目录, 免得覆盖生产的 订阅地址.txt。
# ACCESS_LOG 保持真实路径 —— 顺带验证 token 是否被明文写进日志。
pool.ADDR_FILE = TMP / "addr.txt"

OUTFILE = TMP / "body.bin"


def curl(args, timeout=8):
    """返回 (http_code, body_bytes, stderr)。"""
    if OUTFILE.exists():
        OUTFILE.unlink()
    cmd = [CURL, "-s", "-o", str(OUTFILE), "-w", "%{http_code}",
           "--max-time", str(timeout), "--path-as-is"] + args
    r = subprocess.run(cmd, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    body = OUTFILE.read_bytes() if OUTFILE.exists() else b""
    return (r.stdout or "").strip(), body, (r.stderr or "").strip()


CASES = []


def case(label, args, expect=None, show_body=0):
    CASES.append((label, args, expect, show_body))


T = TOKEN

# ---------- ① Host 头 ----------
H = lambda h: ["-H", f"Host: {h}"]  # noqa: E731
case("Host: evil.com (DNS rebinding)", H("evil.com") + [f"{BASE}/sub/pool.yaml?token={T}"], 403)
case("Host: 127.0.0.1:8789", H(f"127.0.0.1:{PORT}") + [f"{BASE}/sub/pool.yaml?token={T}"], 200)
case("Host: 127.0.0.1 (无端口)", H("127.0.0.1") + [f"{BASE}/sub/pool.yaml?token={T}"], 200)
case("Host: 127.0.0.1:9999 (错端口)", H("127.0.0.1:9999") + [f"{BASE}/sub/pool.yaml?token={T}"], None)
case("Host: localhost:8789", H(f"localhost:{PORT}") + [f"{BASE}/sub/pool.yaml?token={T}"], 200)
case("Host: LOCALHOST:8789 (大写)", H(f"LOCALHOST:{PORT}") + [f"{BASE}/sub/pool.yaml?token={T}"], 200)
case("Host: [::1]:8789", H(f"[::1]:{PORT}") + [f"{BASE}/sub/pool.yaml?token={T}"], 200)
case("Host: [::1] (无端口)", H("[::1]") + [f"{BASE}/sub/pool.yaml?token={T}"], 200)
case("Host: [::1]:9999 (错端口)", H("[::1]:9999") + [f"{BASE}/sub/pool.yaml?token={T}"], 403)
case("Host: [::ffff:127.0.0.1]:8789", H(f"[::ffff:127.0.0.1]:{PORT}") + [f"{BASE}/sub/pool.yaml?token={T}"], 403)
case("Host: 127.0.0.1.evil.com", H(f"127.0.0.1.evil.com:{PORT}") + [f"{BASE}/sub/pool.yaml?token={T}"], 403)
case("Host: evil.com@127.0.0.1", H(f"evil.com@127.0.0.1:{PORT}") + [f"{BASE}/sub/pool.yaml?token={T}"], 403)
case("Host: 127.0.0.1:8789:evil.com", H(f"127.0.0.1:{PORT}:evil.com") + [f"{BASE}/sub/pool.yaml?token={T}"], 403)
case("Host: 127.0.0.1:8789%20(尾空格)", H(f"127.0.0.1:{PORT} ") + [f"{BASE}/sub/pool.yaml?token={T}"], None)
case("Host: (空值)", ["-H", "Host:"] + [f"{BASE}/sub/pool.yaml?token={T}"], 403)
case("Host: evil.com + X-Forwarded-Host:127.0.0.1",
     H("evil.com") + ["-H", "X-Forwarded-Host: 127.0.0.1"] + [f"{BASE}/sub/pool.yaml?token={T}"], 403)
case("Host: evil.com + X-Real-Host:127.0.0.1",
     H("evil.com") + ["-H", "X-Real-Host: 127.0.0.1"] + [f"{BASE}/sub/pool.yaml?token={T}"], 403)

# ---------- ② 令牌 ----------
case("无 token", [f"{BASE}/sub/pool.yaml"], 401)
case("错 token", [f"{BASE}/sub/pool.yaml?token=deadbeef"], 401)
case("空 token ?token=", [f"{BASE}/sub/pool.yaml?token="], 401)
case("正确 token", [f"{BASE}/sub/pool.yaml?token={T}"], 200)
case("?t= 短参形式", [f"{BASE}/sub/pool.yaml?t={T}"], 200)
case("Bearer 头", ["-H", f"Authorization: Bearer {T}", f"{BASE}/sub/pool.yaml"], 200)
case("bearer 小写", ["-H", f"Authorization: bearer {T}", f"{BASE}/sub/pool.yaml"], 200)
case("Bearer 双空格", ["-H", f"Authorization: Bearer  {T}", f"{BASE}/sub/pool.yaml"], 200)
case("路径段 /t/<token>/<file>", [f"{BASE}/t/{T}/pool.yaml"], 200)
case("路径段 /t/<token> (无文件)", [f"{BASE}/t/{T}"], None)
case("路径段 /t/<token>/", [f"{BASE}/t/{T}/"], None)
case("token 大小写翻转", [f"{BASE}/sub/pool.yaml?token={T.upper()}"], 401)
case("token 尾随空格", [f"{BASE}/sub/pool.yaml?token={T}%20"], 401)
case("token 截断", [f"{BASE}/sub/pool.yaml?token={T[:-1]}"], 401)
case("token 前导空格", [f"{BASE}/sub/pool.yaml?token=%20{T}"], 401)
case("状态页 无 token", [f"{BASE}/"], 401)
case("report.json 无 token", [f"{BASE}/report.json"], 401)
case("状态页 正确 token", [f"{BASE}/?token={T}"], 200)
case("非 ASCII token (?token=中文)", [f"{BASE}/?token=%E4%B8%AD%E6%96%87"], None, 300)
case("非 ASCII Bearer 头", ["-H", "Authorization: Bearer \u4e2d\u6587", f"{BASE}/"], None, 300)
case("非 ASCII token 走 /t/ 路径段", [f"{BASE}/t/%E4%B8%AD%E6%96%87/pool.yaml"], None, 300)

# ---------- ③ 请求形式 ----------
case("绝对 URI 形式 GET http://evil/x", ["--request-target", "http://evil.com/x",
     f"{BASE}/"], None)
case("绝对 URI 形式 + 合法 token", ["--request-target", f"http://evil.com/sub/pool.yaml?token={T}",
     f"{BASE}/"], None)
case("URL 里重复 token 参数(先错后对)", [f"{BASE}/sub/pool.yaml?token=bad&token={T}"], None)
case("URL 里重复 token 参数(先对后错)", [f"{BASE}/sub/pool.yaml?token={T}&token=bad"], None)
case("token 在 query 与路径段冲突", [f"{BASE}/t/badtoken/pool.yaml?token={T}"], None)
case("大小写路径 /SUB/pool.yaml", [f"{BASE}/SUB/pool.yaml?token={T}"], None)
case("路径 /sub/POOL.YAML (大小写文件名)", [f"{BASE}/sub/POOL.YAML?token={T}"], None)
case("路径 /sub/pool.yml (扩展名变体)", [f"{BASE}/sub/pool.yml?token={T}"], None)
case("路径 /sub/pool (无扩展名)", [f"{BASE}/sub/pool?token={T}"], None)
case("路径 /pool.yaml (无 /sub/ 前缀)", [f"{BASE}/pool.yaml?token={T}"], None)
case("路径 //sub/pool.yaml", [f"{BASE}//sub/pool.yaml?token={T}"], None)
case("路径 /sub//pool.yaml", [f"{BASE}/sub//pool.yaml?token={T}"], None)
case("HEAD /sub/pool.yaml", ["-I", f"{BASE}/sub/pool.yaml?token={T}"], None)
case("OPTIONS /sub/pool.yaml", ["-X", "OPTIONS", f"{BASE}/sub/pool.yaml?token={T}"], None)
case("POST /sub/pool.yaml", ["-X", "POST", "-d", "x", f"{BASE}/sub/pool.yaml?token={T}"], None)
case("TRACE /sub/pool.yaml", ["-X", "TRACE", f"{BASE}/sub/pool.yaml?token={T}"], None)
case("畸形请求行 (裸 LF)", ["--request-target", "/sub/pool.yaml%0aX", f"{BASE}/"], None)


def main():
    print(f"令牌: {TOKEN}   (来自 state/token.txt)")
    srv = pool.serve(PORT, block=False)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.8)
    print(f"服务实例: http://127.0.0.1:{PORT}   (生产 8787 未受影响)\n")

    fails = []
    for label, args, expect, show in CASES:
        code, body, err = curl(args)
        if code == "" or code == "000":
            code = "000(无响应/断连)"
            note = err.replace("\n", " ")[:90]
        else:
            note = f"{len(body)}B"
            if show and body:
                note += "  body=" + repr(body[:show])[:show + 40]
        mark = "OK "
        if expect is not None:
            mark = "OK " if code == str(expect) else "!! "
            if code != str(expect):
                fails.append((label, code, expect))
        print(f"  [{mark}] {label:<44} -> {code:<16} {note}")

    print(f"\n=== 与预期不符 {len(fails)} 条 ===")
    for label, got, exp in fails:
        print(f"    {label}: 得到 {got}, 期望 {exp}")
    srv.shutdown()


if __name__ == "__main__":
    main()
