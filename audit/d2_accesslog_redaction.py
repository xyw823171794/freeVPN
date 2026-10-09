#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""d2 · access.log 令牌脱敏矩阵 —— 独立复核 "路径段形式漏脱敏"。

背景: _log() 的脱敏只写了
    safe = re.sub(r"([?&](?:token|t)=)[^&\\s]*", r"\\1***", path)
而 handler 明确支持四种令牌投递方式:
    ?token= / ?t= / Authorization: Bearer / 路径段 /t/<token>/<file>
后两种里, 路径段那种会**原样写进 access.log**。

本脚本把 20 种投递/变形逐一打一遍, 每种都读日志新增行,
逐行判定是否含完整令牌。日志重定向到 %TEMP%, 不碰生产的 state/access.log。

用法: python audit/d2_accesslog_redaction.py
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

PORT = 8899
TOKEN = "TESTTOKEN_d2_0123456789abcdef"          # 32 字符, 自选, 不用生产令牌
TMP = Path(os.environ.get("TEMP", ".")) / "freevpn_d2"
TMP.mkdir(parents=True, exist_ok=True)
LOG = TMP / "access_d2.log"
if LOG.exists():
    LOG.unlink()

pool.ACCESS_LOG = LOG                             # 只重定向日志
pool.ADDR_FILE = TMP / "addr.txt"                 # 别覆盖生产的 订阅地址.txt

# ---------------------------------------------------------------- 起服务
srv = pool.PoolServer(("127.0.0.1", PORT),
                      pool.make_handler(PORT, TOKEN, "clash://install-config?url=x"))
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.4)
print(f"测试服务已起: 127.0.0.1:{PORT}   令牌 {TOKEN[:10]}...  日志 {LOG}")


def raw(req: bytes, timeout: float = 6.0) -> str:
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=timeout)
    except Exception as e:
        return f"<连接失败 {e}>"
    try:
        s.sendall(req)
        buf = b""
        while True:
            c = s.recv(65536)
            if not c:
                break
            buf += c
            if len(buf) > 200000:
                break
        return buf.decode("utf-8", "replace")
    except Exception as e:
        return f"<读失败 {e}>"
    finally:
        try:
            s.close()
        except Exception:
            pass


def status_of(resp: str) -> str:
    if resp.startswith("HTTP/"):
        parts = resp.split(" ", 2)
        return parts[1] if len(parts) > 1 else "?"
    return "000"


def log_tail() -> list[str]:
    try:
        return LOG.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []


# (标签, 请求行, 额外头, 期望)
CASES: list[tuple[str, str, dict, str]] = [
    ("① ?token=",              f"/sub/pool.yaml?token={TOKEN}", {}, "应脱敏"),
    ("② ?t=",                  f"/sub/pool.yaml?t={TOKEN}", {}, "应脱敏"),
    ("③ 路径段 /t/<T>/pool.yaml", f"/t/{TOKEN}/pool.yaml", {}, "应脱敏"),
    ("④ 路径段 /t/<T> (无文件)", f"/t/{TOKEN}", {}, "应脱敏"),
    ("⑤ 路径段 /t/<T>/",       f"/t/{TOKEN}/", {}, "应脱敏"),
    ("⑥ Authorization: Bearer", "/sub/pool.yaml", {"Authorization": f"Bearer {TOKEN}"}, "不落盘"),
    ("⑦ ?TOKEN= (大写)",       f"/sub/pool.yaml?TOKEN={TOKEN}", {}, "应脱敏"),
    ("⑧ ?Token= (混合)",       f"/sub/pool.yaml?Token={TOKEN}", {}, "应脱敏"),
    ("⑨ ;token= (分号分隔)",   f"/sub/pool.yaml;token={TOKEN}", {}, "应脱敏"),
    ("⑩ ?x=1&token=",          f"/sub/pool.yaml?x=1&token={TOKEN}", {}, "应脱敏"),
    ("⑪ ?token=&y=1",          f"/sub/pool.yaml?token={TOKEN}&y=1", {}, "应脱敏"),
    ("⑫ ?token=<T>;x=1",       f"/sub/pool.yaml?token={TOKEN};x=1", {}, "应脱敏"),
    ("⑬ 绝对 URI + ?token=",   f"http://evil.example/sub/pool.yaml?token={TOKEN}", {}, "应脱敏"),
    ("⑭ ?token=<T>#frag",      f"/sub/pool.yaml?token={TOKEN}#frag", {}, "应脱敏"),
    ("⑮ %3Ftoken%3D 编码",     f"/sub/pool.yaml%3Ftoken%3D{TOKEN}", {}, "应脱敏"),
    ("⑯ 路径段 + 错 query",     f"/t/{TOKEN}/pool.yaml?token=bad", {}, "应脱敏"),
    ("⑰ 路径段 + 穿越",        f"/t/{TOKEN}/../../state/token.txt", {}, "应脱敏"),
    ("⑱ 令牌在 Host 头",       "/sub/pool.yaml", {"Host": TOKEN}, "应脱敏"),
    ("⑲ 令牌在 UA",            "/sub/pool.yaml", {"User-Agent": TOKEN}, "应脱敏"),
    ("⑳ 双重路径段",           f"/t/{TOKEN}/t/{TOKEN}/pool.yaml", {}, "应脱敏"),
    ("㉑ /sub/<T> (note 字段)", f"/sub/{TOKEN}", {}, "应脱敏"),
    ("㉒ /sub/<T>.yaml",        f"/sub/{TOKEN}.yaml", {}, "应脱敏"),
]

# ⑱ 需要单独构造: 默认请求行里已经带了正确的 Host, 会被 headers.get('Host')
# 取到第一个而掩盖问题。这里用"不预置 Host"的方式单独发一遍。
HOST_ONLY = f"GET /sub/pool.yaml HTTP/1.1\r\nHost: {TOKEN}\r\nConnection: close\r\n\r\n"

print()
print("=" * 92)
print(f"{'用例':<28}{'HTTP':<6}{'日志新增':<9}{'行内含完整令牌':<14}判定")
print("=" * 92)

leaks: list[tuple[str, str]] = []
for label, target, headers, expect in CASES:
    before = len(log_tail())
    if label.startswith("⑱"):
        # Host 头单独放令牌, 不再预置正确的 Host
        resp = raw(HOST_ONLY.encode("utf-8", "replace"))
    else:
        req = f"GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n"
        for k, v in headers.items():
            req += f"{k}: {v}\r\n"
        req += "Connection: close\r\n\r\n"
        resp = raw(req.encode("utf-8", "replace"))
    code = status_of(resp)
    time.sleep(0.12)
    lines = log_tail()
    new = lines[before:]
    hit = [ln for ln in new if TOKEN in ln]
    verdict = "泄露" if hit else "OK"
    if hit:
        leaks.append((label, hit[0]))
    print(f"{label:<28}{code:<6}{len(new):<9}{len(hit):<14}{verdict}   (期望: {expect})")

print("=" * 92)
print()
if leaks:
    print(f"### 结论: {len(leaks)}/{len(CASES)} 个用例把完整令牌写进了 access.log\n")
    names = ["时间", "方法", "状态", "path", "host", "ua", "note"]
    for label, ln in leaks:
        fields = ln.split("\t")
        where = [names[i] if i < len(names) else f"f{i}"
                 for i, v in enumerate(fields) if TOKEN in v]
        print(f"  [{label}]  泄露字段: {','.join(where)}")
        print(f"      原始日志行: {ln[:150]}")
else:
    print("### 结论: 所有用例都没有把完整令牌写进日志")

print()
print("### 落盘日志文件本身")
print(f"  {LOG}")
print(f"  大小 {LOG.stat().st_size if LOG.exists() else 0} 字节, "
      f"共 {len(log_tail())} 行")

srv.shutdown()
srv.server_close()
print("\n(测试服务已停)")
raise SystemExit(1 if leaks else 0)
