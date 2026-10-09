#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A3 · 令牌属性 / 文件权限 / 访问日志。

覆盖:
  ① 令牌熵与生成方式
  ② token_ok 是否恒定时间比较 (含非 ASCII 输入的实际后果)
  ③ 非 ASCII 令牌请求是否会落日志 (异常在 _log 之前抛出 -> 探测不留痕)
  ④ 访问日志是否明文记录令牌
  ⑤ 日志轮转策略是否可被外部噪声触发 (日志擦除)
  ⑥ Host 头 obs-fold 换行注入日志

日志测试一律把 pool.ACCESS_LOG 重定向到临时文件, 不动生产的 state/access.log。
用法: python audit/A3_token_log.py
"""
import secrets
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

PORT = 8791
BASE = f"http://127.0.0.1:{PORT}"
TOKEN = sec.load_or_create_token()
CURL = r"C:\Windows\System32\curl.exe"
TMP = ROOT / "audit" / "_tmp"
TMP.mkdir(parents=True, exist_ok=True)
LOG = TMP / "access_test.log"
pool.ADDR_FILE = TMP / "addr.txt"
pool.ACCESS_LOG = LOG          # 只重定向日志, 不碰生产
OUTFILE = TMP / "body.bin"


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
    except Exception:
        pass
    s.close()
    return buf


def loglines():
    if not LOG.exists():
        return []
    return LOG.read_text(encoding="utf-8", errors="replace").splitlines()


def main():
    print(f"令牌: {TOKEN}")
    srv = pool.serve(PORT, block=False)
    # 客户端提前断开会让 socketserver 打一整条 traceback 到 stderr。
    # 本脚本关注的是令牌与日志逻辑, 这里静默掉噪声(该现象在 A4 里单独量化)。
    srv.handle_error = lambda *a, **k: None
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.8)

    print("\n" + "=" * 70)
    print("① 令牌熵与生成方式")
    print("=" * 70)
    print(f"  实际令牌长度: {len(TOKEN)} 字符, 字符集: "
          f"{''.join(sorted(set(TOKEN)))[:40]}")
    print(f"  生成代码: secrets.token_urlsafe(24) -> 24 字节随机 = 192 bit")
    print(f"  读取门槛: security.py:297  len(t) >= 16 才接受已有文件内容")
    # 长度 < 16 的已有令牌会被静默替换
    print("  注: state/token.txt 若被截断到 <16 字符, 下次启动会静默重新生成")

    print("\n" + "=" * 70)
    print("② token_ok 比较方式")
    print("=" * 70)
    import inspect
    src = inspect.getsource(sec.token_ok)
    print("  security.py:309-312 源码:")
    for line in src.strip().splitlines():
        print("    " + line)
    # 实测: 逐字节前缀匹配的耗时是否恒定
    def bench(guess, n=20000):
        t0 = time.perf_counter()
        for _ in range(n):
            sec.token_ok(guess, TOKEN)
        return (time.perf_counter() - t0) / n * 1e6
    cases = [
        ("完全错误(首字节即错)", "X" * len(TOKEN)),
        ("前缀正确 1 字节", TOKEN[0] + "X" * (len(TOKEN) - 1)),
        ("前缀正确 16 字节", TOKEN[:16] + "X" * (len(TOKEN) - 16)),
        ("前缀正确 31 字节", TOKEN[:-1] + "X"),
        ("完全正确", TOKEN),
    ]
    print("  (逐字节比较的实现在这里会随匹配前缀长度线性变慢)")
    for label, g in cases:
        print(f"    {label:<24} {bench(g):8.3f} us/次")

    print("\n" + "=" * 70)
    print("③ 非 ASCII 令牌 -> 服务端异常, 且不留日志")
    print("=" * 70)
    before = len(loglines())
    print(f"  测试前日志行数: {before}")
    for i in range(5):
        code, body, err = curl([f"{BASE}/?token=%E4%B8%AD%E6%96%87{i}"])
        print(f"  第 {i+1} 次 /?token=中文{i}  -> {code or '000(连接被断开)'}  "
              f"body={len(body)}B  curl: {err[:60]}")
    after = len(loglines())
    print(f"  测试后日志行数: {after}   (增加 {after - before} 行)")
    print(f"  >>> 结论: 客户端拿到的是断连而不是 401, 且这 5 次请求"
          f"{'没有' if after == before else '有'}留下任何日志")

    print("\n" + "=" * 70)
    print("④ 访问日志是否明文记录令牌")
    print("=" * 70)
    code, _, _ = curl([f"{BASE}/sub/pool.yaml?token={TOKEN}"])
    lines = loglines()
    hit = [l for l in lines if TOKEN in l]
    print(f"  发一次正常请求后, 日志中含完整令牌的行数: {len(hit)}")
    for l in hit[-2:]:
        print("    " + l)
    prod = ROOT / "state" / "access.log"
    if prod.exists():
        ptxt = prod.read_text(encoding="utf-8", errors="replace").splitlines()
        n = sum(1 for l in ptxt if TOKEN in l)
        print(f"  生产 state/access.log: 共 {len(ptxt)} 行, 其中 {n} 行含完整令牌")

    print("\n" + "=" * 70)
    print("⑤ 日志轮转: 外部噪声能否触发日志被删")
    print("=" * 70)
    print(f"  轮转代码 pool.py:2022  if size > 1_000_000: ACCESS_LOG.unlink()")
    LOG.write_text("", encoding="utf-8")
    line_bytes = len(f"2026-09-30 00:00:00\tGET\t401\t/sub/pool.yaml?token={TOKEN}"
                     f"\thost=127.0.0.1:{PORT}\tua=curl/8.13.0\ttoken required\n")
    need = 1_000_000 // line_bytes + 20
    print(f"  单行约 {line_bytes} 字节, 需要约 {need} 个请求即可越过 1MB")
    N = need + 50
    sent = [0]
    lock = threading.Lock()

    def flood(k):
        for _ in range(k):
            try:
                s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
                s.sendall(f"GET /sub/pool.yaml HTTP/1.1\r\n"
                          f"Host: 127.0.0.1:{PORT}\r\nConnection: close\r\n\r\n"
                          .encode())
                while s.recv(4096):   # 读到 EOF 再关, 避免服务端写响应时撞上 RST
                    pass
                s.close()
                with lock:
                    sent[0] += 1
            except Exception:
                pass

    t0 = time.time()
    ths = [threading.Thread(target=flood, args=(N // 32 + 1,)) for _ in range(32)]
    [t.start() for t in ths]
    [t.join() for t in ths]
    size = LOG.stat().st_size if LOG.exists() else -1
    print(f"  发出 {sent[0]} 个无令牌请求, 耗时 {time.time()-t0:.1f}s")
    print(f"  测试后日志大小: {size} 字节, 行数: {len(loglines())}")
    print(f"  >>> {'日志已被 unlink 清空 —— 噪声请求可擦掉痕迹' if size < 1000 else '未触发轮转'}")

    print("\n" + "=" * 70)
    print("⑥ Host 头 obs-fold 换行注入日志")
    print("=" * 70)
    LOG.write_text("", encoding="utf-8")
    req = (f"GET /sub/pool.yaml?token={TOKEN} HTTP/1.1\r\n"
           f"Host: 127.0.0.1:{PORT}\r\n"
           f"\tFORGED-BY-ATTACKER 2026-09-30 00:00:00\tGET\t200\t/\tattack\r\n"
           f"Connection: close\r\n\r\n")
    resp = raw(req.encode())
    print(f"  响应: {resp.split(b'\\r\\n')[0].decode('latin-1') if resp else '(无)'}")
    print(f"  日志文件实际内容:")
    for l in loglines():
        print("    |" + l)
    print(f"  >>> {'日志里出现了伪造的独立行' if any('FORGED-BY-ATTACKER' in l and not l.startswith('2026') for l in loglines()) else '未注入'}")

    srv.shutdown()
    print("\n(生产 state/access.log 未被本脚本改动)")


if __name__ == "__main__":
    main()
