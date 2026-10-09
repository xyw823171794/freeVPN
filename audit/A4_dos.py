#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A4 · 服务端 DoS 面: 异常路径写日志 / 慢连接 / 连接上限 / 内存放大。

daemon 模式会把 sys.stdout 与 sys.stderr 一起重定向到 --log 指定的文件
(pool.py:2339-2341), 而 socketserver 的 handle_error 会把每个未处理异常
的完整 traceback 打到 sys.stderr。本脚本忠实模拟这个组合: 把 sys.stderr
接到一个临时文件, 再发触发异常的请求, 量化日志增长。

用法: python audit/A4_dos.py
"""
import ctypes
import socket
import sys
import threading
import time
from pathlib import Path

ROOT = Path(r"E:\AI\freeVPN")
sys.path.insert(0, str(ROOT))
import pool          # noqa: E402
import security as sec  # noqa: E402

PORT = 8792
TOKEN = sec.load_or_create_token()
TMP = ROOT / "audit" / "_tmp"
TMP.mkdir(parents=True, exist_ok=True)
ERRLOG = TMP / "stderr.log"
ACC = TMP / "access_dos.log"
pool.ADDR_FILE = TMP / "addr.txt"
pool.ACCESS_LOG = ACC

# 模拟 daemon --log: stdout/stderr 一起落文件 (pool.py:2339)
_errfh = open(ERRLOG, "a", encoding="utf-8", buffering=1)


def errsize() -> int:
    _errfh.flush()
    return ERRLOG.stat().st_size if ERRLOG.exists() else 0


def mem_mb() -> float:
    """用 tasklist 读本进程工作集 (ctypes 的 psapi 结构体在 3.13 上取不到值)。"""
    import os
    import re
    import subprocess
    r = subprocess.run(["tasklist", "/FI", f"PID eq {os.getpid()}", "/FO", "CSV", "/NH"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    m = re.search(r'"([\d,]+) K"', r.stdout or "")
    return int(m.group(1).replace(",", "")) / 1024 if m else -1.0


def one_shot(payload: bytes, read_all=True, timeout=6):
    s = socket.create_connection(("127.0.0.1", PORT), timeout=timeout)
    s.sendall(payload)
    if read_all:
        try:
            while s.recv(65536):
                pass
        except Exception:
            pass
    s.close()


def main():
    real_stderr, sys.stderr = sys.stderr, _errfh
    print(f"令牌: {TOKEN}")
    print(f"pid={__import__('os').getpid()}  工作集 {mem_mb():.1f} MB")
    srv = pool.serve(PORT, block=False)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.8)
    print(f"服务实例: 127.0.0.1:{PORT}\n")

    def probe_latency(n=5):
        ts = []
        for _ in range(n):
            t0 = time.time()
            try:
                one_shot(f"GET /?token={TOKEN} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n"
                         f"Connection: close\r\n\r\n".encode(), timeout=20)
                ts.append((time.time() - t0) * 1000)
            except Exception as e:
                ts.append(float("nan"))
        return ts

    print("=" * 70)
    print("① 异常路径把 traceback 写进日志 (等价 daemon --log 的效果)")
    print("=" * 70)
    print(f"  基线 stderr 大小: {errsize()} 字节")

    # A. 客户端连上就断开 -> 服务端写响应时撞 RST -> ConnectionResetError
    b0 = errsize()
    for _ in range(50):
        s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
        s.sendall(f"GET /?token={TOKEN} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n\r\n".encode())
        s.close()          # 立刻 RST, 不等响应
    time.sleep(1.5)
    b1 = errsize()
    n_tb_a = (b1 - b0) / 1000
    print(f"  50 次「连上即断」:  stderr 增加 {b1-b0} 字节 (~{n_tb_a:.0f} 条 traceback)")

    # B. 非 ASCII 令牌 -> compare_digest TypeError
    b0 = errsize()
    for i in range(50):
        one_shot(f"GET /?token=%E4%B8%AD%E6%96%87{i} HTTP/1.1\r\n"
                 f"Host: 127.0.0.1:{PORT}\r\nConnection: close\r\n\r\n".encode())
    time.sleep(1.0)
    b1 = errsize()
    print(f"  50 次「非 ASCII 令牌」: stderr 增加 {b1-b0} 字节 (~{(b1-b0)/1000:.0f} 条 traceback)")

    per = max(1, (b1 - b0)) / 50
    print(f"  单次请求平均写入 stderr: {per:.0f} 字节")
    print(f"  >>> 写满 1 GB 需要约 {1024**3/per/1e6:.2f} 百万次请求; "
          f"daemon --log 的文件没有任何大小上限与轮转")

    print()
    print("=" * 70)
    print("② 慢连接 (slowloris): 只发半行请求, 长期占用线程")
    print("=" * 70)
    base_threads = threading.active_count()
    print(f"  基线线程数 {base_threads}, 基线延迟 {['%.0f' % x for x in probe_latency(3)]} ms")
    socks = []
    N = 300
    for _ in range(N):
        try:
            s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
            s.sendall(b"GET /?token=x HTTP/1.1\r\nHost: 127.0.0.1")   # 不发结尾 CRLF
            socks.append(s)
        except Exception as e:
            print(f"  第 {len(socks)+1} 条连接失败: {type(e).__name__}: {e}")
            break
    time.sleep(2.0)
    print(f"  建立 {len(socks)} 条半开连接后: 线程数 {threading.active_count()}, "
          f"工作集 {mem_mb():.1f} MB")
    lat = probe_latency(3)
    print(f"  此时正常请求延迟: {['%.0f' % x for x in lat]} ms")
    print(f"  >>> 半开连接被无限期持有(handler 无 timeout), 线程数与内存随连接数线性增长")
    for s in socks:
        s.close()
    time.sleep(1.0)
    print(f"  关闭后线程数回落: {threading.active_count()}")

    print()
    print("=" * 70)
    print("③ 单请求内存放大 / 超大请求头")
    print("=" * 70)
    m0 = mem_mb()
    for _ in range(200):
        one_shot(f"GET /?token={TOKEN} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n"
                 f"Connection: close\r\n\r\n".encode())
    m1 = mem_mb()
    print(f"  200 次状态页请求: 工作集 {m0:.1f} -> {m1:.1f} MB (差 {m1-m0:+.1f})")
    out_max = max((p.stat().st_size for p in (ROOT / "out").iterdir() if p.is_file()),
                  default=0)
    print(f"  out/ 里最大文件 {out_max} 字节 —— 单响应体上限受产物大小约束, 无放大")
    for label, req in [
        ("超长 Host 头 70000B",
         f"GET /?token={TOKEN} HTTP/1.1\r\nHost: {'a'*70000}\r\nConnection: close\r\n\r\n"),
        ("超长请求行 70000B",
         f"GET /{'a'*70000}?token={TOKEN} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nConnection: close\r\n\r\n"),
    ]:
        try:
            s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
            s.sendall(req.encode())
            resp = s.recv(200).split(b"\r\n")[0].decode("latin-1")
            s.close()
            print(f"  {label:<22} -> {resp}")
        except Exception as e:
            print(f"  {label:<22} -> 异常 {type(e).__name__}")

    srv.shutdown()
    _errfh.flush()
    print(f"\n(本脚本的 stderr 全部写进 {ERRLOG}, 未污染控制台与生产日志)")
    sys.stderr = real_stderr


if __name__ == "__main__":
    main()
