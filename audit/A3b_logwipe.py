#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A3b · 访问日志轮转: 外部噪声能否把日志清空 (痕迹擦除)。

pool.py:2022  if ACCESS_LOG.stat().st_size > 1_000_000: ACCESS_LOG.unlink()
日志路径重定向到 audit/_tmp, 不动生产的 state/access.log。
用法: python audit/A3b_logwipe.py
"""
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(r"E:\AI\freeVPN")
sys.path.insert(0, str(ROOT))
import pool          # noqa: E402
import security as sec  # noqa: E402

PORT = 8794
TMP = ROOT / "audit" / "_tmp"
LOG = TMP / "wipe_test.log"
pool.ACCESS_LOG = LOG
pool.ADDR_FILE = TMP / "addr.txt"
TOKEN = sec.load_or_create_token()
CURL = r"C:\Windows\System32\curl.exe"


def size():
    return LOG.stat().st_size if LOG.exists() else -1


def main():
    print("=" * 74)
    print("① 先把日志撑过 1 MB (用真实请求, 不用手写文件)")
    print("=" * 74)
    srv = pool.serve(PORT, block=False)
    srv.handle_error = lambda *a, **k: None
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.8)

    LOG.write_text("", encoding="utf-8")

    def hit():
        subprocess.run([CURL, "-s", "-o", "NUL", "--max-time", "5",
                        f"http://127.0.0.1:{PORT}/sub/pool.yaml"],
                       capture_output=True)
        return True

    hit()
    line = LOG.stat().st_size
    print(f"  单个请求写入日志 {line} 字节 -> 1 MB 阈值约需 "
          f"{1_000_000 // line} 次请求")
    t0 = time.time()
    sent = 1
    N = 1500
    while sent < N:
        hit()
        sent += 1
    got = size()
    print(f"  实测发出 {sent} 次请求 ({time.time()-t0:.0f}s) -> 日志 {got} 字节 "
          f"({got/1_000_000*100:.1f}% of 1MB)")
    print(f"  >>> 噪声能线性撑大日志, 而轮转阈值只有 1 MB")

    print()
    print("=" * 74)
    print("② 越过阈值后的那一次请求 (触发 unlink)")
    print("=" * 74)
    # 直接把日志摆成"已经被 12000 次请求撑过 1MB"的状态, 再发一次真实请求。
    # _log 只看文件大小, 所以这一步与"真发 12000 次"对内核行为完全等价。
    one = LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-1] + "\n"
    LOG.write_text(one * ((1_200_000 // len(one)) + 1), encoding="utf-8")
    before = size()
    n_lines_before = len(LOG.read_text(encoding="utf-8", errors="replace").splitlines())
    hit()
    after = size()
    n_lines_after = len(LOG.read_text(encoding="utf-8", errors="replace").splitlines())
    print(f"  触发前 {before} 字节 / {n_lines_before} 行")
    print(f"  触发后 {after} 字节 / {n_lines_after} 行")
    print(f"  >>> {'日志被 unlink 后重建 —— 之前所有记录一次性消失' if after < before else '未触发'}")

    print()
    print("=" * 74)
    print("③ 对照: 生产 state/access.log 的现状")
    print("=" * 74)
    prod = ROOT / "state" / "access.log"
    if prod.exists():
        txt = prod.read_text(encoding="utf-8", errors="replace").splitlines()
        hit = sum(1 for l in txt if TOKEN in l)
        print(f"  {prod}: {prod.stat().st_size} 字节 / {len(txt)} 行, "
              f"其中 {hit} 行含完整令牌")
    srv.shutdown()
    print("\n(生产 state/access.log 未被本脚本改动)")


if __name__ == "__main__":
    main()

