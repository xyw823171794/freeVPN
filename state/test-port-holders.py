#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""端口占用者查询回归。

起因: 用户同时看到两种提示 ——「端口 8787 被这些进程占着（查不到，可能刚好
释放了）」和「端口 8787 没有被占用」。两句自相矛盾。

根因有两层:
  ① `port_holders()` 只有 netstat 一条路, 而且整个函数被 `except Exception:
     pass` 包着 —— netstat 被拦/输出异常时**静默**返回空, 界面只能写"查不到"。
  ② `do_free_port()` 把"查不到占用者"直接当成"端口空闲"。

修法: 查询加 Get-NetTCPConnection 回退; 判断"是否空闲"改用 port_listening()
复核, 不再拿"查不到"冒充"空闲"。

跑法: python state/test-port-holders.py
"""
from __future__ import annotations

import socket
import sys

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool  # noqa: E402

PASS, FAIL = [], []


def check(name: str, ok: bool, detail: str = ""):
    (PASS if ok else FAIL).append(name)
    print(f"  [{'OK ' if ok else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def listen_on(port: int):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(1)
    return s


def main() -> int:
    print("=" * 74)
    print("  端口占用者查询回归")
    print("=" * 74)

    print("\n[1] 两条路线各自可用")
    n = pool._port_pids_netstat(8787)
    p = pool._port_pids_powershell(8787)
    check("netstat 路线返回 list", isinstance(n, list), f"{n}")
    check("powershell 路线返回 list", isinstance(p, list), f"{p}")
    check("两条路对同一端口结果一致(都在监听时)", n == p or not n or not p,
          f"netstat={n} ps={p}")

    print("\n[2] 自己起一个监听, 看能不能查到")
    port = free_port()
    srv = listen_on(port)
    try:
        h = pool.port_holders(port)
        check("查到自己刚起的监听", len(h) >= 1, f"{[(x['pid'], x['name']) for x in h]}")
        check("查到的 PID 是本进程", any(x["pid"] == __import__("os").getpid() for x in h),
              f"本进程 {__import__('os').getpid()}, 查到 {[x['pid'] for x in h]}")
    finally:
        srv.close()

    print("\n[3] netstat 挂掉时 powershell 要能兜住")
    orig = pool._port_pids_netstat
    try:
        def boom(port_):
            raise RuntimeError("模拟 netstat 被安全软件拦了")
        pool._port_pids_netstat = boom
        port2 = free_port()
        srv2 = listen_on(port2)
        try:
            h2 = pool.port_holders(port2)
            check("netstat 抛异常时仍能查到占用者", len(h2) >= 1,
                  f"{[(x['pid'], x['name']) for x in h2]}")
        finally:
            srv2.close()
    finally:
        pool._port_pids_netstat = orig

    print("\n[4] 两条路都挂掉时: 返回空, 但不抛异常")
    orig_n, orig_p = pool._port_pids_netstat, pool._port_pids_powershell
    try:
        pool._port_pids_netstat = lambda port_: (_ for _ in ()).throw(RuntimeError("x"))
        pool._port_pids_powershell = lambda port_: (_ for _ in ()).throw(RuntimeError("y"))
        try:
            h3 = pool.port_holders(8787)
            check("两条路都失败时返回空列表(不抛)", h3 == [], f"{h3}")
        except Exception as e:
            check("两条路都失败时返回空列表(不抛)", False, f"{type(e).__name__}: {e}")
    finally:
        pool._port_pids_netstat, pool._port_pids_powershell = orig_n, orig_p

    print("\n[5] 端口必须精确匹配(不能子串命中)")
    port3 = free_port()
    srv3 = listen_on(port3)
    try:
        # 用端口的前缀/后缀去查, 都不该命中
        for probe in (int(str(port3)[:-1] or 0), int(str(port3)[1:] or 0)):
            if probe == port3 or probe <= 0:
                continue
            hit = [x for x in pool.port_holders(probe) if x["pid"] == __import__("os").getpid()]
            check(f"port_holders({probe}) 不命中监听中的 {port3}", not hit, f"{hit}")
    finally:
        srv3.close()

    print("\n[6] 边界输入不炸")
    for bad in (0, 1, 65535, 99999, -1):
        try:
            r = pool.port_holders(bad)
            check(f"port_holders({bad}) 正常返回", isinstance(r, list), f"{len(r)} 条")
        except Exception as e:
            check(f"port_holders({bad}) 正常返回", False, f"{type(e).__name__}: {e}")

    print("\n[7] 空闲端口返回空")
    fp = free_port()
    check("空闲端口查不到占用者", pool.port_holders(fp) == [], f"端口 {fp}")

    print("\n" + "=" * 74)
    print(f"  通过 {len(PASS)} / 失败 {len(FAIL)}")
    for f in FAIL:
        print(f"    FAIL: {f}")
    print("=" * 74)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
