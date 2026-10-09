#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A7 · inject_verge 写用户配置目录: 备份 / 原子性 / 失败行为 / 并发。

全部在 audit/_tmp/verge 这个假客户端目录里做, 不碰真实的 APPDATA。
用法: python audit/A7_verge.py
"""
import shutil
import sys
import threading
import time
from pathlib import Path

ROOT = Path(r"E:\AI\freeVPN")
sys.path.insert(0, str(ROOT))
import pool          # noqa: E402
import security as sec  # noqa: E402

TMP = ROOT / "audit" / "_tmp"
VDIR = TMP / "verge"
SUB = f"http://127.0.0.1:8787/sub/pool.yaml?token={sec.load_or_create_token()}"


def fresh_dir(filler_bytes=0) -> Path:
    if VDIR.exists():
        shutil.rmtree(VDIR, ignore_errors=True)
    VDIR.mkdir(parents=True, exist_ok=True)
    body = {
        "current": "aaaa1111",
        "items": [
            {"uid": "aaaa1111", "type": "remote", "name": "用户原有订阅",
             "file": "aaaa1111.yaml", "url": "https://example.com/a.yaml"},
            {"uid": "bbbb2222", "type": "local", "name": "本地配置",
             "file": "bbbb2222.yaml"},
        ],
        "chain": ["aaaa1111"],
    }
    if filler_bytes:
        body["items"][0]["_filler"] = "x" * filler_bytes
    import yaml
    (VDIR / "profiles.yaml").write_text(
        "# Profiles Config for Clash Verge\n\n"
        + yaml.safe_dump(body, allow_unicode=True, sort_keys=False),
        encoding="utf-8")
    return VDIR


def main():
    pool.VERGE_DIRS = [VDIR]           # 只动假目录
    print(f"假客户端目录: {VDIR}")
    print("=" * 74)
    print("⓪ 前置: 真实环境里 Clash Verge 正在运行时的行为")
    print("=" * 74)
    print(f"  verge_running() 实测 -> {pool.verge_running()}")
    print("  (本机确实有 clash-verge.exe 在跑; 下面把进程检查打桩, 只测写入逻辑)")
    pool.verge_running = lambda: False

    print()
    print("=" * 74)
    print("① 正常路径: 备份 + 写入 + 第二次运行是否更新备份")
    print("=" * 74)
    fresh_dir()
    idx = VDIR / "profiles.yaml"
    bak = VDIR / "profiles.yaml.freevpn.bak"
    orig = idx.read_bytes()
    print(f"  原配置 {len(orig)} 字节; 备份存在: {bak.exists()}")
    r1 = pool.inject_verge(SUB, activate=True)
    print(f"  第一次 inject_verge -> {r1}")
    print(f"  备份存在: {bak.exists()}  备份与原文件一致: {bak.read_bytes() == orig}")
    bak_stat1 = (bak.stat().st_size, bak.stat().st_mtime_ns)
    time.sleep(0.05)
    # 用户手动改了配置
    idx.write_text(idx.read_text(encoding="utf-8") + "# 用户手改\n", encoding="utf-8")
    r2 = pool.inject_verge(SUB, activate=True)
    bak_stat2 = (bak.stat().st_size, bak.stat().st_mtime_ns)
    print(f"  第二次 inject_verge -> {r2}")
    print(f"  备份是否被更新: {bak_stat1 != bak_stat2}  (False = 第二次没有刷新备份)")
    import yaml
    d = yaml.safe_load(idx.read_text(encoding="utf-8"))
    names = [it.get("name") for it in d.get("items", [])]
    print(f"  写入后 items: {names}")
    print(f"  current = {d.get('current')!r}")
    print(f"  用户原有订阅是否还在: {'用户原有订阅' in names}")
    print(f"  用户手改的那行是否还在: {'用户手改' in idx.read_text(encoding='utf-8')}")

    print()
    print("=" * 74)
    print("② 写入是否原子: watcher 抓中间态")
    print("=" * 74)
    fresh_dir(filler_bytes=6 * 1024 * 1024)     # 6MB, 让写入过程足够长
    idx = VDIR / "profiles.yaml"
    print(f"  写入前 profiles.yaml = {idx.stat().st_size} 字节")
    samples = []
    stop = threading.Event()

    def watch():
        while not stop.is_set():
            try:
                samples.append(idx.stat().st_size)
            except OSError:
                samples.append(-1)     # 文件不存在
            time.sleep(0.0002)

    w = threading.Thread(target=watch, daemon=True)
    w.start()
    t0 = time.time()
    r = pool.inject_verge(SUB)
    dt = time.time() - t0
    stop.set()
    w.join(timeout=2)
    after = idx.stat().st_size if idx.exists() else -1
    print(f"  inject_verge -> {r}, 耗时 {dt*1000:.0f} ms")
    print(f"  采样 {len(samples)} 次, 观测到的最小大小 = {min(samples)} 字节")
    print(f"  观测到 0 字节(被截断)的次数: {samples.count(0)}")
    print(f"  观测到的中间态(<最终大小)次数: "
          f"{sum(1 for s in samples if 0 <= s < after)}")
    print(f"  写入后大小 = {after} 字节")
    print(f"  >>> {'非原子写成立: 文件先被清空再逐块写回, 中途崩溃/断电会留下半截配置' if samples.count(0) else '未抓到中间态(窗口太短)'}")

    print()
    print("=" * 74)
    print("③ 写入失败: 只读文件")
    print("=" * 74)
    fresh_dir()
    idx = VDIR / "profiles.yaml"
    before = idx.read_bytes()
    import subprocess
    subprocess.run(["attrib", "+R", str(idx)], capture_output=True)
    print(f"  已把 profiles.yaml 设为只读; 原内容 {len(before)} 字节")
    try:
        r = pool.inject_verge(SUB)
        print(f"  inject_verge 返回 {r} (未抛异常)")
    except Exception as e:
        print(f"  inject_verge 抛出 {type(e).__name__}: {e}")
        print("  >>> 写入失败没有被捕获, 异常直接冒到调用方 (daemon 模式下会写进 --log 文件)")
    subprocess.run(["attrib", "-R", str(idx)], capture_output=True)
    print(f"  原文件是否被破坏: {idx.read_bytes() == before}")

    print()
    print("=" * 74)
    print("④ 并发: 两个线程同时写同一个 profiles.yaml")
    print("=" * 74)
    fresh_dir(filler_bytes=4 * 1024 * 1024)
    idx = VDIR / "profiles.yaml"
    errs = []

    def worker():
        try:
            pool.inject_verge(SUB)
        except Exception as e:
            errs.append(f"{type(e).__name__}: {e}")

    ts = [threading.Thread(target=worker) for _ in range(2)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    raw = idx.read_text(encoding="utf-8")
    ok = True
    try:
        d = yaml.safe_load(raw)
    except Exception as e:
        ok = False
        d = None
        print(f"  结果文件已损坏: {type(e).__name__}: {e}")
    print(f"  文件大小 {len(raw)} 字节; 能否解析: {ok}; 异常: {errs or '无'}")
    if d:
        vp = [it for it in d.get("items", []) if it.get("name") == pool.IMPORT_NAME]
        print(f"  items 总数 {len(d.get('items', []))}, 其中 freeVPN条目 {len(vp)} 条 "
              f"(两个线程各插一条, 期望 2)")
        print(f"  >>> {'丢失更新: 后写的一方覆盖了前一方' if len(vp) < 2 else '两条都在'}")

    print("\n(全程只操作 audit/_tmp/verge, 真实 APPDATA 未被触碰)")


if __name__ == "__main__":
    main()
