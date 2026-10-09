# -*- coding: utf-8 -*-
"""C2b · kill_pids 的 /T 连带杀伤 (修正版: 子进程必须由占用者自己拉起)

首版 PoC 里子进程是**审计脚本**拉起的, 父进程是审计脚本 —— 不是占用者,
所以 /T 当然不会碰它。这一版让监听进程自己 spawn 子进程。
"""
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, r"E:\AI\freeVPN")
import pool  # noqa: E402

PY = sys.executable
TMP = Path(r"E:\AI\_c_test")
TMP.mkdir(parents=True, exist_ok=True)


def listen_wait(port, timeout=12.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        with socket.socket() as s:
            s.settimeout(0.3)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def banner(t):
    print("\n" + "=" * 72)
    print(t)
    print("=" * 72)


banner("C2b · /T 连带杀伤 (占用者自己拉起子进程)")
PORT = 18896
child_pidfile = TMP / f"child_{PORT}.pid"
child_pidfile.unlink(missing_ok=True)

code = (
    "import socket,subprocess,sys,time\n"
    "c=subprocess.Popen([sys.executable,'-c','import time;time.sleep(900)'])\n"
    f"open(r'{child_pidfile}','w').write(str(c.pid))\n"
    "s=socket.socket()\n"
    "s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
    f"s.bind(('127.0.0.1',{PORT}))\n"
    "s.listen(5)\n"
    "time.sleep(900)\n"
)
parent = subprocess.Popen([PY, "-c", code],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
ok = listen_wait(PORT)
for _ in range(30):
    if child_pidfile.exists():
        break
    time.sleep(0.2)
child_pid = int(child_pidfile.read_text().strip()) if child_pidfile.exists() else -1
print(f"  占用者(监听 127.0.0.1:{PORT}) PID = {parent.pid}   监听成功 = {ok}")
print(f"  它自己拉起的子进程 PID        = {child_pid}")
time.sleep(0.8)
print(f"  杀之前: 父活={parent.poll() is None}  子活={pool.sec.pid_alive(child_pid)}")

ok_pids, bad_pids = pool.kill_pids([parent.pid])
time.sleep(1.2)
print(f"  pool.kill_pids([{parent.pid}]) -> 成功={ok_pids} 失败={bad_pids}")
print(f"  杀之后: 父活={parent.poll() is None}  子活={pool.sec.pid_alive(child_pid)}")
if pool.sec.pid_alive(child_pid):
    print("  >>> /T 未连带子进程")
    subprocess.run(["taskkill", "/F", "/PID", str(child_pid)],
                   capture_output=True)
    print("  (收尾清掉子进程)")
else:
    print(f"  >>> /T 连带结束了与端口无关的子进程 PID {child_pid}")

# ---------------------------------------------------------------------------
banner("C2c · 对照: 直接用命令行跑一次 /T, 看 taskkill 的真实语义")
PORT2 = 18895
pidfile2 = TMP / f"child_{PORT2}.pid"
pidfile2.unlink(missing_ok=True)
code2 = code.replace(str(PORT), str(PORT2)).replace(
    str(child_pidfile), str(pidfile2))
p2 = subprocess.Popen([PY, "-c", code2],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
listen_wait(PORT2)
for _ in range(30):
    if pidfile2.exists():
        break
    time.sleep(0.2)
c2 = int(pidfile2.read_text().strip())
print(f"  父 PID={p2.pid}  子 PID={c2}")
r = subprocess.run(["taskkill", "/F", "/T", "/PID", str(p2.pid)],
                   capture_output=True, text=True, encoding="gbk",
                   errors="replace")
time.sleep(1.2)
print(f"  taskkill 输出: {(r.stdout or '').strip()}  rc={r.returncode}")
print(f"  杀之后: 父活={p2.poll() is None}  子活={pool.sec.pid_alive(c2)}")
if pool.sec.pid_alive(c2):
    subprocess.run(["taskkill", "/F", "/PID", str(c2)], capture_output=True)
    print("  (收尾清掉子进程)")

# ---------------------------------------------------------------------------
banner("C1-d2 · 伪造 is_freevpn 标记 (把 freevpn 写在单行命令行里)")
spoof = TMP / "fake_freevpn_listener.py"
spoof.write_text(
    "# freevpn  (这个名字会被 port_holders 当成另一份 freeVPN)\n"
    "import socket, time\n"
    "s = socket.socket()\n"
    "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
    "s.bind(('127.0.0.1', 18894))\n"
    "s.listen(5)\n"
    "time.sleep(900)\n", encoding="utf-8")
sp = subprocess.Popen([PY, str(spoof)],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
listen_wait(18894)
for h in pool.port_holders(18894):
    print(f"  pid={h['pid']} name={h['name']} is_freevpn={h['is_freevpn']}")
    print(f"    cmdline={h['cmdline'][:160]}")
sp.kill()

print("\n" + "=" * 72)
print("C2b/C2c/C1-d2 完成")
print("=" * 72)
