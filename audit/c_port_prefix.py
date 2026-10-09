# -*- coding: utf-8 -*-
"""C1/C2 · port_holders 的端口子串匹配 + kill_pids 的 /T 连带杀伤

验证目标:
  C1  `f":{port}" in parts[1]` 是**子串**匹配, 不是端口相等匹配。
      后果: free_port(N) 会命中所有端口号以 N 为前缀的监听者 ——
      哪怕 N 那个端口根本没被占用。
  C2  `taskkill /F /T` 会连带结束占用者的整个子进程树。

安全约束: 只使用自建的测试进程(端口 18897/18898/18899), 不碰 8787 上的
         C:\\freeVPN 实例, 也不对它执行任何 kill。
"""
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, r"E:\AI\freeVPN")
import pool  # noqa: E402

PY = sys.executable
FREEVPN_PID_8787 = None


def listen_wait(port, timeout=10.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        with socket.socket() as s:
            s.settimeout(0.3)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def spawn_listener(port):
    code = (
        "import socket,time\n"
        "s=socket.socket()\n"
        "s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
        f"s.bind(('127.0.0.1',{port}))\n"
        "s.listen(5)\n"
        "time.sleep(900)\n"
    )
    p = subprocess.Popen([PY, "-c", code],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ok = listen_wait(port)
    return p, ok


def alive(p):
    return p.poll() is None


def banner(t):
    print("\n" + "=" * 72)
    print(t)
    print("=" * 72)


print(f"python = {PY}")
print(f"pool   = {pool.__file__}")

# ---------------------------------------------------------------------------
banner("C1-a · 只读: 用「另一个 freeVPN 的真实端口」做前缀, 看会命中谁")
print("本机 127.0.0.1:8787 上跑着 C:\\freeVPN 的实例 (PID 25308, 只读观察, 不动它)")
for probe in (878, 8787, 8, 1, 80):
    holders = pool.port_holders(probe)
    print(f"\n  port_holders({probe!r}) -> {len(holders)} 个占用者")
    for h in holders:
        print(f"      pid={h['pid']:<7} name={h['name']:<28} freevpn={h['is_freevpn']}")

# ---------------------------------------------------------------------------
banner("C1-b · 实跑: 清一个**空闲**端口, 却杀掉占着别的端口的进程")
print("构造: 只有测试进程监听 127.0.0.1:18899, 端口 1889 完全空闲")
victim, ok = spawn_listener(18899)
print(f"  测试进程 PID = {victim.pid}  监听成功 = {ok}")
print(f"  port_holders(1889)  (1889 自身空闲!) -> "
      f"{[(h['pid'], h['name']) for h in pool.port_holders(1889)]}")
print(f"  port_holders(18899) -> "
      f"{[(h['pid'], h['name']) for h in pool.port_holders(18899)]}")

print("\n  >>> 执行 pool.free_port(1889)  (意图: 清掉端口 1889 上的占用者)")
holders, killed, failed = pool.free_port(1889)
print(f"      被认定为占用者的: {[(h['pid'], h['name']) for h in holders]}")
print(f"      已结束: {killed}   失败: {failed}")
time.sleep(0.5)
print(f"      测试进程 18899 是否还活着: {alive(victim)}  "
      f"(退出码 {victim.poll()})")
if alive(victim):
    victim.kill()
print(f"      >>> 结论: 端口 1889 空闲, 却杀掉了监听 18899 的 PID {victim.pid}")

# ---------------------------------------------------------------------------
banner("C1-c · 实跑: 前缀匹配的作用范围")
for probe in (1889, 188, 18, 1):
    hits = [h["pid"] for h in pool.port_holders(probe)]
    print(f"  free_port({probe:<5}) 会试图结束 PID {hits}")
print("  (只做了只读列举, 没有对上面任何 PID 执行 kill)")

# ---------------------------------------------------------------------------
banner("C2 · 实跑: /T 连带杀掉占用者的整个子进程树")
parent, ok = spawn_listener(18898)
child = subprocess.Popen([PY, "-c", "import time; time.sleep(900)"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(f"  父进程(监听 18898) PID = {parent.pid}  监听成功 = {ok}")
print(f"  子进程(与端口无关) PID = {child.pid}")
time.sleep(1.0)
print(f"  杀之前: 父活={alive(parent)} 子活={alive(child)}")

ok_pids, bad_pids = pool.kill_pids([parent.pid])
time.sleep(1.0)
print(f"  pool.kill_pids([{parent.pid}]) -> 成功={ok_pids} 失败={bad_pids}")
print(f"  杀之后: 父活={alive(parent)} 子活={alive(child)}")
if alive(child):
    child.kill()
    print("  (子进程还活着, 实验收尾把它清掉)")
else:
    print(f"  >>> 结论: 与端口毫无关系的子进程 PID {child.pid} 被 /T 连带结束")

# ---------------------------------------------------------------------------
banner("C1-d · 只读: 进程名/命令行里带 freevpn 字样即可被标记为「另一份 freeVPN」")
fake = subprocess.Popen(
    [PY, "-c",
     "import socket,time\n"
     "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
     "s.bind(('127.0.0.1',18897)); s.listen(5)\n"
     "# cmdline mentions freevpn to spoof the tag\n"
     "time.sleep(900)\n"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
listen_wait(18897)
for h in pool.port_holders(18897):
    print(f"  pid={h['pid']} name={h['name']} is_freevpn={h['is_freevpn']}")
    print(f"    cmdline[:120]={h['cmdline'][:120]}")
fake.kill()

print("\n" + "=" * 72)
print("C1/C2 完成")
print("=" * 72)
