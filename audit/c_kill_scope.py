# -*- coding: utf-8 -*-
"""C10 · 前缀误匹配的实际杀伤力: 当前用户对这些 PID 有没有终止权限

C1 已经证明 `port_holders(N)` 是子串匹配。这一节回答"那又怎样":
对 port_holders(1) / port_holders(8) 列出来的每一个 PID, 用
OpenProcess(PROCESS_TERMINATE) **只探测权限, 不真的终止**,
看哪些是 free_port 真能杀掉的。

(只读探测: OpenProcess 后立刻 CloseHandle, 不调用 TerminateProcess。)
"""
import ctypes
import ctypes.wintypes as wt
import sys

sys.path.insert(0, r"E:\AI\freeVPN")
import pool  # noqa: E402

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.restype = wt.HANDLE
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.CloseHandle.argtypes = [wt.HANDLE]

PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


def can_terminate(pid: int) -> tuple[bool, int]:
    h = k32.OpenProcess(PROCESS_TERMINATE, False, pid)
    if h:
        k32.CloseHandle(h)
        return True, 0
    return False, ctypes.get_last_error()


def banner(t):
    print("\n" + "=" * 72)
    print(t)
    print("=" * 72)


SELF = __import__("os").getpid()
print(f"审计进程 PID = {SELF} (非管理员: "
      f"{not bool(ctypes.windll.shell32.IsUserAnAdmin())})")

for probe in (1, 8, 878, 8787, 80):
    banner(f"port_holders({probe}) 列出的占用者 + 本进程对它们的终止权限")
    holders = pool.port_holders(probe)
    if not holders:
        print("  (无)")
        continue
    for h in holders:
        ok, err = can_terminate(h["pid"])
        mark = "可终止" if ok else f"不可终止 (WinError {err})"
        tag = "  <== 被标记为另一份 freeVPN" if h["is_freevpn"] else ""
        print(f"  PID {h['pid']:<7} {h['name']:<28} {mark}{tag}")
    n_ok = sum(1 for h in holders if can_terminate(h["pid"])[0])
    print(f"  → 共 {len(holders)} 个, 其中 {n_ok} 个本进程有权终止")

banner("对照: 真实 freeVPN 实例所在的 8787")
for h in pool.port_holders(8787):
    ok, err = can_terminate(h["pid"])
    print(f"  PID {h['pid']} {h['name']}  "
          f"{'可终止' if ok else f'不可终止 (WinError {err})'}")
print("  (本次审计只做权限探测, 没有对任何 PID 执行终止)")

banner("说明")
print("  free_port(N) = port_holders(N) -> kill_pids(全部 PID)")
print("  kill_pids 用 taskkill /F /T, 只要 OpenProcess(PROCESS_TERMINATE) 成功, ")
print("  taskkill 就能结束它。所以上表里标'可终止'的 PID 都是 free_port 真能杀的。")
