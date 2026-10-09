# -*- coding: utf-8 -*-
"""C11 · serve() 的端口冲突路径 (只验证失败分支, 不占用 8787)

占用者用自建进程, 端口 8899。serve() 在 bind 失败时会 SystemExit(1),
而写 订阅地址.txt 的代码在 bind 之后 —— 所以这条路径不会碰任何文件。
"""
import socket
import subprocess
import sys
import time
from pathlib import Path

PY = sys.executable
PORT = 8899

code = ("import socket,time\n"
        "s=socket.socket()\n"
        "s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
        f"s.bind(('127.0.0.1',{PORT}))\n"
        "s.listen(5)\n"
        "time.sleep(120)\n")
occ = subprocess.Popen([PY, "-c", code],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
for _ in range(40):
    with socket.socket() as s:
        s.settimeout(0.2)
        if s.connect_ex(("127.0.0.1", PORT)) == 0:
            break
    time.sleep(0.2)
print(f"自建占用者 PID = {occ.pid} 监听 127.0.0.1:{PORT}")

addr = Path(r"E:\AI\freeVPN\订阅地址.txt")
before = addr.read_bytes() if addr.exists() else None
print(f"订阅地址.txt 运行前 mtime = "
      f"{addr.stat().st_mtime if addr.exists() else None}")

r = subprocess.run([PY, str(Path(r"E:\AI\freeVPN\pool.py")), "serve",
                    "--port", str(PORT)],
                   capture_output=True, text=True, timeout=90,
                   encoding="utf-8", errors="replace",
                   cwd=r"E:\AI\freeVPN")
print(f"\nserve --port {PORT} 退出码 = {r.returncode}")
print("---- stdout ----")
print((r.stdout or "").strip())
print("---- stderr ----")
print((r.stderr or "").strip()[:800])

after = addr.read_bytes() if addr.exists() else None
print(f"\n订阅地址.txt 是否被改动: {before != after}")
print("(bind 失败时 SystemExit 发生在写 订阅地址.txt 之前 —— 这条路径不动文件)")

occ.kill()
print("占用者已清理")
