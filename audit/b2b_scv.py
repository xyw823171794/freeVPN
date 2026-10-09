# -*- coding: utf-8 -*-
"""
问题 2 补充: 内核把整型 1 当布尔 true 用 (skip-cert-verify: 1 的绕过依据)。
方法: mihomo 的 /proxies/<name> API 会回显 proxy 的 udp / tfo / mptcp 等布尔字段,
      用 udp: 1 (整数) 看内核是否解析成 true。
      这与 skip-cert-verify 走的是同一个 structure 解码器 (WeaklyTypedInput)。
另外用 Skip-Cert-Verify / SKIP-CERT-VERIFY 的大小写变体 + 非法字符串,
证明键名匹配不区分大小写、且值确实被当 bool 解析。
"""
import json
import pathlib
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, r"E:\AI\freeVPN")
import pool

ROOT = pathlib.Path(r"E:\AI\freeVPN")
WORK = ROOT / "audit" / "_miwork2b"
WORK.mkdir(parents=True, exist_ok=True)
PORT = 17911
SECRET = "freevpn"


def api(path: str, timeout=5):
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}",
                                 headers={"Authorization": f"Bearer {SECRET}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def run_cfg(name: str, proxy_lines: list[str]):
    body = "  - " + proxy_lines[0] + "\n" + "".join(
        "    " + l + "\n" for l in proxy_lines[1:])
    cfg = (f"mixed-port: 17912\nallow-lan: false\nmode: rule\nlog-level: warning\n"
           f"external-controller: 127.0.0.1:{PORT}\nsecret: {SECRET}\n"
           "proxies:\n" + body +
           "proxy-groups:\n  - name: G\n    type: select\n    proxies: [p]\n"
           "rules:\n  - MATCH,G\n")
    p = WORK / f"{name}.yaml"
    p.write_text(cfg, encoding="utf-8")
    t = subprocess.run([str(ROOT / "bin" / "mihomo.exe"), "-d", str(WORK), "-f", str(p), "-t"],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", cwd=str(WORK), timeout=60)
    ok = t.returncode == 0
    msg = ((t.stdout or "") + (t.stderr or "")).strip().splitlines()
    err = next((l for l in msg if "level=error" in l or "level=fatal" in l), "")
    if not ok:
        print(f"  {name:34} mihomo -t 拒绝: {err.strip()[:150]}")
        return
    with open(WORK / f"{name}.log", "wb") as fh:
        proc = subprocess.Popen([str(ROOT / "bin" / "mihomo.exe"), "-d", str(WORK), "-f", str(p)],
                                stdout=fh, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, cwd=str(WORK),
                                creationflags=0x08000000)
        time.sleep(2.0)
        try:
            info = None
            for _ in range(12):
                try:
                    info = api("/proxies/p", timeout=3)
                    break
                except Exception:
                    time.sleep(1.0)
            if info is None:
                raise RuntimeError("API 始终未就绪")
            fields = {k: info.get(k) for k in ("udp", "tfo", "mptcp", "xudp")
                      if k in info}
            print(f"  {name:34} mihomo -t 接受; /proxies/p -> {fields}")
        except Exception as e:
            print(f"  {name:34} mihomo -t 接受; API 读取失败 {e}")
        finally:
            proc.kill()
            proc.wait(timeout=10)
        time.sleep(0.4)


print("=" * 78)
print("### 2.4 整型 -> 布尔 的实际转换 (udp 字段可被 API 观测)")
print("=" * 78)
BASE = ["name: p", "type: ss", "server: 198.51.100.9", "port: 8388",
        "cipher: aes-128-gcm", "password: pw"]
run_cfg("udp_true_bool", BASE + ["udp: true"])
run_cfg("udp_int_1", BASE + ["udp: 1"])
run_cfg("udp_int_0", BASE + ["udp: 0"])
run_cfg("udp_str_true", BASE + ['udp: "true"'])
run_cfg("udp_str_yes", BASE + ['udp: "yes"'])

print()
print("=" * 78)
print("### 2.5 skip-cert-verify 键名大小写与取值类型")
print("=" * 78)
TRO = ["name: p", "type: trojan", "server: 198.51.100.9", "port: 443", "password: pw"]
run_cfg("scv_bool_true", TRO + ["skip-cert-verify: true"])
run_cfg("scv_int_1", TRO + ["skip-cert-verify: 1"])
run_cfg("scv_int_0", TRO + ["skip-cert-verify: 0"])
run_cfg("scv_str_true", TRO + ['skip-cert-verify: "true"'])
run_cfg("scv_KeyCase_1", TRO + ["Skip-Cert-Verify: 1"])
run_cfg("scv_KEYUPPER_abc", TRO + ['SKIP-CERT-VERIFY: "abc"'])
run_cfg("scv_kebab_lower", TRO + ['skip-cert-verify: "y"'])
run_cfg("scv_snake_case", TRO + ["skip_cert_verify: true"])
print()
print("  判定依据: 'SKIP-CERT-VERIFY' 这种全大写键若能触发 bool 类型错误,")
print("  说明内核键名匹配不区分大小写, 则 'Skip-Cert-Verify: 1' 也确实生效,")
print("  而 pool.audit_node 用 p.get('skip-cert-verify') 精确匹配 -> 漏报。")
