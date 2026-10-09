#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""端到端验收: 内核加载 out/pool.yaml -> 复测每个节点 -> 真实 HTTP 请求走通。

这是唯一能证明"池子里的节点真的能用"的测试, 不是看程序自己报的数字。
订阅配置里**故意不写** external-controller, 所以这里叠加一个临时控制端口再加载。
"""
import json
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

sys.path.insert(0, r"E:\AI\freeVPN")
import security as sec  # noqa: E402

ROOT = Path(r"E:\AI\freeVPN")
MIHOMO = ROOT / "bin" / "mihomo.exe"
POOL = ROOT / "out" / "pool.yaml"
VDIR = ROOT / "state" / "verify"
VCFG = VDIR / "verify.yaml"
CTRL = "http://127.0.0.1:9090"
TEST = "http://www.gstatic.com/generate_204"
PROXY = "http://127.0.0.1:7890"


def api(path, timeout=10, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(CTRL + path, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
        return json.loads(raw) if raw else {}


def main():
    VDIR.mkdir(parents=True, exist_ok=True)
    print("=" * 66)
    print("1) 读取订阅并做内核语法校验")
    print("=" * 66)
    cfg = yaml.safe_load(POOL.read_text(encoding="utf-8"))
    proxies = cfg.get("proxies") or []
    groups = cfg.get("proxy-groups") or []
    rules = cfg.get("rules") or []
    print(f"    节点 {len(proxies)} / 分组 {len(groups)} / 规则 {len(rules)}")
    print(f"    订阅里含 external-controller: {'external-controller' in cfg}  (应为 False)")
    print(f"    订阅里含 global-client-fingerprint: {'global-client-fingerprint' in cfg}  (应为 False)")
    print(f"    规则前 3 条: {rules[:3]}")
    cfg["external-controller"] = "127.0.0.1:9090"
    cfg["secret"] = ""
    VCFG.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False), encoding="utf-8")

    r = subprocess.run([str(MIHOMO), "-d", str(VDIR), "-f", str(VCFG), "-t"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace",
                       cwd=str(VDIR), env=sec.kernel_env(),
                       creationflags=sec.kernel_creationflags())
    out = ((r.stdout or "") + (r.stderr or "")).strip()
    print("    " + (out.replace("\n", "\n    ") or "(无输出)"))
    if r.returncode != 0:
        print(">>> 配置非法")
        return 1
    print(">>> 配置合法\n")

    print("=" * 66)
    print("2) 启动内核加载池子")
    print("=" * 66)
    proc = subprocess.Popen([str(MIHOMO), "-d", str(VDIR), "-f", str(VCFG)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            stdin=subprocess.DEVNULL, cwd=str(VDIR),
                            env=sec.kernel_env(),
                            creationflags=sec.kernel_creationflags())
    try:
        for _ in range(40):
            if proc.poll() is not None:
                print(">>> 内核退出, 配置被拒")
                return 1
            try:
                v = api("/version", 2)
                print(f">>> 内核就绪: {v.get('version')}")
                break
            except Exception:
                time.sleep(0.5)
        else:
            print(">>> 内核 API 未就绪")
            return 1

        allp = api("/proxies").get("proxies", {})
        # 注意: Clash API 返回的 type 是首字母大写的(Vmess / Shadowsocks / ...),
        # 所以用"排除分组与内置项"的方式识别真实节点, 别按小写协议名匹配
        GROUP_TYPES = {"Selector", "URLTest", "Fallback", "LoadBalance", "Relay"}
        BUILTIN = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"}
        nodes = [n for n, v in allp.items()
                 if str(v.get("type")) not in GROUP_TYPES and n not in BUILTIN]
        grp = [n for n, v in allp.items() if str(v.get("type")) in GROUP_TYPES]
        print(f">>> 内核识别: {len(nodes)} 个节点, {len(grp)} 个分组")
        print(f"    分组: {grp}")

        print()
        print("=" * 66)
        print("3) 逐个复测 (内核独立重新拨号)")
        print("=" * 66)
        q = urllib.parse.urlencode({"timeout": 5000, "url": TEST})
        alive = []
        for n in nodes:
            try:
                d = api(f"/proxies/{urllib.parse.quote(n, safe='')}/delay?{q}", 15)
                if d.get("delay"):
                    alive.append(n)
                    print(f"  OK  {d['delay']:>5}ms  {n}")
                else:
                    print(f"  --          {n}")
            except Exception:
                print(f"  --          {n}")
        print(f"\n>>> 复测通过 {len(alive)}/{len(nodes)}")

        if not alive:
            print(">>> 没有可用节点, 端到端测试跳过")
            return 1

        print()
        print("=" * 66)
        print("4) 端到端: 通过池子的 mixed-port 真实访问外网")
        print("=" * 66)
        sel = "🚀 节点选择"
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": PROXY, "https": PROXY}))
        # 轮换不同节点各发一次, 而不是对着同一个节点连发 3 次 ——
        # 免费节点会中途挂掉(实测同一个节点第 2 次就回 502 Bad Gateway),
        # 那测的是节点寿命, 不是池子能不能用。
        picks = alive[:3] if len(alive) >= 3 else alive
        ok = 0
        for i, node in enumerate(picks, 1):
            if sel in allp:
                api(f"/proxies/{urllib.parse.quote(sel, safe='')}", 10, "PUT",
                    {"name": node})
                time.sleep(1)
            try:
                t0 = time.time()
                with opener.open(TEST, timeout=25) as resp:
                    print(f">>> 第 {i} 个节点 HTTP {resp.status}  "
                          f"{(time.time()-t0)*1000:.0f}ms  {node}")
                    if resp.status == 204:
                        ok += 1
            except Exception as e:
                print(f">>> 第 {i} 个节点失败: {type(e).__name__}: {e}  {node}")
        print(f"\n>>> 端到端: {ok}/{len(picks)} 个不同节点成功出网")
        return 0 if ok >= max(1, len(picks) - 1) else 1
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=6)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    sys.exit(main())
