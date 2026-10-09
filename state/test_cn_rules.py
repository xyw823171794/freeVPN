# -*- coding: utf-8 -*-
"""国内分流规则验证: 数据文件 / 规则语义 / 内核真实裁决 / 产物端到端。

"节点没有屏蔽国内的连接"这个问题不能靠读代码确认 —— 必须让 mihomo 自己
裁决一遍。这个脚本做四件事:

  [1] 数据文件与规则形状(条数、顺序、模式开关)
  [2] 纯 Python 模拟 mihomo 的匹配语义, 逐条断言关键目标的裁决
  [3] **内核实测**: 把整份规则喂给 mihomo, 经 mixed-port 真实发起连接,
      读日志里的 "match XXX using YYY" —— 内核说了算
  [4] 产物端到端: build_clash 出的 YAML 能被内核校验通过(含 5794 条规则)
  [5] fake-ip 场景: 产物用的就是 fake-ip, 单独验"清单外的国内域名能不能被
      IP 段兜住"(B 站的 b23.tv / biligame.com 就是这一类)

用法: python state/test_cn_rules.py
"""
from __future__ import annotations

import ipaddress
import pathlib
import re
import socket
import subprocess
import sys
import time

sys.path.insert(0, r"E:\AI\freeVPN")
import pool                      # noqa: E402
import security as sec           # noqa: E402

ROOT = pathlib.Path(r"E:\AI\freeVPN")
WORK = ROOT / "state" / "_cnwork"
WORK.mkdir(parents=True, exist_ok=True)
MIXED = 17921
KERNEL = ROOT / "bin" / "mihomo.exe"

PASS, FAIL = [], []


def check(name: str, ok: bool, detail: str = ""):
    (PASS if ok else FAIL).append(name)
    print(f"  [{'OK ' if ok else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))


# --------------------------------------------------------------------------
# [1] 数据文件与规则形状
# --------------------------------------------------------------------------
def part1() -> None:
    print("\n[1] 数据文件与规则形状")
    cidr = ROOT / "cn_cidr.txt"
    dom = ROOT / "cn_domains.txt"
    check("cn_cidr.txt 存在", cidr.exists(), f"{cidr.stat().st_size // 1024 if cidr.exists() else 0} KB")
    check("cn_domains.txt 存在", dom.exists(), f"{dom.stat().st_size // 1024 if dom.exists() else 0} KB")

    n4, n6 = sec.cn_networks(4), sec.cn_networks(6)
    check("IPv4 段已加载", len(n4) > 4000, f"{len(n4)} 条")
    check("IPv6 段已加载(不下发但可查)", len(n6) > 1000, f"{len(n6)} 条")
    check("网段全部合法", all(ipaddress.ip_network(x) for x in n4 + n6))
    check("域名清单已加载", len(sec.cn_domains()) > 150, f"{len(sec.cn_domains())} 条")
    check("域名清单无重复", len(sec.cn_domains()) == len(set(sec.cn_domains())))

    rules = sec.SECURITY_RULES
    check("规则表含国内域名规则", any(r.startswith("DOMAIN-SUFFIX,baidu.com,") for r in rules))
    check("规则表含国内 IP 规则", any(r.startswith("IP-CIDR,1.0.1.0/24,") for r in rules))
    check("默认不带 no-resolve(覆盖长尾域名)", "IP-CIDR,1.0.1.0/24,DIRECT" in rules)

    # 顺序: 敏感站点必须排在国内规则之前 —— 否则 cn_mode=reject 会把银行一起掐掉
    i_icbc = rules.index("DOMAIN-SUFFIX,icbc.com.cn,DIRECT")
    i_cn = min(i for i, r in enumerate(rules) if r.startswith("DOMAIN-SUFFIX,cn,"))
    i_meta = rules.index("IP-CIDR,169.254.169.254/32,REJECT,no-resolve")
    check("云元数据 REJECT 排最前", i_meta < i_icbc < i_cn, f"meta={i_meta} icbc={i_icbc} cn={i_cn}")

    # 模式开关
    off = sec.build_security_rules(cn_mode="off")
    rej = sec.build_security_rules(cn_mode="reject")
    check("cn_mode=off 不含国内规则",
          not any(r.endswith(",DIRECT") and r.startswith("IP-CIDR,1.0.1.0/24") for r in off)
          and len(off) == len(sec._METADATA_RULES) + len(sec._SENSITIVE_RULES)
          + len(sec._PRIVATE_RULES) + len(sec._LOCAL_RULES), f"{len(off)} 条")
    check("cn_mode=reject 用 REJECT", any(r == "DOMAIN-SUFFIX,cn,REJECT" for r in rej)
          and any(r.startswith("IP-CIDR,1.0.1.0/24,REJECT") for r in rej))
    check("cn_mode=reject 不掐敏感站点",
          "DOMAIN-SUFFIX,icbc.com.cn,DIRECT" in rej and rej.index("DOMAIN-SUFFIX,icbc.com.cn,DIRECT")
          < rej.index("DOMAIN-SUFFIX,cn,REJECT"))
    check("不认识的值退回 direct", sec._cn_action("banana")[0] == "direct")


# --------------------------------------------------------------------------
# [2] 规则语义(纯 Python 模拟 mihomo 的匹配顺序)
# --------------------------------------------------------------------------
def match_rule(rules: list[str], target: str) -> str:
    """按 mihomo 的语义顺序匹配一条规则, 返回 "RULE -> ACTION"。

    只实现本测试用到的三种: DOMAIN-SUFFIX / IP-CIDR / MATCH。
    `no-resolve` 的 IP 规则对域名不生效 —— 这里用"目标是不是 IP 字面量"近似。
    """
    host, _, port = target.rpartition(":")
    host = host.strip("[]")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    for r in rules:
        parts = r.split(",")
        if parts[0] == "DOMAIN-SUFFIX" and ip is None:
            if host == parts[1] or host.endswith("." + parts[1]):
                return f"{r} -> {parts[2]}"
        elif parts[0] in ("IP-CIDR", "IP-CIDR6") and ip is not None:
            if ip in ipaddress.ip_network(parts[1], strict=False):
                return f"{r} -> {parts[2]}"
        elif parts[0] == "MATCH":
            return f"{r} -> {parts[1]}"
    return "无匹配"


def part2() -> None:
    print("\n[2] 规则语义(纯 Python, 模拟内核匹配顺序)")
    rules = list(sec.SECURITY_RULES) + ["MATCH,🚀 节点选择"]
    cases = [
        # (目标, 期望动作, 说明)
        ("223.5.5.5:443", "DIRECT", "阿里 DNS —— 国内 IP 必须直连"),
        ("114.114.114.114:53", "DIRECT", "114 DNS"),
        ("1.0.1.1:443", "DIRECT", "CN 段里的普通 IP"),
        ("119.29.29.29:53", "DIRECT", "腾讯 DNS"),
        ("180.76.76.76:53", "DIRECT", "百度 DNS"),
        ("8.8.8.8:443", "🚀 节点选择", "国外 IP 仍走节点"),
        ("1.1.1.1:443", "🚀 节点选择", "国外 IP 仍走节点"),
        ("10.0.0.1:80", "DIRECT", "内网"),
        ("127.0.0.1:80", "DIRECT", "回环"),
        ("169.254.169.254:80", "REJECT", "云元数据 —— 必须排在一切之前"),
        ("www.icbc.com.cn:443", "DIRECT", "银行"),
        ("www.baidu.com:443", "DIRECT", "国内站点"),
        ("www.taobao.com:443", "DIRECT", "国内站点"),
        ("www.bilibili.com:443", "DIRECT", "国内站点"),
        ("www.qq.com:443", "DIRECT", "国内站点"),
        ("sso.gov.cn:443", "DIRECT", "政务(.cn 由 TLD 规则吃掉)"),
        ("my.small-shop.com.cn:443", "DIRECT", "长尾 .cn —— TLD 规则覆盖"),
        ("www.google.com:443", "🚀 节点选择", "国外站点仍走节点"),
        ("github.com:443", "🚀 节点选择", "国外站点仍走节点"),
    ]
    for target, want, note in cases:
        got = match_rule(rules, target)
        act = got.rsplit("->", 1)[-1].strip()
        check(f"{target:<28} {note}", act == want, f"实际 {got}")


# --------------------------------------------------------------------------
# [3] 内核实测 —— 内核说了算
# --------------------------------------------------------------------------
PROBES = [
    ("223.5.5.5:443", "国内 IP(阿里 DNS)", "DIRECT"),
    ("114.114.114.114:53", "国内 IP(114 DNS)", "DIRECT"),
    ("180.76.76.76:53", "国内 IP(百度 DNS)", "DIRECT"),
    ("8.8.8.8:53", "国外 IP", "代理"),
    ("1.1.1.1:443", "国外 IP", "代理"),
    ("169.254.169.254:80", "云元数据", "REJECT"),
    ("10.0.0.1:80", "内网", "DIRECT"),
    ("www.baidu.com:443", "国内域名", "DIRECT"),
    ("www.taobao.com:443", "国内域名", "DIRECT"),
    ("www.bilibili.com:443", "国内域名", "DIRECT"),
    ("www.google.com:443", "国外域名", "代理"),
    ("github.com:443", "国外域名", "代理"),
]


def build_kernel_cfg() -> pathlib.Path:
    cfg = {
        "mixed-port": MIXED, "allow-lan": False, "mode": "rule", "log-level": "info",
        "ipv6": False, "geo-auto-update": False, "find-process-mode": "off",
        "dns": {"enable": True, "ipv6": False,
                "nameserver": ["223.5.5.5", "119.29.29.29"]},
        "proxies": [{"name": "p", "type": "ss", "server": "198.51.100.9",
                     "port": 8388, "cipher": "aes-128-gcm", "password": "pw"}],
        "proxy-groups": [{"name": "G", "type": "select", "proxies": ["p"]}],
        "rules": list(sec.SECURITY_RULES) + ["MATCH,G"],
    }
    p = WORK / "cn-rules.yaml"
    p.write_text(pool._dump_yaml(cfg), encoding="utf-8")
    return p


def part3() -> None:
    print("\n[3] 内核实测(mihomo 真实裁决)")
    subprocess.run(["taskkill", "/F", "/IM", "mihomo.exe"],
                   capture_output=True, text=True, timeout=30)
    time.sleep(1.2)
    cfg = build_kernel_cfg()
    n_rules = len(sec.SECURITY_RULES)
    t0 = time.time()
    r = subprocess.run([str(KERNEL), "-d", str(WORK), "-f", str(cfg), "-t"],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", cwd=str(WORK), timeout=180)
    dt = time.time() - t0
    check(f"内核校验 {n_rules} 条规则通过", r.returncode == 0, f"{dt:.2f}s")
    if r.returncode != 0:
        print("     " + ((r.stdout or "") + (r.stderr or "")).strip()[-500:])
        return

    logf = WORK / "cn.log"
    with open(logf, "wb") as fh:
        proc = subprocess.Popen([str(KERNEL), "-d", str(WORK), "-f", str(cfg)],
                                stdout=fh, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, cwd=str(WORK),
                                creationflags=0x08000000)
        t1 = time.time()
        time.sleep(3.0)
        for target, _, _ in PROBES:
            for _try in range(3):
                try:
                    c = socket.create_connection(("127.0.0.1", MIXED), timeout=5)
                    c.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
                    c.close()
                    break
                except OSError:
                    time.sleep(0.8)
            time.sleep(0.1)
        time.sleep(6)
        proc.kill()
        proc.wait(timeout=10)
    print(f"     内核启动到探测完成 {time.time() - t1:.1f}s")

    log = logf.read_text(encoding="utf-8", errors="replace")
    for target, note, want in PROBES:
        # 内核两种日志格式(拨号成功写 info, 拨号失败/超时写 warn):
        #   info: [TCP] src --> target match RULE using ACTION
        #   warn: [TCP] dial ACTION (match RULE) src --> target error: ...
        # 目标连不上是常态(DIRECT 拨号要等超时), 两种都得认 —— 只认前者会
        # 把"裁决正确但拨号超时"误判成"内核没处理"。
        ma = re.search(r"--> " + re.escape(target) + r" match ([^ ]+) using (\S+?)\"", log)
        if ma:
            rule, action = ma.group(1), ma.group(2)
        else:
            mb = re.search(r"dial (\S+) \(match ([^)]*)\)[^\n]*--> " + re.escape(target), log)
            if not mb:
                check(f"{target:<22} {note}", False, "<日志里没有裁决行>")
                continue
            action, rule = mb.group(1), mb.group(2)
        if want == "代理":
            ok = action not in ("DIRECT", "REJECT")
        else:
            ok = action == want
        check(f"{target:<22} {note:<16} {rule} -> {action}", ok, "" if ok else f"期望 {want}")


# --------------------------------------------------------------------------
# [5] fake-ip 场景 —— 产物用的就是 fake-ip, 这条路径必须单独验
# --------------------------------------------------------------------------
# 为什么单独测: 产物 dns.enhanced-mode = fake-ip, 而 [3] 用的是普通 DNS。
# 域名连接在 fake-ip 下走到 IP 规则(不带 no-resolve)时, 内核要不要触发真实
# 解析, 决定了**没列进 cn_domains.txt 的国内域名**能不能被 CN IP 段兜住 ——
# B 站的 b23.tv / biligame.com 就属于这一类。只测普通 DNS 会漏掉这条路径。
FAKEIP_PROBES = [
    ("www.bilibili.com:443", "清单内 · B站主站", "DIRECT"),
    ("i0.hdslb.com:443", "清单内 · B站图床", "DIRECT"),
    ("upos-sz-mirrorcos.bilivideo.com:443", "清单内 · B站视频CDN", "DIRECT"),
    ("b23.tv:443", "清单外 · B站短链(靠 IP 段兜)", "DIRECT"),
    ("biligame.com:443", "清单外 · B站游戏(靠 IP 段兜)", "DIRECT"),
    ("www.tianqi.com:443", "清单外 · 国内长尾(靠 IP 段兜)", "DIRECT"),
    ("www.google.com:443", "国外 · 必须走节点", "代理"),
]


def part5() -> None:
    print("\n[5] fake-ip 场景(与产物同款 DNS 配置)")
    subprocess.run(["taskkill", "/F", "/IM", "mihomo.exe"],
                   capture_output=True, text=True, timeout=30)
    time.sleep(1.2)
    port = MIXED + 10
    cfg = {
        "mixed-port": port, "allow-lan": False, "mode": "rule", "log-level": "info",
        "ipv6": False, "geo-auto-update": False, "find-process-mode": "off",
        # 与 build_clash 生成的产物一致
        "dns": {
            "enable": True, "ipv6": False,
            "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
            "fake-ip-filter": ["*.lan", "*.local", "*.localdomain",
                               "localhost.ptlogin2.qq.com", "time.*.com"],
            "default-nameserver": ["223.5.5.5", "119.29.29.29"],
            "nameserver": ["223.5.5.5", "119.29.29.29", "https://doh.pub/dns-query"],
        },
        "proxies": [{"name": "p", "type": "ss", "server": "198.51.100.9",
                     "port": 8388, "cipher": "aes-128-gcm", "password": "pw"}],
        "proxy-groups": [{"name": "G", "type": "select", "proxies": ["p"]}],
        "rules": list(sec.SECURITY_RULES) + ["MATCH,G"],
    }
    p = WORK / "cn-fakeip.yaml"
    p.write_text(pool._dump_yaml(cfg), encoding="utf-8")

    logf = WORK / "cn-fakeip.log"
    with open(logf, "wb") as fh:
        proc = subprocess.Popen([str(KERNEL), "-d", str(WORK), "-f", str(p)],
                                stdout=fh, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, cwd=str(WORK),
                                creationflags=0x08000000)
        time.sleep(3.0)
        for target, _, _ in FAKEIP_PROBES:
            for _t in range(3):
                try:
                    c = socket.create_connection(("127.0.0.1", port), timeout=5)
                    c.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
                    c.close()
                    break
                except OSError:
                    time.sleep(0.8)
            time.sleep(0.15)
        time.sleep(8)
        proc.kill()
        proc.wait(timeout=10)

    log = logf.read_text(encoding="utf-8", errors="replace")
    for target, note, want in FAKEIP_PROBES:
        ma = re.search(r"--> " + re.escape(target) + r" match ([^ ]+) using (\S+?)\"", log)
        if ma:
            rule, action = ma.group(1), ma.group(2)
        else:
            mb = re.search(r"dial (\S+) \(match ([^)]*)\)[^\n]*--> " + re.escape(target), log)
            if not mb:
                check(f"{target:<38} {note}", False, "<日志里没有裁决行>")
                continue
            action, rule = mb.group(1), mb.group(2)
        ok = (action not in ("DIRECT", "REJECT")) if want == "代理" else (action == want)
        check(f"{target:<38} {note:<26} {rule} -> {action}", ok, "" if ok else f"期望 {want}")


# --------------------------------------------------------------------------
# [4] 产物端到端
# --------------------------------------------------------------------------
def part4() -> None:
    print("\n[4] 产物端到端(build_clash -> 内核校验)")
    nodes = [
        {"name": f"节点{i}", "type": "ss", "server": f"198.51.100.{i}",
         "port": 8388, "cipher": "aes-128-gcm", "password": "pw", "_region": "US"}
        for i in range(1, 6)
    ]
    text = pool.build_clash(nodes, "freeVPN · 测试")
    p = WORK / "freevpn.yaml"
    p.write_text(text, encoding="utf-8")
    check("产物含国内 IP 规则", "IP-CIDR,1.0.1.0/24,DIRECT" in text)
    check("产物含国内域名规则", "DOMAIN-SUFFIX,baidu.com,DIRECT" in text)
    check("产物头注释写明国内分流", "国内分流" in text.splitlines()[2], text.splitlines()[2][:70])
    check("产物顶层键未被污染", "tun" not in [ln.split(":")[0].strip('"') for ln in text.splitlines()])

    r = subprocess.run([str(KERNEL), "-d", str(WORK), "-f", str(p), "-t"],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", cwd=str(WORK), timeout=180)
    check("产物被内核接受", r.returncode == 0, f"{len(text) // 1024} KB")
    if r.returncode != 0:
        print("     " + ((r.stdout or "") + (r.stderr or "")).strip()[-400:])

    # 对照: off 模式回到原样, 用来确认"大出来的体积"确实来自国内规则
    saved = sec.SECURITY_RULES
    try:
        sec.SECURITY_RULES = sec.build_security_rules(cn_mode="off")
        off_text = pool.build_clash(nodes, "freeVPN · 测试")
    finally:
        sec.SECURITY_RULES = saved
    print(f"     产物 {len(text) // 1024} KB (关掉国内规则时 {len(off_text) // 1024} KB)")
    check("国内规则确实是体积来源", len(text) > len(off_text) + 200_000)


def main() -> int:
    print("=" * 78)
    print("  freeVPN · 国内分流规则验证")
    print("=" * 78)
    part1()
    part2()
    part3()
    part4()
    part5()
    print("\n" + "=" * 78)
    print(f"  通过 {len(PASS)} / 失败 {len(FAIL)}")
    for f in FAIL:
        print(f"    FAIL: {f}")
    print("=" * 78)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
