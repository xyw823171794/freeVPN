# -*- coding: utf-8 -*-
"""
问题 6 验证: 分流规则覆盖度。
用 mihomo 的规则匹配日志做功能验证 (不是读代码猜):
把 SECURITY_RULES 原样喂给内核, 然后让 mixed-port 去连一批目标,
读日志里 "match XXX using YYY" 这一行, 得到内核的真实裁决。
所有探测并发发出, 之后统一等 18 秒再解析日志 (DIRECT 拨号失败要等超时)。
"""
import pathlib
import re
import socket
import subprocess
import sys
import time

sys.path.insert(0, r"E:\AI\freeVPN")
import pool
import security as sec

ROOT = pathlib.Path(r"E:\AI\freeVPN")
WORK = ROOT / "audit" / "_miwork6"
WORK.mkdir(parents=True, exist_ok=True)
MIXED = 17907

TARGETS = [
    # (目标, 说明, 期望)
    ("169.254.169.254:80", "云元数据共享 IP (AWS/Azure/GCP/华为/Oracle)", "REJECT"),
    ("100.100.100.200:80", "阿里云元数据", "应 REJECT, 至少不能走代理"),
    ("169.254.169.123:80", "链路本地同段非 .254", "DIRECT"),
    ("127.0.0.1:80", "回环", "DIRECT"),
    ("10.0.0.1:80", "RFC1918", "DIRECT"),
    ("172.16.0.1:80", "RFC1918", "DIRECT"),
    ("192.168.1.1:80", "RFC1918", "DIRECT"),
    ("100.64.0.1:80", "CGNAT 100.64/10", "DIRECT"),
    ("224.0.0.1:80", "IPv4 组播", "DIRECT"),
    ("255.255.255.255:80", "广播", "REJECT"),
    ("0.0.0.0:80", "0.0.0.0/8", "未覆盖?"),
    ("240.0.0.1:80", "240/4 保留", "未覆盖?"),
    ("192.0.0.1:80", "192.0.0.0/24 IETF", "未覆盖?"),
    ("192.0.2.1:80", "TEST-NET-1", "未覆盖?"),
    ("198.51.100.1:80", "TEST-NET-2", "未覆盖?"),
    ("203.0.113.1:80", "TEST-NET-3", "未覆盖?"),
    ("198.18.0.1:80", "198.18/15 基准测试段", "未覆盖?"),
    ("[::1]:80", "IPv6 回环 ::1", "未覆盖?"),
    ("[fd00::1]:80", "IPv6 ULA fd00::/8", "DIRECT"),
    ("[fe80::1]:80", "IPv6 链路本地", "DIRECT"),
    ("[2001:db8::1]:80", "IPv6 文档段", "未覆盖?"),
    ("[ff02::1]:80", "IPv6 组播", "未覆盖?"),
    ("8.8.8.8:80", "普通公网", "走代理"),
    ("www.icbc.com.cn:443", "工商银行", "DIRECT"),
    ("www.cmbchina.com:443", "招商银行", "DIRECT"),
    ("www.95588.com:443", "工行短域名", "DIRECT"),
    ("www.cmbc.com.cn:443", "民生银行", "清单里没有"),
    ("www.citicbank.com:443", "中信银行", "清单里没有"),
    ("www.bankofshanghai.com:443", "上海银行", "清单里没有"),
    ("www.jsbchina.cn:443", "江苏银行", "清单里没有"),
    ("www.webank.com:443", "微众银行", "清单里没有"),
    ("pay.weixin.qq.com:443", "微信支付", "清单里没有"),
    ("www.alipay.com:443", "支付宝", "DIRECT"),
    ("www.12306.cn:443", "铁路 12306", "DIRECT"),
    ("www.gov.cn:443", "政务", "DIRECT"),
    ("metadata.google.internal:80", "GCP 元数据域名", "REJECT"),
    ("metadata.tencentyun.com:80", "腾讯云元数据域名", "清单里没有"),
    ("metadata.azure.com:80", "Azure 元数据域名", "清单里没有"),
    ("metadata.google.internal.nip.io:80", "GCP 元数据域名绕过变体", "清单里没有"),
    ("nas.local:443", "内网域名", "DIRECT"),
]


def build_cfg() -> pathlib.Path:
    cfg = {
        "mixed-port": MIXED, "allow-lan": False, "mode": "rule", "log-level": "info",
        "proxies": [{"name": "p", "type": "ss", "server": "198.51.100.9",
                     "port": 8388, "cipher": "aes-128-gcm", "password": "pw"}],
        "proxy-groups": [{"name": "G", "type": "select", "proxies": ["p"]}],
        "rules": list(sec.SECURITY_RULES) + ["MATCH,G"],
    }
    p = WORK / "rules.yaml"
    p.write_text(pool._dump_yaml(cfg), encoding="utf-8")
    return p


def main():
    # 清掉可能残留的内核进程, 避免 mixed-port 被占导致后续探测全被拒
    subprocess.run(["taskkill", "/F", "/IM", "mihomo.exe"],
                   capture_output=True, text=True, timeout=30)
    time.sleep(1.5)
    cfg = build_cfg()
    r = subprocess.run([str(ROOT / "bin" / "mihomo.exe"), "-d", str(WORK), "-f", str(cfg),
                        "-t"], capture_output=True, text=True, encoding="utf-8",
                       errors="replace", cwd=str(WORK), timeout=120)
    print(f"规则条数: {len(sec.SECURITY_RULES)}; 内核校验退出码 {r.returncode}")
    print("   ", ((r.stdout or "") + (r.stderr or "")).strip().splitlines()[-1][:160])
    print()

    logf = WORK / "rules.log"
    with open(logf, "wb") as fh:
        proc = subprocess.Popen([str(ROOT / "bin" / "mihomo.exe"), "-d", str(WORK),
                                 "-f", str(cfg)], stdout=fh, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, cwd=str(WORK),
                                creationflags=0x08000000)
        time.sleep(3.5)
        for target, note, expect in TARGETS:
            ok = False
            for attempt in range(4):
                try:
                    c = socket.create_connection(("127.0.0.1", MIXED), timeout=5)
                    c.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
                    c.close()
                    ok = True
                    break
                except Exception as e:
                    time.sleep(0.8)
            if not ok:
                print(f"  !! {target} 发送失败 {e}")
            time.sleep(0.15)
        # mihomo 在拨号之前就写下 match 行, 等 6 秒足够
        print(f"已顺序发出 {len(TARGETS)} 个探测, 等 6 秒收日志 ...\n")
        time.sleep(6)
        proc.kill()
        proc.wait(timeout=10)

    log = logf.read_text(encoding="utf-8", errors="replace")
    print("=" * 104)
    print(f"  {'目标':<34}{'说明':<34}{'内核实际裁决'}")
    print("=" * 104)
    for target, note, expect in TARGETS:
        # 内核两种日志格式:
        #   info:  [TCP] src --> target match RULE using ACTION
        #   warn:  [TCP] dial ACTION (match RULE) src --> target error: ...
        ma = re.search(r"--> " + re.escape(target) + r" match (\S+) using (\S+?)\"", log)
        mb = re.search(r"dial (\S+) \(match ([^)]*)\)[^\n]*--> " + re.escape(target), log)
        if ma:
            verdict = f"{ma.group(1)}  ->  {ma.group(2)}"
        elif mb:
            verdict = f"{mb.group(2)}  ->  {mb.group(1)}"
        elif f"--> {target}" in log:
            verdict = "<出现但无 match 行>"
        else:
            verdict = "<完全没出现>"
        print(f"  {target:<34}{note:<34}{verdict}")
    print()
    print("规则原文:")
    for r_ in sec.SECURITY_RULES:
        print("   ", r_)


if __name__ == "__main__":
    main()
