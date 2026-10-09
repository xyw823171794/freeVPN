# -*- coding: utf-8 -*-
"""生成 cn_cidr.txt —— 第⑤层分流规则用的中国大陆 IP 段。

为什么需要它: 产物规则的兜底是 `MATCH,🚀 节点选择`。在这份数据缺席时,
**所有未命中敏感清单的流量(含全部国内站点)都会进免费节点** —— 节点持有者
能看到你访问了哪些国内服务, 国内站点还会因为境外 IP 触发风控/异地登录。
见 security.py 第⑤层。

为什么内联 CIDR 而不是 `GEOIP,CN`: 后者要客户端本地有 MMDB/dat 文件,
缺失时内核**直接拒绝整份配置**(实测 90 秒超时 "test failed"), 订阅会整体
失效。内联 5000 多条 IP-CIDR 只是让产物大 ~230 KB, 换"一定加载得起来"。

数据源是 APNIC 官方委托文件, 只取 allocated/assigned 且地址数为 2 的幂的记录,
聚合相邻段后落盘。域名侧的数据在 cn_domains.txt(手工维护, 不从 geosite 抄 ——
本机那份 geosite:cn 有 11 万条, 里面混着 `0000f0deb5f4e6c3.com` 这类噪音)。

重新生成:
    python state/gen-cn-rules.py
    python state/gen-cn-rules.py --apnic state/delegated-apnic-latest.txt   # 离线
"""
from __future__ import annotations

import argparse
import datetime
import ipaddress
import pathlib
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
APNIC_URL = "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"


def _prefix_v4(count: int) -> int:
    """APNIC 的 ipv4 字段给的是地址**数量**(2 的幂), 换算成前缀长度。"""
    return 32 - (count - 1).bit_length()


def parse_apnic(text: str, code: str = "CN") -> tuple[list, list]:
    v4, v6 = [], []
    for ln in text.splitlines():
        if ln.startswith("#") or "|" not in ln:
            continue
        f = ln.split("|")
        if len(f) < 7 or f[1].strip().upper() != code:
            continue
        if f[6].strip() not in ("allocated", "assigned"):
            continue
        try:
            if f[2] == "ipv4":
                n = int(f[4])
                if n < 1 or n & (n - 1):
                    continue          # 不是 2 的幂: 数据变了, 宁可丢也不猜
                v4.append(ipaddress.ip_network(f"{f[3]}/{_prefix_v4(n)}", strict=False))
            elif f[2] == "ipv6":
                v6.append(ipaddress.ip_network(f"{f[3]}/{int(f[4])}", strict=False))
        except ValueError:
            continue
    return v4, v6


def load_apnic(local: str | None) -> str:
    if local:
        return pathlib.Path(local).read_text(encoding="utf-8", errors="replace")
    print(f"[*] 拉取 {APNIC_URL} ...")
    req = urllib.request.Request(APNIC_URL, headers={"User-Agent": "freeVPN/gen-cn-rules"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return r.read().decode("utf-8", "replace")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apnic", help="本地 delegated-apnic-latest 文件(不联网)")
    ap.add_argument("--out", default=str(ROOT), help="输出目录")
    ap.add_argument("--code", default="CN", help="国家码")
    args = ap.parse_args()

    code = args.code.upper()
    raw4, raw6 = parse_apnic(load_apnic(args.apnic), code)
    col4 = sorted(ipaddress.collapse_addresses(raw4), key=lambda n: int(n.network_address))
    col6 = sorted(ipaddress.collapse_addresses(raw6), key=lambda n: int(n.network_address))
    pct = sum(n.num_addresses for n in col4) / 2 ** 32
    print(f"[*] {code} IPv4: {len(raw4)} 条委托 -> 聚合 {len(col4)} 条 ({pct:.2%} v4 空间)")
    print(f"[*] {code} IPv6: {len(raw6)} 条委托 -> 聚合 {len(col6)} 条")

    lines = [
        f"# freeVPN · {code} IP 段 (第⑤层分流规则的数据源, 每行一个 CIDR)",
        "# 来源: APNIC delegated-apnic-latest (ftp.apnic.net), 只取 allocated/assigned",
        f"# 生成: {datetime.date.today().isoformat()}   "
        f"IPv4 {len(col4)} 条 / IPv6 {len(col6)} 条 (已聚合相邻段)",
        "# 重新生成: python state/gen-cn-rules.py",
        "# 用途: 国内 IP 的连接直连, 永不进免费节点 —— 见 security.py 第⑤层",
        "#",
        "# [ipv4]",
    ]
    lines += [str(n) for n in col4]
    lines += ["#", "# [ipv6]"]
    lines += [str(n) for n in col6]

    p = pathlib.Path(args.out) / "cn_cidr.txt"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[+] {p}  {p.stat().st_size / 1024:.0f} KB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
