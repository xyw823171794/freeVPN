#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一次性工具: 从聚合清单里挖出可用订阅源, 验证后输出候选清单。
   HTTP/SOCKS 代理列表会被剔除 —— 那不是翻墙节点, 混进来会污染池子。"""
import concurrent.futures as cf
import re
import sys
import urllib.request

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LIST_SOURCES = [
    "https://ghfast.top/https://raw.githubusercontent.com/lza6/free-VPN/main/README.md",
]
UA = "clash-verge/v2.2.3 (freeVPN)"

# 明显的 HTTP/SOCKS 裸代理列表, 排除
DROP_PAT = re.compile(
    r"(socks4|socks5|/http\.txt|hideip|proxy_list|http\.txt|allive|proxy-scraper)", re.I)
# 需要的: 真节点订阅
KEEP_PAT = re.compile(
    r"(v2ray|clash|vmess|vless|trojan|ss\.txt|sub|node|proxy|config|list|mix|free|meta|share)",
    re.I)


def norm(u: str) -> str | None:
    u = u.strip().rstrip(").,;\"'")
    u = u.split("#")[0]
    if not u.startswith("http"):
        return None
    m = re.match(r"https://github\.com/([^/]+)/([^/]+)/(?:blob|raw)/([^/]+)/(.+)", u)
    if m:
        u = f"https://raw.githubusercontent.com/{m.group(1)}/{m.group(2)}/{m.group(3)}/{m.group(4)}"
    if "raw.githubusercontent.com" in u or "jsdelivr" in u or "gist.githubusercontent" in u \
       or "github.io" in u or "ghfast.top" in u or "gh-proxy" in u:
        return u
    return None


def fetch(u: str, timeout: int = 25):
    req = urllib.request.Request(u, headers={"User-Agent": UA, "Accept-Encoding": "identity"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(400_000)
        return u, len(body), body
    except Exception as e:
        return u, -1, str(e).encode()


def main():
    cands: set[str] = set()
    for ls in LIST_SOURCES:
        try:
            req = urllib.request.Request(ls, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=40) as r:
                txt = r.read().decode("utf-8", "replace")
        except Exception as e:
            print(f"[!] 清单拉取失败 {ls}: {e}")
            continue
        for m in re.finditer(r"https?://[^\s\)\]\"'<>]+", txt):
            n = norm(m.group(0))
            if n and not DROP_PAT.search(n) and KEEP_PAT.search(n):
                cands.add(n)
    print(f"[*] 候选 {len(cands)} 条, 开始并发验证 ...\n")

    ok = []
    with cf.ThreadPoolExecutor(max_workers=24) as ex:
        for u, size, body in ex.map(fetch, sorted(cands)):
            if size <= 0:
                continue
            head = body[:4000].decode("utf-8", "replace")
            # 必须是节点内容, 不能是 README 之类
            looks = ("://" in head) and re.search(
                r"(vmess|vless|trojan|ss|hysteria2?|tuic)://|proxies:", head, re.I)
            if not looks:
                continue
            ok.append((size, u))
            print(f"  OK {size/1024:>7.1f}KB  {u}")
    ok.sort(reverse=True)
    print(f"\n[✓] 可用 {len(ok)} 条")
    out = "\n".join(u for _s, u in ok)
    with open(r"E:\AI\freeVPN\state\candidates_ok.txt", "w", encoding="utf-8") as f:
        f.write(out + "\n")
    print("已写入 state/candidates_ok.txt")


if __name__ == "__main__":
    main()
