#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""发现候选节点源: 用 GitHub API 列出仓库文件, 挑出像订阅的。

抄一份网上的源列表塞进 sources.txt 是没用的 —— 得先确认:
  ① 文件真的能拉到(不是 404 / 不是被删的分支)
  ② 内容真的能解析成节点(不是空文件 / 不是 HTML 错误页)
  ③ 节点不是全死的
这个脚本只做第 ① 步的候选发现, 后面两步由 test-new-sources.py 做。
"""
import json
import sys
import urllib.error
import urllib.request

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

REPOS = [
    "Au1rxx/free-vpn-subscriptions",
    "ninjastrikers/nexus-nodes",
    "hamedcode/port-based-v2ray-configs",
    "cysk003/freeSub",
    "hans-thomas/v2ray-subscription",
    "SnapdragonLee/SystemProxy",
    "lza6/free-VPN",
    # 现有 sources.txt 里的备用源所属仓库, 顺便看看有没有更好的文件
    "xiaoji235/airport-free",
    "wuqb2i4f/xray-config-toolkit",
    "roosterkid/openproxylist",
    "mohamadfg-dev/telegram-v2ray-configs-collector",
    "igareck/vpn-configs-for-russia",
    "Kwinshadow/TelegramV2rayCollector",
    "LalatinaHub/Mineral",
    "mfbpn/tg_mfbpn_sub",
]

# 像订阅的文件名/路径特征
HINTS = ("sub", "node", "clash", "v2ray", "vless", "vmess", "trojan",
         "all", "mix", "list", "config", "yaml", "yml", "txt", "base64")
# 明确不要的
BAD = ("readme", "license", ".md", ".png", ".jpg", ".svg", ".gif",
       "package.json", ".gitignore", "workflow", "issue", "template",
       "requirement", ".py", ".js", ".ts", ".json", ".sh", ".bat", ".html")


def api(url: str):
    req = urllib.request.Request(url, headers={
        "User-Agent": "freeVPN-source-discovery",
        "Accept": "application/vnd.github+json",
    })
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


found = {}
for repo in REPOS:
    print(f"\n=== {repo} ===")
    try:
        info = api(f"https://api.github.com/repos/{repo}")
        branch = info.get("default_branch", "main")
        pushed = info.get("pushed_at", "?")
        size = info.get("size", 0)
        print(f"  默认分支 {branch}  最后推送 {pushed}  仓库 {size} KB")
    except Exception as e:
        print(f"  [跳过] 拿不到仓库信息: {type(e).__name__}")
        continue

    try:
        tree = api(f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1")
    except Exception as e:
        print(f"  [跳过] 拿不到文件树: {type(e).__name__}")
        continue

    blobs = [t for t in tree.get("tree", []) if t.get("type") == "blob"]
    cands = []
    for t in blobs:
        path = t["path"]
        low = path.lower()
        if any(b in low for b in BAD):
            continue
        if not any(h in low for h in HINTS):
            continue
        if t.get("size", 0) < 2000:          # 太小, 不像订阅
            continue
        cands.append((t.get("size", 0), path))
    cands.sort(reverse=True)
    print(f"  候选文件 {len(cands)} 个 (按大小):")
    for sz, path in cands[:6]:
        print(f"    {sz/1024:8.1f} KB  {path}")
        found.setdefault(repo, []).append(
            f"https://raw.githubusercontent.com/{repo}/{branch}/{path}")

print()
print("=" * 70)
print("候选 URL 汇总")
print("=" * 70)
out = []
for repo, urls in found.items():
    for u in urls:
        print(f"  {u}")
        out.append(u)

with open(r"E:\AI\freeVPN\state\candidates_new.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(out) + "\n")
print(f"\n共 {len(out)} 个, 已写入 state/candidates_new.txt")
