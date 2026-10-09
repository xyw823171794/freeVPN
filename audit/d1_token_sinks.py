#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""d1 · 令牌落盘点穷举 + 每个落盘点的 ACL 分级。

审计问题: state/token.txt 的 ACL 被收紧到 SYSTEM+当前用户, 但令牌明文出现在
别处。要回答两件事:
  ① 到底有多少个文件含令牌明文 (穷举, 不是抽样)
  ② 每个文件的 ACL 是否比 token.txt 宽松 —— 宽松 = 别的本机用户能读走令牌

同时列出**目录**的 ACL: 文件级收紧挡不住"目录可删文件"——
把 token.txt 删掉再建一个自己知道内容的, 令牌就被替换了。

本脚本**只读**, 不写任何被审计的文件。
用法: python audit/d1_token_sinks.py
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(r"E:\AI\freeVPN")
sys.path.insert(0, str(ROOT))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import security as sec  # noqa: E402

VERGE = Path(os.environ.get("APPDATA", "")) / "io.github.clash-verge-rev.clash-verge-rev"
LOCAL = Path(os.environ.get("LOCALAPPDATA", ""))

# 部署位置 -> 该位置自己的 token.txt
DEPLOYMENTS = {
    "源码版 E:\\AI\\freeVPN": ROOT,
    "打包版 C:\\freeVPN": Path(r"C:\freeVPN"),
    "dist 版 E:\\AI\\freeVPN\\dist\\freeVPN": ROOT / "dist" / "freeVPN",
}

# 额外要扫的外部落点 (浏览器历史 / 剪贴板历史 / Clash Verge 配置)
EXTRA_ROOTS = {
    "Clash Verge 配置目录": VERGE,
    "剪贴板历史(持久化)": LOCAL / "Microsoft" / "Windows" / "Clipboard",
    "活动时间线 ActivitiesCache": LOCAL / "ConnectedDevicesPlatform",
    "Chrome 历史": LOCAL / "Google" / "Chrome" / "User Data" / "Default",
    "Edge 历史": LOCAL / "Microsoft" / "Edge" / "User Data" / "Default",
}

BIN_EXT = {".exe", ".dll", ".pyd", ".png", ".jpg", ".ico", ".zip", ".so",
           ".lib", ".db", ".mmdb", ".dat", ".pdb", ".ttf", ".bin"}
MAX_BYTES = 60 * 1024 * 1024


def icacls(path: Path) -> list[str]:
    """返回 icacls 的 ACE 行(去掉成功统计行)。"""
    try:
        r = subprocess.run(["icacls", str(path)], capture_output=True, text=True,
                           encoding=sec.console_encoding(), errors="replace",
                           timeout=25, creationflags=sec.hidden_flags())
    except Exception as e:
        return [f"<icacls 失败: {e}>"]
    out = []
    for ln in (r.stdout or "").splitlines():
        s = ln.strip()
        # icacls 的中文版会把成功统计行也打出来("已成功处理 1 个文件..."),
        # 只认真正的 ACE 行 —— 它们一定带 "主体:(权限)" 结构。
        if not s or ":(" not in s:
            continue
        out.append(s)
    return out


def _principal(ace: str) -> str:
    """从 icacls 的一行里抽出主体名。icacls 的格式是 `主体:(权限)`。"""
    return ace.split(":(")[0].strip()


def _is_privileged(principal: str) -> bool:
    """主体是不是"受信任的少数" —— SYSTEM / Administrators / 当前用户 / 完整性标签。"""
    p = principal.lower()
    if "mandatory label" in p or "owner rights" in p:
        return True
    if "nt authority\\system" in p or p.endswith("\\system"):
        return True
    if "administrators" in p:
        return True
    user = (os.environ.get("USERNAME") or "").lower()
    if user and p.endswith("\\" + user):
        return True
    return False


def acl_grade(path: Path) -> tuple[str, str]:
    """把 ACL 归成 收紧 / 宽松 / 未知。

    判据不看具体组名(机器上可能有自定义组, 硬编码会漏), 而是看
    **有没有当前用户/SYSTEM/Administrators 之外的主体**。有 -> 宽松。
    """
    aces = icacls(path)
    extra = []
    for a in aces:
        pr = _principal(a)
        if not pr:
            continue
        if not _is_privileged(pr):
            extra.append(a)
    if extra:
        return "宽松", " | ".join(extra)
    if any("SYSTEM" in a for a in aces):
        return "收紧", " | ".join(aces)
    return "未知", " | ".join(aces)


def scan_file(p: Path, needles: list[bytes]) -> dict:
    try:
        b = p.read_bytes()
    except Exception:
        return {}
    hits = {n.decode("utf-8", "replace"): b.count(n) for n in needles if b.count(n)}
    return hits or {}


def main() -> int:
    print("=" * 78)
    print("d1 · 令牌落盘点穷举 + ACL 分级")
    print("=" * 78)

    findings: list[dict] = []
    tokens: dict[str, str] = {}

    # ---- ① 各部署位置自己的令牌 ----
    print("\n### ① 各部署位置的 token.txt\n")
    for label, base in DEPLOYMENTS.items():
        tf = base / "state" / "token.txt"
        if not tf.exists():
            print(f"  {label:<40} 无 token.txt")
            continue
        tok = tf.read_text(encoding="utf-8", errors="replace").strip()
        tokens[label] = tok
        grade, detail = acl_grade(tf)
        print(f"  {label}")
        print(f"      token.txt  {tf}")
        print(f"      长度 {len(tok)}  前缀 {tok[:6]}...  ACL={grade}")
        for d in detail.split(" | "):
            print(f"          {d}")

    # ---- ② 每个部署位置内部穷举 ----
    print("\n### ② 部署位置内部穷举 (字节级搜索)\n")
    for label, base in DEPLOYMENTS.items():
        tok = tokens.get(label)
        if not tok:
            continue
        nb = tok.encode("utf-8")
        print(f"  --- {label}   (令牌 {tok[:6]}...)")
        scanned = 0
        for p in base.rglob("*"):
            try:
                if not p.is_file():
                    continue
                if p.suffix.lower() in BIN_EXT:
                    continue
                if p.stat().st_size > MAX_BYTES:
                    continue
            except Exception:
                continue
            scanned += 1
            hits = scan_file(p, [nb])
            if hits:
                grade, detail = acl_grade(p)
                rel = p.relative_to(base)
                print(f"      [命中 {hits[tok]:>3} 次] {rel}   ACL={grade}")
                if grade == "宽松":
                    print(f"          {detail[:150]}")
                findings.append({
                    "deployment": label, "file": str(p), "count": hits[tok],
                    "acl": grade, "acl_detail": detail,
                    "rel": str(rel),
                })
        print(f"      (扫了 {scanned} 个文本文件)")

    # ---- ③ 外部落点 ----
    print("\n### ③ 外部落点 (浏览器历史 / 剪贴板 / Clash Verge 配置)\n")
    all_tokens = [t for t in tokens.values() if t]
    for label, base in EXTRA_ROOTS.items():
        if not base.exists():
            print(f"  {label:<34} (不存在)")
            continue
        n_hit = 0
        n_scan = 0
        for p in base.rglob("*"):
            try:
                if not p.is_file() or p.stat().st_size > MAX_BYTES:
                    continue
            except Exception:
                continue
            n_scan += 1
            try:
                b = p.read_bytes()
            except Exception:
                continue
            for tok in all_tokens:
                if tok.encode("utf-8") in b:
                    grade, detail = acl_grade(p)
                    print(f"  [{label}] {p}")
                    print(f"      令牌 {tok[:6]}... 命中 {b.count(tok.encode('utf-8'))} 次  ACL={grade}")
                    findings.append({
                        "deployment": label, "file": str(p),
                        "count": b.count(tok.encode("utf-8")),
                        "acl": grade, "acl_detail": detail, "rel": str(p),
                    })
                    n_hit += 1
                    break
        print(f"  {label:<34} 扫 {n_scan} 个文件, 命中 {n_hit}")

    # ---- ④ 目录级 ACL (文件级收紧能否被绕过) ----
    print("\n### ④ 目录级 ACL —— 文件收紧挡不住目录删除权\n")
    for label, base in DEPLOYMENTS.items():
        for d in (base, base / "state"):
            if not d.exists():
                continue
            grade, detail = acl_grade(d)
            print(f"  {label} :: {d.name or d}  ACL={grade}")
            for x in detail.split(" | "):
                print(f"      {x}")

    # ---- ⑤ 汇总 ----
    print("\n### ⑤ 汇总\n")
    loose = [f for f in findings if f["acl"] == "宽松"]
    print(f"  含令牌的文件共 {len(findings)} 个, 其中 ACL 宽松 {len(loose)} 个")
    for f in loose:
        print(f"    [{f['acl']}] {f['rel']}  ({f['count']} 次)")

    out = Path(os.environ.get("TEMP", ".")) / "freevpn_d1_result.json"
    try:
        out.write_text(json.dumps(findings, ensure_ascii=False, indent=2),
                       encoding="utf-8")
        print(f"\n  (明细已写 {out})")
    except Exception as e:
        print(f"\n  (写明细失败: {e})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
