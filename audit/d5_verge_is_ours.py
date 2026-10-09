#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""d5 · inject_verge 的数据侧 —— profiles.yaml 读回来之后会发生什么。

三件事:
  ① is_ours() 按 URL 子串删除条目 —— 会不会误删用户自己的正常订阅?
  ② profiles.yaml 里的畸形字段会不会让导入直接崩 (未捕获异常)?
  ③ safe_load / safe_dump 往返会不会破坏用户的配置?

全部在 %TEMP% 下造一个假的 Clash Verge 配置目录来做, 不碰真实配置。
用法: python audit/d5_verge_is_ours.py
"""
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(r"E:\AI\freeVPN")
sys.path.insert(0, str(ROOT))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool          # noqa: E402
import security as sec  # noqa: E402

WORK = Path(tempfile.mkdtemp(prefix="freevpn_d5_"))
VERGE = WORK / "verge"
VERGE.mkdir(parents=True)

print("=" * 78)
print("d5 · inject_verge 的数据侧")
print("=" * 78)
print(f"假 Clash Verge 目录: {VERGE}\n")

# 把外部依赖钉住: 不碰真实客户端目录、不发网络请求、不当成"客户端在跑"
pool.find_verge_dir = lambda: VERGE
pool.probe_sub_url = lambda url, *a, **k: 200
pool.verge_running = lambda: False
pool.close_verge = lambda *a, **k: True
pool.relaunch_verge = lambda *a, **k: True

SUB = "http://127.0.0.1:8787/sub/pool.yaml?token=freevpn_realtoken_0123456789"

TEMPLATE = """# Profiles Config for Clash Verge
# 这是用户自己写的注释 —— 导入之后还在吗?
items:
{items}
current: {current}
"""


def write_idx(items: list[str], current: str = '"keep-me"') -> None:
    """用 YAML flow sequence 写, 免得缩进踩坑。"""
    body = ", ".join(items)
    (VERGE / "profiles.yaml").write_text(
        f"# Profiles Config for Clash Verge\n"
        f"# 这是用户自己写的注释 —— 导入之后还在吗?\n"
        f"items: [{body}]\ncurrent: {current}\n",
        encoding="utf-8")


def run_import(activate: bool = False) -> tuple[bool, str]:
    """跑真实的 inject_verge, 把 stdout 收起来。返回 (成功?, 输出)。"""
    import io
    import contextlib
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            ok = pool.inject_verge(SUB, activate=activate)
        return bool(ok), buf.getvalue()
    except Exception as e:
        return False, buf.getvalue() + f"\n!! 未捕获异常 {type(e).__name__}: {e}"


def items_after() -> list[dict]:
    import yaml
    d = yaml.safe_load((VERGE / "profiles.yaml").read_text(encoding="utf-8")) or {}
    return [x for x in (d.get("items") or []) if isinstance(x, dict)]


# ---------------------------------------------------------------- ① 误删
print("### ① is_ours() 的 URL 子串匹配 —— 会不会误删用户自己的条目\n")
print("  判据 (pool.py:2243-2248):")
print("      if it.get('name') == 'freeVPN': return True")
print("      return '127.0.0.1:<port>/sub/' in (it.get('url') or '')\n")

CASES = [
    ("用户自己的条目, url 指向本机 8787 的别的路径",
     '{"uid":"mine1","type":"remote","name":"我的机场",'
     '"url":"http://127.0.0.1:8787/sub/mine.yaml?token=usersecret"}'),
    ("用户把订阅转存到 CDN, URL 里带原地址",
     '{"uid":"mine2","type":"remote","name":"CDN 缓存",'
     '"url":"https://cdn.example.com/fetch?u=http://127.0.0.1:8787/sub/pool.yaml"}'),
    ("用户自己的本地 clash 服务, 恰好也监听 8787",
     '{"uid":"mine3","type":"remote","name":"local-clash",'
     '"url":"http://127.0.0.1:8787/sub/config.yaml"}'),
    ("完全不相关的条目 (对照)",
     '{"uid":"other","type":"remote","name":"另一个机场",'
     '"url":"https://example.com/sub?token=abc"}'),
]

def items_raw() -> list:
    import yaml
    d = yaml.safe_load((VERGE / "profiles.yaml").read_text(encoding="utf-8")) or {}
    return d.get("items") or []


def uids() -> list[str]:
    return [str(x.get("uid")) for x in items_raw() if isinstance(x, dict)]


def names() -> list[str]:
    return [str(x.get("name")) for x in items_raw() if isinstance(x, dict)]


for label, item in CASES:
    write_idx([item, '{"uid":"other","type":"remote","name":"另一个机场",'
                     '"url":"https://example.com/sub?token=abc"}'])
    before = names()
    ok, out = run_import()
    after = names()
    lost = [n for n in before if n not in after]
    print(f"  --- {label}")
    print(f"      导入前条目: {before}")
    print(f"      导入后条目: {after}   (import 返回 {ok})")
    print(f"      丢失的条目: {lost if lost else '无'}")

# ---------------------------------------------------------------- ② 畸形字段
print("\n### ② profiles.yaml 里的畸形字段会不会让导入崩\n")
MALFORMED = [
    ("url 是数字", '{"uid":"a","name":"x","url":12345}'),
    ("url 是布尔", '{"uid":"a","name":"x","url":true}'),
    ("url 是 null", '{"uid":"a","name":"x","url":null}'),
    ("url 是列表", '{"uid":"a","name":"x","url":[1,2]}'),
    ("items 是字符串", None),      # 特判: items 整体换成字符串
    ("items 是字典", None),
    ("条目是字符串", '"just a string"'),
    ("条目是数字", '42'),
]

for label, item in MALFORMED:
    if label == "items 是字符串":
        (VERGE / "profiles.yaml").write_text(
            'items: "hello"\ncurrent: x\n', encoding="utf-8")
    elif label == "items 是字典":
        (VERGE / "profiles.yaml").write_text(
            'items: {"a": 1, "b": 2}\ncurrent: x\n', encoding="utf-8")
    else:
        write_idx([item], current='null')
    ok, out = run_import()
    tail = [x for x in out.strip().splitlines() if x.strip()][-2:]
    print(f"  --- {label}")
    print(f"      返回 {ok}   {' | '.join(tail)[:150]}")

print("\n  items 被换掉之后的实际文件内容:")
for label in ("items 是字符串", "items 是字典"):
    if label == "items 是字符串":
        (VERGE / "profiles.yaml").write_text(
            'items: "hello"\ncurrent: x\n', encoding="utf-8")
    else:
        (VERGE / "profiles.yaml").write_text(
            'items: {"a": 1, "b": 2}\ncurrent: x\n', encoding="utf-8")
    ok, out = run_import()
    raw = (VERGE / "profiles.yaml").read_text(encoding="utf-8")
    print(f"  --- {label} -> 导入后:")
    for ln in raw.splitlines():
        if "items" in ln or "- " in ln or ln.strip().startswith("current"):
            print(f"        {ln}")

# ---------------------------------------------------------------- ③ 往返
print("\n### ③ safe_load -> safe_dump 往返损失\n")
ORIG = """# Profiles Config for Clash Verge
# 这段注释是用户手写的
defaults: &def
  option: {update_interval: 60}
items:
  - {uid: keep, type: remote, name: 保留, url: "https://x/y", option: *def}
current: keep
extra_field_user_added: 42
"""
(VERGE / "profiles.yaml").write_text(ORIG, encoding="utf-8")
ok, out = run_import()
after_raw = (VERGE / "profiles.yaml").read_text(encoding="utf-8")
print(f"  导入前 {len(ORIG.splitlines())} 行, 导入后 {len(after_raw.splitlines())} 行")
for probe in ("# 这段注释是用户手写的", "&def", "*def",
              "extra_field_user_added", "update_interval: 60"):
    print(f"      {probe!r:<32} 还在: {'是' if probe in after_raw else '**丢了**'}")

# 恶意 tag / 别名炸弹
print("\n### ④ safe_load 的恶意输入\n")
import yaml  # noqa: E402
EVIL = [
    ("python/object tag", "!!python/object/apply:os.system ['calc']"),
    ("python/name tag", "!!python/name:os.system"),
    ("别名炸弹 (有限版)",
     "a: &a [1,2,3]\nb: &b [*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b]\n"
     "d: &d [*c,*c,*c,*c]\ne: [*d,*d,*d,*d]\n"),
    ("深嵌套 (5000 层)", "a: " + "[" * 5000 + "]" * 5000),
]
for label, doc in EVIL:
    import time as _t
    t0 = _t.time()
    try:
        got = yaml.safe_load(doc)
        dt = _t.time() - t0
        size = len(json.dumps(got, default=str)) if got is not None else 0
        print(f"  {label:<22} 解析成功 {dt:.2f}s, 结果体积 {size} 字节")
    except Exception as e:
        dt = _t.time() - t0
        print(f"  {label:<22} 抛 {type(e).__name__} ({dt:.2f}s): {str(e)[:70]}")

shutil.rmtree(WORK, ignore_errors=True)
print(f"\n(隔离目录已清理: {WORK})")
raise SystemExit(0)
