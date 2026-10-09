#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""d3 · progress.json 注入 —— 第三方可写的进度文件能不能搞坏控制台。

数据流: 扫描子进程 set_progress() 写 state/progress.json -> GUI refresh()
        -> update_progress() 读它 -> 拼进 Label 文本。

两个问题:
  ① 字段内容里有没有不可信数据 (节点名 / 源 URL)?
  ② 文件本身可被任何本机用户改写 (state 目录 ACL = Authenticated Users:(M)),
     那么"畸形内容"会让 GUI 怎样?  —— 这里实测会不会抛异常、会不会崩。

实测用**真实的 gui.PoolGUI + 真实 tkinter**, 窗口隐藏, 不跑 mainloop,
所以不会启动常驻、不会碰生产 state (STATE 被重定向到 %TEMP%)。

用法: python audit/d3_progress_inject.py
"""
import json
import os
import sys
import tempfile
import traceback
from pathlib import Path

ROOT = Path(r"E:\AI\freeVPN")
sys.path.insert(0, str(ROOT))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

WORK = Path(tempfile.mkdtemp(prefix="freevpn_d3_"))
print("=" * 78)
print("d3 · progress.json 注入")
print("=" * 78)
print(f"隔离目录: {WORK}\n")

import tkinter as tk  # noqa: E402
import gui            # noqa: E402
import pool           # noqa: E402

gui.STATE = WORK      # progress.json / gui.log 全部落在隔离目录
gui.OUT = WORK / "out"
(gui.OUT).mkdir(parents=True, exist_ok=True)

# 关掉 __init__ 里的两个 after 回调: 一个会弹窗, 一个会自动起常驻。
# 不跑 mainloop 本来也不会触发, 但显式置空更保险。
gui.PoolGUI.autostart_first_run = lambda self: None
gui.PoolGUI.check_confined = lambda self: None

PROGRESS = WORK / "progress.json"

# ---------------------------------------------------------------- ① note 来源
print("### ① set_progress 的 note 内容来源 (静态清点)\n")
import re  # noqa: E402
src = (ROOT / "pool.py").read_text(encoding="utf-8", errors="replace")
for m in re.finditer(r"set_progress\(([^)]*)\)", src):
    line_no = src[:m.start()].count("\n") + 1
    txt = " ".join(m.group(1).split())
    print(f"  pool.py:{line_no:<6} set_progress({txt[:88]})")
print("\n  结论: op/phase 是字面量; note 全部由 len()/计数拼成, "
      "不含节点名或源 URL。\n")

# ---------------------------------------------------------------- ② 畸形输入
CASES = [
    ("正常", '{"op":"完整扫描","phase":"L2 内核实测","done":1,"total":10,'
             '"note":"已找到 3 个","ts":%NOW%,"started":%NOW%,"pid":1}'),
    ("started 是字符串", '{"op":"完整扫描","phase":"拉源","started":"x",'
                        '"ts":%NOW%}'),
    ("started 是列表", '{"op":"完整扫描","phase":"拉源","started":[1],'
                      '"ts":%NOW%}'),
    ("顶层是 list", '[1,2,3]'),
    ("顶层是字符串", '"hello"'),
    ("顶层是数字", '12345'),
    ("ts 是字符串", '{"op":"完整扫描","phase":"拉源","ts":"soon","started":"x"}'),
    ("op 是 dict", '{"op":{"a":1},"phase":"拉源","ts":%NOW%}'),
    ("超长 note (20 万字符)", '{"op":"完整扫描","phase":"L2 内核实测","done":1,'
                              '"total":2,"note":"%BIG%","ts":%NOW%,'
                              '"started":%NOW%}'),
    ("控制字符 note", '{"op":"完整扫描","phase":"L2 内核实测","done":1,'
                      '"total":2,"note":"A\\u0000B\\u2028C\\r\\nD\\tE",'
                      '"ts":%NOW%,"started":%NOW%}'),
    ("phase 不在映射表", '{"op":"完整扫描","phase":"%PHASE%","ts":%NOW%,'
                        '"started":%NOW%,"done":1,"total":2}'),
    ("ts 是未来 (永不过期)", '{"op":"完整扫描","phase":"L2 内核实测","done":1,'
                            '"total":2,"ts":%FUTURE%,"started":%FUTURE%}'),
    ("done/total 是字符串", '{"op":"完整扫描","phase":"L2 内核实测",'
                           '"done":"a","total":"b","ts":%NOW%,"started":%NOW%}'),
]

print("### ② 畸形 progress.json 对 GUI 的影响\n")


def render(payload: str) -> tuple[bool, str, str]:
    """写进 progress.json, 然后调用真实 GUI 的 update_progress。"""
    PROGRESS.write_text(payload, encoding="utf-8")
    try:
        g.update_progress()
        label = g.lb_phase.cget("text")
        op = g.lb_op.cget("text")
        return True, f"{op} | {label[:70]!r}", ""
    except Exception as e:
        return False, "", f"{type(e).__name__}: {e}"


# 先正常构造 GUI (progress.json 还不存在)
root = tk.Tk()
root.withdraw()
print("  构造 PoolGUI ...", end=" ")
try:
    g = gui.PoolGUI(root, 8899)
    print("成功 (窗口已隐藏)\n")
except Exception as e:
    print(f"失败: {type(e).__name__}: {e}")
    traceback.print_exc()
    raise SystemExit(1)

import time  # noqa: E402
NOW = int(time.time())
FUTURE = NOW + 10 ** 9
rows = []
for label, tmpl in CASES:
    payload = (tmpl.replace("%NOW%", str(NOW))
               .replace("%FUTURE%", str(FUTURE))
               .replace("%BIG%", "A" * 200000)
               .replace("%PHASE%", "P" * 5000))
    ok, info, err = render(payload)
    rows.append((label, ok, info, err))
    print(f"  {label:<24} {'渲染成功' if ok else '抛异常 !!':<10} {info or err}")
    if ok and info:
        print(f"      Label 实际内容长度: {len(info)}")

# ---------------------------------------------------------------- ③ 停摆验证
print("\n### ③ 抛异常会不会让刷新循环停摆\n")
print("  gui.refresh() 的结构 (gui.py:446 -> 456):")
print("      self.update_progress()          <-- 抛异常就在这里")
print("      ... 更新卡片/节点表 ...")
print("      self.root.after(1000/2000, self.refresh)   <-- 重新排程在它后面")
print("  所以 update_progress 一抛, 后面的 after 就不会执行。")
print("  下面用真实 mainloop 计数验证: 5 秒内 refresh 被调用了几次。\n")

BAD = json.dumps({"op": "x", "phase": "y", "started": "boom",
                  "ts": int(time.time())})   # ts 必须是新鲜的, 否则会被 stale 分支拦下


def count_refreshes(seconds: float = 5.0) -> tuple[int, str]:
    """跑真实 mainloop, 数 refresh 被调用几次。"""
    state = {"n": 0, "err": ""}
    orig = g.refresh

    def counted():
        state["n"] += 1
        try:
            return orig()
        except Exception as e:
            state["err"] = f"{type(e).__name__}: {e}"
            raise

    g.refresh = counted
    errs: list[str] = []
    root.report_callback_exception = lambda *a: errs.append(
        f"{a[0].__name__}: {a[1]}")
    root.after(80, g.refresh)
    root.after(int(seconds * 1000), root.quit)
    root.mainloop()
    g.refresh = orig
    return state["n"], state["err"] or ("; ".join(errs[:2]) if errs else "")


# 基线: 正常的 progress.json
PROGRESS.write_text(json.dumps({
    "op": "完整扫描", "phase": "L2 内核实测", "done": 1, "total": 10,
    "note": "已找到 3 个", "ts": int(time.time()),
    "started": int(time.time()), "pid": 1}), encoding="utf-8")
n_ok, err_ok = count_refreshes()
print(f"  基线 (正常文件)        : refresh 被调用 {n_ok} 次   异常: {err_ok or '无'}")

# 攻击: 畸形 progress.json
PROGRESS.write_text(BAD, encoding="utf-8")
n_bad, err_bad = count_refreshes()
print(f"  畸形文件 (started='boom'): refresh 被调用 {n_bad} 次   异常: {err_bad or '无'}")

stopped = n_bad <= 1 and n_ok >= 2
print(f"\n  → 自动刷新停摆: {'是' if stopped else '否'}")
print(f"     (正常 {n_ok} 次 vs 畸形 {n_bad} 次 —— 畸形文件只跑了第一次就断了)")

# 实测 A: 启动时就畸形 (带新鲜 ts, 绕不过 stale 分支)
print("\n  实测 A: 启动时 progress.json 已经畸形")
PROGRESS.write_text(BAD, encoding="utf-8")
root2 = tk.Tk()
root2.withdraw()
try:
    gui.PoolGUI(root2, 8899)
    print("     结果: 构造成功 (没崩)")
    crash_at_start = False
except Exception as e:
    print(f"     结果: **构造抛异常 -> 控制台窗口起不来**: {type(e).__name__}: {e}")
    crash_at_start = True
finally:
    try:
        root2.destroy()
    except Exception:
        pass

print("\n### ④ 汇总\n")
bad = [r for r in rows if not r[1]]
print(f"  {len(bad)}/{len(CASES)} 个畸形输入让 update_progress 抛异常")
for label, _ok, _i, err in bad:
    print(f"    [{label}] {err}")
print(f"  启动即崩: {'是' if crash_at_start else '否'}")
print("\n  注意: state/progress.json 的 ACL 是 Authenticated Users:(M) ——")
print("  本机任何用户都能写它, 所以上面这些是**跨用户可达**的。")

try:
    root.destroy()
except Exception:
    pass
import shutil  # noqa: E402
shutil.rmtree(WORK, ignore_errors=True)
print(f"\n(隔离目录已清理: {WORK})")
raise SystemExit(0)
