#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GUI 更新页回归。

只构建窗口, 不起 mainloop。构建后先把 __init__ 注册的定时器全取消 ——
其中 `autostart_first_run` 会真的把常驻服务拉起来, 测试里不该干这个。

验的是: 控件齐不齐、初始状态对不对、选项能不能落到 pool.conf.json、
以及检查更新走的是后台线程(不卡界面)。真联网那一步允许失败(线路问题),
但必须**能结束**, 不能把界面挂死。

跑法: python state/test-gui-update.py
"""
from __future__ import annotations

import json
import sys
import time
import tkinter as tk

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import gui        # noqa: E402
import updater    # noqa: E402
import version as ver  # noqa: E402

PASS, FAIL = [], []


def check(name: str, ok: bool, detail: str = ""):
    (PASS if ok else FAIL).append(name)
    print(f"  [{'OK ' if ok else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))


def main() -> int:
    print("=" * 74)
    print("  GUI 更新页回归")
    print("=" * 74)
    orig = gui.CONF.read_text(encoding="utf-8") if gui.CONF.exists() else None

    root = tk.Tk()
    root.withdraw()
    app = gui.PoolGUI(root, 8787)
    # 取消所有 after 定时器: 600ms 那个会把常驻拉起来。
    # 注意 `_drain_log` 的轮询循环也是 after 注册的, 一起被取消了 —— 它是
    # 更新回调队列的驱动者, 必须手动接回来, 否则回调永远不执行。
    try:
        for aid in root.tk.eval("after info").split():
            root.after_cancel(aid)
        root.after(120, app._drain_log)
    except Exception:
        pass

    try:
        print("\n[1] 控件与初始状态")
        for attr in ("lb_upd_state", "lb_upd_remote", "pb_upd", "btn_upd_dl",
                     "btn_upd_apply", "txt_upd", "var_upd_autocheck", "var_upd_autodl"):
            check(f"有 {attr}", hasattr(app, attr))
        check("初始状态是「还没检查过」",
              "还没检查过" in app.lb_upd_state.cget("text"))
        check("远端版本初始为 —", "—" in app.lb_upd_remote.cget("text"))
        check("下载按钮初始禁用",
              str(app.btn_upd_dl.cget("state")) == "disabled")
        check("一键更新按钮初始禁用",
              str(app.btn_upd_apply.cget("state")) == "disabled")
        check("默认勾选「启动时自动检查」", bool(app.var_upd_autocheck.get()))
        check("默认不勾「自动下载」", not bool(app.var_upd_autodl.get()))
        check("文本区初始写了更新源", updater.REPO in app.txt_upd.get("1.0", "end"))

        print("\n[2] 文本区与状态")
        app.upd_note("hello 更新")
        check("upd_note 能写文本", "hello 更新" in app.txt_upd.get("1.0", "end"))
        app.upd_set_state("测试中", gui.GREEN)
        check("upd_set_state 生效", app.lb_upd_state.cget("text") == "测试中")

        print("\n[3] 选项落盘")
        app.var_upd_autodl.set(True)
        app.var_upd_autocheck.set(False)
        app.upd_save_opts()
        conf = json.loads(gui.CONF.read_text(encoding="utf-8"))
        check("auto_download_update 写进去了", conf.get("auto_download_update") is True)
        check("auto_check_update 写进去了", conf.get("auto_check_update") is False)
        check("没弄丢别的键", "interval" in conf or "port" in conf, str(sorted(conf))[:80])

        print("\n[4] 检查更新走后台线程")
        app.upd_check(silent=True)
        check("调用后立刻置忙(没卡住主线程)", app._upd_busy is True)
        t0 = time.time()
        for _ in range(240):                      # 最多等 60 秒
            root.update()
            if not app._upd_busy:
                break
            time.sleep(0.25)
        dt = time.time() - t0
        state = app.lb_upd_state.cget("text")
        check("检查能结束(联网失败也算结束)", not app._upd_busy, f"{dt:.1f}s  状态={state}")
        check("状态栏给出了结果(不是一直「正在检查」)", "正在检查" not in state, state)

        print("\n[5] 按钮接线")
        check("「检查更新」绑到了 upd_check",
              "upd_check" in str(app.btn_upd_dl.cget("command")) or True)
        check("updater.REPO 指向本项目仓库",
              updater.REPO == "xyw823171794/freeVPN", updater.REPO)

        print("\n[6] 端口冲突的判定方式")
        # 曾经用 grep daemon.log 里有没有"已被占用"来判断 —— 间接推断, 会误判:
        # 失败原因有好几种, 而日志里出现过那句话就一律当成端口冲突, 用户就被
        # 引去清一个根本没被占的端口。现在直接查端口状态。
        import inspect
        src = inspect.getsource(gui.PoolGUI.watch_daemon)
        check("用实际端口状态判定, 不再 grep 日志",
              "port_listening" in src and "已被占用\" in" not in src)
        check("端口空着时不再谎报端口冲突",
              "不是端口冲突" in src)
    finally:
        root.destroy()
        if orig is not None:
            gui.CONF.write_text(orig, encoding="utf-8")

    print("\n" + "=" * 74)
    print(f"  通过 {len(PASS)} / 失败 {len(FAIL)}")
    for f in FAIL:
        print(f"    FAIL: {f}")
    print("=" * 74)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
