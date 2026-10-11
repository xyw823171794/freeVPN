#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
freeVPN · 桌面控制台
===================
tkinter 写的单窗口控制台，不依赖任何第三方库。

设计上刻意做成"读文件 + 起子进程"，而不是跟常驻服务做 IPC：
  · 状态从 out/report.json、state/pool.json 读 —— 常驻服务只负责写文件
  · 操作（扫描/导入/自启）都是起一个 pool.py 子进程，输出流式回显到日志页
这样 GUI 崩了不影响池子，池子崩了 GUI 也能告诉你哪儿不对。

用法：python pool.py gui
"""
from __future__ import annotations

import json
import os
import queue
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from datetime import datetime
from pathlib import Path

import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import security as sec  # noqa: E402
import version as ver  # noqa: E402
# 在线更新: 只下载 + 生成替换脚本, 不自动执行(见 updater.py 开头)
import updater  # noqa: E402

# 打包成 exe 后 __file__ 在临时解包目录, 根目录必须用 exe 自己所在的位置
ROOT = sec.app_root()
OUT = ROOT / "out"
STATE = ROOT / "state"
CONF = ROOT / "pool.conf.json"
PY = sys.executable
# 重新调起自己: 源码运行时是 `python -u pool.py`, 打包后是 exe 自己
BASE_CMD = sec.self_cmd()

BG = "#0e1116"
PANEL = "#161b22"
FG = "#d7dde5"
DIM = "#8b949e"
GREEN = "#7ee787"
AMBER = "#ffa657"
BLUE = "#79c0ff"
RED = "#ff7b72"

# 关键: 从 GUI(pythonw, 无控制台)起任何控制台子进程时, 不加这个标志
# Windows 会给它分配一个新控制台 —— 表现为屏幕上一个黑窗一闪而过。
# 之前 refresh() 每 2 秒调一次 wmic 查常驻进程, 就是它在闪。
NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def run_hidden(cmd, timeout: int = 20):
    """起一个不弹窗的子进程。GUI 里所有 subprocess 调用都必须走这里。"""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          encoding=sec.console_encoding(), errors="replace",
                          creationflags=NO_WINDOW)


def proxy_tip() -> str:
    """直连 GitHub 不通时的提示(国内是常态: TCP 能连、TLS 握手被打断)。"""
    if os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy"):
        return ("当前已设 HTTPS_PROXY —— 如果它本身不通，换一个代理端口再启动本程序。")
    return ("国内直连 GitHub 经常被掐（表现为连接重置 / 握手超时）。\n"
            "给本程序指一个代理再启动即可：\n\n"
            "    set HTTPS_PROXY=http://127.0.0.1:7897\n"
            "    freeVPN.exe\n\n"
            "端口按你代理软件里实际的监听端口改。")


def pid_alive(pid: int) -> bool:
    """进程是否还活着 —— 走 Win32 API, 不起子进程。"""
    return sec.pid_alive(pid)


def port_listening(port: int) -> bool:
    try:
        with socket.socket() as s:
            s.settimeout(0.4)
            return s.connect_ex(("127.0.0.1", port)) == 0
    except Exception:
        return False


def load_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def human_age(sec: float | None) -> str:
    if sec is None:
        return "?"
    if sec < 90:
        return f"{sec:.0f} 秒前"
    if sec < 5400:
        return f"{sec/60:.0f} 分钟前"
    return f"{sec/3600:.1f} 小时前"


# tkinter 不做字体回退, emoji 会渲染成方框。节点名里的旗帜/图标纯装饰,
# 表格里另有"地区"列, 所以显示前直接剥掉。
_EMOJI = re.compile(
    "[\U0001F000-\U0001FAFF\U00002600-\U000027BF\U0001F1E6-\U0001F1FF"
    "\U00002B00-\U00002BFF\U0000FE0F\U00002190-\U000021FF\U00002000-\U0000206F]"
)


def plain(s) -> str:
    return re.sub(r"\s+", " ", _EMOJI.sub("", str(s or ""))).strip()


def daemon_pids() -> list[int]:
    """常驻进程的 PID —— 读 daemon 写的 pid 文件, 不产生任何子进程。

    这里以前是每 2 秒跑一次 wmic, 于是屏幕上每 2 秒闪一个控制台窗口。
    现在纯粹是读文件 + Win32 探活, 零窗口。
    """
    try:
        raw = (STATE / "daemon.pid").read_text(encoding="utf-8")
        pids = [int(x) for x in raw.split() if x.strip().isdigit()]
    except Exception:
        return []
    return [p for p in pids if pid_alive(p)]


class PoolGUI:
    # (列 id, 表头, 宽度, 排序键)
    # 数字列按数值排 —— 按字符串排的话 1000ms 会跑到 200ms 前面。
    # 取不到值的列返回 None, fill_tree 会把它们单独挑出来永远沉底:
    # "没测出延迟"不等于"最慢", 降序时浮到最前面是误导。
    COLS = (
        ("name", "节点", 420, lambda n: plain(n.get("name", "")).lower()),
        ("type", "协议", 90, lambda n: str(n.get("type", ""))),
        ("region", "地区", 70, lambda n: str(n.get("_region", ""))),
        ("real", "实测延迟", 100, lambda n: n.get("_real")),
        ("tcp", "TCP", 90, lambda n: n.get("_tcp")),
    )

    def __init__(self, root: tk.Tk, port: int = 8787):
        self.root = root
        self.port = port
        self.logq: queue.Queue[str] = queue.Queue()
        # 更新线程 -> 主线程的回调队列。
        # **不要**从工作线程直接调 root.after: tkinter 不是线程安全的,
        # 实测回调会丢(状态永远停在"正在检查")。走队列, 主线程轮询。
        self._updq: queue.Queue = queue.Queue()
        self.proc: subprocess.Popen | None = None
        self.busy = False
        self._nodes: list[dict] = []
        self._sig = None
        self.sort_col: str | None = None   # None = 保持池子自己的顺序
        self.sort_desc = False
        self._prog_active = False          # 进度条当前是否在显示"进行中"
        self._prog_running = False         # 不确定模式的动画是否已启动
        self._token_cache = ""             # 落盘时用来抹令牌
        # 日志同时落盘, 方便排错(用户报错时我们看不到界面上的日志页)
        try:
            STATE.mkdir(parents=True, exist_ok=True)
            self._gui_log = open(STATE / "gui.log", "a", encoding="utf-8")
            self._gui_log.write(f"\n===== 控制台启动 {datetime.now():%Y-%m-%d %H:%M:%S} "
                                f"v{ver.__version__} =====\n")
            self._gui_log.flush()
        except Exception:
            self._gui_log = open(os.devnull, "w", encoding="utf-8")

        root.title(f"{ver.__title__} · 控制台  v{ver.__version__}")
        root.geometry("1020x740")
        root.minsize(860, 600)
        root.configure(bg=BG)

        self._style()
        self._build()
        self.refresh()
        self._drain_log()
        # 被按路径关起来的话, 后面每一步都会莫名其妙地失败(导入、开机自启、
        # 甚至写日志)。在第一次点击之前就把这件事说清楚。
        self.root.after(300, self.check_confined)
        # 首次打开时自己把常驻拉起来 —— 用户要的是"双击就能用",
        # 而不是打开一个空壳再去点按钮。之后由常驻自己按节奏刷新。
        self.root.after(600, self.autostart_first_run)
        # 启动 4 秒后悄悄查一次更新 —— 放在最后, 不跟前面几件事抢网络
        self.root.after(4000, self.upd_auto_check)

    def check_confined(self):
        why = sec.write_confined()
        if not why:
            return
        self.say("=" * 56)
        self.say("!! 本程序被限制只能写自己附近")
        self.say("   " + why.replace("\n", "\n   "))
        self.say(f"   程序位置: {sec.app_root()}")
        self.say("   后果: 导入客户端、开机自启、部分日志都会失败。")
        self.say("   解决: 把整个文件夹移到别处再跑, 例如 C:\\freeVPN\\")
        self.say("        (state/ 要一起带走, 否则订阅令牌会变)")
        self.say("=" * 56)
        messagebox.showwarning(
            "程序位置有问题",
            f"{why}\n\n"
            f"程序位置：\n{sec.app_root()}\n\n"
            "后果：导入客户端、设置开机自启都会失败（写不进去）。\n\n"
            "解决：把整个文件夹移到别处再跑，例如 C:\\freeVPN\\\n"
            "注意 state/ 要一起带走，否则订阅令牌会变、"
            "客户端里已填的订阅地址会 401。")

    def autostart_first_run(self):
        """全新目录第一次打开: 没有产物也没有常驻在跑, 就直接起一个。"""
        if getattr(self, "_autostarted", False):
            return
        if daemon_pids():
            return
        if (OUT / "report.json").exists():
            return
        if port_listening(self.port):
            self.say(f"端口 {self.port} 已被占用，不自动启动常驻。")
            self.say("占用者可能是另一个 freeVPN实例（源码版或另一份打包版）。")
            self.say("要么关掉它，要么把本程序的端口改掉再重开。")
            return
        self._autostarted = True
        self.say("首次运行：自动启动常驻并跑第一轮扫描 …")
        self.toggle_daemon()

    # ---------------- 外观 ----------------
    def _style(self):
        st = ttk.Style()
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure(".", background=BG, foreground=FG, fieldbackground=PANEL)
        st.configure("TFrame", background=BG)
        st.configure("TLabel", background=BG, foreground=FG)
        st.configure("Dim.TLabel", background=BG, foreground=DIM)
        st.configure("Big.TLabel", background=BG, foreground=GREEN,
                     font=("Consolas", 15, "bold"))
        st.configure("TButton", background="#21262d", foreground=FG,
                     borderwidth=0, padding=(10, 6), font=("Microsoft YaHei UI", 9))
        st.map("TButton",
               background=[("active", "#30363d"), ("disabled", "#161b22")],
               foreground=[("disabled", DIM)])
        st.configure("Accent.TButton", background="#238636", foreground="#ffffff")
        st.map("Accent.TButton", background=[("active", "#2ea043")])
        st.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                     foreground=FG, borderwidth=0, rowheight=22)
        st.configure("Treeview.Heading", background="#21262d", foreground=DIM,
                     borderwidth=0)
        st.map("Treeview", background=[("selected", "#1f6feb")])
        st.configure("TNotebook", background=BG, borderwidth=0)
        st.configure("TNotebook.Tab", background="#21262d", foreground=DIM,
                     padding=(14, 7))
        st.map("TNotebook.Tab",
               background=[("selected", PANEL)], foreground=[("selected", GREEN)])
        st.configure("TEntry", fieldbackground=PANEL, foreground=FG,
                     insertcolor=FG, borderwidth=0)
        st.configure("TLabelFrame", background=BG, foreground=DIM)
        st.configure("TLabelFrame.Label", background=BG, foreground=DIM)

    # ---------------- 布局 ----------------
    def _build(self):
        top = ttk.Frame(self.root, padding=(16, 14, 16, 8))
        top.pack(fill="x")

        self.lb_title = ttk.Label(top, text=ver.__title__, style="Big.TLabel")
        self.lb_title.pack(side="left")
        ttk.Label(top, text=f"v{ver.__version__}", style="Dim.TLabel") \
            .pack(side="left", padx=(8, 0), pady=(6, 0))
        self.lb_state = ttk.Label(top, text="", style="Dim.TLabel")
        self.lb_state.pack(side="left", padx=(14, 0))

        self.lb_health = ttk.Label(top, text="", style="Dim.TLabel")
        self.lb_health.pack(side="right")

        # 状态卡片
        cards = ttk.Frame(self.root, padding=(16, 0, 16, 8))
        cards.pack(fill="x")
        self.card_nodes = self._card(cards, "入池节点", "—")
        self.card_regions = self._card(cards, "覆盖地区", "—")
        self.card_age = self._card(cards, "上次刷新", "—")
        self.card_sources = self._card(cards, "源可用", "—")
        for c in (self.card_nodes, self.card_regions, self.card_age, self.card_sources):
            c.pack(side="left", expand=True, fill="x", padx=(0, 8))

        # 操作按钮
        bar = ttk.Frame(self.root, padding=(16, 4, 16, 10))
        bar.pack(fill="x")
        self.btns = {}
        for key, label, cb, style in [
            ("full", "完整扫描", lambda: self.run_action("all"), None),
            ("quick", "快车道复检", lambda: self.run_action("quick"), None),
            ("import", "一键导入到客户端", self.do_import, "Accent.TButton"),
            ("page", "打开状态页", self.open_page, None),
        ]:
            b = ttk.Button(bar, text=label, command=cb,
                           style=style if style else "TButton")
            b.pack(side="left", padx=(0, 8))
            self.btns[key] = b

        self.btn_daemon = ttk.Button(bar, text="启动常驻", command=self.toggle_daemon)
        self.btn_daemon.pack(side="left", padx=(0, 8))
        self.btn_auto = ttk.Button(bar, text="开机自启", command=self.toggle_autostart)
        self.btn_auto.pack(side="left", padx=(0, 8))
        self.btn_freeport = ttk.Button(bar, text="清端口占用", command=self.do_free_port)
        self.btn_freeport.pack(side="left")

        # 进度条 —— 扫描要跑 1~3 分钟, 之前那段时间界面上完全是黑的:
        # 输出全在「日志」页, 人在「节点」页什么都看不到。
        strip = tk.Frame(self.root, bg=PANEL)
        strip.pack(fill="x", padx=16, pady=(0, 8))
        self.lb_dot = tk.Label(strip, text="●", bg=PANEL, fg=DIM,
                               font=("Microsoft YaHei UI", 10))
        self.lb_dot.pack(side="left", padx=(10, 6), pady=7)
        self.lb_op = tk.Label(strip, text="就绪", bg=PANEL, fg=FG,
                              font=("Microsoft YaHei UI", 9, "bold"))
        self.lb_op.pack(side="left", pady=7)
        self.lb_elapsed = tk.Label(strip, text="", bg=PANEL, fg=DIM,
                                   font=("Consolas", 9))
        self.lb_elapsed.pack(side="left", padx=(10, 0), pady=7)
        self.lb_phase = tk.Label(strip, text="", bg=PANEL, fg=BLUE,
                                 font=("Microsoft YaHei UI", 9))
        self.lb_phase.pack(side="right", padx=(0, 12), pady=7)
        self.prog = ttk.Progressbar(strip, mode="determinate", maximum=100,
                                    length=220)
        self.prog.pack(side="right", padx=12, pady=7)

        # 订阅地址
        addr = ttk.Frame(self.root, padding=(16, 0, 16, 10))
        addr.pack(fill="x")
        ttk.Label(addr, text="订阅地址", style="Dim.TLabel").pack(side="left")
        self.var_addr = tk.StringVar(value="")
        e = ttk.Entry(addr, textvariable=self.var_addr, font=("Consolas", 9))
        e.pack(side="left", fill="x", expand=True, padx=(10, 8))
        ttk.Button(addr, text="复制", command=self.copy_addr).pack(side="left")

        # 页签
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=16, pady=(0, 12))
        self.nb = nb          # 存起来: 截图脚本和"跳到某页"要用

        # 节点
        f1 = ttk.Frame(nb, padding=8)
        nb.add(f1, text="  节点  ")
        self.tree = ttk.Treeview(f1, columns=[c[0] for c in self.COLS],
                                 show="headings", height=14)
        for cid, title, width, _key in self.COLS:
            # 点列头排序: 再点一次切换升降序
            self.tree.heading(cid, text=title,
                              command=lambda c=cid: self.sort_by(c))
            self.tree.column(cid, width=width,
                             anchor="w" if cid == "name" else "center")
        vs = ttk.Scrollbar(f1, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vs.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")

        # 日志
        f2 = ttk.Frame(nb, padding=8)
        nb.add(f2, text="  日志  ")
        self.log = scrolledtext.ScrolledText(
            f2, bg=PANEL, fg=FG, insertbackground=FG, borderwidth=0,
            font=("Consolas", 9), wrap="word", state="disabled")
        self.log.pack(fill="both", expand=True)
        for tag, col in (("ok", GREEN), ("warn", AMBER), ("err", RED), ("dim", DIM)):
            self.log.tag_config(tag, foreground=col)

        # 设置
        f3 = ttk.Frame(nb, padding=16)
        nb.add(f3, text="  设置  ")
        conf = load_json(CONF) or {}
        self.vars = {}
        rows = [
            ("interval", "完整扫描间隔（分钟）", "对齐时钟刻度，30 = :00 / :30"),
            ("fast", "快车道间隔（分钟）", "只重测池内节点，几秒完成"),
            ("l2_workers", "L2 内核并发", "实测 192 最优；768 会开始丢节点"),
            ("neg_ttl", "负缓存有效期（秒）", "失败节点多久后重新给机会，默认 5400"),
            ("neg_l1_fails", "L1 连续失败几次才跳过", "实测跳过组存活率 3.0% vs 对照 92.2%"),
            ("neg_l2_fails", "L2 连续失败几次才跳过", "0 = 关闭（实测它没有预测力，默认关）"),
        ]
        for i, (k, label, hint) in enumerate(rows):
            ttk.Label(f3, text=label).grid(row=i * 2, column=0, sticky="w", pady=(10, 0))
            v = tk.StringVar(value=str(conf.get(k, "")))
            self.vars[k] = v
            ttk.Entry(f3, textvariable=v, width=14, font=("Consolas", 10)) \
                .grid(row=i * 2, column=1, sticky="w", padx=(14, 14), pady=(10, 0))
            ttk.Label(f3, text=hint, style="Dim.TLabel") \
                .grid(row=i * 2 + 1, column=0, columnspan=3, sticky="w", padx=(0, 0))
        ttk.Button(f3, text="保存设置", command=self.save_conf) \
            .grid(row=len(rows) * 2 + 1, column=0, sticky="w", pady=(18, 0))
        ttk.Label(f3, text="改完需要重启常驻才生效（点上面的「启动常驻」会重起）",
                  style="Dim.TLabel") \
            .grid(row=len(rows) * 2 + 2, column=0, columnspan=3, sticky="w", pady=(8, 0))

        # 更新
        f4 = ttk.Frame(nb, padding=16)
        nb.add(f4, text="  更新  ")
        self._build_update(f4)

    # ---------------- 更新页 ----------------
    def _build_update(self, parent):
        """检查 / 下载 / 准备替换。

        **只下载, 不自动执行** —— Windows 上程序没法覆盖正在运行的自己, 而且
        "下载即执行"本来就是最糟的更新设计(见 updater.py 开头)。这里下完生成
        一个替换脚本, 由用户关掉程序后双击。
        """
        conf = load_json(CONF) or {}
        self._upd_busy = False
        self._upd_info: dict | None = None
        # 点了"一键更新"但还没下载 → 下完自动接着走替换
        self._upd_apply_after_download = False

        box = ttk.LabelFrame(parent, text=" 版本 ", padding=12)
        box.pack(fill="x")
        ttk.Label(box, text=f"当前   v{ver.__version__}   ({ver.__release_date__})") \
            .grid(row=0, column=0, sticky="w")
        self.lb_upd_remote = ttk.Label(box, text="最新   —", style="Dim.TLabel")
        self.lb_upd_remote.grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Button(box, text="检查更新", command=self.upd_check) \
            .grid(row=0, column=1, rowspan=2, padx=(24, 0))
        self.lb_upd_state = ttk.Label(box, text="还没检查过", style="Dim.TLabel")
        self.lb_upd_state.grid(row=2, column=0, columnspan=2, sticky="w", pady=(10, 0))
        self.pb_upd = ttk.Progressbar(box, mode="determinate", maximum=100, length=360)
        self.pb_upd.grid(row=3, column=0, columnspan=2, sticky="w", pady=(6, 0))

        opt = ttk.LabelFrame(parent, text=" 自动 ", padding=12)
        opt.pack(fill="x", pady=(12, 0))
        self.var_upd_autocheck = tk.BooleanVar(
            value=bool(conf.get("auto_check_update", True)))
        self.var_upd_autodl = tk.BooleanVar(
            value=bool(conf.get("auto_download_update", False)))
        ttk.Checkbutton(opt, text="启动时自动检查更新",
                        variable=self.var_upd_autocheck,
                        command=self.upd_save_opts).pack(anchor="w")
        ttk.Checkbutton(opt, text="发现新版时自动下载（只是下载，装不装由你点）",
                        variable=self.var_upd_autodl,
                        command=self.upd_save_opts).pack(anchor="w", pady=(6, 0))

        act = ttk.Frame(parent)
        act.pack(fill="x", pady=(14, 0))
        self.btn_upd_apply = ttk.Button(act, text="一键更新并重启",
                                        style="Accent.TButton",
                                        command=self.upd_apply, state="disabled")
        self.btn_upd_apply.pack(side="left")
        self.btn_upd_dl = ttk.Button(act, text="只下载", command=self.upd_download,
                                     state="disabled")
        self.btn_upd_dl.pack(side="left", padx=(8, 0))
        ttk.Button(act, text="打开更新目录", command=self.upd_open_dir) \
            .pack(side="left", padx=(8, 0))
        ttk.Button(act, text="看仓库", command=self.upd_open_repo) \
            .pack(side="left", padx=(8, 0))

        self.txt_upd = scrolledtext.ScrolledText(
            parent, height=9, bg=PANEL, fg=FG, insertbackground=FG, borderwidth=0,
            font=("Consolas", 9), wrap="word", state="disabled")
        self.txt_upd.pack(fill="both", expand=True, pady=(12, 0))
        self.upd_note(f"更新源: https://github.com/{updater.REPO}\n\n"
                      "点「检查更新」看有没有新版。下载完成后，关掉本程序、"
                      "双击生成的 apply-update.bat 即可完成替换。\n\n"
                      "state\\ out\\ bin\\ 订阅地址.txt 都不会被覆盖。")

    def upd_set_state(self, text: str, color: str = DIM):
        self.lb_upd_state.config(text=text, foreground=color)

    def upd_note(self, text: str):
        self.txt_upd.config(state="normal")
        self.txt_upd.delete("1.0", "end")
        self.txt_upd.insert("end", text)
        self.txt_upd.config(state="disabled")

    def upd_check(self, silent: bool = False):
        if self._upd_busy:
            return
        self._upd_busy = True
        self.btn_upd_dl.config(state="disabled")
        self.btn_upd_apply.config(state="disabled")
        self.pb_upd.config(value=0)
        self.upd_set_state("正在检查 GitHub …", BLUE)
        threading.Thread(target=self._upd_check_worker, args=(silent,),
                         daemon=True).start()

    def _upd_check_worker(self, silent: bool):
        info, err = None, None
        try:
            info = updater.remote_info()
        except Exception as e:                     # 网络/解析都可能炸
            err = e
        self._upd_post(self._upd_check_done, info, err, silent)

    def _upd_check_done(self, info, err, silent: bool):
        self._upd_busy = False
        if err is not None:
            self.upd_set_state(f"检查失败：{type(err).__name__}", RED)
            if not silent:
                self.say(f"[!] 检查更新失败: {type(err).__name__}: {err}")
                messagebox.showerror("检查更新失败", f"{err}\n\n{proxy_tip()}")
            return

        rv = (info or {}).get("version") or ""
        if not rv:
            self.upd_set_state("查不到远端版本（网络不通，或仓库还没有 release/tag）", AMBER)
            self.lb_upd_remote.config(text="最新   —", foreground=DIM)
            if not silent:
                messagebox.showwarning("查不到版本", proxy_tip())
            return

        self._upd_info = info
        kind = {"release": "Release（含打包的 exe）",
                "release-source": "Release（只有源码包）",
                "source": "main 分支源码"}.get(info.get("kind"), str(info.get("kind")))
        newer = updater.is_newer(rv, ver.__version__)
        self.lb_upd_remote.config(text=f"最新   v{rv}   （{kind}）",
                                  foreground=GREEN if newer else DIM)

        if not newer:
            self.upd_set_state(f"已是最新（v{rv}）", DIM)
            self.upd_note(f"本地 v{ver.__version__} 已经是最新。\n\n"
                          f"更新源: https://github.com/{updater.REPO}\n"
                          f"远端来源: {kind}")
            return

        self.upd_set_state(f"发现新版本 v{rv}", GREEN)
        self.btn_upd_dl.config(state="normal")
        self.btn_upd_apply.config(state="normal")
        self.say(f"[更新] 发现新版本 v{rv}（{kind}）")
        notes = (info.get("notes") or "").strip()
        body = [f"v{ver.__version__}  →  v{rv}", f"来源: {kind}"]
        if info.get("published"):
            body.append(f"发布于: {info['published']}")
        body.append("")
        body.append(notes if notes else "（这次没有写更新说明）")
        body.append("")
        body.append("点「下载并准备更新」——下载完关掉本程序、双击 apply-update.bat 完成替换。")
        self.upd_note("\n".join(body))

        if self.var_upd_autodl.get():
            self.say("[更新] 已开启自动下载，开始下载 …")
            self.upd_download()

    def upd_apply(self):
        """一键更新并重启。

        Windows 上程序没法覆盖正在运行的自己, 所以这条路是: 下载 → 启动一个
        **分离的**替换脚本 → 本程序立刻退出 → 脚本等进程退出后覆盖文件, 再把
        新版本拉起来。用户看到的就是"程序自己关了又开了"。
        """
        if self._upd_busy or not self._upd_info:
            return
        rv = self._upd_info.get("version") or ""
        if not rv:
            return
        stage = updater.update_dir() / rv
        if (stage / "payload").exists():
            # 已经下过了 —— 重新生成一次脚本, 保证里面烘的版本目录名是对的
            self._upd_launch(updater.write_apply_script(stage), rv)
        else:
            self._upd_apply_after_download = True
            self.upd_download()

    def _upd_launch(self, bat, rv: str):
        if not messagebox.askyesno(
                "一键更新并重启",
                f"把 freeVPN 更新到 v{rv}。\n\n"
                "程序会自己关掉，几秒钟后自动打开新版本。\n"
                "state\\ out\\ bin\\ 订阅地址.txt 都不会被动。\n\n"
                "现在开始吗？"):
            self._upd_apply_after_download = False
            return
        # 先把常驻停掉 —— 脚本要等所有同目录的 freeVPN.exe 退出, daemon 不停
        # 它会一直等(实测卡死)。GUI 自己马上也会退出, 脚本会把两个都拉回来。
        n = updater.stop_resident()
        if n:
            self.say(f"[更新] 已停掉同目录的 freeVPN 进程 {n} 个（脚本稍后拉回）")
        if updater.launch_apply(bat):
            self.say(f"[更新] 已交给替换脚本，本程序即将退出并自动重启到 v{rv}")
            try:
                self._gui_log.flush()
            except Exception:
                pass
            self.root.destroy()
            # 立刻退出, 不走清理 —— 文件必须马上被释放, 否则脚本的 robocopy
            # 会撞上"正在使用中"。日志上面已经 flush 过了。
            os._exit(0)
        else:
            self._upd_apply_after_download = False
            messagebox.showerror("启动失败",
                                 f"没能启动替换脚本，请手动双击：\n{bat}")

    def upd_download(self):
        if self._upd_busy or not self._upd_info:
            return
        rv = self._upd_info.get("version") or ""
        if not rv:
            return
        self._upd_busy = True
        self.btn_upd_dl.config(state="disabled")
        self.btn_upd_apply.config(state="disabled")
        self.pb_upd.config(value=0)
        self.upd_set_state(f"正在下载 v{rv} …", BLUE)
        threading.Thread(target=self._upd_dl_worker,
                         args=(self._upd_info, rv), daemon=True).start()

    def _upd_dl_worker(self, info: dict, rv: str):
        bat, err, n = None, None, 0
        try:
            stage = updater.update_dir() / rv
            if stage.exists():
                shutil.rmtree(stage, ignore_errors=True)
            stage.mkdir(parents=True, exist_ok=True)
            pkg = stage / f"freeVPN-{rv}.zip"
            updater.download(
                info["url"], pkg, quiet=True,
                on_progress=lambda g, t: self._upd_post(self._upd_progress, g, t))
            payload = stage / "payload"
            payload.mkdir(parents=True, exist_ok=True)
            root_dir, n = updater.extract_package(pkg, payload)
            pv = updater.package_version(root_dir)
            if pv and updater.ver_tuple(pv) != updater.ver_tuple(rv):
                raise ValueError(f"包内版本 {pv} 与远端声明 {rv} 不一致，已放弃")
            bat = updater.write_apply_script(stage)
        except Exception as e:
            err = e
        self._upd_post(self._upd_dl_done, bat, err, rv, n)

    def _upd_progress(self, got: int, total: int):
        if total:
            pct = min(100, got * 100 // total)
            self.pb_upd.config(value=pct)
            self.upd_set_state(
                f"正在下载 {got // 1048576}MB / {total // 1048576}MB   {pct}%", BLUE)
        else:
            self.upd_set_state(f"正在下载 {got // 1024}KB …", BLUE)

    def _upd_dl_done(self, bat, err, rv: str, n: int):
        self._upd_busy = False
        if err is not None:
            self.upd_set_state(f"下载失败：{type(err).__name__}", RED)
            self.btn_upd_dl.config(state="normal")
            self.btn_upd_apply.config(state="normal")
            self._upd_apply_after_download = False
            self.say(f"[!] 下载更新失败: {type(err).__name__}: {err}")
            messagebox.showerror("下载失败", f"{err}\n\n{proxy_tip()}")
            return
        self.pb_upd.config(value=100)
        # 点的是"一键更新并重启" → 下完直接接着走替换, 不再多问一遍
        if self._upd_apply_after_download:
            self._upd_apply_after_download = False
            self._upd_launch(bat, rv)
            return
        self.upd_set_state(f"v{rv} 已就绪 —— 关掉本程序后双击 {bat.name}", GREEN)
        self.say(f"[更新] v{rv} 已下载并解压（{n} 个文件）")
        self.say(f"[更新] 关掉 freeVPN 后双击: {bat}")
        self.upd_note(
            f"v{rv} 已下载并解压完成。\n\n"
            f"替换脚本: {bat}\n\n"
            "接下来：\n"
            "  1. 关掉本窗口（常驻也要退干净）\n"
            f"  2. 双击 {bat.name}\n"
            "  3. 它会覆盖程序文件，然后自动启动新版本\n\n"
            "state\\ out\\ bin\\ 订阅地址.txt 都不会被动。")
        if messagebox.askyesno(
                "更新已就绪",
                f"v{rv} 已下载并解压。\n\n"
                f"关掉程序后双击 {bat.name} 就能完成替换。\n\n"
                "现在打开更新目录吗？"):
            self.upd_open_dir()

    def upd_save_opts(self):
        try:
            conf = load_json(CONF) or {}
            conf["auto_check_update"] = bool(self.var_upd_autocheck.get())
            conf["auto_download_update"] = bool(self.var_upd_autodl.get())
            CONF.write_text(json.dumps(conf, ensure_ascii=False, indent=2),
                            encoding="utf-8")
            self.say(f"更新设置已保存（自动检查={conf['auto_check_update']}, "
                     f"自动下载={conf['auto_download_update']}）")
        except Exception as e:
            self.say(f"[!] 保存更新设置失败: {e}")

    def upd_open_dir(self):
        d = updater.update_dir()
        try:
            d.mkdir(parents=True, exist_ok=True)
            os.startfile(str(d))
        except Exception as e:
            messagebox.showerror("打不开更新目录", str(e))

    def upd_open_repo(self):
        try:
            os.startfile(f"https://github.com/{updater.REPO}")
        except Exception as e:
            messagebox.showerror("打不开", str(e))

    def upd_auto_check(self):
        """启动时静默查一次 —— 有新版才出声。"""
        if not self.var_upd_autocheck.get():
            return
        self.upd_check(silent=True)

    def _card(self, parent, title, value):
        f = tk.Frame(parent, bg=PANEL, highlightthickness=0)
        tk.Label(f, text=title, bg=PANEL, fg=DIM,
                 font=("Microsoft YaHei UI", 8)).pack(anchor="w", padx=12, pady=(9, 0))
        lb = tk.Label(f, text=value, bg=PANEL, fg=GREEN,
                      font=("Consolas", 16, "bold"))
        lb.pack(anchor="w", padx=12, pady=(0, 9))
        f._value = lb
        return f

    # ---------------- 刷新 ----------------
    def refresh(self):
        rep = load_json(OUT / "report.json") or {}
        pool = load_json(STATE / "pool.json") or {}
        nodes = pool.get("nodes") or []

        running = port_listening(self.port)
        daemon = bool(daemon_pids())

        # 端口有人听 ≠ 是我们的服务。别的程序（比如源码版的常驻）占了同一个
        # 端口时, 这里必须说清楚 —— 否则用户会以为服务好着, 然后点「启动常驻」
        # 却因为端口冲突起不来, 还看不到任何报错。
        if daemon and running:
            self.lb_state.config(text=f"服务运行中 · 常驻运行中", foreground=GREEN)
        elif running and not daemon:
            self.lb_state.config(
                text=f"端口 {self.port} 被别的程序占用 · 常驻未运行", foreground=AMBER)
        elif daemon and not running:
            self.lb_state.config(text="常驻在跑但服务没起来", foreground=AMBER)
        else:
            self.lb_state.config(text="服务未运行 · 常驻未运行", foreground=AMBER)

        ts = rep.get("ts")
        age = (time.time() - ts) if ts else None
        self.card_nodes._value.config(text=str(rep.get("final", "—")))
        self.card_regions._value.config(text=str(len(rep.get("regions") or {}) or "—"))
        self.card_age._value.config(
            text=human_age(age),
            foreground=GREEN if (age or 9e9) < 3600 else AMBER)
        self.card_sources._value.config(
            text=f"{rep.get('sources_ok', 0)}/{rep.get('sources_total', 0)}")

        health = "新鲜" if (age or 9e9) < 3600 else ("偏旧" if (age or 9e9) < 10800 else "已过期")
        au = rep.get("audit") or {}
        self.lb_health.config(
            text=f"{health} · 拦截 {au.get('blocked', 0)} / 告警 {au.get('warned', 0)}")

        self.btn_daemon.config(text="停止常驻" if daemon else "启动常驻")
        auto_on = (Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows"
                   / "Start Menu" / "Programs" / "Startup" / "freeVPN.vbs").exists()
        self.btn_auto.config(text="取消开机自启" if auto_on else "设置开机自启")

        tok = ""
        try:
            tok = (STATE / "token.txt").read_text(encoding="utf-8").strip()
        except Exception:
            pass
        if tok:
            self.var_addr.set(f"http://127.0.0.1:{self.port}/sub/pool.yaml?token={tok}")
        else:
            # 全新解压出来还没启动过常驻时, token 还不存在 —— 别留个空框让人以为坏了
            self.var_addr.set("（点「启动常驻」后自动生成）")

        self.update_progress()

        # 节点表（只在数据变化时重建，免得每 2 秒闪一次）
        self._nodes = nodes
        sig = tuple(n.get("name") for n in nodes[:200])
        if sig != self._sig:
            self._sig = sig
            self.fill_tree()

        # 扫描进行中时刷快一点, 进度条才跟手; 空闲时不用那么勤
        self.root.after(1000 if self._prog_active else 2000, self.refresh)

    def sort_by(self, col: str):
        """点列头排序。同一列再点一次切换升降序。"""
        if self.sort_col == col:
            self.sort_desc = not self.sort_desc
        else:
            self.sort_col = col
            self.sort_desc = False
        self.fill_tree()

    def fill_tree(self):
        """按当前排序重建表格。排序状态在自动刷新时也会保持。"""
        rows = list(self._nodes[:200])
        if self.sort_col:
            key = next((k for c, _t, _w, k in self.COLS if c == self.sort_col), None)
            if key:
                try:
                    present = [n for n in rows if key(n) is not None]
                    missing = [n for n in rows if key(n) is None]
                    present.sort(key=key, reverse=self.sort_desc)
                    # 取不到值的永远沉底, 不随升降序翻转
                    rows = present + missing
                except Exception:
                    pass
        self.tree.delete(*self.tree.get_children())
        for n in rows:
            self.tree.insert("", "end", values=(
                plain(n.get("name", "")), n.get("type", ""),
                n.get("_region", ""),
                f"{n['_real']}ms" if n.get("_real") else "—",
                f"{n['_tcp']}ms" if n.get("_tcp") else "—"))
        # 表头箭头
        for cid, title, _w, _k in self.COLS:
            arrow = ""
            if cid == self.sort_col:
                arrow = " ▼" if self.sort_desc else " ▲"
            self.tree.heading(cid, text=title + arrow)

    # 各阶段在整轮扫描里占的比重。
    # 不这么分的话进度条会在 L2 一填到底, 但扫描还在跑 —— L2 是按分片报进度的
    # (1000/2000/2236), 最后一片要几十秒, 那段时间条子早就 100% 了, 看着像卡死。
    PHASE_SPAN = {
        "拉源": (2, 15),
        "解析去重": (15, 20),
        "安全审计": (20, 22),
        "L1 TCP 探活": (22, 65),
        "L2 内核实测": (65, 97),
        "写产物": (97, 100),
    }
    # 快车道只做 L2, 单独一套
    FAST_SPAN = {"L2 内核实测": (2, 97), "写产物": (97, 100)}

    def update_progress(self):
        """按扫描进度文件刷新顶部进度条。

        进度是**子进程写文件、GUI 读文件** —— 所以常驻在后台自动扫描时这里
        同样会动, 不只是 GUI 自己触发的操作。扫描要跑 1~3 分钟, 之前那段
        时间界面上完全是黑的。
        """
        pr = load_json(STATE / "progress.json")
        # 进度文件是"正在跑"的标志; 但进程被强杀时会留下残file, 用 ts 兜一下
        stale = pr and (time.time() - pr.get("ts", 0) > 120)
        if not pr or stale:
            if self._prog_active:
                self._prog_active = False
                self.lb_dot.config(fg=GREEN)
                self.lb_op.config(text="就绪", fg=FG)
                self.lb_elapsed.config(text="")
                self.lb_phase.config(text="上次操作已结束")
                self.prog.config(value=0)
                self.root.after(4000, lambda: self.lb_phase.config(text=""))
            return

        self._prog_active = True
        op = pr.get("op", "扫描")
        phase = pr.get("phase", "")
        done, total = pr.get("done") or 0, pr.get("total") or 0
        note = pr.get("note") or ""
        el = time.time() - (pr.get("started") or pr.get("ts") or time.time())

        self.lb_dot.config(fg=AMBER)
        self.lb_op.config(text=f"{op}进行中", fg=AMBER)
        self.lb_elapsed.config(text=f"已 {int(el)//60}分{int(el)%60:02d}秒")

        bits = [phase]
        if total:
            bits.append(f"{done}/{total}")
        if note:
            bits.append(note)
        self.lb_phase.config(text="  ·  ".join(x for x in bits if x))

        span = self.FAST_SPAN if "快车道" in op else self.PHASE_SPAN
        lo, hi = span.get(phase, (0, 100))
        if total:
            self._stop_indeterminate()
            pct = lo + (hi - lo) * min(1.0, done / float(total))
            self.prog.config(mode="determinate", value=pct)
        else:
            # 拉源/去重/审计没有可数的总量 —— 用不确定模式, 至少让它"在动"
            self.prog.config(mode="indeterminate")
            if not getattr(self, "_prog_running", False):
                self._prog_running = True
                self.prog.start(60)

    def _stop_indeterminate(self):
        if getattr(self, "_prog_running", False):
            self._prog_running = False
            self.prog.stop()

    def _drain_log(self):
        try:
            while True:
                line = self.logq.get_nowait()
                self.log.config(state="normal")
                tag = "dim"
                if any(k in line for k in ("[✓]", "OK ", "PASS", "成功")):
                    tag = "ok"
                elif any(k in line for k in ("[!]", "FAIL", "警告")):
                    tag = "warn"
                elif any(k in line for k in ("Error", "Traceback", "异常")):
                    tag = "err"
                self.log.insert("end", line + "\n", tag)
                self.log.see("end")
                self.log.config(state="disabled")
        except queue.Empty:
            pass
        self._drain_upd()
        self.root.after(120, self._drain_log)

    def _upd_post(self, fn, *args):
        """从更新线程把回调丢给主线程执行。"""
        self._updq.put((fn, args))

    def _drain_upd(self):
        """主线程侧: 把更新线程排下的回调跑掉。"""
        try:
            while True:
                fn, args = self._updq.get_nowait()
                try:
                    fn(*args)
                except Exception as e:
                    self.logq_put(f"!! 更新回调异常: {type(e).__name__}: {e}")
        except queue.Empty:
            pass

    # ---------------- 操作 ----------------
    def say(self, text: str):
        self.logq_put(f"[{datetime.now():%H:%M:%S}] {text}")

    def logq_put(self, line: str):
        """写一行到日志页, **同时落 state/gui.log**。

        落文件是为了排错 —— 用户报"导入失败"时, 日志页的内容我们看不到,
        只能猜。

        **但落盘前必须把令牌抹掉**: 子进程的输出里有带令牌的订阅地址,
        而 gui.log 的 ACL 是 `Authenticated Users:(M)` —— 任何本机用户可读。
        实测 gui.log 里有 13 行含完整令牌, token.txt 自己的 ACL 收紧就被
        这样绕过去了。屏幕上仍然显示完整地址(用户要用)。
        """
        self.logq.put(line)
        try:
            self._gui_log.write(self._scrub(line) + "\n")
            self._gui_log.flush()
        except Exception:
            pass

    def _scrub(self, s: str) -> str:
        """把令牌从要落盘的文本里抹掉。"""
        tok = self._token_cache
        if not tok:
            try:
                tok = (STATE / "token.txt").read_text(encoding="utf-8").strip()
                self._token_cache = tok
            except Exception:
                return s
        if not tok:
            return s
        out = s.replace(tok, "***")
        try:
            out = out.replace(urllib.parse.quote(tok, safe=""), "***")
        except Exception:
            pass
        return out

    def set_busy(self, busy: bool):
        self.busy = busy
        for b in self.btns.values():
            b.config(state="disabled" if busy else "normal")

    def run_action(self, *argv, label: str = "", tip: str = "", on_done=None):
        if self.busy:
            messagebox.showinfo("正在忙", "上一个操作还没结束，等它跑完。")
            return
        cmd = BASE_CMD + list(argv)
        self.set_busy(True)
        self.say(f"$ {' '.join(Path(p).name if i == 0 else p for i, p in enumerate(cmd))}")

        def worker():
            rc = -1
            try:
                p = subprocess.Popen(
                    cmd, cwd=str(ROOT), stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                    text=True, encoding="utf-8", errors="replace",
                    bufsize=1, creationflags=NO_WINDOW)
                for line in p.stdout:
                    self.logq_put(line.rstrip("\n"))
                p.wait()
                rc = p.returncode
                self.logq_put(f"—— 结束，退出码 {rc}")
            except Exception as e:
                self.logq_put(f"!! 启动失败: {type(e).__name__}: {e}")
            finally:
                self.root.after(0, lambda: self.set_busy(False))
                if on_done is not None:
                    self.root.after(0, lambda: on_done(rc))
                # 有些操作失败了只写日志没人看得见 —— 人在「节点」页的话
                # 根本不知道发生了什么。给一个弹窗 + 一句能照做的事。
                elif rc != 0 and tip:
                    self.root.after(0, lambda: messagebox.showwarning(label or "操作失败", tip))

        threading.Thread(target=worker, daemon=True).start()

    def port_holders(self) -> list[dict]:
        """列出占着本程序端口的进程。"""
        try:
            import pool as _pool          # pool.py 里已经有现成的实现
            return _pool.port_holders(self.port)
        except Exception:
            return []

    def do_free_port(self, ask: bool = True) -> bool:
        """清掉占着端口的进程。

        只动**这个端口**的占用者 —— 不要一杆子打翻所有 python.exe,
        那会杀掉用户自己正在跑的东西。
        """
        if self.busy:
            messagebox.showinfo("正在忙", "上一个操作还没结束，等它跑完。")
            return False
        holders = self.port_holders()
        if not holders:
            if ask:
                # "查不到占用者" ≠ "端口空闲"。以前这里直接报"没有被占用",
                # 而用户上一秒可能刚看到"端口被占用"的提示 —— 两句自相矛盾的话
                # 摆在一起, 只会让人觉得程序坏了。用 port_listening 复核再下结论。
                if port_listening(self.port):
                    messagebox.showwarning(
                        "端口被占用，但查不到占用者",
                        f"端口 {self.port} 确实有东西在监听，但没查出是哪个进程。\n\n"
                        "可能的原因：\n"
                        "  · netstat / Get-NetTCPConnection 被安全软件拦了\n"
                        "  · 占用者属于别的用户，当前权限看不到\n\n"
                        "手动看一眼：\n"
                        f"    netstat -ano | findstr :{self.port}\n"
                        "最后一列是 PID，再到任务管理器里按 PID 找那个进程。")
                else:
                    messagebox.showinfo("端口空闲", f"端口 {self.port} 没有被占用。")
            return True
        if ask:
            lines = []
            for h in holders:
                tag = "   ← 另一份 freeVPN" if h.get("is_freevpn") else ""
                lines.append(f"  {h['name']}  (PID {h['pid']}){tag}")
                if h.get("cmdline"):
                    lines.append(f"      {h['cmdline'][:90]}")
            if not messagebox.askyesno(
                    "清掉端口占用",
                    f"端口 {self.port} 被这些进程占着：\n\n" + "\n".join(lines) +
                    "\n\n要结束它们吗？\n"
                    "（只动这个端口上的进程，不会影响别的东西）"):
                return False
        self.run_action("free-port", "--port", str(self.port))
        return True

    def do_import(self):
        """一键导入。普通路径失败时问一句, 然后走可靠路径。

        两条路径的差别:
          · 深链 clash://install-config —— 靠客户端自己的单例转发, 有些机器上
            新实例拿不到单例锁就直接报错退出了 (os error 5 / 拒绝访问)
          · 直接写 profiles.yaml —— 可靠, 但**客户端必须先退出**
            (它把配置读在内存里, 退出时会整个写回)
        """
        if self.busy:
            messagebox.showinfo("正在忙", "上一个操作还没结束，等它跑完。")
            return
        self.set_busy(True)
        self.say("$ import")

        def worker():
            rc = -1
            try:
                p = subprocess.Popen(
                    BASE_CMD + ["import"], cwd=str(ROOT), stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                    text=True, encoding="utf-8", errors="replace",
                    bufsize=1, creationflags=NO_WINDOW)
                for line in p.stdout:
                    self.logq_put(line.rstrip("\n"))
                p.wait()
                rc = p.returncode
            except Exception as e:
                self.logq_put(f"!! {type(e).__name__}: {e}")
            self.root.after(0, lambda: self._import_done(rc))

        threading.Thread(target=worker, daemon=True).start()

    def _import_done(self, rc: int):
        self.set_busy(False)
        if rc != 0:
            ok = messagebox.askyesno(
                "导入没成功",
                "直接写配置和深链都没成功（详情见「日志」页）。\n\n"
                "要不要重试一次？会先关掉 Clash Verge 再写，"
                "写入后再把它打开。\n\n"
                "（如果「订阅地址」那行能正常拉取，也可以直接复制它手动添加）")
            if ok:
                self.run_action("import", "--restart")
            else:
                self.say("已跳过。可以手动把「订阅地址」加进客户端。")
            return

        # 写成功了。但 Clash Verge 只在**启动时**读 profiles.yaml ——
        # 它正在运行的话，新订阅要重启才看得到。
        if not sec.process_running("clash-verge.exe"):
            self.say("导入成功（详情见「日志」页）")
            return
        ok = messagebox.askyesno(
            "已写入订阅",
            "freeVPN 已经写进 Clash Verge 的订阅列表了。\n\n"
            "不过 Clash Verge 只在启动时读一次配置 —— 它现在正在运行，"
            "所以列表里暂时还看不到。\n\n"
            "要现在重启它吗？（约 10 秒）")
        if ok:
            self.run_action("import", "--restart")
        else:
            self.say("已写入。手动重启 Clash Verge 就能看到 freeVPN。")

    def open_page(self):
        tok = ""
        try:
            tok = (STATE / "token.txt").read_text(encoding="utf-8").strip()
        except Exception:
            pass
        url = f"http://127.0.0.1:{self.port}/?token={tok}"
        if not port_listening(self.port):
            messagebox.showwarning("服务没起", "订阅服务没在跑，先点「启动常驻」。")
            return
        try:
            os.startfile(url)
        except Exception as e:
            messagebox.showerror("打开失败", str(e))

    def copy_addr(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.var_addr.get())
        self.say("订阅地址已复制到剪贴板")

    def toggle_daemon(self):
        pids = daemon_pids()
        if pids:
            if not messagebox.askyesno("停止常驻", f"结束 {len(pids)} 个 pool.py 进程？"):
                return
            for pid in pids:
                run_hidden(["taskkill", "/PID", str(pid), "/T", "/F"])
            try:
                (STATE / "daemon.pid").unlink(missing_ok=True)
            except Exception:
                pass
            self.say(f"已停止 {len(pids)} 个进程")
            self.root.after(1200, self.refresh)
            return
        # 启动
        log = STATE / "daemon.log"
        try:
            # 常驻自己的输出也要落到日志里。以前这里用 DEVNULL 丢掉, 于是
            # "在等下一个刻度"、"端口被占用"这类信息用户完全看不到 ——
            # 点了启动常驻之后界面毫无反应, 只能干等。
            STATE.mkdir(parents=True, exist_ok=True)
            log.write_text("", encoding="utf-8")
            self._logfh = open(log, "ab")
            self.proc = subprocess.Popen(
                BASE_CMD + ["daemon", "--port", str(self.port), "--log", str(log)],
                cwd=str(ROOT), stdout=self._logfh, stderr=self._logfh,
                stdin=subprocess.DEVNULL, creationflags=NO_WINDOW)
            self.say(f"常驻已启动 (PID {self.proc.pid})，日志 {log}")
            self.say("首轮完整扫描要 1~3 分钟，期间订阅是空的")
            self.watch_daemon(self.proc, log)
        except Exception as e:
            messagebox.showerror("启动失败", str(e))
        self.root.after(1500, self.refresh)

    def watch_daemon(self, proc: subprocess.Popen, logpath: Path):
        """盯着刚起来的常驻: 前 8 秒就退出 = 启动失败, 把日志尾部摊给用户看。

        之前这里不管返回值, 于是端口冲突之类的失败只写进了 daemon.log ——
        GUI 上一点反应都没有, 用户看到的就是"点了启动常驻没反应"。
        """

        def watch():
            for _ in range(16):
                time.sleep(0.5)
                if proc.poll() is not None:
                    rc = proc.returncode
                    tail = []
                    try:
                        lines = logpath.read_text(
                            encoding="utf-8", errors="replace").splitlines()
                        tail = [x for x in lines if x.strip()][-14:]
                    except Exception:
                        pass
                    self.logq_put(f"!! 常驻启动失败，退出码 {rc}")
                    for line in tail:
                        self.logq_put("   " + line)
                    msg = "\n".join(tail[-8:]) or "（日志是空的）"
                    joined = "\n".join(tail)
                    port_busy = ("已被占用" in joined) or ("WinError 10048" in joined)

                    def report():
                        if port_busy:
                            holders = self.port_holders()
                            who = "\n".join(
                                f"  {h['name']}  (PID {h['pid']})"
                                + ("   ← 另一份 freeVPN" if h.get("is_freevpn") else "")
                                for h in holders) or (
                                "  （查不到占用者。手动看一眼：\n"
                                f"     netstat -ano | findstr :{self.port}\n"
                                "   最后一列是 PID）")
                            if messagebox.askyesno(
                                    "端口被占用",
                                    f"常驻起不来：端口 {self.port} 被这些进程占着。\n\n"
                                    f"{who}\n\n"
                                    "要结束它们、然后重新启动常驻吗？\n"
                                    "（只动这个端口上的进程，不会影响别的东西）"):
                                self.do_free_port(ask=False)
                                # free-port 跑完再启动, 否则会撞上同一个端口
                                self.run_action(
                                    "free-port", "--port", str(self.port),
                                    on_done=lambda rc: self.root.after(
                                        800, self.toggle_daemon))
                            return
                        messagebox.showerror(
                            "常驻启动失败",
                            f"退出码 {rc}\n\n{msg}\n\n完整日志: {logpath}")

                    self.root.after(0, report)
                    self.root.after(200, self.refresh)
                    return
            self.logq_put("常驻已稳定运行（前 8 秒没有退出）")

        threading.Thread(target=watch, daemon=True).start()

    def toggle_autostart(self):
        auto = (Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows"
                / "Start Menu" / "Programs" / "Startup" / "freeVPN.vbs")
        self.run_action("autostart", *(["--remove"] if auto.exists() else []))
        self.root.after(2000, self.refresh)

    def save_conf(self):
        conf = load_json(CONF) or {}
        for k, v in self.vars.items():
            s = v.get().strip()
            if s == "":
                continue
            try:
                conf[k] = int(s) if s.lstrip("-").isdigit() else float(s)
            except ValueError:
                messagebox.showerror("格式不对", f"{k} 要是数字，收到 {s!r}")
                return
        try:
            CONF.write_text(json.dumps(conf, ensure_ascii=False, indent=2),
                            encoding="utf-8")
            self.say(f"设置已保存到 {CONF.name}")
            messagebox.showinfo("已保存", "重启常驻后生效。")
        except Exception as e:
            messagebox.showerror("保存失败", str(e))


def main(port: int = 8787):
    root = tk.Tk()
    PoolGUI(root, port)
    root.mainloop()
    return 0
