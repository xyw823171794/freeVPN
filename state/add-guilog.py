#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""让控制台把日志同时落到 state/gui.log。

排错用: 用户报"导入失败"时, 日志页的内容我们看不到, 只能猜。
落一个文件下来, 直接读它就知道卡在哪一步。
"""
import re
import sys
from pathlib import Path

ROOT = Path(r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
g = ROOT / "gui.py"
s = g.read_text(encoding="utf-8")
orig = s

# 1) 所有 logq.put(...) 改成 logq_put(...)
n = len(re.findall(r"self\.logq\.put\(", s))
s = s.replace("self.logq.put(", "self.logq_put(")
print(f"  替换 logq.put -> logq_put: {n} 处")

# 2) say() 里刚加的那个 logline 去掉, 统一走 logq_put
s = s.replace('''    def logline(self, line: str):
        """把子进程输出同时写进日志页和 state/gui.log。

        落文件是为了排错 —— 用户报"导入失败"时, 日志页的内容我们看不到,
        只能猜。有了这个文件, 直接读它就知道卡在哪一步。
        """
        self.logq_put(line)
        try:
            self._gui_log.write(line + "\\n")
            self._gui_log.flush()
        except Exception:
            pass
''', '''    def logq_put(self, line: str):
        """写一行到日志页, **同时落 state/gui.log**。

        落文件是为了排错 —— 用户报"导入失败"时, 日志页的内容我们看不到,
        只能猜。有了这个文件, 直接读它就知道卡在哪一步。
        """
        self.logq.put(line)
        try:
            self._gui_log.write(line + "\\n")
            self._gui_log.flush()
        except Exception:
            pass
''')
print("  改写 logline -> logq_put")

# 3) __init__ 里打开日志文件
anchor = "        self._prog_running = False         # 不确定模式的动画是否已启动"
if anchor in s:
    s = s.replace(anchor, anchor + '''
        # 日志同时落盘, 方便排错(用户报错时我们看不到界面上的日志页)
        try:
            STATE.mkdir(parents=True, exist_ok=True)
            self._gui_log = open(STATE / "gui.log", "a", encoding="utf-8")
            self._gui_log.write(f"\\n===== 控制台启动 {datetime.now():%Y-%m-%d %H:%M:%S} "
                                f"v{ver.__version__} =====\\n")
            self._gui_log.flush()
        except Exception:
            self._gui_log = open(os.devnull, "w", encoding="utf-8")''')
    print("  已加日志文件初始化")
else:
    print("  [!!] 找不到插入点")

g.write_text(s, encoding="utf-8")
print(f"  文件大小 {len(orig)} -> {len(s)}")
