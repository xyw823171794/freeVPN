# -*- coding: utf-8 -*-
"""快速探测: _CTRL_RE 未覆盖的 Unicode 行分隔符能否在产物 YAML 里制造换行。"""
import sys
sys.path.insert(0, r"E:\AI\freeVPN")
import pool, security  # noqa

CANDIDATES = {
    "U+2028 LINE SEPARATOR": "\u2028",
    "U+2029 PARAGRAPH SEP": "\u2029",
    "U+0085 NEL": "\x85",
    "U+000A LF": "\n",
    "U+000B VT": "\x0b",
    "U+000C FF": "\x0c",
    "U+001C FS": "\x1c",
    "U+007F DEL": "\x7f",
    "U+FEFF BOM": "\ufeff",
    "U+0000 NUL": "\x00",
}

print("=== 1. scrub() 对各类分隔符的存活情况 ===")
for label, ch in CANDIDATES.items():
    survived = pool.scrub(ch) == ch
    print(f"  {label:26} 经 scrub 存活: {survived}")

print()
print("=== 2. Python str.splitlines() 是否把它当行边界 ===")
for label, ch in CANDIDATES.items():
    n = len(("a" + ch + "b").splitlines())
    print(f"  {label:26} splitlines 段数={n}  (2 = 被当作换行)")

print()
print("=== 3. PyYAML 读入端是否把它当行边界 ===")
import yaml
for label, ch in CANDIDATES.items():
    doc = "a: 1" + ch + "b: 2"
    try:
        got = yaml.safe_load(doc)
    except Exception as e:
        got = f"<{type(e).__name__}>"
    print(f"  {label:26} safe_load -> {got!r}")
