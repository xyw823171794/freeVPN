#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""功能测试: 列头排序。重点验数字列是按数值排, 不是按字符串。"""
import sys
import tkinter as tk

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import gui  # noqa: E402

FAIL = []


def check(label, got, want):
    ok = got == want
    if not ok:
        FAIL.append(label)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not ok:
        print(f"         得到 {got}")
        print(f"         期望 {want}")


root = tk.Tk()
root.withdraw()
g = gui.PoolGUI(root, 8787)

# 故意用会暴露字符串排序错误的延迟值: 1000 在字符串序里小于 200
g._nodes = [
    {"name": "🇭🇰 香港A", "type": "vmess", "_region": "HK", "_real": 1000, "_tcp": 30},
    {"name": "🇯🇵 日本B", "type": "ss", "_region": "JP", "_real": 200, "_tcp": 300},
    {"name": "🇺🇸 美国C", "type": "vless", "_region": "US", "_real": 50, "_tcp": 20},
    {"name": "🇸🇬 新加坡D", "type": "trojan", "_region": "SG", "_tcp": 15},  # 无 _real
]
g.fill_tree()


def names():
    return [g.tree.item(i)["values"][0] for i in g.tree.get_children()]


def heading(cid):
    return g.tree.heading(cid)["text"]


print("=== 初始顺序 (池子自己的顺序) ===")
print(f"  {names()}")
check("初始保持原序", names(), ["香港A", "日本B", "美国C", "新加坡D"])

print()
print("=== 按「实测延迟」升序 ===")
g.sort_by("real")
print(f"  {names()}")
check("数值升序(不是字符串序)", names(),
      ["美国C", "日本B", "香港A", "新加坡D"])   # 50 < 200 < 1000, 无值的沉底
check("表头带升序箭头", heading("real"), "实测延迟 ▲")

print()
print("=== 再点一次 → 降序 ===")
g.sort_by("real")
print(f"  {names()}")
# 没测出延迟的(新加坡D)无论升降都沉底 —— 它不等于"最慢"
check("数值降序(缺失值仍沉底)", names(),
      ["香港A", "日本B", "美国C", "新加坡D"])
check("表头带降序箭头", heading("real"), "实测延迟 ▼")

print()
print("=== 按「TCP」升序 ===")
g.sort_by("tcp")
print(f"  {names()}")
check("TCP 升序", names(), ["新加坡D", "美国C", "香港A", "日本B"])
check("旧列箭头已清除", heading("real"), "实测延迟")

print()
print("=== 按「协议」升序 (字符串) ===")
g.sort_by("type")
print(f"  {names()}")
check("协议升序", names(), ["日本B", "新加坡D", "美国C", "香港A"])

print()
print("=== 按「地区」升序 ===")
g.sort_by("region")
print(f"  {names()}")
check("地区升序", names(), ["香港A", "日本B", "新加坡D", "美国C"])

print()
print("=== 自动刷新时排序是否保持 ===")
g.sort_by("real")           # 当前是 region 降序? 不, 换到 real
g.sort_by("real")
order_before = names()
g._sig = None               # 模拟数据变化触发重建
g.fill_tree()
check("重建后排序保持", names(), order_before)
check("箭头仍正确", heading("real"), "实测延迟 ▼")

root.destroy()
print()
print(f"=== {len(FAIL)} 项失败 ===" if FAIL else "=== 全部通过 ===")
sys.exit(1 if FAIL else 0)
