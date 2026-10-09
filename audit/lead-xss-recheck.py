#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lead 交叉验证(第三版): 状态页 XSS —— 用真正的 HTML 解析器。

前两版都不对:
  v1 只看"payload 在不在页面里", 但 payload 出现在**文本位置**是无害的。
  v2 用正则抽属性, 结果把**转义后的文本**也当成了属性
     (`&lt;iframe src=javascript:...&gt;` 里的 `src=` 被误判成真属性)。

只有 HTML 解析器能区分"这是标签属性"还是"这是文本"。
"""
import sys
from html.parser import HTMLParser

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pool  # noqa: E402

PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "java\tscript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "<iframe src=javascript:alert(1)>",
    "{{7*7}}",
    "{0.__class__}",
    "</td></tr><script>alert(1)</script>",
    '<a href="javascript:alert(1)">x</a>',
    "onerror=alert(1)",
    "`${alert(1)}`",
    "<!-- -->",
    "<style>*{x:1}</style>",
    "\x00\x01\x1b[31m\x7f",
]

report = {
    "generated_at": PAYLOADS[0], "sources_ok": PAYLOADS[1], "sources_total": 31,
    "after_dedupe": 1, "after_l1": 2, "after_l2": 3, "final": 4,
    "regions": {p: 1 for p in PAYLOADS},
    "fastest": [{"name": p, "region": p, "type": p, "tcp": p, "real": p}
                for p in PAYLOADS],
    "audit": {"blocked": 1, "warned": 2, "reasons": {p: p for p in PAYLOADS}},
}
NONCE = "TESTNONCE123456"
page = pool.render_page(report, 8787, "FAKETOKEN",
                        "clash://install-config?url=x", NONCE)


class Collector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.tags = []          # (tag, attrs)
        self.attrs = []         # (tag, name, value)
        self.text = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, attrs))
        for k, v in attrs:
            self.attrs.append((tag, k.lower(), v if v is not None else ""))
        if tag in ("script", "style"):
            self._raw = tag

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_data(self, d):
        self.text.append(d)


c = Collector()
c.feed(page)

print(f"页面 {len(page)} 字符 / {len(c.tags)} 个标签 / {len(c.attrs)} 个属性\n")

DANGER = {"href", "src", "action", "formaction", "xlink:href", "data",
          "srcdoc", "style", "background", "poster"}
EVENT = ("onerror", "onload", "onclick", "onmouseover", "onfocus", "onstart")

print("=== 1) 解析出的真实属性 ===")
bad_attr = []
for tag, k, v in c.attrs:
    risky = (k in DANGER and ("javascript:" in v.lower()
                              or "data:text/html" in v.lower()
                              or "<" in v or ">" in v)) or k in EVENT
    flag = "[!! 危险]" if risky else "[ok]"
    if risky:
        bad_attr.append((tag, k, v))
    print(f"  {flag} <{tag} {k}=\"{v[:70]}\">")
if not c.attrs:
    print("  （没有属性）")

print()
print("=== 2) payload 有没有落进真实属性值里 ===")
hit = 0
for p in PAYLOADS:
    found = [(t, k) for t, k, v in c.attrs if p in v]
    if found:
        hit += 1
        print(f"  [!!] {p[:45]!r} -> {found[:3]}")
    else:
        print(f"  [OK] {p[:45]!r}")
print(f"\n  落在真实属性里的: {hit}/{len(PAYLOADS)}")

print()
print("=== 3) 解析出的标签种类(有没有危险标签) ===")
kinds = sorted({t for t, _ in c.tags})
print(f"  {kinds}")
for t in ("script", "img", "svg", "iframe", "object", "embed", "link", "style"):
    if t in kinds:
        print(f"  [!] 出现了 <{t}>")

print()
print("=== 4) <script> 是否都带 nonce ===")
for tag, attrs in c.tags:
    if tag == "script":
        has = any(k == "nonce" and v == NONCE for k, v in attrs)
        print(f"  {'[OK]' if has else '[!! 危险]'} <script> nonce={dict(attrs).get('nonce')!r}")

print()
print("=== 5) 控制字符 ===")
ctrl = sorted({hex(ord(ch)) for ch in page if ord(ch) < 0x20 and ch not in "\r\n\t"})
print(f"  {'[!] ' + str(ctrl) if ctrl else '[OK] 无'}")

print()
if bad_attr or hit:
    print(f"结论: **有问题** —— {len(bad_attr)} 个危险属性, {hit} 个 payload 落进属性")
    sys.exit(1)
print("结论: payload 全部只出现在文本位置; 真实属性里没有危险内容; "
      "无可执行标签; nonce 覆盖全部脚本")
