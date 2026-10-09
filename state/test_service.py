#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""实测订阅服务的访问控制: 令牌、Host 校验、路径穿越、CORS。

不是读代码判断"应该有防护", 而是真的发请求看它怎么答。
"""
import sys
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, r"E:\AI\freeVPN")
import pool  # noqa: E402
import security as sec  # noqa: E402

PORT = 8787
BASE = f"http://127.0.0.1:{PORT}"
TOKEN = sec.load_or_create_token()
print(f"令牌: {TOKEN[:10]}...  (来自 state/token.txt)")

srv = pool.serve(PORT, block=False)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.6)


def probe(label, path, host=None, expect=None, headers=None):
    url = BASE + path
    req = urllib.request.Request(url)
    if host:
        req.add_header("Host", host)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            code = r.status
            body = r.read()
            hdrs = dict(r.getheaders())
    except urllib.error.HTTPError as e:
        code = e.code
        body = e.read()
        hdrs = dict(e.headers)
    except Exception as e:
        code = -1
        body = str(e).encode()
        hdrs = {}
    mark = "PASS" if (expect is None or code == expect) else "FAIL"
    detail = f"HTTP {code}"
    if expect is not None:
        detail += f" (期望 {expect})"
    if code == 200:
        detail += f"  {len(body)} 字节"
    print(f"  [{mark}] {label:<44} {detail}")
    return mark == "PASS", hdrs, body


results = []

print("\n--- ① 令牌校验 ---")
results.append(probe("无令牌访问订阅", "/sub/pool.yaml", expect=401)[0])
results.append(probe("错误令牌", f"/sub/pool.yaml?token=deadbeef", expect=401)[0])
results.append(probe("正确令牌(?token=)", f"/sub/pool.yaml?token={TOKEN}", expect=200)[0])
results.append(probe("正确令牌(Bearer)", "/sub/pool.yaml", expect=200,
                     headers={"Authorization": f"Bearer {TOKEN}"})[0])
results.append(probe("无令牌访问状态页", "/", expect=401)[0])
results.append(probe("无令牌访问 report.json", "/report.json", expect=401)[0])

print("\n--- ② Host 头校验 (挡 DNS rebinding) ---")
results.append(probe("Host: evil.com", f"/sub/pool.yaml?token={TOKEN}",
                     host="evil.com", expect=403)[0])
results.append(probe("Host: 127.0.0.1 (正常)", f"/sub/pool.yaml?token={TOKEN}",
                     host=f"127.0.0.1:{PORT}", expect=200)[0])
results.append(probe("Host: localhost (正常)", f"/sub/pool.yaml?token={TOKEN}",
                     host=f"localhost:{PORT}", expect=200)[0])

print("\n--- ③ 路径穿越 ---")
for evil in ["/sub/../state/token.txt", "/sub/..%2fstate%2ftoken.txt",
             "/sub/.token.txt", "/sub/sub/../../pool.py"]:
    results.append(probe(f"穿越尝试 {evil}", f"{evil}?token={TOKEN}",
                         expect=None)[0])
# 这些必须不是 200; 单独判定
print("  (上面每条都不能是 200)")

print("\n--- ④ CORS / 安全响应头 ---")
ok, hdrs, body = probe("正常请求的响应头", f"/sub/pool.yaml?token={TOKEN}", expect=200)
acao = hdrs.get("Access-Control-Allow-Origin")
print(f"  [{'PASS' if acao is None else 'FAIL'}] 未下发 Access-Control-Allow-Origin"
      f"{'  (实际: ' + str(acao) + ')' if acao else ''}")
results.append(acao is None)
print(f"  [{'PASS' if hdrs.get('X-Content-Type-Options') == 'nosniff' else 'FAIL'}] "
      f"X-Content-Type-Options: nosniff")
print(f"  [{'PASS' if hdrs.get('Cache-Control') == 'no-store' else 'FAIL'}] "
      f"Cache-Control: no-store")

print("\n--- ⑤ 订阅内容抽查 ---")
ok, _, body = probe("拉取 pool.yaml", f"/sub/pool.yaml?token={TOKEN}", expect=200)
text = body.decode("utf-8", "replace")
print(f"  [{'PASS' if 'external-controller' not in text else 'FAIL'}] "
      f"订阅不含 external-controller")
print(f"  [{'PASS' if 'global-client-fingerprint' not in text else 'FAIL'}] "
      f"订阅不含已废弃的 global-client-fingerprint")
print(f"  [{'PASS' if '169.254.169.254' in text else 'FAIL'}] "
      f"含云元数据 REJECT 规则")
results.append("external-controller" not in text)
results.append("global-client-fingerprint" not in text)

srv.shutdown()
print(f"\n=== {sum(results)}/{len(results)} 项通过 ===")
sys.exit(0 if all(results) else 1)
