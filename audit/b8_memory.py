# -*- coding: utf-8 -*-
"""
问题 8 验证: MAX_RESPONSE_BYTES=8MB 与 clamp_text 是否真的防住了内存放大
(base64 解码膨胀、gzip 压缩炸弹、YAML 别名展开)。
"""
import http.server
import socketserver
import sys
import threading
import time
import tracemalloc
import zlib

sys.path.insert(0, r"E:\AI\freeVPN")
import pool
import security as sec

PORT = 18411


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/big":
            n = int(self.headers.get("X-Size", "0")) or 9 * 1024 * 1024
            self.send_response(200)
            self.send_header("Content-Length", str(n))
            self.end_headers()
            chunk = b"A" * 65536
            sent = 0
            while sent < n:
                self.wfile.write(chunk[: min(65536, n - sent)])
                sent += 65536
        elif path == "/gz":
            raw = b"proxies:\n" + b"  - server: 1.2.3.4\n    port: 443\n" * 2000000
            comp = zlib.compress(raw, 9)
            self.send_response(200)
            self.send_header("Content-Length", str(len(comp)))
            self.send_header("Content-Encoding", "gzip")
            self.end_headers()
            self.wfile.write(comp)
        elif path == "/inf":
            self.send_response(200)
            self.end_headers()
            try:
                while True:
                    self.wfile.write(b"B" * 65536)
            except Exception:
                pass
        else:
            self.send_response(404)
            self.end_headers()


class Srv(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def measure(label: str, fn, *a):
    tracemalloc.start()
    t0 = time.perf_counter()
    try:
        r = fn(*a)
        err = None
    except Exception as e:
        r, err = None, f"{type(e).__name__}: {e}"
    dt = time.perf_counter() - t0
    cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print(f"  {label:34} 耗时={dt:7.2f}s 峰值Py分配={peak/1048576:7.1f}MB  "
          f"结果={str(r)[:60]!r} {err or ''}")
    return r, peak, dt


if __name__ == "__main__":
    srv = Srv(("127.0.0.1", PORT), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.5)
    print(f"本地测试服务器 http://127.0.0.1:{PORT}")
    print(f"MAX_RESPONSE_BYTES = {sec.MAX_RESPONSE_BYTES} "
          f"({sec.MAX_RESPONSE_BYTES//1048576}MB)")
    print(f"MAX_PARSE_CHARS    = {sec.MAX_PARSE_CHARS} "
          f"({sec.MAX_PARSE_CHARS//1048576}MB)")
    print()

    print("=" * 78)
    print("### 8.1 fetch_one 对超大响应的处理")
    print("=" * 78)
    for size, tag in ((1024 * 1024, "1MB"), (8 * 1024 * 1024 - 1, "8MB-1"),
                      (8 * 1024 * 1024, "8MB"), (9 * 1024 * 1024, "9MB"),
                      (64 * 1024 * 1024, "64MB")):
        import urllib.request
        url = f"http://127.0.0.1:{PORT}/big"

        def go(u=url, s=size):
            req = urllib.request.Request(u, headers={"X-Size": str(s),
                                                      "Accept-Encoding": "identity"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = r.read(sec.MAX_RESPONSE_BYTES + 1)
            if len(data) > sec.MAX_RESPONSE_BYTES:
                return f"拒绝(len={len(data)})"
            return f"接受(len={len(data)})"
        measure(f"服务端声明 {tag}", go)

    print()
    print("### 8.2 fetch_one 真身 (走模块函数) 对 9MB / 64MB 的处理")
    for size, tag in ((9 * 1024 * 1024, "9MB"), (64 * 1024 * 1024, "64MB")):
        url = f"http://127.0.0.1:{PORT}/big?size={size}"
        # fetch_one 用 mirror_urls(url) -> 非 GitHub 直连; 用 header 无法注入,
        # 所以按 Content-Length 走: 让 /big 默认返回 9MB, 64MB 用 query 区分
        r, peak, dt = measure(f"fetch_one {tag}", pool.fetch_one, url, 30)
        print(f"      -> 返回 text 是否为 None: {r[1] is None}")

    print()
    print("=" * 78)
    print("### 8.3 gzip 压缩炸弹")
    print("=" * 78)
    raw_len = len(b"proxies:\n" + b"  - server: 1.2.3.4\n    port: 443\n" * 2000000)
    print(f"  服务端准备: 解压后 {raw_len/1048576:.1f}MB, 压缩后约 "
          f"{len(zlib.compress(b'x'*raw_len, 9))/1048576:.2f}MB(参考值)")
    r, peak, dt = measure("fetch_one 拉 /gz", pool.fetch_one,
                          f"http://127.0.0.1:{PORT}/gz", 30)
    if r and r[1] is not None:
        print(f"      -> 收到 {len(r[1])} 字符 (urllib 不自动解压, 未被放大)")
        print(f"      -> 头 40 字符: {r[1][:40]!r}")

    print()
    print("=" * 78)
    print("### 8.4 YAML 别名炸弹: yaml_bomb 能否拦住")
    print("=" * 78)
    LAUGH = "a: &a [x,x,x,x,x,x,x,x,x]\n" + "".join(
        f"{chr(98+i)}: &{chr(98+i)} [*{chr(97+i)},*{chr(97+i)},*{chr(97+i)},"
        f"*{chr(97+i)},*{chr(97+i)},*{chr(97+i)},*{chr(97+i)},*{chr(97+i)}]\n"
        for i in range(8))
    print(f"  经典 Billion Laughs (flow 式, 9 层): {len(LAUGH)} 字节")
    print(f"  yaml_bomb 判定为炸弹: {sec.yaml_bomb(LAUGH)}")
    print(f"  锚点正则命中数: {len(sec._ANCHOR_RE.findall(LAUGH))}, "
          f"别名正则命中数: {len(sec._ALIAS_RE.findall(LAUGH))}")
    import yaml as _y
    measure("yaml.safe_load(billion laughs)", _y.safe_load, LAUGH)
    # 行尾式锚点 (会被 yaml_bomb 抓到)
    LAUGH2 = "proxies:\n" + "".join(f"  - &a{i}\n    server: 1.2.3.4\n"
                                    for i in range(200))
    print(f"  行尾式锚点 200 个: yaml_bomb = {sec.yaml_bomb(LAUGH2)} (True=拦住)")
    print()
    print("  PyYAML 深嵌套 (非别名): 用嵌套 flow 序列")
    for depth in (100, 300, 600, 1200):
        s = "[" * depth + "]" * depth
        measure(f"safe_load 嵌套深度={depth}", _y.safe_load, s)

    print()
    print("=" * 78)
    print("### 8.5 base64 解码膨胀与 clamp_text")
    print("=" * 78)
    import base64
    payload = "vmess://" + base64.b64encode(b"x" * (1024 * 1024)).decode() + "\n"
    print(f"  输入 {len(payload)/1048576:.2f}MB 的 base64 链接文本")
    measure("parse_any(1MB base64)", pool.parse_any, payload)
    big = base64.b64encode(b"vless://u@1.2.3.4:443\n" * 200000).decode()
    print(f"  双层 base64: 外层 {len(big)/1048576:.2f}MB")
    measure("parse_any(外层 base64)", pool.parse_any, big)
    clamped = sec.clamp_text("A" * (20 * 1024 * 1024))
    print(f"  clamp_text(20MB) -> {len(clamped)/1048576:.2f}MB (上限 "
          f"{sec.MAX_PARSE_CHARS/1048576:.0f}MB)")

    print()
    print("=" * 78)
    print("### 8.6 _mini_yaml_proxies 在超大/超深输入上的表现")
    print("=" * 78)
    big_mini = "proxies:\n" + "".join(
        f"  - name: n{i}\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n"
        f"    cipher: aes-128-gcm\n    password: pw\n" for i in range(60000))
    print(f"  6 万节点块式文本: {len(big_mini)/1048576:.2f}MB")
    measure("_mini_yaml_proxies(6万节点)", pool._mini_yaml_proxies, big_mini)
    deep = "proxies:\n  - server: 1.2.3.4\n    port: 1\n"
    ind = 4
    for i in range(1500):
        deep += " " * ind + f"k{i}:\n"
        ind += 1
    print(f"  1500 层缩进: {len(deep)/1048576:.3f}MB")
    r, peak, dt = measure("_mini_yaml_proxies(1500层缩进)", pool._mini_yaml_proxies, deep)
    if r:
        d, cur = 0, r[0]
        while isinstance(cur, dict) and cur:
            cur = list(cur.values())[-1] if isinstance(list(cur.values())[-1], dict) else {}
            d += 1
            if d > 5000:
                break
        print(f"      -> 造出的 dict 嵌套深度 ≈ {d}")
    print()
    print("=" * 78)
    print("### 8.7 放大倍数的定量: 4MB 上限内的输入能造出多少内存")
    print("=" * 78)
    import base64 as _b64
    inner = "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443#n\n" * 120000
    outer = _b64.b64encode(inner.encode()).decode()
    clamped = sec.clamp_text(outer)
    print(f"  clamp_text 之后输入 = {len(clamped)/1048576:.2f}MB "
          f"(MAX_PARSE_CHARS={sec.MAX_PARSE_CHARS})")
    tracemalloc.start()
    t0 = time.perf_counter()
    nodes = pool.parse_any(clamped)
    dt = time.perf_counter() - t0
    cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print(f"  parse_any -> {len(nodes)} 个节点, 耗时 {dt:.2f}s, "
          f"峰值 Py 分配 {peak/1048576:.1f}MB  (放大 {peak/len(clamped.encode()):.1f}×)")
    print(f"  PER_SOURCE_CAP={pool.PER_SOURCE_CAP} 是在 parse_any **返回之后**才截断的,")
    print(f"  即峰值内存与源体积成正比, 16 个源并发时理论峰值 ≈ "
          f"{peak/1048576*16/1024:.2f}GB")

    print()
    print("### 8.8 PyYAML 深嵌套 safe_load 的耗时标度")
    for depth in (600, 800, 1000, 1200, 1500):
        s = "[" * depth + "]" * depth
        tracemalloc.start()
        t0 = time.perf_counter()
        try:
            _y.safe_load(s)
            err = ""
        except Exception as e:
            err = f"{type(e).__name__}"
        dt = time.perf_counter() - t0
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        print(f"  嵌套深度={depth:<6} 输入={2*depth:<6}字节 耗时={dt:8.3f}s "
              f"峰值={peak/1048576:.1f}MB {err}")

    srv.shutdown()
