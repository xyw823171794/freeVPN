# freeVPN (freeVPN)

> 当前版本 **v1.4.0**（见 `version.py` 与 `CHANGELOG.md`）

把公开免费订阅源聚合成**一个**节点池：自动去重、双层真实测活、安全审计、按地区分组，
对外给一个本地订阅地址。客户端填一次，之后池子自己刷新，你只挑节点。

## 安全设计

这个池子的根本风险不是"节点慢"，而是**节点配置来自完全不可信的公开源**。
匿名第三方可以往里塞任意字段、任意服务器地址、任意命名。所以按信任边界分五层设防：

| 层 | 位置 | 挡什么 |
|---|---|---|
| ① 输入隔离 | `security.py` | 响应体超 8MB 丢弃；YAML 锚点炸弹（Billion Laughs）整源丢弃；送解析的文本上限 4MB |
| ② 节点审计 | `security.py` | 回环/内网/保留 IP、内网域名、敏感端口（22/3389/6379/27017…）、假凭证、诱导性命名、伪装知名品牌 |
| ③ 进程隔离 | `pool.py` | 内核环境变量剔除密钥类变量与 `*_PROXY`；独立工作目录；禁 tun（不改系统路由表）；禁 GEO 数据下载；不共享控制台与 stdin；POSIX 下加 rlimit 并降权 nobody |
| ④ 访问控制 | `pool.py` | 只监听 `127.0.0.1`；token 认证；Host 头校验挡 DNS rebinding；不发 CORS 头；路径穿越防护 |
| ⑤ 分流规则 | `security.py` | 云元数据端点 `REJECT`；银行/支付/政务/身份域名强制 `DIRECT`；内网段 `DIRECT`；**国内域名与国内 IP 段 `DIRECT`** |

具体拦掉的东西（都是实测遇到的真实样本）：

- **诱饵节点**：`NoMoreWalls` 源里投放的 `127.0.0.53`（命名"防范境外势力渗透"）——回环地址能连通本机，会骗过 TCP 探活，必须按 IP 段过滤。
- **内网指向**：`192.168.x` / `10.x` / `172.16-31.x` / `evil.local` 之类，等于把你导进内网。
- **敏感端口**：`vmess` 节点落在 22/3389/6379 这类端口，通常是源在拿你当跳板探内网。
- **假凭证**：`88888888-8888-8888-8888-888888888888` 之类的占位 UUID。
- **云元数据 SSRF**：`169.254.169.254` 被规则层直接 `REJECT`，防恶意配置偷云凭证。
- **国内节点**：`🇨🇳 CN` 节点不是翻墙节点，命中即丢。
- **国内流量**：兜底规则是 `MATCH,🚀 节点选择`，没补国内规则时**所有国内站点都会跟着进节点**。已补 —— 见下面「国内流量不进节点」。

**这套设计不声称能让免费节点变安全。** 节点持有者始终能看到你的明文目标域名和未加密流量。
别在上面登网银、主邮箱、公司账号。上面每一层都只做一件事：把可控风险压到最低。

### 国内流量不进节点

⑤ 层原来只挡了银行/政务这些"明显敏感"的域名，剩下的全落在兜底的
`MATCH,🚀 节点选择` 上 —— 也就是**没被点名的国内站点（含全部长尾）都会走免费节点**：
节点持有者能看到你访问了哪些国内服务，国内站点还会因为境外 IP 触发风控
（异地登录、验证码、拦截）。现在规则层的顺序是：

```
云元数据 REJECT → 银行/支付/政务 DIRECT → 国内域名 DIRECT
  → 内网/回环 DIRECT → 国内 IP 段 DIRECT → 其余走节点
```

敏感站点必须排在国内规则**前面** —— 银行也在 `cn` 的覆盖范围里，排后面会被
`cn_mode=reject` 一并掐掉。

数据在两份**可以直接编辑**的文件里（放一份在 exe 旁边就能覆盖内置的）：

| 文件 | 内容 | 来源 |
|---|---|---|
| `cn_cidr.txt` | 中国大陆 IP 段 5495 条（聚合后，占 v4 空间 7.98%） | APNIC 官方委托数据；`python state/gen-cn-rules.py` 重新生成 |
| `cn_domains.txt` | 国内域名后缀 215 条 | 手工维护；`cn` 一条就吃掉所有 `.cn` / `.com.cn` / `.gov.cn` |

**为什么内联 CIDR/域名，而不是 `GEOIP,CN` / `GEOSITE,cn`**：那两条要客户端本地有
MMDB/dat 文件，缺失时内核**直接拒绝整份配置**（实测 90 秒超时后 `test failed`），
订阅会整体失效 —— 这个失败模式比"产物大 200 KB"严重得多。代价只是产物从 5 KB
变成 209 KB。

`pool.conf.json` 里的开关（改完重启 `start.bat` 生效）：

| 键 | 默认 | 含义 |
|---|---|---|
| `cn_mode` | `direct` | `direct` 国内直连 / `reject` 国内直接掐断（连直连都不给）/ `off` 不下发国内规则 |
| `cn_resolve` | `true` | IP 规则是否解析域名后再判定：`true` 能覆盖没列进 `cn_domains.txt` 的国内长尾域名（代价：未命中的连接多一次 DNS 查询，有缓存）；`false` 只匹配本来就是 IP 的连接 |

实测（`python state/test_cn_rules.py`，60 项全绿）—— **是内核自己裁决的，不是读代码猜的**：

```
223.5.5.5:443        IPCIDR(223.0.0.0/12)        -> DIRECT
180.76.76.76:53      IPCIDR/180.76.0.0/14       -> DIRECT
8.8.8.8:53           Match/                     -> G        ← 国外照旧走节点
www.baidu.com:443    DomainSuffix(baidu.com)    -> DIRECT
www.google.com:443   Match/                     -> G
169.254.169.254:80   IPCIDR(169.254.169.254/32) -> REJECT
```

**清单外的国内域名不会漏**：产物是 `fake-ip` 模式，域名连接走到 IP 规则时内核会
做一次真实解析，解析出的国内 IP 命中 CN 段照样直连。实测（同款 fake-ip 配置）：

```
www.bilibili.com:443  DomainSuffix(bilibili.com)  -> DIRECT   ← 在清单里
b23.tv:443            IPCIDR(175.0.0.0/12)        -> DIRECT   ← 不在清单, 靠 IP 段兜住
biligame.com:443      IPCIDR(212.64.0.0/17)       -> DIRECT   ← 同上
www.google.com:443    Match/                      -> G
```

5794 条规则内核校验 0.05 秒。

## 安全审计记录

这套东西做过一次双人分头审计（服务端/进程边界 + 不可信输入/产物），
报告在 [`audit/A-server.md`](audit/A-server.md) 与 [`audit/B-data.md`](audit/B-data.md)，
验证脚本在 `audit/` 下。**所有结论都附了实跑输出**，不是读代码猜的。

共 27 条发现（2 严重 / 5 高 / 10 中 / 9 低 / 1 信息）+ 28 条「已排除」。
以下是修掉的重点：

| 编号 | 问题 | 修法 |
|---|---|---|
| **A-01** | 内核控制端口密钥硬编码 `"freevpn"` + 固定 19090；mihomo API 回 `Access-Control-Allow-Origin: *` 并放行 `Authorization`+`PATCH`。**任意网页**在探测窗口期可 `PATCH /configs {"allow-lan":true,"bind-address":"0.0.0.0"}`，把本机代理端口开成局域网开放代理（实测 204，监听真的变成 `0.0.0.0`） | 控制端口与密钥改为每个内核实例随机生成；删除模块级常量 |
| **B-1** | 产物 YAML 顶层注入：`U+2028/U+2029/U+0085` 不被 `scrub` 清除却被 YAML 当换行，而键名不加引号 → **单条恶意节点**即可注入 `tun`/`tunnels`/`hosts` 顶层键，绕过 `harden_kernel_config` 的 `pop("tun")`（实测内核真的去建 TUN 设备） | 行分隔符纳入清洗；键名一律引号化；产物反解自校验顶层键集合 |
| **A-02** | 状态页存储型 XSS：节点名来自不可信源且未转义，6/6 payload 原样进响应体 | `html.escape` 全量转义 + nonce CSP + 移除内联 `onclick` |
| **A-03** | 令牌明文写进 `state/access.log`（生产日志 146/170 行含完整令牌）；1MB 阈值用 `unlink()` 而非归档，约 1 万次请求就能把日志整份删掉 | 日志里 `token=`/`t=` 脱敏；轮转改为归档 |
| **B-2/A-07** | 节点字段全量透传：`dialer-proxy`/`interface-name`/`routing-mark`/`smux`/`tun` 等 24 个内核级字段原样下发且被内核接受 | 按协议类型的字段白名单（含嵌套 `ws-opts` 等） |
| **B-3** | `127.0.0.1.nip.io` 这类通配 DNS 域名零告警通过审计，内核解析成回环并真的连上本机端口 | 审计拦截通配 DNS 后缀 + L1 探活时校验**实际连到的 peer IP** |
| **B-4** | `AD_PAT` 是 O(n³)，`clean_name` 的 `n[:38]` 截断在正则之后 → 一条 32KB 恶意节点名能挂住十几小时 | 先截断再跑正则 |
| **A-04** | 非 ASCII 令牌让 `compare_digest` 抛 `TypeError`：客户端收到断连而非 401，且该请求不写访问日志（不留痕） | 比较 bytes 并捕获异常 |
| **A-06** | `kernel_env` 是关键词黑名单，`GITHUB_PAT`/`KUBECONFIG`/`VAULT_ADDR`/`DOCKER_CONFIG` 实测泄漏进内核进程 | 改为白名单（键名统一大写比较） |
| **B-7** | `skip-cert-verify: 1` / `Skip-Cert-Verify` 变体绕过审计（内核解码器不区分大小写、下划线当横线） | 键名归一 + 布尔字段归一成真 `bool` |
| **B-8** | 分流规则漏掉腾讯云/Azure 元数据域名、10 个内网段、10+ 家银行 | 规则从 49 条补到 84 条 |
| **B-9** | 畸形 tuic uuid 拼进通用订阅链接，结构破损污染客户端 | uuid 格式校验 |
| A-08 | `inject_verge` 非原子写（抓到过 0 字节中间态） | 写临时文件 + `os.replace` 原子替换；备份带时间戳轮转 |
| A-09 | 无连接数上限、handler 无超时 | handler `timeout = 15` |
| A-10 | `os.chmod(0o600)` 在 Windows 上不动 ACL，`Users` 可读令牌 | 改用 `icacls` 收紧到当前用户 + SYSTEM |
| A-11 | Host 头 obs-fold 可往日志注入伪造行 | 日志字段控制字符清洗 |
| A-13 | `host_ok` 的 IPv4 分支不校验端口 | 端口必须一致，多值 Host 直接拒 |

**回归测试**（都在 `state/` 下，改代码后请跑）：

```bash
python state/verify-fixes.py     # 逐条重放上述漏洞, 30 项必须全绿
python state/test_protocols.py   # 字段白名单不能把协议必填字段过滤掉 (10 种协议)
python state/test_service.py     # 访问控制 16 项
python state/test_naming.py      # 节点名/分组名冲突
python state/test_cn_rules.py    # 国内分流: 数据文件 + 规则语义 + 内核真实裁决 + fake-ip 场景 (60 项)
python state/test-l1-udp.py      # L1 不能把 QUIC(hysteria/tuic) 节点当死节点筛掉 (22 项)
python state/verify.py           # 端到端: 内核加载产物 + 真实 HTTP 出网
```

其中 `test_protocols.py` 是为一次真实回归加的：加字段白名单时把键名归一小写化做过头，
`alterId` 变成 `alterid`，内核直接拒绝整批配置（`has unset fields: alterId`），
L2 几乎每片都失败。

**审计里确认没问题的部分**（都跑了验证）：路径穿越 52 个 payload 全部挡住（含双重编码、
短名、ADS、UNC、保留名）；Host 校验确实挡 DNS rebinding 且不采信 `X-Forwarded-Host`；
令牌 192 bit 且恒定时间比较；订阅服务与内核端口都只绑回环；超大请求头被 431/414 拦住；
无请求走私。

## 快速开始

双击 `start.bat`：起订阅服务 + 每 30 分钟自动重刷池子。

> 想要个窗口界面？双击 **`一键启动.bat`** —— 见下面「桌面控制台」一节。

### 一键导入（推荐）

等首轮跑完（5~10 分钟），浏览器打开状态页，点绿色的 **「导入到 Clash Verge / Clash Party」** 按钮——
会调起客户端并弹出确认框，点导入即可。

导入后它是一个**带自动更新的远程订阅**，池子每轮刷新都会自动同步过去，以后不用再管。

命令行同样可以：

```bash
python pool.py import              # 调起客户端弹确认框 (安全, 推荐)
python pool.py import --inject     # 全自动写入, 不需要点确认
python pool.py import --inject --activate   # 顺便设为当前使用中的配置
```

`--inject` 会直接写进 Clash Verge 的配置目录，**前提是客户端已退出**——它把 `profiles.yaml`
读进内存，退出时整个写回，运行中改等于白改。所以这个模式会先检查进程、先备份原配置、
只追加一条条目、绝不动你已有的订阅。检测到的客户端：

| 客户端 | 深链协议 |
|---|---|
| Clash Verge / Clash Verge Rev | `clash://` |
| Clash Party (mihomo-party) | `mihomo://` |
| FlClash | `flclash://` |

### 手动方式

打开项目根目录的 **`订阅地址.txt`**，里面就是三行纯地址，整行复制填进客户端即可。
控制台输出同样是每行一个地址，状态页上还有点一下自动全选的输入框。

| 用途 | 路径 |
|---|---|
| Clash / Mihomo / Clash Verge / ClashX | `/sub/pool.yaml` |
| 小火箭 / v2rayN / v2rayNG / Karing | `/sub/pool.txt` |
| 单个地区 | `/sub/hk.yaml` `/sub/jp.yaml` `/sub/us.yaml` … |

地址形如 `http://127.0.0.1:8787/sub/pool.yaml?token=<令牌>`。令牌存在 `state/token.txt`，
首次运行自动生成。服务只监听回环，并校验 Host 头。

> **别把说明文字一起复制。** 客户端只看开头是不是 `http://`，带上 `Clash:`、`|` 或中文标签
> 就会直接报「无效的订阅链接，请输入以 http:// 或 https:// 开头的地址」——这个报错发生在
> 客户端本地，请求根本没发出来，所以排查时不要往服务端找。用 `订阅地址.txt` 或状态页的
> 输入框复制就不会踩这个坑。

首轮要跑 5~10 分钟才有产物，期间订阅是空的。

## 桌面控制台

双击 **`一键启动.bat`**，或：

```bash
python pool.py gui
```

单窗口，纯 tkinter，不依赖任何第三方库。里面能干这些事：

| 区域 | 内容 |
|---|---|
| 状态卡 | 入池节点 / 覆盖地区 / 上次刷新新鲜度 / 源可用 |
| 操作 | 完整扫描、快车道复检、一键导入到客户端、打开状态页、启动·停止常驻、设置·取消开机自启 |
| 节点页 | 节点名、协议、地区、实测延迟、TCP 延迟；**点列头排序**，再点切换升降序 |
| 日志页 | 所有操作都是起子进程，输出**流式回显**在这里 |
| 设置页 | 扫描间隔、L2 并发、负缓存参数，直接写 `pool.conf.json` |
| 订阅地址 | 输入框 + 复制按钮 |

排序有两个细节：数字列按**数值**排（按字符串排的话 1000ms 会跑到 200ms 前面）；
取不到值的行**永远沉底**，升降序都不翻转——"没测出延迟"不等于"最慢"，
让它浮到降序最前面是误导。排序状态在自动刷新时保持。

设计上刻意做成**读文件 + 起子进程**，而不是跟常驻服务做 IPC：状态从
`out/report.json`、`state/pool.json` 读，操作都是起一个 `pool.py` 子进程。
好处是 GUI 崩了不影响池子，池子崩了 GUI 也能告诉你哪儿不对。

> 节点名里的旗帜 emoji 在 tkinter 里会渲染成方框（它不做字体回退），
> 所以表格里显示前会剥掉——地区信息另有独立列。

## 后续更新

免费节点寿命常常只有几小时，所以"更新"不是一次性的事。这里有三层，各管一段：

| 层 | 频率 | 耗时 | 干什么 |
|---|---|---|---|
| **快车道** | 每 5 分钟 | **约 4 秒** | 只重测池内现有节点，把死掉的踢出去 |
| **完整扫描** | 每 30 分钟 | 4~5 分钟 | 重新拉源、全量探活、发现新节点 |
| **客户端侧** | 每 30 分钟 | — | Clash Verge 自动拉取最新订阅 |

三层叠起来的效果：池内节点死掉最多 5 分钟就被换掉，新节点最多 35 分钟进池子，
客户端最多 35 分钟同步一次。**你什么都不用做。**

实测一次快车道：池内 34 个节点里已经死了 15 个，3.8 秒扫完并重建产物——
这就是为什么需要它，等完整扫描的话那 15 个死节点会在客户端里挂十几分钟。

### 排程对齐时钟刻度，不漂移

刷新**不是**"上次跑完 + 间隔"，而是对齐时钟刻度：

- 30 分钟档永远落在 `:00` / `:30`
- 5 分钟档永远落在 `:00` `:05` `:10` …

区别在哪：完整扫描本身要 4~5 分钟。按"跑完 + 间隔"排，30 分钟档实际变成 35 分钟，
而且每轮继续往后漂；对齐刻度后与扫描耗时完全无关。实测日志：

```
[09:25:01] 快车道复检 —— 交给子进程, 本进程继续服务订阅
```

### 改刷新节奏

编辑 `pool.conf.json`（改完重启 `start.bat`）：

```json
{
  "interval": 30,
  "fast": 5,
  "l2_workers": 48
}
```

命令行参数优先于配置文件，所以临时试一个节奏可以直接：

```bash
python pool.py daemon --interval 15 --fast 2
```

`python pool.py status` 会显示当前排程和下次触发时刻。

### 手动操作

```bash
python pool.py status     # 池子现在什么状态: 新鲜度/节点数/服务是否在跑
python pool.py quick      # 快车道, 几秒
python pool.py all        # 完整扫描
python pool.py daemon     # 常驻: 快车道 + 完整扫描 + 订阅服务
```

或者双击 `refresh.bat`（= 完整扫描一次）。

### 开机自启

想让它在后台一直跑、不用每次手动开窗口：

```bash
python pool.py autostart            # 设置登录时自启
python pool.py autostart --remove   # 取消
```

做法是在**启动文件夹**放一个 `freeVPN.vbs`，用 `pythonw.exe` 隐藏窗口启动，
输出写进 `state/daemon.log`。不用计划任务是因为 `schtasks` 建登录任务需要管理员权限
（实测直接 `Access is denied`），而启动文件夹当前用户就能写，取消也只是删个文件。

查看是否在跑：`python pool.py status`；看日志：`type state\daemon.log`。

**注意**：如果你已经双击 `start.bat` 开着一个窗口，就不要再注册自启——两个实例会抢
8787 端口，第二个会直接报错退出（这是刻意设计的，见「排错」）。

## 为什么不是普通聚合器

免费节点列表 90% 是死的，剩下 10% 里还有一半是"TCP 能连但出不了网"。普通聚合器只做拼列表，
所以你会看到一堆连不上的节点。这个池子做两件事：

**L1 · TCP 探活** — asyncio 并发 500，对每个 `server:port` 打两次 TCP 握手取最小值，秒级干掉死节点。
**QUIC 协议（hysteria / hysteria2 / tuic）跳过这一步**：它们走 UDP、不监听 TCP，TCP 握手必然失败，
探测就是错杀 —— 实测这批节点的 L1 通过率只有 0~15%，而 L2 可用率 38%~100%；跳过之后
L1 误杀从占 L2 可用量的 25% 降到 0（详见 `CHANGELOG` v1.4.1）。

**L2 · 内核实测** — 把 L1 存活节点喂给 mihomo 内核，通过 `/proxies/{name}/delay` 逐个真实拨号
`gstatic.com/generate_204`。**只有真能出网的才进池子。**

实测数据（30 个源，一轮）：

| 阶段 | 数量 | 说明 |
|---|---|---|
| 拉取原始 | ~15000 | 30 个源，单源上限 2500 |
| 指纹去重 | ~7000 | 同一节点来自 10 个源也只留 1 个 |
| 安全审计 | -0.3% | 拦截回环/内网/敏感端口等 |
| L1 TCP 存活 | ~35% | 大量 CDN IP 有响应但代理已死 |
| L2 真能出网 | **~1%** | 这就是免费节点的真实可用率 |

**关于 1%**：`162.159.x.x` / `172.64.x.x` 这类 Cloudflare CDN 节点的 TCP 延迟极低（40~50ms），
会霸占 L1 排序前列，但实测绝大多数握手即死。所以 L2 候选做了**按 /24 网段限流**（同段最多 4 个），
否则候选池会被同几段 CDN 假节点填满，真节点根本轮不到被测试。

**关于分片**：内核遇到坏节点会 fail-fast 拒绝整份配置（实测 1675 个里有 25+ 个脏节点）。
所以 L2 按 250 个一片分批加载，每片独立做配置校验并自愈剔除，坏节点最多毁掉一片而不是整轮。

## 性能

一轮完整扫描的分段耗时（`python pool.py all` 末尾会打印）：

| 阶段 | 最初 | 现在 | 倍数 |
|---|---|---|---|
| 拉源 | 12.0s | 10.2s | — |
| 解析+去重 | 3.8s | 3.6s | — |
| 安全审计 | 0.1s | 0.1s | — |
| **L1 TCP 探活** | **131.9s** | **21.2s** | **6.2x** |
| **L2 内核实测** | **133.9s** | **29.9s** | **4.5x** |
| 写产物 | 0.2s | 0.2s | — |
| **合计** | **282.0s** | **69.4s** | **4.06x** |

节点数没有损失（入池 63~69，和优化前的 46~102 同一量级）。

### 改了什么

**L1 负缓存 —— 最大的一笔**（131.9 → 21.2s）。一轮要探 1 万个候选，其中七成是死的，
每个白等满超时；而免费源里相当一部分是**长期死的**，下一轮原样再来一遍。
现在连续失败 2 次且最后一次在 90 分钟内的节点直接跳过（实测一轮跳过 7300 个）。

这个缓存不是拍脑袋开的，代价核算过：**被跳过的节点里只有 3.0% 还活着，
对照组 92.2%** —— 差 30 倍，说明"连续失败两次"是强预测信号。折算约少发现 7 个可用节点，
换 57 秒。

**L2 并发 48 → 192**。交错重复实验（A/B/A/B 交替，让节点自身抖动均摊）：
48 并发中位 15.1s / 找到 14 个，192 并发中位 6.1s / 找到 16 个。2.46x 且找得更多。

**L2 分片 250 → 1000**。内核启动从 10.8s 降到 1.1s，实际测速从 80.1s 降到 30.5s——
分片太小的话每片都要重启内核，192 个 worker 在 250 个节点的片里利用率也差。

**L1 超时节点不再重试**。原来每个节点固定探两次取最小延迟，可死节点超时一次就要等满
5 秒，重试等于再等一遍。现在只有"非超时失败"才重试。

**prune 定位不到坏节点时改为二分**，不再整片丢弃。

### 试过但否掉的（都有数据）

**L2 也加负缓存 —— 实测后关掉了。** 直觉上 L2 通过率只有 2%，失败过的应该更该跳过。
但一测就露馅：**被跳过的 L2 节点仍有 1.7% 能出网，而整体通过率是 2.2%** —— 几乎没差别。
"L2 失败过一次"根本不是有效预测信号，开了就是按比例丢节点换时间（实测会少约 33 个）。
所以这个开关默认关闭，留在 `--neg-l2-fails` 里，附带说明。

**L1 并发 500 → 1500 —— 陷阱。** 耗时 36.6s → 19.6s 看着很香，但**存活数掉 27%**
（1358 → 976）。交错复测：同并发两次差异仅 1.2%，所以这是并发本身导致的，不是节点抖动。

**L1 超时 5.0 → 3.0s —— 也是陷阱。** 省 14.9s，但**存活数掉 14.2%**。
注意：从 `l1.json` 的 `_tcp` 字段算会得出"只损失 0.4%"的错误结论——那是**两次尝试的最小值**，
低估了首次尝试耗时。

**L2 并发 192 → 768。** 吞吐 181 个/秒，但找到的节点从 50 掉到 21，内核开始拒绝拨号。

结论：这几个"提速"都是用丢节点换的。池子本来就只有 60~100 个可用节点，丢 14~27% 不划算。

### 顺手抓到的 bug

`_CTRL_RE` 只清了 `\x00-\x1f\x7f` 和 `\x85`，**漏了 C1 控制符 `\x80-\x9f` 的其余部分**。
YAML 同样禁止它们，于是内核报 `yaml: control characters are not allowed`；
而这个错误不带 `proxy N:` 索引，prune 定位不到具体节点，**整片候选被静默丢弃**。
之前日志里那句"配置被拒但定位不到坏节点"就是它。

### 复现这些数字

```bash
python state/bench-perf2.py      # L2 并发: 交错重复 A/B 对比
python state/bench-l1b.py        # L1 并发: 区分"并发有害"与"节点衰减"
python state/bench-l1c.py        # L1 超时: 5.0s vs 3.0s
python state/diag-l1-vs-l2.py    # L1 误杀排查: 全量送 L2 再按协议对比
python state/bench-negcache.py   # L1 负缓存: 被跳过的节点真实存活率 vs 对照组
python state/bench-negcache-l2.py # L2 负缓存: 同上 (结论是它没有预测力)
```

## 打包发布

```bash
python pack.py            # 出独立可执行文件
python pack.py --zip      # 顺便压成 zip
python pack.py --zip --kill   # 有实例在跑时先结束它
```

产物（版本号取自 `version.py`）：

```
dist/freeVPN/
├── freeVPN.exe       双击即开控制台（2.8 MB）
├── bin/mihomo.exe    Mihomo 内核（58 MB）
├── VERSION           版本标记，方便收件人核对
├── sources.txt / pool.conf.json / cn_cidr.txt / cn_domains.txt
├── README.md / CHANGELOG.md / 使用说明.txt
└── _internal/        Python 运行时（PyInstaller 放的）

dist/freeVPN-v1.0.0-win64.zip     33 MB ← 发这个
```

整个目录拷给别人，双击 `freeVPN.exe` 就能用，**不需要装 Python**。

命令行同样可用（exe 自带子命令）：

```bash
freeVPN.exe --version  看版本
freeVPN.exe            双击 = 打开控制台
freeVPN.exe status     看状态
freeVPN.exe all        手动完整扫描一轮
freeVPN.exe daemon     常驻刷新 + 订阅服务
freeVPN.exe autostart  设置开机自启
```

### 版本管理

版本号只在 `version.py` 里定义一处，`pool.py` / `gui.py` / `pack.py` 都从它取。
`--version`、状态页、GUI 标题栏、`report.json`、打包产物名全都跟着走。
改版本号时同步更新 `CHANGELOG.md`。

### 打包时的几个坑

**不能用 `--windowed`。** windowed 模式下 PyInstaller 会把 `sys.stdout` 换成空写入器，
GUI 就捕获不到扫描子进程的输出了——日志页会一直空白。所以用 `--console` 打包，
再在 `launcher.py` 里于 GUI 启动时把控制台窗口隐藏掉。

**`ROOT` 必须改。** 冻结后 `__file__` 指向 PyInstaller 的临时解包目录，
拿它当根目录会让 `bin/mihomo.exe`、`state/`、`out/` 全部找不到。
现在统一走 `security.app_root()`：冻结时返回 exe 所在目录，否则返回源码目录。

**子进程要重新调起自己。** 源码模式是 `python -u pool.py <子命令>`，
打包后没有 `pool.py` 了，得是 `freeVPN.exe <子命令>`。统一走 `security.self_cmd()`，
开机自启写的 VBS 也用它。

**打包前要确认没有实例在跑。** PyInstaller 到 COLLECT 阶段会清理 `dist/`，
而运行中的 exe 锁着里面的文件，直接构建就报
`PermissionError: [WinError 5] 拒绝访问`。而且 PyInstaller 的 exe 是
"引导器 + 子进程"结构，关掉窗口不一定全退——`pack.py` 会预检并提示加 `--kill`。

**包里不放这些东西**（`pack.py` 会跳过）：`state/token.txt`（那是密钥）、
`state/*.log`（访问日志里出现过令牌）、`state/l1_hist.json`（本机运行痕迹）、
`out/`、`audit/`、`__pycache__`。已验证 zip 里干净。

## 命令

```bash
python pool.py fetch                  # 只拉源, 看各源产出与地区分布
python pool.py all                    # 全流程跑一轮
python pool.py all --no-l2            # 跳过内核测速, 只做 TCP (快很多)
python pool.py all --l2-workers 96    # 提高内核测速并发
python pool.py all --reuse-l1         # 复用上次 L1 结果, 调 L2 参数时用
python pool.py serve --port 8787      # 只起订阅服务
python pool.py gui                    # 打开桌面控制台
python pool.py import                 # 一键导入到已装的客户端
python pool.py status                 # 池子新鲜度 / 节点数 / 服务是否在跑
python pool.py quick                  # 快车道: 只重测池内节点, 约 4 秒
python pool.py autostart              # 设置开机自启
python pool.py daemon --interval 30   # 常驻: 完整扫描 + 快车道 + 服务 (start.bat 用的就是这个)
python security.py                    # 安全模块自检 (7 个探针)
```

## 产物

| 文件 | 内容 |
|---|---|
| `out/freevpn.yaml` | Clash 全量配置，含地区分组 + url-test 自动选择 + fallback 故障转移 + 安全分流规则（含国内直连，见「国内流量不进节点」） |
| `out/freevpn.txt` | base64 通用订阅（小火箭/v2rayN） |
| `out/hk.yaml` `jp.yaml` `us.yaml` ... | 各地区独立订阅（节点数 ≥ 2 的地区才生成），规则与全量一致 |
| `out/report.json` | 本轮统计：源存活、安全审计、各层数量、地区分布、最快节点 |

生成的分组结构：

- `🚀 节点选择` — 手动选择，下拉里包含自动组、各地区组和全部节点
- `♻️ 自动选择` — url-test，全池测速，每 120 秒重选
- `🛡️ 故障转移` — fallback，最快 30 个，当前节点挂了自动切下一个
- `🇭🇰 香港` `🇯🇵 日本` ... — 各地区 url-test，延迟最低的自动生效

## 换源 / 扩池

编辑 `sources.txt`，一行一个 URL，`#` 注释。程序会自动尝试直连 + `ghfast.top` /
`gh-proxy.com` / `ghproxy.net` 镜像回退，所以写裸 `raw.githubusercontent.com` 地址就行。

想扩池：取消文件末尾"备用源"区块的注释，或调大 `pool.py` 里的 `PER_SOURCE_CAP`。
池子规模 ≈ 总节点数 × 1%，想要 100 个可用节点就得喂进去约 10000 个候选。

想挖新源：`python state/discover_sources.py` 会从聚合清单里批量验证候选源。

## 改国内分流

`cn_domains.txt` 一行一个域名后缀，`cn_cidr.txt` 一行一个 CIDR —— 都是纯文本，
改完下一轮扫描即生效（不用重启服务）。

- 加自己的站点：往 `cn_domains.txt` 写一行。
- 整体关掉 / 换成掐断：改 `pool.conf.json` 的 `cn_mode`（`direct` / `reject` / `off`）。
- 想让某个域名**强制走节点**：只从 `cn_domains.txt` 删不够 —— 解析后落在国内 IP 段
  仍会被 `cn_resolve` 那条兜住，得同时把 `cn_resolve` 设成 `false`，再在客户端侧覆写。
- 更新 IP 段：`python state/gen-cn-rules.py`（`--apnic <本地文件>` 可离线跑）。
  域名清单不依赖它，两者互不影响。

## 排错

**客户端报「无效的订阅链接，请输入以 http:// 或 https:// 开头的地址」。**
这个报错发生在客户端本地，请求根本没发出去，所以别往服务端找。原因是复制时把说明文字一起带上了
（`Clash:` 前缀、Markdown 表格的 `|`、中文标签）。用 `订阅地址.txt` 或状态页的输入框复制。

**客户端报「failed to fetch remote profile with status 404 Not Found」。**
说明请求到了服务端但路径没匹配上。**看 `state/access.log`**，里面记了客户端真正请求的
`方法 / 状态码 / 完整路径 / Host / User-Agent`，一眼就能看出它到底要什么。服务端已经容忍了
这些常见差异，通常不会再 404：

| 客户端可能的行为 | 服务端处理 |
|---|---|
| 把 `pool.yaml` 编码成 `pool%2Eyaml` | 路径解码后再匹配 |
| 扩展名写成 `.yml` 或不写 | `.yaml` / `.yml` / 无后缀都试 |
| 大小写被改写 | 大小写不敏感兜底 |
| 吃掉 `/sub/` 前缀 | 根路径下的订阅名也认 |
| 令牌塞在路径里 | 支持 `/t/<令牌>/pool.yaml` |
| 令牌用 `?t=` 或 Bearer 头 | 四种形式都收 |

**`[SRV] 端口 8787 已被占用`。** 上一个实例还在跑。服务刻意关掉了 `allow_reuse_address`
（Windows 上它等价于 `SO_REUSEPORT`，会让新旧两个实例同时监听同一端口，改了代码却看到旧行为）。
先 `taskkill /F /IM python.exe` 再启动。

**双击 `start.bat` 报一堆「不是内部或外部命令」、`'0.1' 不是内部或外部命令`、中文变乱码。**
`.bat` 文件必须是**纯 ASCII**。cmd.exe 按控制台代码页逐字节解析批处理文件，UTF-8 的中文
被当成 GBK 读会导致字节对齐错位，解析器在词中间断开——`127.0.0.1` 会被切成 `127.0.` 和 `0.1`
两个 token，于是报「不是内部或外部命令」。现在两个 `.bat` 里没有任何中文，所有中文提示都由
`pool.py` 打印。**以后改 `.bat` 时请保持 ASCII**，中文写进 Python。

**服务起来了但订阅是空的。** 首轮要 5~10 分钟才有产物，看控制台进度或状态页。

**`[L2] 内核启动失败` / `配置被拒`。** 说明候选里混进了内核不接受的节点，程序会自动剔除重试；
如果连续剔除仍不通过，该片会被跳过（不会毁掉整轮）。跑 `python state/debug_kernel.py` 能抓到内核的真实报错。

**池子节点很少。** 这是免费节点的真实可用率（约 1%），不是 bug。想扩池见上一节。

## 目录

```
freeVPN/
├── pool.py                 主程序 (聚合/探活/生成/服务)
├── gui.py                  桌面控制台 (tkinter, 无第三方依赖)
├── security.py             安全模块 (隔离/审计/规则/访问控制)
├── sources.txt             源清单 (改这个)
├── pool.conf.json          刷新节奏与扫描参数 (含国内分流开关)
├── cn_cidr.txt             国内 IP 段, 第⑤层规则的数据源 (可直接编辑)
├── cn_domains.txt          国内域名后缀, 同上
├── 订阅地址.txt             启动后生成, 三行纯地址, 直接复制
├── 一键启动.bat            打开桌面控制台 (纯 ASCII, 别加中文)
├── launcher.py             打包入口 (双击 exe 时开 GUI)
├── pack.py                 一键打包为独立 exe
├── start.bat               一键启动常驻 (纯 ASCII, 别加中文)
├── refresh.bat             手动刷一轮
├── bin/mihomo.exe          Mihomo Meta 内核 (L2 测速用)
├── out/                    生成的订阅产物
├── audit/                  安全审计报告与 PoC 脚本
└── state/
    ├── token.txt           订阅服务访问令牌
    ├── daemon.pid          常驻进程 PID (控制台靠它判断常驻在不在跑)
    ├── cache.json          节点历史表现
    ├── l1.json             L1 结果缓存
    ├── l1_hist.json        L1 负缓存 (哪些节点反复失败)
    ├── kernel/             内核临时配置与工作目录
    ├── discover_sources.py 源发现工具
    ├── verify.py           端到端验收 (内核加载 + 真实出网)
    ├── verify-fixes.py     漏洞复验 (30 项)
    ├── test_protocols.py   协议白名单回归
    ├── test_service.py     访问控制回归
    ├── test_naming.py      节点名/分组名冲突回归
    ├── bench-*.py          性能实验脚本 (结论都可复现)
    └── debug_*.py          诊断工具
```

## 验收

三个测试，都是**真的发请求**看结果，不是读代码判断"应该有防护"：

```bash
python security.py            # 安全模块自检: 7 个探针(诱饵节点/内网IP/敏感端口/关闭证书校验/诱导命名)
python state/test_naming.py   # 回归测试: 节点名与分组名撞名会废掉整份配置(内核报 ProxyGroup 自引用)
python state/test_service.py  # 实测访问控制: 令牌 / Host 校验 / 路径穿越 / CORS / 订阅内容抽查
python state/verify.py        # 端到端: 内核加载产物 -> 独立复测 -> 通过 mixed-port 真实 HTTP 请求
```

`state/verify.py` 是唯一能证明"池子里的节点真能用"的测试——不看程序自己报的数字，
而是让内核独立加载 `out/pool.yaml`、重新拨号复测、再通过 mixed-port 发真实请求。
期望输出末尾：`HTTP 204`（gstatic 的 generate_204 正常返回）。

实测结果（31 节点池）：

```
配置合法 (test is successful)
内核识别 32 个节点 / 11 个分组
逐个复测通过 19/32
端到端: HTTP 204  345ms / 747ms / 329ms
访问控制: 16/16 项通过
```

复测 19/32 是正常的——免费节点本身会抖动，故障转移组就是为这个准备的。

## 已知限制

- 免费节点寿命通常只有几小时到几天，所以**别关掉 daemon**——它的价值就在于每 30 分钟把死掉的换掉。
- L2 全量测速一轮要几分钟，这是真实可用率决定的，不是实现问题。
- 池子越大越稳（单源挂掉不影响），但免费源本身随时可能关站或换域名。
