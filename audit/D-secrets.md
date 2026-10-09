# 安全审计 D · 密钥与数据边界

- 目标：`E:\AI\freeVPN`（freeVPN 公开免费代理订阅聚合器）
- 范围：令牌落盘点穷举、`inject_verge` 数据侧、`progress.json` 注入、`find_resource` 资源遮蔽、
  GUI 新表面、`_resolve_sub` / 状态页复验
- 方法：**全部结论由实跑得出**。PoC 在 `audit/d1_*.py` … `audit/d8_*.py`，
  临时目录一律在 `%TEMP%` 下，`C:\freeVPN`（正在运行的实例）只做**只读**检查
- 审计性质：未修改 `pool.py` / `security.py` / `gui.py`，未改 `C:\freeVPN` 任何文件
- 环境：Windows 10/11（`DESKTOP-CJ40M9U`，当前用户 `xyw`）/ Python 3.13 / PyYAML 6.0.3

## 被审计版本指纹

审计**开始时**（16:02）源码状态：

```
pool.py     159639 字节  mtime 2026-10-08 15:46:17
security.py  29091 字节  mtime 2026-10-08 15:30:01
gui.py       40453 字节  mtime 2026-10-08 15:39:18
version.py   1.3.6
```

**审计过程中源码被他人改动过**（不是本审计做的）。审计结束时（16:40）的状态：

```
pool.py      SHA256 F50BBBACD5A69DE90458D15AE307829DB4A427C5144B52F4965A954B52DD0263
             164173 字节, mtime 2026-10-08 16:38:10
security.py  SHA256 A19A7A41EE16A84A54CF4892547EA6E3CDBC9E234C6661AC1A49C1A5847F4D20
              32413 字节, mtime 2026-10-08 16:37:50
gui.py       SHA256 160AD01C112C909C19B88469F0E5C50C5798262A4866999621B82374D2B1B821
              41445 字节, mtime 2026-10-08 16:37:06
version.py   1.3.7
```

影响：
1. 报告里的**行号以审计时点为准**，在最终版本上可能漂移，定位请以代码片段为准。
2. D-04 是**新代码引入的回归**，我在 16:52 实测复现，并在 16:55 单独上报了 Lead。

## 环境变更时间线（本审计期间）

| 时间 | 事件 | 谁 |
|---|---|---|
| 16:02–16:15 | 采集基线：`C:\freeVPN\state` 及其下文件 ACL = `Authenticated Users:(I)(M)`；`daemon.log` 含令牌 45 次、`gui.log` 10 次 | 本审计 |
| ≈16:41 | `security.py` 新增 `harden_install_dir()` 并在 `C:\freeVPN` 上执行（带 `/T`）→ **每个已存在文件变成零 ACE** | Lead |
| 16:50 | 本审计复查时发现 ACL 异常、`daemon.log`/`gui.log` 报 Access denied，立刻上报 Lead（附 `%TEMP%` 复现） | 本审计 |
| ≈16:52 | 现场抢救（`takeown` + `icacls /reset`）+ 改为**不带 `/T`** 的正确写法 | Lead |
| 16:58 | 本审计独立复核修复结果（见 D-01 / D-02 / D-04 的"当前状态"） | 本审计 |

**报告里每一条都标了"审计时点"与"当前状态"** —— 两者不混用。
本审计**全程没有修改** `C:\freeVPN` 的任何文件、没有杀它的进程，也没有改 `pool.py` / `security.py` / `gui.py`。

## 复现命令

```
cd E:\AI\freeVPN
python -u audit\d1_token_sinks.py        # 令牌落盘点穷举 + ACL 分级
python -u audit\d2_accesslog_redaction.py # access.log 脱敏矩阵 (22 用例)
python -u audit\d3_progress_inject.py     # progress.json 注入 (真实 tkinter + mainloop)
python -u audit\d4_resource_shadow.py     # find_resource 遮蔽 / 内核替换
python -u audit\d5_verge_is_ours.py       # is_ours 误删 / profiles.yaml 往返
python -u audit\d6_gui_surface.py         # 端口抢占 / daemon.pid / daemon.log 弹窗
python -u audit\d7_route_recheck.py       # _resolve_sub / CSP nonce / 校验顺序 复验
python -u audit\d8_acl_harden.py          # harden_install_dir 的 ACL 副作用
```

---

## D-01 【高】安装目录的 ACL 允许**任何本机用户**替换 `freeVPN.exe` / `bin\mihomo.exe`

**位置**
- `C:\freeVPN`、`C:\freeVPN\bin`、`C:\freeVPN\bin\mihomo.exe`、`C:\freeVPN\freeVPN.exe`、`C:\freeVPN\state`
- `security.py:491-497 find_resource() / find_kernel()`
- `pool.py:78  MIHOMO = sec.find_kernel() or (BIN / "mihomo.exe")`
- `pool.py:1387`（`Kernel.check()` 跑 `mihomo -t`）、`pool.py:1443`（`Kernel.start()` 真正启动内核）

**证据 1 · 权限位（硬证据）**

```
> icacls C:\freeVPN\bin\mihomo.exe
C:\freeVPN\bin\mihomo.exe BUILTIN\Administrators:(I)(F)
                          NT AUTHORITY\SYSTEM:(I)(F)
                          BUILTIN\Users:(I)(RX)
                          NT AUTHORITY\Authenticated Users:(I)(M)   <==

> (Get-Acl C:\freeVPN\bin\mihomo.exe).Sddl
O:S-1-5-21-...-1001G:S-1-5-21-...-513D:AI(A;ID;FA;;;BA)(A;ID;FA;;;SY)
(A;ID;0x1200a9;;;BU)(A;ID;0x1301bf;;;AU)
```

`0x1301bf` = `FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | DELETE |
FILE_DELETE_CHILD | READ_CONTROL | SYNCHRONIZE`。**能改内容、能删、能改名** —— 等价于整份替换。

`C:\freeVPN` 目录本身同样是 `Authenticated Users:(M)`，且 `C:\freeVPN\freeVPN.exe` 同样。
这个 ACL 是从 `C:\` 继承来的（Windows 在盘根下新建目录的默认 ACL）。

**证据 2 · `find_resource` 的优先级确实是"外面赢"**（`d4_resource_shadow.py`）

```
### ① find_resource 优先级: 外面 vs 内置(_MEIPASS)
  app_root()      = ...\app
  bundle_dir()    = ...\_internal
  find_resource() = ...\app\bin\mihomo.exe
  内容            = b'OUTSIDE-KERNEL'
  → 外面赢: 是
  删掉外面的之后再找 = ...\_internal\bin\mihomo.exe  (b'BUNDLED-KERNEL')
  → 兜底逻辑正常

### ② pool.MIHOMO 在冻结模式下指向哪
  子进程 import pool 后 pool.MIHOMO = ...\app\bin\mihomo.exe
  → 等于外面那个文件: 是
```

**证据 3 · 那个文件真的会被执行**

```
### ③ 被替换的文件会不会真被执行
  把 python.exe 复制成 ...\app\bin\mihomo.exe
  以内核启动参数执行它: exit=1
  输出: "Could not find platform independent libraries <prefix>\n
        ...\\app\\bin\\mihomo.exe: can't find '__main__' module in ..."
  → 被遮蔽路径上的二进制被执行: 是

  真实代码路径复核 (pool.Kernel().check):
  MIHOMO = ...\app\bin\mihomo.exe
  check() -> -1
```

**影响**

| 被替换的对象 | 触发条件 | 后果 |
|---|---|---|
| `bin\mihomo.exe` | 每轮 L2 实测（`Kernel.check()` + `Kernel.start()`） | 攻击者的程序**以受害者身份**执行，且每几分钟自动重跑 |
| `freeVPN.exe` | 用户下次双击 | 同上 |
| `out\pool.yaml` | 客户端拉订阅 | 往用户的 VPN 客户端注入任意代理节点 |
| `state\*` | 直接改 | 见 D-02 / D-06 / D-07 / D-08 |

注意 `kernel_env()`（`security.py:260-265`）会清掉环境变量、`kernel_creationflags()` 不给新控制台 ——
这些隔离**都挡不住"二进制本身就是攻击者的"**。`find_resource` 的"外面优先"是给用户换内核版本用的
便利设计，但它同时是一个**未加校验的可执行文件加载点**。

**当前状态（16:58 复核）**

Lead 已对运行实例 `C:\freeVPN` 做了正确的目录级收紧，D-01 在**这台机器的这个安装**上已消解：

```
> icacls C:\freeVPN
C:\freeVPN NT AUTHORITY\SYSTEM:(OI)(CI)(F)
           DESKTOP-CJ40M9U\xyw:(OI)(CI)(F)          <-- Authenticated Users 没了

> icacls C:\freeVPN\bin\mihomo.exe
C:\freeVPN\bin\mihomo.exe NT AUTHORITY\SYSTEM:(I)(F)
                          DESKTOP-CJ40M9U\xyw:(I)(F)  <-- 继承生效, 不是空 DACL

> icacls C:\freeVPN\freeVPN.exe
C:\freeVPN\freeVPN.exe NT AUTHORITY\SYSTEM:(I)(F)
                       DESKTOP-CJ40M9U\xyw:(I)(F)
```

**但仍然有效的部分**（这是本条的审计结论，不因一次手工修复而消失）：

1. **源码版 / dist 版不会自动收紧**。自动收紧只在冻结环境触发：

   ```
   pool.py:3657   if sec.is_frozen() and sec.dir_is_loose(sec.app_root()):
   pool.py:3660       if sec.harden_install_dir(sec.app_root()):
   ```

   `E:\AI\freeVPN`、`E:\AI\freeVPN\dist\freeVPN` 仍然继承 `C:\` / `E:\` 的默认宽松 ACL
   （`Authenticated Users:(M)` + `Users:(RX)`），`bin\mihomo.exe` 同样。
2. **任何一台新解压的机器**（`使用说明.txt` 教的"解压到任意目录双击"）都会先落在宽松 ACL 上，
   首次运行才收紧 —— 首次运行之前就是一个可被替换的窗口，而用户往往是从压缩包直接双击。
3. **`find_resource` 的"外面优先"逻辑本身没变**：即使 ACL 收紧了，只要有任何途径能往
   `bin/` 写一个同名文件（比如用户自己从网上"下载了新版内核"替换），它就会被无条件执行，
   没有版本/签名校验。

**修复建议**

1. 安装/首次启动时对安装目录做**正确**的 ACL 收紧（见 D-04 的正确写法），
   目标是"仅 `SYSTEM` + 当前用户 + `Administrators`"。
2. `find_kernel()` 增加来源校验：内核文件必须**不是**由 `Authenticated Users` / `Users` 可写的位置提供的；
   或者只在 `app_root()` 与 `bundle_dir()` 之间做**内容一致性校验**（比对 SHA256），
   外面那份不一致时拒绝执行并告警。
3. 打包版优先用 `_MEIPASS` 里的内核（`--onefile` 时它在用户临时目录，权限默认收紧），
   把"用户换内核"改成显式的 `--kernel <path>` 开关，而不是默认优先级。
4. 安装说明（`使用说明.txt`）里加一句：把整个文件夹放在**非盘根**的位置（如 `%LOCALAPPDATA%\freeVPN`），
   并在首次运行后核对一次目录 ACL。

---

## D-02 【高】令牌明文落盘在 ACL 宽松的文件里 —— `token.txt` 的收紧被绕过

**位置**
- `security.py:577-599 tighten_file_perms()` —— 只被 `load_or_create_token()`（token.txt）
  和 `pool.py:3316`（`订阅地址.txt`）调用，**日志从未被收紧**
- `pool.py:3543-3547` daemon 把 `sys.stdout/sys.stderr` 重定向到 `--log <daemon.log>`
- `pool.py:3233-3250 serve()` 打印含令牌的订阅地址 → 进 daemon.log
- `gui.py:589-599 logq_put()` 把子进程输出原样落 `state/gui.log`；`import` 子进程会打印订阅地址
- `pool.py:2206` / `pool.py:2217` `inject_verge` 把含令牌的 `profiles.yaml` 备份到
  `profiles.yaml.freevpn.<stamp>.bak`（最多留 5 份），失败时改存 `state/profiles.yaml.<stamp>.bak`

**证据 1 · 穷举（`d1_token_sinks.py`）**

审计时点（16:02-16:15）的实测结果：

```
### ② 部署位置内部穷举 (字节级搜索)

  --- 源码版 E:\AI\freeVPN   (令牌 ifBl9q...)
      [命中   3 次] 订阅地址.txt                        ACL=收紧
      [命中   1 次] state\access.log                   ACL=宽松
      [命中   3 次] state\daemon.log                   ACL=宽松
      [命中   1 次] state\token.txt                    ACL=收紧
      (扫了 1262 个文本文件)
  --- 打包版 C:\freeVPN   (令牌 rClUur...)
      [命中   3 次] 订阅地址.txt                        ACL=收紧
      [命中  45 次] state\daemon.log                   ACL=宽松
      [命中  10 次] state\gui.log                      ACL=宽松
      [命中   1 次] state\profiles.yaml.20261008-145503.bak  ACL=宽松
      [命中   1 次] state\token.txt                    ACL=收紧
      (扫了 972 个文本文件)
  --- dist 版 E:\AI\freeVPN\dist\freeVPN
      [命中   3 次] 订阅地址.txt                        ACL=收紧
      [命中   3 次] state\d2.log                       ACL=宽松
      [命中  12 次] state\gui.log                      ACL=宽松
      [命中   1 次] state\profiles.yaml.20261008-145503.bak  ACL=宽松
      [命中   1 次] state\token.txt                    ACL=收紧
      [命中   3 次] state\x.log                        ACL=宽松
      (扫了 968 个文本文件)

### ③ 外部落点
  [Clash Verge 配置目录] ...\io.github.clash-verge-rev.clash-verge-rev\profiles.yaml                          命中 1 次
  [Clash Verge 配置目录] ...\profiles.yaml.freevpn.20261008-154443.bak                                          命中 1 次
  [Clash Verge 配置目录] ...\profiles.yaml.freevpn.20261008-154446.bak                                          命中 1 次
  [Clash Verge 配置目录] ...\profiles.yaml.freevpn.20261008-154731.bak                                          命中 1 次
  [Clash Verge 配置目录] ...\profiles.yaml.freevpn.20261008-155002.bak                                          命中 1 次
  [Clash Verge 配置目录] ...\profiles.yaml.freevpn.20261008-155006.bak                                          命中 1 次
  剪贴板历史(持久化)    扫 5 个文件, 命中 0
  活动时间线 ActivitiesCache  扫 9 个文件, 命中 0
  Chrome 历史           扫 4204 个文件, 命中 0
  Edge 历史             扫 9858 个文件, 命中 0

### ⑤ 汇总
  含令牌的文件共 30 个, 其中 ACL 宽松 18 个
```

**证据 2 · 宽松 ACL 的具体主体**

```
> icacls C:\freeVPN\state\daemon.log
C:\freeVPN\state\daemon.log BUILTIN\Administrators:(I)(F)
                            NT AUTHORITY\SYSTEM:(I)(F)
                            BUILTIN\Users:(I)(RX)
                            NT AUTHORITY\Authenticated Users:(I)(M)

> icacls C:\freeVPN\state\token.txt      (对照: 这个是对的)
C:\freeVPN\state\token.txt NT AUTHORITY\SYSTEM:(F)
                           DESKTOP-CJ40M9U\xyw:(F)
```

`Authenticated Users:(M)` = 任何已登录用户可读**可改**。`token.txt` 的收紧完全被日志绕过。

**证据 3 · 令牌是从哪条路径进去的**

`daemon.log` 里的令牌来自 `serve()` 的横幅（`pool.py:3225-3250`）：

```
  或手动复制地址 —— 整行复制, 不要带前面的说明文字
  Clash / Mihomo / Clash Verge / ClashX
http://127.0.0.1:8787/sub/pool.yaml?token=<32 字符明文>
```

`gui.log` 里的令牌来自 GUI 的 `import` 动作：`do_import()` 起子进程、`logq_put()` 逐行落盘，
而 `cmd_import()`（`pool.py:2775/2779/2789/2809/2813`）会打印 `订阅地址: <含令牌>`。

`state\profiles.yaml.*.bak` 来自 `inject_verge` 的"备份失败改存到 state/"退路（`pool.py:2217-2220`）。

**当前状态（16:58 复核）**

`state/` 目录收紧之后，"任何本机用户可读"这一半已经消失：

```
> icacls C:\freeVPN\state\daemon.log
C:\freeVPN\state\daemon.log NT AUTHORITY\SYSTEM:(I)(F)
                            DESKTOP-CJ40M9U\xyw:(I)(F)      <-- 不再是 Authenticated Users:(M)

> (Get-Content C:\freeVPN\state\daemon.log)   -> 1111 字符, 可读
> (Get-Content C:\freeVPN\state\gui.log)      -> 18274 字符, 可读
```

**但"令牌不该落盘"这一半仍然成立**，而且换了个更麻烦的位置：

```
=== 令牌在各文件里的命中数 (16:58) ===
  C:\freeVPN\state\daemon.log     0     (重启后新日志, 旧的横幅已被重置)
  C:\freeVPN\state\gui.log       14     <-- 仍在写
  C:\freeVPN\state\access.log     0
  C:\freeVPN\订阅地址.txt          3     (文件已收紧, 可接受)

=== gui.log 里的原文 (令牌已替换为 <TOKEN>) ===
      http://127.0.0.1:8787/sub/pool.yaml?token=<TOKEN>
       http://127.0.0.1:8787/sub/pool.yaml?token=<TOKEN>
    订阅地址: http://127.0.0.1:8787/sub/pool.yaml?token=<TOKEN>
```

`gui.log` 的令牌来自 `gui.py:589-599 logq_put()` 把 `import` 子进程的输出原样落盘，
而 `cmd_import()` 会打印 `订阅地址: ...?token=...`。**代码没改，落盘点就还在** ——
只是现在读它需要当前用户的身份，而不是"任何已登录用户"。

**真正没被修掉的是 Clash Verge 配置目录**（当前仍然有效）：

```
> icacls C:\Users\xyw\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev
DESKTOP-CJ40M9U\CodexSandboxUsers:(I)(OI)(CI)(RX)      <-- 本机组, 非特权成员可读
NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
BUILTIN\Administrators:(I)(OI)(CI)(F)
DESKTOP-CJ40M9U\xyw:(I)(OI)(CI)(F)

=== 命中令牌的文件 (16:58) ===
  profiles.yaml
  profiles.yaml.freevpn.20261008-155006.bak
  profiles.yaml.freevpn.20261008-162351.bak
  profiles.yaml.freevpn.20261008-162353.bak
  profiles.yaml.freevpn.20261008-162514.bak
  profiles.yaml.freevpn.20261008-162516.bak
```

`inject_verge` 每次导入都新增一份 `.bak`（最多留 5 份 + 之前手工的 1 份），
**每一份都是令牌的完整副本**，而目录对本机组可读。这个目录**不在 `harden_install_dir` 的作用范围里**，
所以 D-04 的修复没有覆盖它。

**影响（不因"本地用户才能读"而降级）**

这台机器上的**任何其他登录账户**、以及**任何以别的身份运行的进程**都能：
1. 读走令牌（`Authenticated Users` 有 `(M)`，读只是它的一部分）；
2. 用令牌直接拉订阅：`curl "http://127.0.0.1:8787/sub/pool.yaml?token=<偷来的>"`。
   回环端口在 Windows 上**不区分用户** —— 令牌是唯一的屏障，Host 校验只挡 DNS rebinding。
   拿到令牌 = 拿到用户筛过的可用节点全集（服务器地址 + 端口 + 密码/UUID）；
3. 访问状态页 `/?token=<偷来的>`、`report.json`，读到用户的池子统计；
4. **改写**这些日志（`(M)` 含 `DELETE`）→ 见 D-08。

**修复建议**

1. **不该落的就别落**：`serve()` 的订阅地址横幅在 `--log` 模式下应写成 `token=***`；
   `cmd_import()` 的 `订阅地址:` 行同理（真要给用户看，写到已经收紧的 `订阅地址.txt`）。
2. **该落的必须收紧**：`load_or_create_token()` 里除了 `tighten_file_perms(tf)`，
   还要对 `STATE` 目录整体收紧（正确写法见 D-04），让**新产生的**文件也继承收紧后的 ACL。
3. `inject_verge` 的备份里含令牌 —— 备份到 `state/` 的那份必须一起收紧；
   备份到 Clash Verge 目录的那份，至少在文档里提示"这些 .bak 含订阅令牌，别外发"。
4. 给令牌加**轮换**能力：目前令牌只在 `token.txt` 缺失或短于 16 字符时才重新生成，
   没有任何"怀疑泄露就换一个"的入口。建议加 `pool.py rotate-token` 子命令，
   顺带提示"客户端里的订阅地址要一起改"。

---

## D-03 【高】抢占订阅端口 —— 不读任何文件就能拿到令牌，还能替换订阅内容

**位置**：`pool.py:3119-3128 PoolServer`（`allow_reuse_address = False`）、
订阅地址由 `pool.py:3204` 生成，客户端拉取的永远是 `127.0.0.1:<port>`。

**证据**（`d6_gui_surface.py` 第 ① 节）

```
### ① 抢占订阅端口 -> 直接截获客户端发来的令牌

  假服务已绑 127.0.0.1:8891 (未验证任何令牌)
  现在模拟客户端拉订阅 (它会把订阅地址整条发过来):
    请求 http://127.0.0.1:8891/sub/pool.yaml?token=LEAKTEST_TOKEN_0123456789abc...
  假服务收到: GET /sub/pool.yaml?token=LEAKTEST_TOKEN_0123456789abcdef HTTP/1.1
      → 里面含完整令牌: 是
      → 客户端拿到的订阅内容由攻击者决定 (proxies: [])
```

（用 8891 做等价验证：结论只取决于"客户端连的是回环端口、令牌在 URL 里"，
与具体端口号无关。真实部署里这个端口是 8787。）

**影响**

只要 freeVPN 的常驻**没在跑**（用户没设自启、刚重启完、手动停了、或者被 D-07 杀掉了），
本机任何用户都能先占住 8787：

1. **截获令牌** —— 客户端下次拉订阅就把 `?token=` 送过来，**不需要读任何文件、不需要 ACL 权限**；
2. **替换订阅内容** —— 假服务返回攻击者构造的 `pool.yaml`，用户客户端加载后
   全部流量走攻击者的节点 = **完整中间人**；
3. 抢占期间真 freeVPN 起不来（`PoolServer` 故意关掉 `SO_REUSEADDR`，会直接报端口占用）。

这条把 D-02 的"读日志拿令牌"降级成"可选的第二手段"——攻击者根本不用读文件。

**修复建议**

1. 令牌**不要放在 URL 里**（URL 会进客户端日志、浏览器历史、代理日志）。
   改用 `Authorization: Bearer`（服务端已经支持）或一个自定义头。
   这同时能修掉 D-05。
2. 服务端在绑定前先探测端口：若已被占用，区分"是自己人"和"是别人"，
   是别人时**明确告警**（现在只有一句"端口被占用"，且只在 GUI 弹窗里）。
3. 客户端的订阅地址里带一个**每次拉取都校验的**自签名 challenge（如 `X-FreeVPN-Sig`），
   假服务拿不到签名就答不上来 —— 但这需要客户端支持，属于长期方案。
4. 短期最有效的一条：**开机自启默认打开**，把暴露窗口压到最小。

---

## D-04 【高 · 回归】新加的 `harden_install_dir()` 会把目录下已有文件的 ACL 清空

**位置**：`security.py:516-553 harden_install_dir()`

```python
r = subprocess.run(
    ["icacls", str(root),
     "/inheritance:r",
     "/grant:r", f"{user}:(OI)(CI)F",
     "/grant:r", "SYSTEM:(OI)(CI)F",
     "/T", "/C", "/Q"], ...)
```

**证据 · 现象**

审计中途复查 `C:\freeVPN` 时发现它已经变了：

```
> icacls C:\freeVPN\state
C:\freeVPN\state NT AUTHORITY\SYSTEM:(OI)(CI)(F)
                 DESKTOP-CJ40M9U\xyw:(OI)(CI)(F)

> icacls C:\freeVPN\state\daemon.log
C:\freeVPN\state\daemon.log
Successfully processed 1 files; Failed processing 0 files      <-- 一个 ACE 都没有

> Get-Content C:\freeVPN\state\daemon.log
Access to the path 'C:\freeVPN\state\daemon.log' is denied.
```

**证据 · 复现**（`d8_acl_harden.py`，在 `%TEMP%` 造的等价目录树，未碰 `C:\freeVPN`）

```
### 收紧之前
  state\daemon.log   ...\state\daemon.log NT AUTHORITY\SYSTEM:(I)(F) / BUILTIN\Administrators:(I)(F)
                                           / OWNER RIGHTS:(I)(F)          可读: True

### 执行 security.harden_dir_perms(目录)
  icacls ...\state /inheritance:r /grant:r xyw:(OI)(CI)F /grant:r SYSTEM:(OI)(CI)F /T /C /Q
  调用 harden_install_dir() -> True

### 收紧之后
  state              NT AUTHORITY\SYSTEM:(OI)(CI)(F) / DESKTOP-CJ40M9U\xyw:(OI)(CI)(F)   ← 目录 OK
  state\daemon.log   **icacls 输出为空 —— DACL 里没有任何 ACE**   可读: False
  state\gui.log      **icacls 输出为空 —— DACL 里没有任何 ACE**   可读: False
  state\sub\deep.txt **icacls 输出为空 —— DACL 里没有任何 ACE**   可读: False
```

**机理**：`(OI)(CI)` 是**容器继承标志**，只对目录有意义。icacls 对**文件**执行这条 grant 时不产生 ACE，
而 `/inheritance:r` 已经把文件原有的继承 ACE 全切掉了 —— 文件于是变成"零 ACE"。

**影响**

1. `state/token.txt` 变成空 DACL 后，`load_or_create_token()`（`security.py:613-627`）
   的 `tf.read_text()` **没有 try 包住** → 下次启动直接抛 `PermissionError` → 服务起不来。
2. `gui.py:784` 的 `log.write_text("")` 对不可写文件抛异常 → 点「启动常驻」弹「启动失败」。
3. 所有日志不可读，排错能力归零；`daemon.pid` 不可读 → GUI 判定"常驻没在跑"。
4. 这不是"更安全"，而是**把可用性打没了**，并且需要管理员/所有者手工逐个文件抢救。

**修复建议**

```python
# 正确写法: 目录用继承标志, 内容物用普通权限 (不带 OI/CI)
subprocess.run(["icacls", str(root), "/inheritance:r",
                "/grant:r", f"{user}:(OI)(CI)F",
                "/grant:r", "SYSTEM:(OI)(CI)F"], ...)
subprocess.run(["icacls", str(root), "/T", "/C", "/Q",
                "/grant:r", f"{user}:F",
                "/grant:r", "SYSTEM:F"], ...)
```

或者更简单：全程不带继承标志 —— `icacls <root> /inheritance:r /grant:r <user>:F /grant:r SYSTEM:F /T /C /Q`
（目录照样能被子项继承，因为子项各自拿到了显式 ACE）。

另外：
- 执行前先**探测**能否改（`dir_is_loose()` 已有），只在确实宽松时才动；
- 改完立刻**自检**：读一次 `token.txt`、写一次 `state/.wtest-<pid>`，失败就回滚并告警；
- 已经受害的文件需要：`icacls <file> /grant:r <user>:F /grant:r SYSTEM:F`。

**当前状态（16:58 复核）· 已修复**

Lead 在收到告警后约 2 分钟内完成抢救，并采纳了"**去掉 `/T`，只对根目录设 `(OI)(CI)`，让子项继承**"
的修法（比我建议的"分两步"少一次 icacls 调用，也不存在中间状态）。本审计独立复核：

```
> icacls C:\freeVPN
C:\freeVPN NT AUTHORITY\SYSTEM:(OI)(CI)(F)
           DESKTOP-CJ40M9U\xyw:(OI)(CI)(F)          <-- 显式 ACE

> icacls C:\freeVPN\freeVPN.exe
C:\freeVPN\freeVPN.exe NT AUTHORITY\SYSTEM:(I)(F)
                       DESKTOP-CJ40M9U\xyw:(I)(F)    <-- (I) 继承生效, 不是空 DACL

> icacls C:\freeVPN\state
C:\freeVPN\state NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
                 DESKTOP-CJ40M9U\xyw:(I)(OI)(CI)(F)

> icacls C:\freeVPN\state\token.txt
C:\freeVPN\state\token.txt NT AUTHORITY\SYSTEM:(F)
                           DESKTOP-CJ40M9U\xyw:(F)

=== 可读性实测 ===
  OK  token.txt      34 字符
  OK  daemon.log     1111 字符
  OK  gui.log        18274 字符
  OK  daemon.pid     5 字符
```

`security.py` 的 `harden_install_dir()` 也同步改了（去掉 `/T`、加了加固后复查：
挑根目录第一个文件查 `icacls`，输出为空或仍含 `authenticated users` / `builtin\users` 就返回 `False`，
不再报假成功）。

**这条仍然要写进报告的原因**：
1. 它证明了"用 `icacls /T` + `(OI)(CI)` 收紧目录"这个写法**在 Windows 上会静默摧毁文件权限**，
   而 icacls 自己还会打印 `Successfully processed 1057 files`；
2. 它暴露了修复本身**没有回归测试**：`harden_install_dir` 只在 `is_frozen()` 时被调用
   （`pool.py:3657`），源码版跑不到这条路径，而它一跑就作用在用户的真实安装上；
3. 抢救需要 `takeown /R` + `icacls /reset`，对普通用户来说等于"重装"。**这个代价必须在设计阶段避免。**

**回归测试建议**（补进 `state/verify-fixes.py` 之类）：
在 `%TEMP%` 造 `root/{a.txt, sub/b.txt}` → 调 `harden_install_dir(root)` → 断言
`icacls` 对**每个文件**都有非空 ACE、且都能读；再断言 `dir_is_loose(root) is False`。
`audit/d8_acl_harden.py` 就是现成的模板。

---

## D-05 【中高】`access.log` 的令牌脱敏只覆盖 3/4 种投递形式 —— 22 个用例里 14 个泄露

**位置**：`pool.py:2968`

```python
safe = re.sub(r"([?&](?:token|t)=)[^&\s]*", r"\1***", path)
```

而 handler 明确支持四种投递方式（`pool.py:3000-3010`）：`?token=` / `?t=` /
`Authorization: Bearer` / **路径段 `/t/<token>/<file>`**。脱敏只认前两种的两种写法。

**证据**（`d2_accesslog_redaction.py`，22 个用例）

```
用例                          HTTP  日志新增     行内含完整令牌       判定
① ?token=                   200   1        0             OK
② ?t=                       200   1        0             OK
③ 路径段 /t/<T>/pool.yaml      200   1        1             泄露
④ 路径段 /t/<T> (无文件)          404   1        1             泄露
⑤ 路径段 /t/<T>/               404   1        1             泄露
⑥ Authorization: Bearer     200   1        0             OK
⑦ ?TOKEN= (大写)              401   1        1             泄露
⑧ ?Token= (混合)              401   1        1             泄露
⑨ ;token= (分号分隔)            401   1        1             泄露
⑩ ?x=1&token=               200   1        0             OK
⑪ ?token=&y=1               200   1        0             OK
⑫ ?token=<T>;x=1            401   1        0             OK
⑬ 绝对 URI + ?token=          200   1        0             OK
⑭ ?token=<T>#frag           200   1        0             OK
⑮ %3Ftoken%3D 编码            401   1        1             泄露
⑯ 路径段 + 错 query             401   1        1             泄露
⑰ 路径段 + 穿越                  404   1        1             泄露
⑱ 令牌在 Host 头                403   1        1             泄露
⑲ 令牌在 UA                    401   1        1             泄露
⑳ 双重路径段                     404   1        1             泄露
㉑ /sub/<T> (note 字段)        401   1        1             泄露
㉒ /sub/<T>.yaml             401   1        1             泄露

### 结论: 14/22 个用例把完整令牌写进了 access.log
```

真实日志行（节选）：

```
[③ 路径段 /t/<T>/pool.yaml]  泄露字段: path
    2026-10-08 16:08:14	GET	200	/t/TESTTOKEN_d2_0123456789abcdef/pool.yaml	host=127.0.0.1:8899	ua=	served pool.yaml
[⑦ ?TOKEN= (大写)]           泄露字段: path
    2026-10-08 16:08:21	GET	401	/sub/pool.yaml?TOKEN=TESTTOKEN_d2_0123456789abcdef	host=...	ua=	token required
[⑱ 令牌在 Host 头]           泄露字段: host
    2026-10-08 16:08:22	GET	403	/sub/pool.yaml	host=TESTTOKEN_d2_0123456789abcdef	ua=	forbidden host
[⑲ 令牌在 UA]                泄露字段: ua
    2026-10-08 16:08:22	GET	401	/sub/pool.yaml	host=127.0.0.1:8899	ua=TESTTOKEN_d2_0123456789abcdef	token required
```

**要点**

- **③ 是唯一"既通过认证又落明文"的形式**：`/t/<token>/pool.yaml` 返回 200 并正常服务文件，
  说明它是**被支持的官方投递方式**（A 轮 `A1_gate.py:88` 也确认过 200）。任何用这种方式的客户端，
  令牌都会明文进日志。而 Lead 的交叉验证脚本已经在源码版的 `state/access.log` 里留下了 1 处真实样本。
- ⑦⑧⑨⑮ 是"落盘但认证失败"：`token_ok` 只认小写 `token`/`t`，但这些写法的原文进了日志。
- ⑱⑲ 说明**脱敏只作用于 `path` 字段，`host` / `ua` / `note` 三个字段完全没管**。
- ⑳㉑㉒ 是路径段的其他变形。
- `_log` 的 docstring 自己写着"令牌必须脱敏 —— 日志不该成为密钥的第二个落盘点。之前这里写的是
  原始 self.path, 生产日志里 146/170 行都含完整令牌" —— 四种形式只堵了三种。

**修复建议**

```python
def _redact(self, s: str) -> str:
    s = re.sub(r"([?&](?:token|t)=)[^&\s]*", r"\1***", s, flags=re.I)   # 大小写
    s = re.sub(r"(^|/)t/[^/\s]+", r"\1t/***", s)                        # 路径段
    if token and token in s:                                            # 兜底: 值级
        s = s.replace(token, "***")
    return s
```

再对 `host` / `ua` / `note` 一起调用它（`note` 里 `fn!r` 来自路径，同样可控）。
**最根本的修法还是 D-03 建议 1：令牌别放 URL。**

附带一条：轮转归档 `access.log.1`（`pool.py:2965`）同样从未被 `tighten_file_perms` 处理过，
且 `ACCESS_LOG.replace(...)` 会**覆盖**上一份归档（丢数据）。审计时三个部署里都还没有 `access.log.1`。

---

## D-06 【中】`progress.json` 完全未校验 —— 控制台启动即崩 / 自动刷新停摆

**位置**
- 写：`pool.py:3266-3289 set_progress()`（内容全部由程序自己拼）
- 读：`gui.py:509-559 update_progress()`，由 `gui.py:394 refresh()` 调用
- 文件：`state/progress.json`（`pool.py:1560`）

**证据 1 · 内容侧是干净的（这一半不成立）**

```
### ① set_progress 的 note 内容来源 (静态清点)
  pool.py:1280   set_progress(op, "L1 TCP 探活", done, total)
  pool.py:1297   set_progress(op, "L1 TCP 探活", 0, total)
  pool.py:1533   set_progress(op, "L2 内核实测", min((ci + 1)
  pool.py:2353   set_progress("快车道复检", "L2 内核实测", 0, len(cur)
  pool.py:3365   set_progress("完整扫描", "拉源", 0, 0, f"{len(load_sources())
  pool.py:3372   set_progress("完整扫描", "解析去重", 0, 0, f"原始 {len(raw)
  pool.py:3376   set_progress("完整扫描", "安全审计", 0, len(nodes)
  pool.py:3404   set_progress("完整扫描", "L2 内核实测", 0, len(cand)
  pool.py:3429   set_progress("完整扫描", "写产物", 0, 0)

  结论: op/phase 是字面量; note 全部由 len()/计数拼成, 不含节点名或源 URL。
```

**节点名、源 URL 不会进 progress.json** —— 这条假设**不成立**，可以排除。

**证据 2 · 文件侧是敞开的（这一半成立）**

`state/progress.json` 落在 `state/` 下，审计时点 ACL 是 `Authenticated Users:(M)` —— 本机任何用户可写。
`gui.py` 直接 `json.loads` 之后 `pr.get(...)`，**没有任何类型校验**。实测（真实 tkinter + 真实 `update_progress`）：

```
### ② 畸形 progress.json 对 GUI 的影响

  正常                       渲染成功       完整扫描进行中 | 'L2 内核实测  ·  1/10  ·  已找到 3 个'
  started 是字符串             抛异常 !!     TypeError: unsupported operand type(s) for -: 'float' and 'str'
  started 是列表              抛异常 !!     TypeError: unsupported operand type(s) for -: 'float' and 'list'
  顶层是 list                 抛异常 !!     AttributeError: 'list' object has no attribute 'get'
  顶层是字符串                   抛异常 !!     AttributeError: 'str' object has no attribute 'get'
  顶层是数字                    抛异常 !!     AttributeError: 'int' object has no attribute 'get'
  ts 是字符串                  抛异常 !!     TypeError: unsupported operand type(s) for -: 'float' and 'str'
  op 是 dict                渲染成功       {'a': 1}进行中 | '拉源'
  超长 note (20 万字符)         渲染成功       完整扫描进行中 | 'L2 内核实测  ·  1/2  ·  AAAA...'
  控制字符 note                渲染成功       完整扫描进行中 | 'L2 内核实测  ·  1/2  ·  A\x00B\u2028C\r\nD\tE'
  phase 不在映射表              渲染成功       完整扫描进行中 | 'PPP...'
  ts 是未来 (永不过期)            渲染成功       完整扫描进行中 | 'L2 内核实测  ·  1/2'
  done/total 是字符串          抛异常 !!     ValueError: could not convert string to float: 'b'

### ③ 抛异常会不会让刷新循环停摆
  基线 (正常文件)        : refresh 被调用 6 次   异常: 无
  畸形文件 (started='boom'): refresh 被调用 1 次   异常: TypeError: unsupported operand type(s) for -: 'float' and 'str'

  → 自动刷新停摆: 是
     (正常 6 次 vs 畸形 1 次 —— 畸形文件只跑了第一次就断了)

  实测 A: 启动时 progress.json 已经畸形
     结果: **构造抛异常 -> 控制台窗口起不来**: TypeError: unsupported operand type(s) for -: 'float' and 'str'

### ④ 汇总
  7/13 个畸形输入让 update_progress 抛异常
  启动即崩: 是
```

**机理**：`gui.py:446` 的 `update_progress()` 在 `refresh()` 里，而 `refresh()` 末尾（`gui.py:456`）
才 `self.root.after(1000/2000, self.refresh)` 重新排程。异常一抛，排程断掉，**界面从此不再刷新**。
`__init__`（`gui.py:168`）里是**直接调用** `refresh()`，所以启动时就已经是畸形的文件会让窗口根本起不来。

**另外两条轻的**（渲染成功但语义被扭曲）：
- `ts` 写成未来时间 → `stale` 判定永假 → 进度条永远显示"进行中"（误导用户以为在扫描）；
- `op` 是 dict / 20 万字符 note / 控制字符，都能直接进 Label。

**修复建议**

```python
# gui.py update_progress 开头统一收口
pr = load_json(STATE / "progress.json")
if not isinstance(pr, dict):
    pr = None
if pr is not None:
    for k in ("op", "phase", "note"):
        if not isinstance(pr.get(k), str):
            pr[k] = ""
    for k in ("done", "total"):
        if not isinstance(pr.get(k), (int, float)) or isinstance(pr.get(k), bool):
            pr[k] = 0
    for k in ("ts", "started"):
        if not isinstance(pr.get(k), (int, float)) or isinstance(pr.get(k), bool):
            pr.pop(k, None)
    pr["note"] = pr["note"][:200]
```

再把 `refresh()` 的 `after` 排程挪到**最前面**（或用 `try/finally`），保证一次渲染失败不会让整个
刷新循环死掉。最后：`state/` 目录收紧后（D-04 正确修法），这条的跨用户可达性自然消失。

---

## D-07 【中】`daemon.pid` 可被第三方改写 → 控制台会 `taskkill` 任意 PID

**位置**：`pool.py:3596-3601`（写 pid）、`gui.py:112-123 daemon_pids()`（读 pid）、
`gui.py:763-776 toggle_daemon()`（读到就 `taskkill /PID <pid> /T /F`）

**证据**（`d6_gui_surface.py` 第 ③ 节）

```
### ③ daemon.pid 被改写 -> 控制台会杀掉那个 PID

  受害者进程 (与 freeVPN 无关): PID 37188, 还活着=True
  第三方把 ...\daemon.pid 写成 37188
  gui.daemon_pids() 读到: [37188]
  → 控制台把它当成'自己的常驻进程'了

  模拟用户点「停止常驻」:
     弹窗内容: 停止常驻|||结束 1 个 pool.py 进程？
     受害者进程 PID 37188 还活着: False
     → 被跨用户数据驱动的 taskkill 打掉了: 是
```

**影响**

- 弹窗文案是"结束 1 个 **pool.py** 进程？" —— 但代码从不校验那个 PID 到底是不是 pool.py。
- 本机任何用户写一行数字，就能让**用户自己点一下按钮**去杀掉一个任意进程（同用户权限内）。
  受害者进程会被 `/T` 连整棵子进程树一起带走。
- 反向用法：攻击者填一个不可能被杀掉的 PID（如系统进程）→ 用户以为"停了"，实际常驻还在跑，
  `daemon.pid` 被 unlink 掉（`gui.py:771`）→ 之后 GUI 永远显示"常驻未运行"，用户失去控制手段。

**修复建议**

1. `daemon_pids()` 读回 PID 后**校验进程身份**：
   用 `QueryFullProcessImageName` 拿映像路径，确认它等于 `sec.self_cmd()[0]`（或 `sys.executable` + `pool.py`），
   不匹配就丢弃并提示"daemon.pid 被篡改"。
2. `daemon.pid` 写成 `pid\t<启动时间戳>\t<可执行文件路径>`，读回时三项都对才认。
3. `toggle_daemon` 里改用 `kill_pids(..., tree=False)`（`pool.py:3202`）而不是硬编码 `/T` ——
   `/T` 的影响面比"停掉自己的常驻"大得多，`kill_pids` 的 docstring 里已经写明这个教训。

---

## D-08 【中】`daemon.log` 可被第三方写入 → 内容原样进用户的模态弹窗

**位置**：`gui.py:797-852 watch_daemon()`（把日志尾部 8 行塞进 `messagebox`）、
`pool.py:2525-2544`（自启时把 stdout 重定向到 `state/daemon.log`）

**证据**（`d6_gui_surface.py` 第 ④ 节）

```
### ④ daemon.log 被第三方写入 -> 原样进用户的模态弹窗

  第三方往 ...\daemon.log 写了 6 行诱导文本
  (该文件在真实部署里是 C:\freeVPN\state\daemon.log,
   实测 ACL = NT AUTHORITY\Authenticated Users:(M) —— 任何本机用户可写)

  实际弹窗标题: 常驻启动失败
  实际弹窗内容:
      退出码 1

      ========================
        freeVPN 安全更新提示
        检测到订阅令牌需要重新确认。
        请在弹出的下一个窗口里点「是」以继续。
        官方提示：不要关闭本窗口。
      ========================

      完整日志: ...\daemon.log

  → 第三方写入的文本被原样显示给用户: 是
```

**影响**：这是一条**可跨用户触发的 UI 欺骗（spoofing）**通道。攻击者可控文本会出现在
一个标题为"常驻启动失败"的模态弹窗里 —— 用户对这类弹窗的信任度天然很高。
配合 D-07，可以把"点「是」"导向一个会执行动作的分支（`askyesno` 之后跟着 `do_free_port` / 重启常驻）。

**修复建议**

1. 弹窗只显示**程序自己生成的**摘要，日志原文放到"日志"页里（用户主动去看）；
   必须显示日志时，逐行加前缀 `| ` 并显式标注"以下内容来自日志文件，可能被篡改"。
2. `state/` 目录收紧后（D-04 正确修法）这条的跨用户可达性消失。
3. 给日志加**完整性标记**：daemon 每次启动写一行随机 nonce 作为首行，
   GUI 读日志时校验首行 nonce 是否存在 —— 第三方追加的内容会在 nonce 之前/之后错位。

---

## D-09 【中】`is_ours()` 按 URL 子串匹配删除条目 —— 会误删用户自己的订阅

**位置**：`pool.py:2237-2250`

```python
self_url_mark = f"127.0.0.1:{_port}/sub/"
def is_ours(it) -> bool:
    if it.get("name") == IMPORT_NAME:      # "freeVPN"
        return True
    return self_url_mark in (it.get("url") or "")
items = [it for it in (data.get("items") or []) if not is_ours(it)]
```

**证据**（`d5_verge_is_ours.py` 第 ① 节，在 `%TEMP%` 造的假 Clash Verge 目录里跑真实 `inject_verge`）

```
  --- 用户自己的条目, url 指向本机 8787 的别的路径
      导入前条目: ['我的机场', '另一个机场']
      导入后条目: ['另一个机场', 'freeVPN']   (import 返回 True)
      丢失的条目: ['我的机场']
  --- 用户把订阅转存到 CDN, URL 里带原地址
      导入前条目: ['CDN 缓存', '另一个机场']
      导入后条目: ['另一个机场', 'freeVPN']   (import 返回 True)
      丢失的条目: ['CDN 缓存']
  --- 用户自己的本地 clash 服务, 恰好也监听 8787
      导入前条目: ['local-clash', '另一个机场']
      导入后条目: ['另一个机场', 'freeVPN']   (import 返回 True)
      丢失的条目: ['local-clash']
```

**影响**：三种真实场景都会**静默删除**用户自己的订阅条目，而 `import` 返回 `True`（"成功"）：

1. 用户自己有别的工具/配置指向 `127.0.0.1:8787/sub/...`；
2. 用户把订阅**转存到 CDN**，URL 里带着原地址（`?u=http://127.0.0.1:8787/sub/pool.yaml`）——
   这是很常见的"订阅缓存"做法；
3. 用户自己起过一个本地 clash 服务，恰好也用 8787。

被删的条目如果正好是 `current`，`inject_verge` 会把 `current` 改指向新条目（`pool.py:2270-2282`），
用户的默认配置被**静默换掉**。备份在 `profiles.yaml.freevpn.*.bak` 里，但用户不会去看。

**修复建议**

```python
def is_ours(it) -> bool:
    if not isinstance(it, dict):
        return False
    if it.get("name") == IMPORT_NAME:
        return True
    url = it.get("url")
    if not isinstance(url, str):
        return False
    try:
        p = urllib.parse.urlparse(url)
    except Exception:
        return False
    # 必须"主机+端口+路径前缀"三项都精确匹配, 不做子串
    return (p.hostname in ("127.0.0.1", "localhost") and p.port == _port
            and p.path.startswith("/sub/"))
```

并且：删除前先打印"即将删除 N 条：<名字/uid 列表>"，让用户在 GUI 里能看到；
或者干脆只删 `name == IMPORT_NAME` 且 `url` 指向本机当前端口的条目。

---

## D-10 【中低】`profiles.yaml` 的畸形字段：未捕获异常 + 条目列表被破坏

**位置**：`pool.py:2224-2263`（`safe_load` → 过滤 → `safe_dump`）、`pool.py:2284-2292`（原子替换）

**证据**（`d5_verge_is_ours.py` 第 ② 节）

```
  --- url 是数字
      返回 False   ... | !! 未捕获异常 TypeError: argument of type 'int' is not iterable
  --- url 是布尔
      返回 False   ... | !! 未捕获异常 TypeError: argument of type 'bool' is not iterable
  --- url 是 null      返回 True
  --- url 是列表        返回 True
  --- items 是字符串     返回 True
  --- items 是字典       返回 True

  items 被换掉之后的实际文件内容:
  --- items 是字符串 -> 导入后:
        items:
        - h
        - e
        - l
        - l
        - o
        - uid: PF4fGDi4dD5M
        current: PF4fGDi4dD5M
  --- items 是字典 -> 导入后:
        items:
        - a
        - b
        - uid: 3lBqNVmmJghL
        current: 3lBqNVmmJghL
```

**影响**

1. `url` 是数字/布尔时，`"..." in 12345` 抛 `TypeError`。这段代码**不在 try 里**，
   `cmd_import` 也没有兜底 → 用户看到一串 traceback，导入整体失败。
   `profiles.yaml` 是 **Clash Verge 写的文件**，字段类型不受我们控制，这不是理论问题。
2. `items` 不是 list 时，`[it for it in (data.get("items") or []) ...]` 会把**字符串按字符迭代**、
   把**字典按键迭代**，然后写回 —— 用户的订阅列表被**破坏**成 `[h, e, l, l, o]`。
   原文件虽然备份了，但用户的客户端会立刻加载到一份坏配置。

**证据 · 往返损失**（第 ③ 节）

```
  导入前 8 行, 导入后 22 行
      '# 这段注释是用户手写的'   还在: **丢了**
      '&def'                    还在: **丢了**
      '*def'                    还在: **丢了**
      'extra_field_user_added'  还在: 是
      'update_interval: 60'     还在: 是
```

用户手写的注释和 YAML 锚点全部丢失（`safe_load` → `safe_dump` 往返的固有限制）。
未知的顶层字段能保留，这一点是好的。

**证据 · `safe_load` 本身是安全的**（第 ④ 节）

```
  python/object tag      抛 ConstructorError
  python/name tag        抛 ConstructorError
  别名炸弹 (有限版)        解析成功 0.00s, 结果体积 4000 字节
  深嵌套 (5000 层)        抛 RecursionError (0.82s)
```

`yaml.safe_load` 挡住了 `!!python/*` 反序列化，`RecursionError` 也被 `inject_verge` 的
`except Exception` 捕获（`pool.py:2226-2228` → 打印"解析 profiles.yaml 失败, 未做任何改动"并返回 False）。
**没有代码执行面**。

**修复建议**

```python
raw_items = data.get("items")
if not isinstance(raw_items, list):
    print(f"[!] profiles.yaml 的 items 不是列表 (是 {type(raw_items).__name__}), 未做任何改动")
    return False
items = [it for it in raw_items if not is_ours(it)]
```

`is_ours` 里按 D-09 的建议加 `isinstance(url, str)` 判断。
另外把 `inject_verge` 的整个主体包一层 `try/except`，失败时打印可读原因而不是 traceback。

---

## D-11 【低】`is_freevpn` 判据可伪装 —— 弹窗里给攻击者进程打上"自己人"标记

**位置**：`pool.py:3193-3196`

```python
low = (name + " " + cmdline).lower()
out.append({..., "is_freevpn": "freevpn" in low})
```

**证据**（`d6_gui_surface.py` 第 ② 节）

```
  子进程还活着: True
  起了一个普通 python 进程, 命令行里塞了 'freevpn-kernel-helper.exe'
  占住端口 8892, port_holders() 返回 1 条:
      pid=14688  name='python.exe'  is_freevpn=True
      cmdline='...\python.exe -c "import socket,time;s=socket.socket();s.bind((\'127.0.0.1\',8892)...'
      → 会被标成「另一份 freeVPN」: 是
      → 但它其实是: python.exe 起的任意脚本

  用真实的 do_free_port() 拼出弹窗内容:
      弹窗标题: 清掉端口占用
      | 端口 8892 被这些进程占着：
      |
      |   python.exe  (PID 14688)   ← 另一份 freeVPN
      |       ...\python.exe -c "import socket,time;s...
      |
      | 要结束它们吗？
      | （只动这个端口上的进程，不会影响别的东西）
```

**影响**：`← 另一份 freeVPN` 这个标记的语义是"这是我们自己的东西，结束它没问题"。
攻击者只要在自己的命令行里塞一个 `freevpn` 子串就能获得这个标记 ——
既可用于**诱导用户点「是」**，也可反过来让真正的 freeVPN 进程被误杀。

**修复建议**：改成按**映像路径**判定，而不是子串：
`is_freevpn = Path(exe_path).resolve() in {sec.app_root()/ "freeVPN.exe", Path(sys.executable)}`，
并在命令行里只匹配完整的可执行文件名（`\bfreevpn\.exe\b`），不做裸子串。

---

## D-12 【中】目录级 ACL 未收紧 —— 文件级收紧可以被"删除 + 重建"绕过

**位置**：`security.py:577-599 tighten_file_perms()` 只作用于**单个文件**

**证据**（`d1_token_sinks.py` 第 ④ 节，审计时点）

```
  打包版 C:\freeVPN :: freeVPN  ACL=宽松
      BUILTIN\Users:(I)(OI)(CI)(RX)
      NT AUTHORITY\Authenticated Users:(I)(M)
      NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(IO)(M)
  打包版 C:\freeVPN :: state  ACL=宽松
      （同上）
```

目录的 `(M)` 含 `FILE_DELETE_CHILD` 与 `DELETE`，所以任何本机用户可以：

1. 删掉 `state/token.txt`，**自己新建一个**内容已知的 `token.txt`（新文件继承目录的宽松 ACL）；
2. freeVPN 下次启动 `load_or_create_token()` 读到它（长度 ≥ 16 就接受）→ **令牌被攻击者控制**；
3. 用户客户端里已经填好的订阅地址全部 401（因为令牌变了），而攻击者拿到的是有效令牌。

同理可以删掉 `daemon.log` / `progress.json` / `daemon.pid` 换成任意内容（D-06/07/08 的可达性都建立在这一点上）。
**文件级 ACL 收紧在"目录本身宽松"的前提下没有意义。**

**修复建议**：对 `app_root()` 整体做一次正确的目录级收紧（D-04 的正确写法），
并在每次启动时用 `dir_is_loose()` 复查一次、失败时在 GUI 顶部持续告警。

---

## 未成立 / 已排除的假设

| 假设 | 实测结果 | 依据 |
|---|---|---|
| `progress.json` 的 `note` 会带上节点名或源 URL | **不成立** | 10 个 `set_progress` 调用点的 note 全部是 `len()` 计数（d3 ①） |
| `yaml.safe_load` 读恶意 `profiles.yaml` 能触发代码执行 | **不成立** | `!!python/object` 抛 `ConstructorError`；深嵌套 `RecursionError` 被捕获（d5 ④） |
| `_resolve_sub` 存在路径穿越 | **不成立** | 16 种编码/变体全部 404，无一读到 `state/token.txt`（d7 ①） |
| CSP nonce 可预测或与页面不一致 | **不成立** | 三次请求 nonce 互不相同、长度 22、header 与页面一致（d7 ②） |
| 令牌校验在 Host 校验之前，未认证请求可探测 | **不成立** | Host 错一律 403（含"正确令牌"），Host 对才 401/200（d7 ③） |
| GUI 打开状态页会把令牌写进浏览器历史 | **不成立** | Chrome / Edge History 字节级搜索令牌命中 0（d1 ③，扫 14062 个文件） |
| `copy_addr()` 的剪贴板内容会被持久化 | **不成立** | 剪贴板历史 `Pinned\` 目录命中 0；`ActivitiesCache.db` 被占用读不到，未能排除 |
| `port_holders` 的命令行里塞换行可以伪造弹窗行 | **不成立** | wmic 输出按行解析，`CommandLine=` 只取第一行，换行被截断（d6 诊断） |
| `_resolve_sub` 的 `OUT.iterdir()` 回退分支可读外部文件 | **未证实** | 该分支只在 `OUT` 直接子项里按名字匹配，需要攻击者先在 `out/` 放符号链接；未构造成功 |
| `wmic` 可用（`port_holders` 拿命令行的前提） | **不成立（环境）** | 本机 `wmic` 缺失，`port_holders` 回退到 `tasklist`，`cmdline` 恒为空 |

---

## 修复优先级

| 优先级 | 条目 | 一句话 | 状态 |
|---|---|---|---|
| P0 | D-04 | `harden_install_dir` 的 `/T` 写法会清空文件权限 —— 运行实例上已实际发生 | **已修复**（Lead，16:52；本审计 16:58 复核） |
| P0 | D-01 | 安装目录 ACL 收紧到 SYSTEM + 当前用户（**用正确写法**），这是所有跨用户攻击的前提 | 运行实例**已修复**；源码版/dist 版**仍宽松**（`is_frozen()` 才自动收紧） |
| P1 | D-03 | 令牌从 URL 移出（`Authorization` 头），这同时修掉 D-05 的根因 | **未修** |
| P1 | D-02 | `--log` 模式下不打印带令牌的订阅地址；`gui.log` 落盘点；Clash Verge 目录的 `.bak` 群 | `state/` 已收紧；**落盘点仍在**（gui.log 14 次、Clash Verge 目录 6 份含令牌且对本机组可读） |
| P2 | D-06 / D-07 / D-08 | 三个 `state/` 数据文件：读入时全部做类型与身份校验，弹窗只显示程序自己的摘要 | **未修**（ACL 收紧后跨用户可达性消失，但本用户内的其他进程仍可写） |
| P2 | D-09 / D-10 | `is_ours` 改精确匹配；`items` 非 list 时拒绝写入 | **未修** |
| P3 | D-11 / D-12 | 判据改精确匹配；目录级收紧 + 启动自检 | 部分（D-12 的目录收紧已做，启动自检未见） |

---

## 附录 · PoC 脚本

| 脚本 | 覆盖 |
|---|---|
| `audit/d1_token_sinks.py` | 令牌落盘点穷举（3 个部署 + 5 类外部落点）、ACL 分级、目录级 ACL |
| `audit/d2_accesslog_redaction.py` | `access.log` 脱敏矩阵 22 用例 |
| `audit/d3_progress_inject.py` | `progress.json` 13 种畸形输入 × 真实 tkinter + 真实 mainloop 计数 |
| `audit/d4_resource_shadow.py` | `find_resource` 优先级、`pool.MIHOMO` 指向、替身被执行、真实 `Kernel.check()` 路径、ACL 权限位 |
| `audit/d5_verge_is_ours.py` | `is_ours` 误删 3 场景、`profiles.yaml` 8 种畸形字段、往返损失、`safe_load` 恶意输入 |
| `audit/d6_gui_surface.py` | 端口抢占截获令牌、`is_freevpn` 伪装 + 真实 `do_free_port` 弹窗、`daemon.pid` 劫持、`daemon.log` 进弹窗 |
| `audit/d7_route_recheck.py` | 路径穿越 16 变体、CSP nonce、Host/令牌校验顺序、正常路径可用性 |
| `audit/d8_acl_harden.py` | `harden_install_dir` 把子文件 DACL 清空的复现 |

所有脚本的临时文件都在 `%TEMP%\freevpn_d*`，运行结束自动清理；
`C:\freeVPN`（运行实例）全程只做 `icacls` / `Get-Content` 只读访问。
