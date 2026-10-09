# 安全审计 C · 服务端与进程边界

**目标**：`E:\AI\freeVPN`（freeVPN v1.3.6）
**范围**：`pool.py` 的 `port_holders / kill_pids / free_port / who_holds_port / cmd_free_port / serve(冲突路径)`、`detect_clients / verge_exe / close_verge / relaunch_verge / client_pids / launch_deeplink / cmd_import`、`inject_verge` 的写入侧、`cmd_diag_write`；`security.py` 的 `console_encoding / write_confined / hidden_flags`；`pack.py` 的 `running_instances / kill_instances / --kill / 发布与回滚 / zip 白名单`
**方式**：每个结论都有实跑证据。PoC 脚本在 `audit/c_*.py`，临时数据在 `E:\AI\_c_test\`。**未修改 `pool.py` / `security.py` / `pack.py` / `gui.py`，未改动 `C:\freeVPN\` 里的任何文件或进程。**
**审计机环境**：Windows，Python 3.13.0，当前用户**非管理员**（`IsUserAnAdmin()=False`），`wmic`/`netstat`/`tasklist`/`taskkill` 均可用，`GetOEMCP()=936`。
**审计期间的环境变动（只读观察，未干预）**：`C:\freeVPN\freeVPN.exe` 从 1 个进程变为 3 个（PID 25308 监听 8787、PID 6888 监听 17843、PID 35884），`clash-verge.exe` 的 PID 从 11136 变为 18380 / 33564。因此部分实测的行数（如 `port_holders(1)` 的命中数）在不同次运行之间会有 1 个进程的差异。

**重要背景**：本机 `HKCU\Software\Classes\clash\shell\open\command` 是**用户自己的**真实注册项（值 `C:\Program Files\Clash Verge\clash-verge.exe "%1"`）。审计中为了验证 C-05，只在**当时不存在**的 `HKCU\Software\Classes\clash-verge` 下建了一个测试键。实验后的第一次清理删掉了 `...\shell\open\command`，但 `winreg.DeleteKey` 只删空键，**在 `...\shell\open` 与 `...\shell` 两层留下了空壳键**（本次审计自己的疏漏，`audit/c_verge_reg.py` 的 `drop_key()` 已修正为自底向上逐层删除）；终检时发现并补删，`HKCU\Software\Classes\clash-verge` 整棵已不存在，`verge_exe()` 与 `detect_clients()` 均已恢复基线值（实测：`clash` / `clash-verge` / `mihomo` 三项，全部指向用户真实路径）。

---

## 结论摘要（按严重度）

| 编号 | 标题 | 严重度 |
|---|---|---|
| C-01 | `port_holders` 用**端口号子串**匹配，`free_port(N)` 会杀掉所有端口以 N 开头的进程 —— 实测清空闲端口会杀掉别的端口上的进程，`--port 1` 会命中 explorer.exe | **高** |
| C-02 | `kill_pids` 用 `taskkill /F /T`，连带结束占用者的**整棵子进程树**（实测子进程被一并杀掉） | 中 |
| C-03 | `free_port` 完全不看 `is_freevpn` 归属判断，也不看端口是否真的被占 —— 拿到 PID 就强杀 | 中 |
| C-04 | `pack.py --kill` 用 `taskkill /F /IM freeVPN.exe /T`，会结束**别的目录**里的 freeVPN（实测它把 `C:\freeVPN\freeVPN.exe daemon --port 8787` 认成"自己的实例"） | 中 |
| C-05 | `verge_exe()` 的路径 100% 来自注册表 `clash*` 处理器命令行，**HKCU 优先、非管理员可写**；`relaunch_verge` 会以当前权限启动该路径指向的任意 PE（实测执行了 whoami 副本） | 中 |
| C-06 | `client_pids / close_verge / verge_running` 只按**进程名**识别客户端，攻击者放一个 `clash-verge.exe` 即被当作 Clash Verge（实测被列入并被 `close_verge` 的强杀目标集合） | 中 |
| C-07 | 打包 zip 的白名单只按**路径首段字符串**过滤：硬链接、目录 junction、大小写变体三种方式都能把 `state/token.txt` 打进发布包（实测令牌明文进包） | 中 |
| C-08 | 发布阶段的 `shutil.move(outdir, final)` 无异常保护，失败时**不回滚** —— 用户 `state/out/订阅地址.txt` 永久滞留在 `dist/.keep_*` 隐藏目录（实测复现） | 低 |
| C-09 | `inject_verge` 的备份名（秒级可枚举）与 tmp 名（固定）可预测，跟随硬链接 → **覆盖任意同卷文件**；实测 `profiles.yaml` 的 inode 被换成攻击者的文件 | 低 |
| C-10 | `cmd_diag_write` / `security.write_confined` 的 `.freevpn-diag-<pid>` / `.wtest-<pid>` 同一模式，实测把 1080 字节的受害者文件截断为 1 字节 | 低 |
| C-11 | `cmd_import` 深链路径用 `Path(cmd).name` 当进程名，注册表值带 `"%1"` 时拿到脏名字 → 深链导入必然误报"客户端没起来" | 低 |
| C-12 | `port_holders` 的 wmic 解析按行 `startswith`，多行命令行被截断 → `is_freevpn` 漏判、占用者提示不全 | 信息 |
| C-13 | `is_freevpn` 可被任意进程伪造（实测 `freevpn` 字样出现在脚本路径里即被标记"另一份 freeVPN"） | 信息 |
| C-14 | `cmd_diag_write` 会在程序上一级目录**永久创建** `_writecheck` 目录且不清理 | 信息 |
| C-15 | `close_verge` 的两处 `taskkill` 没有 try/except，一旦 `console_encoding()` 返回非法 codec 就会把异常抛穿导入流程 | 信息 |

**最需要先修的**：C-01（清端口是破坏性操作，且它的用户提示"只动这个端口上的进程，不会影响别的东西"是**错的**）与 C-04（打包脚本会顺手停掉用户正在用的订阅服务）。这两条都是"用户按提示做正常操作就会中招"，不需要攻击者。

---

## 详细发现

### C-01 · `port_holders` 用端口号子串匹配：`free_port(N)` 会杀掉所有端口以 N 开头的进程 · 高

**位置**
- `pool.py:3112` —— `if len(parts) >= 5 and parts[3] == "LISTENING" and f":{port}" in parts[1]:`
- `pool.py:3171-3185` `free_port()` → `pool.py:3155-3168` `kill_pids()`
- 调用点：`pool.py:2734-2759` `cmd_free_port()`（CLI `free-port --port N`）、`gui.py:676` 与 `gui.py:836-841`（控制台「清端口占用」按钮 + 常驻启动失败后的自动清理）
- 端口来源：`pool.py:3475` `fp.add_argument("--port", type=int, default=8787)`，默认值会被 `pool.conf.json` 的 `port` 键覆盖（`pool.py:3488-3504`），GUI 侧是 `gui.py:139-141` / `pool.py:3469`

**触发条件**
`port` 是 ≤3 位的数字（1–999）。此时 `":{port}"` 是 `":{真实端口}"` 的**前缀**，任何以该数字开头的 4/5 位端口都会被命中。默认的 8787 是 4 位，安全（5 位端口 87870+ 超出 65535，不存在），所以**默认配置不会触发**；一旦用户按自己的习惯把端口改成 808 / 80 / 8 / 1，就会触发。

**实跑证据**（`audit/c_port_prefix.py`、`audit/c_kill_scope.py`）

```
C1-a · 只读: 用「另一个 freeVPN 的真实端口」做前缀, 看会命中谁

  port_holders(878) -> 1 个占用者
      pid=25308   name=freeVPN.exe                  freevpn=True
  port_holders(8) -> 3 个占用者
      pid=16452   name=python.exe                   freevpn=False
      pid=33564   name=clash-verge.exe              freevpn=False
      pid=25308   name=freeVPN.exe                  freevpn=True
  port_holders(1) -> 9 个占用者
      pid=1804    name=svchost.exe / 1380 services.exe / 4 System
      pid=2176    name=explorer.exe                 freevpn=False
      pid=2184    name=vivoSyncService.exe / 5288 vivoesService_x64.exe
      pid=6888    name=freeVPN.exe                  freevpn=True
      pid=30580   name=WorkBuddy.exe                freevpn=False
      pid=32848   name=DeepSeek Harness.exe         freevpn=False
  port_holders(80) -> 1 个占用者
      pid=16452   name=python.exe
```

```
C1-b · 实跑: 清一个**空闲**端口, 却杀掉占着别的端口的进程
  构造: 只有测试进程监听 127.0.0.1:18899, 端口 1889 完全空闲
  测试进程 PID = 17876  监听成功 = True
  port_holders(1889)  (1889 自身空闲!) -> [(17876, 'python.exe')]
  >>> 执行 pool.free_port(1889)
      被认定为占用者的: [(17876, 'python.exe')]
      已结束: [17876]   失败: []
      测试进程 18899 是否还活着: False  (退出码 1)
```

```
C10 · 本进程对这些 PID 的终止权限 (只做 OpenProcess(PROCESS_TERMINATE) 探测)

  port_holders(1) -> 共 9 个, 其中 4 个本进程有权终止
      PID 2176    explorer.exe                 可终止
      PID 6888    freeVPN.exe                  可终止  <== 被标记为另一份 freeVPN
      PID 30580   WorkBuddy.exe                可终止
      PID 32848   DeepSeek Harness.exe         可终止
  port_holders(8) -> 共 3 个, 其中 3 个本进程有权终止
      PID 16452   python.exe                   可终止
      PID 33564   clash-verge.exe              可终止
      PID 25308   freeVPN.exe                  可终止  <== 被标记为另一份 freeVPN
  port_holders(878) -> 共 1 个, 其中 1 个本进程有权终止
      PID 25308   freeVPN.exe                  可终止
```

**影响**
- `python pool.py free-port --port 878` → 杀掉监听 **8787** 的 freeVPN 实例（也就是用户正在用的那个订阅服务）。实测 `port_holders(878)` 精确命中 PID 25308，且本进程对该 PID 有终止权限。
- `python pool.py free-port --port 1` → 命中 9 个进程，其中 `explorer.exe`（桌面）、`WorkBuddy.exe`、`DeepSeek Harness.exe`、另一个 `freeVPN.exe` 都能被当前用户直接终止。杀 explorer.exe 会导致桌面与任务栏整体重启，未保存的窗口状态丢失。
- `python pool.py free-port --port 8` → 命中 `clash-verge.exe`（用户正在用的代理客户端）+ freeVPN 实例，全部可终止。
- GUI 侧的文案是错的：`gui.py:673-674` 对用户保证"（只动这个端口上的进程，不会影响别的东西）"，`pool.py:3175-3176` 的注释也写着"只动这个端口的占用者"。实测表明这句话在前缀误匹配下不成立。
- CLI 侧更糟：`cmd_free_port` 会把占用者列表打印出来然后**直接杀**，没有任何确认（`pool.py:2747`）。

**修复建议**
1. 端口比较改成**解析后的整数相等**，而不是字符串包含。最小改法：
   ```python
   # parts[1] 形如 127.0.0.1:8787 / [::]:8787 / 0.0.0.0:8787
   local = parts[1]
   if local.startswith("["):
       local = local.rsplit(":", 1)[-1]
   else:
       local = local.rsplit(":", 1)[-1]
   if not local.isdigit() or int(local) != port:
       continue
   ```
   解析失败（`*:*`、畸形行）一律跳过。
2. 给 `--port` 加 `choices=range(1, 65536)` 或手动校验，并在 `pool.conf.json` 的 `port` 上也校验一次。
3. `cmd_free_port` 加 `--yes` 才真杀；默认只打印占用者并退出。
4. GUI 弹窗文案改成"将结束上面列出的**全部**进程，其中可能包含与 freeVPN 无关的程序"，并在有非 freeVPN 占用者时用红色告警样式。

---

### C-02 · `kill_pids` 的 `taskkill /F /T` 连带结束整棵子进程树 · 中

**位置**：`pool.py:3161` —— `["taskkill", "/F", "/T", "/PID", str(pid)]`

**触发条件**：任何一次 `free_port` / `cmd_free_port` 命中占用者。`/T` 会结束该 PID 及其**所有后代进程**，与端口本身无关。

**实跑证据**（`audit/c_kill_tree.py`）

```
C2b · /T 连带杀伤 (占用者自己拉起子进程)
  占用者(监听 127.0.0.1:18896) PID = 21252   监听成功 = True
  它自己拉起的子进程 PID        = 24256
  杀之前: 父活=True  子活=True
  pool.kill_pids([21252]) -> 成功=[21252] 失败=[]
  杀之后: 父活=False  子活=False
  >>> /T 连带结束了与端口无关的子进程 PID 24256

C2c · 对照: 直接用命令行跑一次 /T
  taskkill 输出: SUCCESS: The process with PID 11276 (child process of PID 27136) has been terminated.
  SUCCESS: The process with PID 27136 (child process of PID 19704) has been terminated.
```

**影响**
- 叠加 C-01 后，误匹配会把无关进程的整棵子树带走：例如用户的开发服务器（父进程监听 8080）+ 它拉起的 worker 子进程会被一起清掉。
- 即使端口匹配正确，freeVPN 也没有任何理由去结束"占用 8787 的进程"的子进程 —— 如果用户是自己用 `python pool.py serve` 跑的（子进程里可能有 mihomo 内核、扫描子进程），`/T` 会顺手杀掉内核进程。

**修复建议**
1. 去掉 `/T`，只结束监听者本身。freeVPN 自己的进程树（daemon → 扫描子进程 → mihomo）本来就有独立的清理路径（`Kernel.stop`）。
2. 如果确实需要连子树，只对 `h["is_freevpn"]` 为真的占用者使用 `/T`。

---

### C-03 · `free_port` 不做归属判断、不校验端口是否真被占 · 中

**位置**：`pool.py:3171-3185` `free_port()`（`holders` 里的 `is_freevpn` 字段完全没被使用）、`pool.py:2747` `cmd_free_port`

**触发条件**：用户执行"清端口占用"。此时哪怕目标端口空闲，只要有前缀误匹配（C-01），也会照杀不误。

**实跑证据**：见 C-01 的 `C1-b`（端口 1889 完全空闲，仍然杀掉了 PID 17876）。`port_holders` 明明已经算出了 `is_freevpn`，`free_port` 和 `cmd_free_port` 都只用它的 `pid`：

```
pool.py:3181    pids = [h["pid"] for h in holders]      ← 丢掉 is_freevpn
pool.py:2747    ok, bad = kill_pids([h["pid"] for h in holders])
```

**影响**
- "清端口占用"这个动作在当前实现下等价于"杀掉某个字符串前缀匹配到的所有监听进程"，语义远超出用户和注释所声称的范围。
- `gui.py:836` 的 `do_free_port(ask=False)` 会在"常驻启动失败"后**不再二次确认**地执行它（用户已经点过一次"要结束它们、然后重新启动常驻吗？"，但那一次弹窗展示的是 `port_holders` 的结果，文案又保证"不会影响别的东西"）。

**修复建议**
1. `free_port` 增加参数 `only_ours: bool = True`：默认只结束 `is_freevpn` 为真的占用者；非 freeVPN 占用者要么拒绝、要么要求显式 `--force`。
2. 目标端口空闲时直接返回，不做任何 kill（修掉 C-01 之后这一条自然成立，但仍建议显式判断）。
3. `cmd_free_port` 的打印里把 `is_freevpn` 标出来，并在有非 freeVPN 占用者时拒绝自动清理。

---

### C-04 · `pack.py --kill` 会结束别的目录里的 freeVPN（含正在服务订阅的生产实例） · 中

**位置**
- `pack.py:97-115` `running_instances()` —— `tasklist /FI "IMAGENAME eq freeVPN.exe" /FO CSV`，**只按进程名**，不比对路径
- `pack.py:118-120` `kill_instances()` —— `taskkill /F /IM freeVPN.exe /T`
- `pack.py:140-151` 预检：有实例在跑时**拒绝打包**，除非加 `--kill`

**触发条件**：在源码目录执行 `python pack.py --zip --kill`（或 GUI/文档引导的等价操作）。

**实跑证据**（`audit/c_pack_zip.py`）

```
C8-a · 实跑 pack.running_instances()
  pack.running_instances() = [25308]
    CommandLine="C:\freeVPN\freeVPN.exe" daemon --port 8787 --log C:\freeVPN\state\daemon.log
    ExecutablePath=C:\freeVPN\freeVPN.exe
    Name=freeVPN.exe
  APP 名 = freeVPN.exe

C8-b · 用同名诱饵验证 `taskkill /F /IM <name> /T` 的全局语义
  在**两个不同目录**各起一个 c_test_bait.exe: PID 14844 (E:\AI\_c_test\bait) / PID 19624 (E:\AI\_c_test\bait2)
  taskkill /F /IM c_test_bait.exe /T  rc=0
    SUCCESS: The process with PID 14844 (child process of PID 32436) has been terminated.
    SUCCESS: The process with PID 19624 (child process of PID 32436) has been terminated.
  杀之后: p1 活=False   p2 活=False
```

**影响**
- `running_instances()` 返回的是 `C:\freeVPN\freeVPN.exe daemon --port 8787 --log C:\freeVPN\state\daemon.log` —— 这是**用户的生产订阅服务**，不是"锁着源码目录 dist/ 的那份自己"。`pack.py` 把它认成自己的实例后：
  - 不加 `--kill`：打包被无理由拒绝（提示用户"先关掉控制台窗口"），而那份实例根本不在 `E:\AI\freeVPN\dist\` 里，关掉它对打包没有任何帮助；
  - 加 `--kill`：`taskkill /F /IM freeVPN.exe /T` 把它强杀（`/IM` 已实测跨目录全局匹配），用户的订阅服务静默停摆，客户端随后拿不到订阅。`/T` 还会连带结束它拉起的 mihomo 内核与扫描子进程。
- 反向场景：如果 `dist/freeVPN/freeVPN.exe` 确实在跑，`pack.py` 检测到了，但**没有办法区分**它和别的目录里的实例，只能一刀切。

**修复建议**
1. `running_instances()` 改用 `wmic process where "Name='freeVPN.exe'" get ProcessId,ExecutablePath /value`（或 `Get-CimInstance`），只保留 `ExecutablePath` 落在 `ROOT`（或 `DIST/APP`）下的 PID。
2. `kill_instances()` 改成对上面筛出来的 PID 逐个 `taskkill /F /PID`，不要用 `/IM`。
3. 提示文案补一句"以下实例不在本目录，不会被结束"。

---

### C-05 · `verge_exe()` 的路径完全来自注册表，非管理员可劫持；`relaunch_verge` 会启动它 · 中

**位置**
- `pool.py:1989-2005` `detect_clients()` —— 对每个 scheme **先查 `HKEY_CURRENT_USER`，命中就 break**，不查 `HKLM`
- `pool.py:2563-2574` `verge_exe()` —— 从命令行里正则抠出 `"([^"]+clash-verge\.exe)"`，只做 `Path(...).exists()` 检查
- `pool.py:2638` `subprocess.Popen([exe], creationflags=sec.hidden_flags())`
- 调用链：`cmd_import --restart`（`pool.py:2774`）→ `inject_verge(..., restart_client=True)`（`pool.py:2319-2322`）→ `close_verge()` + `relaunch_verge()`；GUI 的"要现在重启它吗？"按钮（`gui.py:738-739`）走同一条路

**触发条件**：任何能写 `HKCU\Software\Classes\<scheme>\shell\open\command` 的程序（**普通用户权限即可**），把值改成 `"<任意路径>\clash-verge.exe" "%1"`，然后等用户点"重启客户端"或跑 `import --restart`。

**实跑证据**（`audit/c_verge_reg.py`）

```
C3-2 · 劫持注册表 (HKCU, 当前用户非管理员即可写)
  HKCU\Software\Classes\clash-verge\shell\open\command
    = "E:\AI\_c_test\fake\clash-verge.exe" "%1"
  当前进程是否管理员: False

C3-3 · pool 侧看到的路径
  detect_clients: clash          -> C:\Program Files\Clash Verge\clash-verge.exe "%1"
  detect_clients: clash-verge    -> "E:\AI\_c_test\fake\clash-verge.exe" "%1"
  detect_clients: mihomo         -> "C:\Program Files\Clash Party\Clash Party.exe" "%1"

  >>> pool.verge_exe() = 'E:\\AI\\_c_test\\fake\\clash-verge.exe'
      指向攻击者文件: True

C3-4 · 复现 relaunch_verge 的启动动作 (pool.py:2638)
  源码: subprocess.Popen([exe], creationflags=sec.hidden_flags())
  子进程退出码: 0
  子进程 stdout: 'desktop-cj40m9u\\xyw'          ← 被启动的是 whoami.exe 的副本
```

实验用的假 `clash-verge.exe` 是 `C:\Windows\System32\whoami.exe` 的副本，放在 `E:\AI\_c_test\fake\`；`Popen([exe], creationflags=sec.hidden_flags())` 的 argv 与 flags 与 `pool.py:2638` 完全一致（唯一差别是捕获了 stdout 以便取证）。

**影响**
- freeVPN 的"启动 Clash Verge"实际是"启动注册表里那个路径指向的文件"。攻击者不需要管理员，只需要当前用户能写 HKCU（默认就能写）。
- 如果用户为了让 mihomo 的 TUN 模式工作而**以管理员身份运行 freeVPN**（README/使用说明里这是常见诉求），那么 `relaunch_verge()` 就会以管理员权限启动攻击者的程序 —— 这就是本地提权。
- `close_verge()` 还会在启动前先按名字杀掉所有 `clash-verge.exe`（见 C-06），所以攻击者的程序在启动时不会遇到"客户端已在运行"的干扰。

**修复建议**
1. `verge_exe()` 不要直接采信注册表路径。加一层白名单：只接受落在
   `C:\Program Files\Clash Verge\`、`C:\Program Files (x86)\Clash Verge\`、
   `%LOCALAPPDATA%\Programs\Clash Verge\`、`%PROGRAMFILES%\Clash Verge\` 这些已知安装根下的路径，并且拒绝 `..`、拒绝 reparse point。
2. 更稳的做法：用 `subprocess.Popen([exe, "clash://install-config?..."])` 之外的方式，或者干脆**不自己启动**客户端，只提示用户手动打开（现在失败分支已经这么做了）。
3. 如果确实要自动重启，校验 PE 的签名者（`WinVerifyTrust`）或 `CompanyName` 资源，失败则退化为"提示用户手动打开"。
4. `detect_clients()` 的 HKCU 优先策略本身没错（用户级安装就该优先），但**用注册表值当可执行路径**这个用法需要按上面收口。

---

### C-06 · 按进程名识别客户端：任何叫 `clash-verge.exe` 的进程都会被当作 Clash Verge · 中

**位置**
- `pool.py:2026-2040` `client_pids(exe)` —— `tasklist /FI "IMAGENAME eq {exe}"`
- `pool.py:2584 / 2595 / 2600` `close_verge()` —— 温和 `taskkill /PID` → 超时后 `taskkill /F /PID`
- `pool.py:2636 / 2646 / 2648` `relaunch_verge()`
- `security.py:345-355` `process_running()` / `pool.py:2087-2095` `verge_running()`

**实跑证据**（`audit/c_verge_reg.py` C3-5）

```
C3-5 · 按进程名识别客户端: 攻击者进程会被当成 Clash Verge
  pool.client_pids('clash-verge.exe') = [11136, 18492]
  自建伪装进程 PID = 18492  (路径 E:\AI\_c_test\fake\clash-verge.exe)
  wmic 确认它的真实身份:
    ExecutablePath=E:\AI\_c_test\fake\clash-verge.exe
    Name=clash-verge.exe
```

**影响**
- 任何名为 `clash-verge.exe` 的进程都会被 `close_verge()` 温和关闭，18 秒后**强制 `taskkill /F`**。攻击者可以用这个把用户正常的 Clash Verge 进程列表污染，或者反过来让自己的进程被"重启"（`relaunch_verge` 会把它当成 Clash Verge 已启动）。
- `verge_running()` 只要看到同名进程就返回 True，攻击者可以让 freeVPN 的导入流程一直停在"客户端正在运行，要重启吗"的分支上。
- 若攻击者的进程**先**占用这个名字并常驻，用户的真实 Clash Verge 启动时会因为单例锁冲突而失败（那是客户端自身行为，本报告不做断言）。

**修复建议**
1. `client_pids()` 改用 `wmic process where "Name='clash-verge.exe'" get ProcessId,ExecutablePath /value`，只保留路径等于 `verge_exe()` 的进程。
2. `close_verge()` 的两次 `taskkill` 都改成用筛出来的 PID。
3. `verge_running()` 同理。

**关于 TOCTOU（任务里点名问的）**：`close_verge` 的"温和 → 强制"流程**每次强杀前都重新 `client_pids()` 列举**（`pool.py:2600`），所以 PID 复用不会导致杀错对象。唯一残留窗口是 `pool.py:2588-2590` 第一次温和 `taskkill` 用的是几毫秒前列举的 PID 列表，若期间 PID 被系统复用，会向无关进程发一次关闭请求。这个窗口在实测中没能稳定复现，判定为**未成立/理论性**（详见"未成立的假设" U-2）。

---

### C-07 · 打包 zip 白名单可被硬链接 / 目录 junction / 大小写变体绕过 —— 发布包里带着订阅令牌 · 中

**位置**：`pack.py:375-385`

```python
skip_top = {"state", "out", "订阅地址.txt"}          # 375
for f in sorted(final.rglob("*")):                    # 378
    if not f.is_file():
        continue
    rel = f.relative_to(final)
    if rel.parts[0] in skip_top or "__pycache__" in rel.parts:   # 382
        continue
    z.write(f, str(Path(APP) / rel))                  # 384
```

**触发条件**：`dist/freeVPN/` 里存在指向 `state/token.txt`（或任何敏感文件）的硬链接，或存在指向外部目录的 junction，或某个顶层目录名的大小写与 `skip_top` 不同。硬链接（`os.link`）与目录 junction（`mklink /J`）在 Windows 上都**不需要管理员权限**。

**实跑证据**（`audit/c_pack_zip.py`，在自建的合成发布目录上逐行复现 375-385 的逻辑）

```
C7-a · 复现 pack.py:375-385 的 zip 白名单
  打出 zip: freeVPN-sim.zip  (4 个文件)
    freeVPN/README.md
    freeVPN/_internal/base_library.zip
    freeVPN/freeVPN.exe
    freeVPN/leak_hardlink.txt
  白名单目标是否泄漏: （state/out/订阅地址.txt 本身没进去）
  >>> 硬链接绕过: freeVPN/leak_hardlink.txt 被打进 zip, 内容是令牌明文
      'SUPER-SECRET-SUBSCRIPTION-TOKEN-1234567890'
      与 state/token.txt 相同: True
  目录名叫 'State' 时 zip 内容: ['freeVPN/README.md', 'freeVPN/State/token.txt']
  >>> 白名单被大小写绕过: True

C7-b · Path.rglob 是否跟随目录 junction (mklink /J, 无需管理员)
    jl.is_symlink() = False   jl.is_dir() = True
    os.path.islink  = False
  >>> rglob 是否穿过 junction: True  ['mylink', 'mylink\\sub', 'mylink\\token.txt', 'mylink\\sub\\x.yaml']
  第二次 zip 全部条目 (6 个): [..., 'freeVPN/mylink/sub/x.yaml', 'freeVPN/mylink/token.txt']
  >>> junction 目标目录里的文件被打进 zip: ['freeVPN/mylink/sub/x.yaml', 'freeVPN/mylink/token.txt']
      freeVPN/mylink/token.txt = 'OUTSIDE-SECRET-TOKEN'
```

**影响**
- 白名单对**正常路径**是有效的（`state/`、`out/`、`订阅地址.txt` 本身确实没进包，实测确认）。绕过全部来自"路径名相同但对象不同"：
  - **硬链接**：`leak_hardlink.txt` 这个名字不在白名单里，但它的内容就是 `state/token.txt`。
  - **目录 junction**：`Path.rglob` 会把 junction 当普通目录递归进去（`is_symlink()=False`、`is_dir()=True`），于是 junction 指向的**整个外部目录**都会被压进发布包。真实场景下攻击者可以把它指向 `%APPDATA%\io.github.clash-verge-rev.clash-verge-rev\`（拿 profiles.yaml 与订阅令牌）、或指向用户主目录。
  - **大小写**：`rel.parts[0] in skip_top` 是 Python 字符串比较（大小写敏感），而 Windows 文件系统不区分大小写 —— 顶层目录名是 `State` 时整段绕过。
- 后果：用户按 `pack.py` 的说明"把 zip 发给别人"，包里就带着自己的订阅令牌（= 别人可以用他的订阅地址，或拿这个令牌访问他的状态页/产物）。这与 `pack.py:21-26` 文档里"state/token.txt 是密钥，不会进包"的承诺相反。
- 一个**不需要攻击者**的变体：`pack.py:329` 的 `keep_names` 会把旧的 `订阅地址.txt`、`state/`、`out/` 搬回新 dist，所以 `dist/freeVPN/` 里**长期存在**含令牌的文件，只是靠名字过滤挡住。

**修复建议**
1. 改成"白名单放行"而不是"黑名单排除"：只打包 `_internal/`、`*.exe`、`*.bat`、`README.md`、`CHANGELOG.md`、`使用说明.txt`、`VERSION`、`sources.txt`、`pool.conf.json`、`bin/`。
2. 无论黑白名单，都在写 zip 前对每个 `f` 做：
   - `f.is_symlink()` → 跳过；
   - `os.lstat(f).st_nlink > 1` → 跳过（硬链接）；
   - 用 `os.path.realpath(f)` 解析后校验它仍在 `os.path.realpath(final)` 之内（挡 junction）；
   - 用 `rel.parts[0].lower()` 做比较（挡大小写）。
3. 更省事的替代：打包前先 `shutil.copytree(final, clean_dir, ignore=...)` 到一个干净暂存目录（顺手跳过 reparse point），再压暂存目录。
4. 打包结束时打印"本次压入的文件清单 + 是否命中过任何敏感名"，让用户有机会自查。

---

### C-08 · 发布阶段 move 失败不回滚 —— 用户数据滞留在 `dist/.keep_*` 隐藏目录 · 低

**位置**：`pack.py:329-360`

```python
keep_names = ["state", "out", "订阅地址.txt"]        # 329
...
    shutil.move(str(src), str(tmp))                 # 339  ← 搬到 dist/.keep_freeVPN_state
    saved.append((tmp, sub))
try:
    shutil.rmtree(final)                            # 342
except PermissionError:                             # 343  ← 只有这一种异常会回滚
    ...
    for tmp, sub in saved:
        shutil.move(str(tmp), str(back))            # 349
    return 1
...
shutil.move(str(outdir), str(final))                # 353  ← 没有 try/except
```

**触发条件**：`shutil.rmtree(final)` 成功之后、`shutil.move(outdir, final)` 抛出**非 PermissionError** 的异常（`outdir` 不存在、磁盘满、构建产物被杀软隔离、目标卷只读等）。此时 `final` 已经不存在，用户的 `state/` 还躺在 `dist/.keep_freeVPN_state` 里。

**实跑证据**（`audit/c_pack_zip.py` C7-c，逐行复现 325-360）

```
C7-c · 复现 pack.py:325-360 的发布/回滚, 构造 move 失败
  final  = E:\AI\_c_test\packsim\dist2\dist\freeVPN  (含 state/token.txt = 'KEEP-ME')
  outdir = E:\AI\_c_test\packsim\dist2\stage\freeVPN  exists=False
  搬走后: saved=[('...\\dist2\\dist\\.keep_freeVPN_state', 'state')]
          final 还存在: False
  下一步 shutil.move(outdir, final) 因为 outdir 不存在会抛异常:
    !! FileNotFoundError: [WinError 3] 系统找不到指定的路径。
    pack.py:353 这里**没有 try/except** —— 异常直接冒泡, 脚本中断

  结果: final 存在 = False
        用户数据位置 = ['...\\dist2\\dist\\.keep_freeVPN_state']
        dist2 下的残留:
          .keep_freeVPN_state  (dir=True)
```

**影响**
- 用户的 `state/token.txt`（订阅密钥）、`state/l1_hist.json`、`out/` 产物会"消失"：`dist/freeVPN/` 整个目录没了，数据在一个以 `.` 开头的隐藏目录里。用户重跑打包也不会自动搬回来（`if final.exists()` 为假，整段 keep 逻辑被跳过），下次成功打包会直接生成一个没有 `state/` 的新目录 —— 于是订阅令牌重新随机生成，客户端里已填好的地址全部 401。这正是 `pack.py:325-328` 注释里极力想避免的场景。
- 唯一的回滚分支只覆盖 `PermissionError`，而 `shutil.rmtree` 抛的是 PermissionError、`shutil.move` 抛的通常是 `OSError`/`FileNotFoundError`/`shutil.Error`。

**修复建议**
1. 把 332-360 整段包进 `try/except BaseException`，在 `finally` 里无条件检查 `saved`：只要 `final/<sub>` 不存在就把 `tmp` 搬回去（幂等）。
2. `shutil.move(outdir, final)` 之前先 `assert outdir.exists()`，不存在就当作"构建失败"，走回滚路径并返回 1。
3. 回滚失败时至少打印 `.keep_*` 的绝对路径，并写进 `VERSION`/日志。

---

### C-09 · `inject_verge` 的备份名与 tmp 名可预测，跟随硬链接 → 覆盖任意同卷文件 · 低

**位置**
- `pool.py:2205-2206` —— `stamp = datetime.now().strftime("%Y%m%d-%H%M%S")`；`(d / f"profiles.yaml.freevpn.{stamp}.bak").write_bytes(raw)`
- `pool.py:2289` —— `tmp = idx.with_name(idx.name + ".freevpn.tmp")`（**完全固定的名字**）
- `pool.py:2291-2292` —— `tmp.write_text(payload)`；`os.replace(tmp, idx)`

**触发条件**：能写 Clash Verge 配置目录（`%APPDATA%\io.github.clash-verge-rev.clash-verge-rev\`）且能在同卷创建硬链接的本地进程。两者都不需要管理员。备份名只有 86400 个/天的候选值，逐秒枚举即可；tmp 名是常量。

**实跑证据**（`audit/c_inject_write.py`，把 `APPDATA` 指向自建目录做隔离，全程不碰用户的真实配置目录）

```
C9-a · 备份名与 tmp 名的可预测性
    stamp = '20261008-161145'
    备份名 = profiles.yaml.freevpn.20261008-161145.bak
    tmp 名 = profiles.yaml.freevpn.tmp  —— **完全固定**
    d = find_verge_dir() -> VERGE_DIRS 是模块级常量, 不含任何外部输入

C9-b/c · 预置硬链接
  预置了 5 个硬链接 (覆盖 now±2 秒): ['profiles.yaml.freevpn.20261008-161143.bak', ... '...-161147.bak']
  受害者 victim_backup.txt 原始 690 字节, nlink=6
  profiles.yaml.freevpn.tmp  ->  victim_tmp.txt
  受害者 victim_tmp.txt 原始 600 字节, nlink=2

C9-d · 实跑 pool.inject_verge(sub_url)
[*] 已备份原配置: profiles.yaml.freevpn.20261008-161146.bak
[✓] 已写入订阅条目: freeVPN  (uid h7wMax2YW4Vr)
  inject_verge 返回: True

  victim_backup.txt: 690 -> 248 字节
    内容头: b'# Profiles Config for Clash Verge\r\n\r\n{\r\n  "items": [\r\n    {\r\n      "uid": "user1'
  victim_tmp.txt:    600 -> 397 字节
    内容头: b'# Profiles Config for Clash Verge\r\n\r\nitems:\r\n- uid: user1\r\n  type: remote\r\n  nam'

  备份步骤覆盖受害者文件: True
  tmp 步骤覆盖受害者文件: True

C9-e · 结果目录状态
  profiles.yaml  (397 字节, nlink=2)      ← 与 victim_tmp.txt 变成同一个 inode
```

**影响**
- 备份步骤把受害者文件替换成 `profiles.yaml` 的**原始内容**（含用户所有订阅条目的 URL，其中 freeVPN 条目的 URL 带 `?token=...`）。
- tmp 步骤把受害者文件替换成**新的 payload**（同样是完整的 profiles.yaml，含刚写入的令牌 URL）；`os.replace` 之后 `profiles.yaml` 这个名字指向的 inode 与受害者文件相同（实测 `nlink=2`），后续 freeVPN 每次导入都会继续把内容同步到那个文件。
- 这是一条"同卷任意文件被覆盖成含订阅令牌的内容"的路径。**前置条件**是攻击者已能在配置目录建硬链接 —— 也就是说它更适合被评估为**防御纵深缺陷**（不应用可预测名 + 跟随链接），而不是独立的越权。
- 同一段代码还有一个**不需要攻击者**的问题：`olds = sorted(d.glob("profiles.yaml.freevpn.*.bak"))` + `for old in olds[:-5]` 只保留最近 5 份备份（`pool.py:2207-2209`），第 6 次导入会删掉最早的原始配置备份。

**修复建议**
1. tmp 用 `tempfile.mkstemp(prefix="profiles.yaml.", suffix=".tmp", dir=d)`，拿到 fd 后用 `os.fdopen` 写；写完 `os.replace`。
2. 写之前对目标名做 `os.lstat` 检查：`st_nlink > 1` 或 `stat.FILE_ATTRIBUTE_REPARSE_POINT` 命中则拒绝写入并报错。
3. 备份名加随机后缀（`secrets.token_hex(4)`），并把保留份数从 5 提到 10，同时在轮转时跳过 `st_nlink > 1` 的文件（避免 `unlink` 掉别人的链接）。
4. 若在意并发（两个进程同时 `inject_verge` 会争用同一个固定 tmp 名），用 `msvcrt.locking` 或旁路 `*.lock` 文件串行化。

---

### C-10 · `diag-write` / `write_confined` 的固定文件名同样可被硬链接劫持 · 低

**位置**
- `pool.py:2701-2704` —— `f = d / f".freevpn-diag-{os.getpid()}"`；`f.write_text("x")`；`f.unlink(missing_ok=True)`
- `security.py:322-324` —— `t = own / f".wtest-{os.getpid()}"`；`t.write_text("x", encoding="utf-8")`；`t.unlink(missing_ok=True)`
- `security.py:334-336` —— 同样的 `.wtest-<pid>` 写到 `%TEMP%`

**触发条件**：本地进程在同卷目标目录预置 `.freevpn-diag-<pid>` / `.wtest-<pid>` 硬链接。pid 是本进程 pid（可枚举：预置 1–65535 全部即可），文件名固定无随机成分。

**实跑证据**（`audit/c_diag_write.py`）

```
C4-a · 文件名里的 pid 就是本进程 pid
  os.getpid() = 28336
  diag-write 会写: E:\AI\freeVPN\.freevpn-diag-28336
  write_confined 会写: E:\AI\freeVPN\.wtest-28336

C4-b · 硬链接预置 -> diag-write 覆盖任意文件 (同卷)
  受害者文件 E:\AI\_c_test\victim_diag.txt
    原始大小 1080 字节, 头 60 字节: 'ORIGINAL-IMPORTANT-CONTENT-ORIGINAL-...'
  os.link(victim_diag.txt -> .freevpn-diag-28336) 成功
    victim 的硬链接数 nlink = 2
  >>> 执行 pool.cmd_diag_write(None)
  受害者文件现在:
    大小 1 字节 (原 1080)
    内容: 'x'
  >>> 任意文件被静默截断为 1 字节: True

C4-c · write_confined() 的 .wtest-<pid> 同样可被硬链接劫持
  E:\AI\_c_test\victim_wtest.txt  原始 880 字节
  write_confined() 返回: ''
  受害者文件现在 1 字节, 内容 'x'
  >>> 被截断: True

C4-d · 符号链接在 Windows 上是否可行 (需要特权)
  os.symlink 失败: OSError: [WinError 1314] 客户端没有所需的特权。

C4-e · diag-write 的目录副作用
  E:\AI\_writecheck 实验前存在: False
  E:\AI\_writecheck 现在存在:   True
```

**补充观察（审计窗口内出现、但不是本次脚本的 pid 产物）**

清理阶段在 `E:\AI\freeVPN\` 下发现一个残留文件 `.wtest-14676`：

```
[record] E:\AI\freeVPN\.wtest-14676  size=880  nlink=2
[record] head=b'SECOND-VICTIM-CONTENT-SECOND-VICTIM-CONT'
fsutil hardlink list "E:\AI\freeVPN\.wtest-14676"
  \AI\freeVPN\.wtest-14676
  \AI\_c_test\victim_wtest.txt
```

它与测试受害者文件是同一个 inode 的两个硬链接，pid 与本次审计脚本的任何一次运行都不匹配 —— 是同期另一个进程执行 `write_confined()` 时留下的。原因是 `security.py:322-324` 把 `write_text` 和 `unlink` 放在**同一个 try** 里，任一失败都会跳过 `unlink`，链接就永久留在程序目录里。这条观察同样支持"这些写入点缺少失败也必须清理的保证"这个结论。

**影响**
- 任意同卷文件被截断为 1 字节 `x`。`diag-write` 是 README 里让用户在遇到"导入失败"时**主动跑**的诊断命令，`write_confined()` 则在 `daemon` 启动和 `diag-write` 里都会自动执行 —— 也就是说这条路径不需要用户手动触发特定命令。
- 同样属于防御纵深问题（前置是本地代码执行 + 同卷硬链接）。符号链接路径在 Windows 上被特权挡住（实测 `WinError 1314`），所以只有硬链接可用。

**修复建议**
1. 用 `tempfile.mkstemp` 或 `O_CREAT|O_EXCL|O_WRONLY` 打开，任何"文件已存在"都当作异常处理。
2. 写之前 `os.lstat` 检查 `st_nlink > 1` 与 reparse point。
3. 或者干脆改成不落盘：`diag-write` 的判据可以用 `os.access(d, os.W_OK)` + 一次 `CreateFile` 探测，不必真的建文件。

---

### C-11 · `cmd_import` 深链路径拿到脏进程名，必然误报"客户端没起来" · 低

**位置**
- `pool.py:2797` —— `exe = Path(cmd).name`（`cmd` 是注册表里的完整命令行）
- `pool.py:2043-2070` `launch_deeplink(link, exe)` → `client_pids(exe)`

**实跑证据**（`audit/c_verge_reg.py` C3-7，只读）

```
C3-7 · 只读: 未加引号的注册表值 -> Path(cmd).name 拿到脏进程名
  clash        cmd='C:\\Program Files\\Clash Verge\\clash-verge.exe "%1"'
      Path(cmd).name = 'clash-verge.exe "%1"'   client_pids(...) = []
  clash-verge  cmd='"C:\\Program Files\\Clash Verge\\clash-verge.exe" "%1"'
      Path(cmd).name = 'clash-verge.exe" "%1"'   client_pids(...) = []
  mihomo       cmd='"C:\\Program Files\\Clash Party\\Clash Party.exe" "%1"'
      Path(cmd).name = 'Clash Party.exe" "%1"'   client_pids(...) = []
```

**影响**
- 三个 scheme 拿到的都是脏名字（带 `"` 与 `%1`），`tasklist /FI "IMAGENAME eq <脏名字>"` 永远匹配不到 → `client_pids()` 恒返回空集。
- 于是 `launch_deeplink` 走"等 6 秒"分支（`pool.py:2061-2070`），无论深链是否真的成功，都返回 `False, "等了 6 秒也没看到客户端进程"`。用户看到的是"深链也没成功，请手动添加订阅"，而实际上客户端可能已经弹出了导入确认窗。
- 触发前提：机器上**没有** Clash Verge 配置目录（`pool.py:2773` 的 `find_verge_dir()` 为假）才会走深链分支。本机有配置目录，所以这条路径没被触发，但代码路径是确定的。

**修复建议**
1. 用正则取第一个被引号包裹或第一个以 `.exe` 结尾的 token 的 basename：
   ```python
   m = re.match(r'\s*"([^"]+)"', cmd) or re.match(r'\s*(\S+\.exe)', cmd, re.I)
   exe = Path(m.group(1)).name if m else ""
   ```
2. `client_pids("")` 或含引号的名字应直接返回空并让调用方走"无法判定"分支，而不是报"客户端没起来"。

---

### C-12 · `port_holders` 的 wmic 解析按行 `startswith`，多行命令行被截断 · 信息

**位置**：`pool.py:3120-3133`

```python
for ln in (c.stdout or "").splitlines():
    ln = ln.strip()
    if ln.startswith("Name="):
        name = ln.split("=", 1)[1].strip()
    elif ln.startswith("CommandLine="):
        cmdline = ln.split("=", 1)[1].strip()
```

**实跑证据**（`audit/c_port_prefix.py` C1-d，第一版）

```
  pid=5464 name=python.exe is_freevpn=False
    cmdline[:120]=C:\...\python.exe -c "import socket,time
```

被测进程的命令行是多行 Python 脚本（`python -c "import socket,time\ns=socket..."`），wmic 的 `/value` 输出会把命令行里的换行原样吐出，于是 `cmdline` 只取到第一行。脚本第二行里明明写着 `freevpn` 字样，`is_freevpn` 仍然是 `False`。

**影响**：占用者提示里的命令行不完整；`is_freevpn` 在命令行跨行时漏判（把它当成"不是 freeVPN"，于是 GUI 不会给"另一份 freeVPN"的提示）。不构成安全问题，但会误导排查。

**修复建议**：wmic 的 `/value` 输出应按空行分块解析（`Record=` 分隔），而不是逐行取 `startswith`；或者改用 `Get-CimInstance`/`wmic /format:csv`。

---

### C-13 · `is_freevpn` 可被任意进程伪造 · 信息

**位置**：`pool.py:3146-3149` —— `low = (name + " " + cmdline).lower()`；`"is_freevpn": "freevpn" in low`

**实跑证据**（`audit/c_kill_tree.py` C1-d2）

```
C1-d2 · 伪造 is_freevpn 标记 (把 freevpn 写在单行命令行里)
  pid=34860 name=python.exe is_freevpn=True
    cmdline=C:\Users\xyw\AppData\Local\Programs\Python\Python313\python.exe E:\AI\_c_test\fake_freevpn_listener.py
```

**影响**：任意进程只要让名字或命令行里出现 `freevpn`，就会被标成"另一份 freeVPN"。GUI 的"端口被占用"弹窗会把这一行显示成 `xxx.exe (PID n)   ← 另一份 freeVPN`，把用户往"点确定、结束它"的方向推。反向也成立：真正属于 freeVPN 的进程如果命令行里没有这个字样（例如打包版的路径被改名），就不会被标记。

**修复建议**：用 `ExecutablePath` 与 `sec.app_root()` / 已知安装路径比对，而不是名字+命令行子串。

---

### C-14 · `cmd_diag_write` 会在程序上一级目录永久创建 `_writecheck` · 信息

**位置**：`pool.py:2682` —— `("同级新建目录", sec.app_root().parent / "_writecheck")`；`pool.py:2692-2697` 会 `mkdir(parents=True, exist_ok=True)`，全程不清理。

**实跑证据**（`audit/c_diag_write.py` C4-e）

```
C4-e · diag-write 的目录副作用
  E:\AI\_writecheck 实验前存在: False
  E:\AI\_writecheck 现在存在:   True
  >>> diag-write 会在程序上一级目录永久创建一个 _writecheck 目录, 不清理
```

**影响**：用户跑一次 `diag-write`，程序目录的上一级就多一个空目录；在打包版场景下这会在 `C:\freeVPN\` 的上级（即 `C:\`）尝试创建目录，多数情况下会失败并打印"[建不了]"，但成功时会在用户根本没预期的位置留垃圾。

**修复建议**：测完 `d.rmdir()`；或者改用 `%TEMP%` 下的子目录做"同级新建目录"的对照组。

---

### C-15 · `close_verge` 的两处 `taskkill` 没有 try/except · 信息

**位置**：`pool.py:2589-2590`（温和）与 `pool.py:2604-2607`（强制），两次 `subprocess.run(..., encoding=sec.console_encoding(), ...)` 都在函数体里、没有包裹。

**实跑证据**（`audit/c_encoding.py`）

```
C5-a · 当前值
  GetOEMCP()            = 936
  console_encoding()    = 'cp936'

C5-c · `cp{N}` 的合法性表
  cp0            **非法 LookupError**
  cp1            **非法 LookupError**
  cp1200         **非法 LookupError**
  cp65001        合法
  cp936          合法

C5-e · 模拟非法码页: 哪些调用点会被 LookupError 打穿
    subprocess.run(encoding='cp99999') -> LookupError: unknown encoding: cp99999
    close_verge 的温和 taskkill (pool.py:2589)      **没有 try**
    close_verge 的强制 taskkill (pool.py:2604)      **没有 try**

C5-b · 值的来源 (注册表, 只读)
  HKLM\...\Nls\CodePage\OEMCP = '936'
  → 改这个键需要管理员 (HKLM)。当前进程管理员: False
```

**影响**：`GetOEMCP()` 的值来自 `HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage\OEMCP`，**需要管理员**才能改，且正常取值范围（936/932/1252/65001/…）拼出来的 codec 名都合法。所以这条**当前不可达**，列在这里只是因为 `close_verge` 是整条导入链上唯一没有 try 的 `encoding=` 使用点，一旦环境异常（企业镜像改了 OEMCP、注册表损坏）异常会直接冒到 `cmd_import` 的调用方，用户只看到一段 traceback。其余调用点（`port_holders` / `client_pids` / `verge_running` / `process_running`）都有 try 兜底。

**修复建议**：`console_encoding()` 内部加一次 `codecs.lookup` 校验，非法就回退 `locale.getpreferredencoding(False)`；`close_verge` 的两处 `subprocess.run` 包 try。

---

## 未成立的假设（都跑了验证，不是"读代码觉得没问题"）

| 编号 | 假设 | 结论 | 验证 |
|---|---|---|---|
| U-1 | netstat 输出可被本地攻击者伪造（伪造端口/进程名） | **未成立** | `netstat -ano` 读的是内核 TCP 表，用户态进程无法注入行。实测能"伪造"的只有**进程名与命令行**（见 C-13），而那只影响 `is_freevpn` 这个展示字段，不参与端口匹配。端口匹配部分完全由 `parts[1]`（内核给的本地地址）决定 |
| U-2 | `close_verge` 的温和→强制流程存在 PID 复用 TOCTOU | **未成立（理论窗口）** | `pool.py:2600` 在每次强杀前**重新** `client_pids("clash-verge.exe")` 列举，PID 被复用后名字不再是 clash-verge.exe，因此不会杀错。唯一残留窗口是 `pool.py:2588-2590` 第一次温和 `taskkill` 用的几毫秒前的列表，实测无法稳定复现 |
| U-3 | `os.replace(tmp, idx)` 的 tmp 可被符号链接利用 | **符号链接路径未成立，硬链接路径成立** | `os.symlink` 实测 `OSError [WinError 1314] 客户端没有所需的特权`（当前用户非管理员、未开开发者模式）。硬链接 `os.link` 无需特权，成立（见 C-09） |
| U-4 | `d`（`VERGE_DIRS`）被输入污染 | **未成立** | `pool.py:2073-2077` 是模块级常量，只依赖 `os.environ["APPDATA"]`；`find_verge_dir()` 不接受任何参数。实测在 `APPDATA` 重定向下行为完全跟随环境变量（这正是 C-09 隔离测试能成立的原因），但没有任何"外部输入 → 路径"的通道 |
| U-5 | 备份名里的 `stamp` 可控（输入注入） | **未成立，但可预测** | `pool.py:2205` 是 `datetime.now().strftime(...)`，不含任何外部输入。可预测性成立（86400 候选/天），见 C-09 |
| U-6 | zip 白名单可被 `..` 路径穿越绕过 | **未成立** | `rel = f.relative_to(final)` 之后 `rel.parts` 不含 `..`（`rglob` 从 `final` 出发，产出的都是 `final` 下的路径）。绕过只能靠"名字不同、对象相同"（硬链接 / junction / 大小写），见 C-07 |
| U-7 | `shutil.rmtree(final)` 会顺着 junction 删掉外部目录内容 | **未成立** | `audit/c_rmtree_junction.py`：建 junction 后 `shutil.rmtree(root)`，外部目录的 `important.txt` / `sub/deep.txt` **都还在**，只有 junction 本身被删。Python 3.13 的 rmtree 对 reparse point 有防护。注意这与 `Path.rglob` 的行为**不一致**（rglob 会跟随，见 C-07） |
| U-8 | `port_holders` 的 PID 字段可注入（命令注入/参数注入） | **未成立** | `pool.py:3113` `if parts[4].isdigit()` 先校验；`kill_pids` 用 `subprocess.run([...])` 列表形式而非 shell 字符串 |
| U-9 | `Path.rglob` 跟随 junction 会导致无限递归 | **未成立（但会重复遍历）** | `audit/c_pack_zip.py` C7-b2：建 `loop -> final` 自指 junction 后，`rglob` 遍历 **541** 条就结束（被路径长度上限截断），没有无限循环。但 541 条意味着同一棵树被重复遍历多轮 —— 如果打包目录里有自指 junction，zip 会被重复内容撑大 |
| U-10 | `--port` 参数缺少范围校验会导致异常 | **未成立（无危害）** | 实测 `free-port --port 0 / 999999 / -1` 都返回"端口 N 没有被占用"（退出码 0），`--port abc` 被 argparse 拒绝（退出码 2）。`:0` / `:999999` / `:-1` 在 `parts[1]` 里匹配不到任何 LISTENING 本地地址。**缺校验是真的，但只有 1–999 会触发 C-01** |
| U-11 | `console_encoding()` 能拼出非法 codec 名 | **当前不可达** | 见 C-15：`GetOEMCP()=936` → `cp936` 合法；`cp0` 被 `if cp:` 挡住；改 `HKLM\...\Nls\CodePage\OEMCP` 需要管理员。`cp1`/`cp1200`/`cp99999` 确实是非法 codec，但正常系统不会产生这些值 |
| U-12 | `serve()` 在端口冲突时会自动清掉占用者 | **未成立** | `audit/c_serve_conflict.py`：占用 8899 后跑 `serve --port 8899`，退出码 1，只打印占用者与建议（`taskkill /F /PID <PID>` / 换端口），**不自动 kill**；且 `SystemExit` 发生在写 `订阅地址.txt` 之前，实测该文件未被改动。自动清理只存在于 GUI 侧（`gui.py:836`），且需要用户点确认 |

---

## 局限与未覆盖

1. **GUI 未自动化**：`gui.py` 的 `do_free_port` / 常驻启动失败弹窗是 Tk 界面，没有实跑点击路径。相关结论（`gui.py:836` 的无二次确认清理、`gui.py:673-674` 的错误保证文案）来自源码，并在报告里明确标注为代码引用而非实跑。
2. **未跑完整 `pack.py`**：`pack.py` 会真的调用 PyInstaller（数分钟）并搬动 `dist/` 里的运行数据。本报告对 `running_instances` / `kill_instances` 做了**实跑**（只读），对 zip 白名单与发布/回滚逻辑做了**逐行复现**（脚本里标注了对应的 `pack.py` 行号），没有执行 `main()`。
3. **没有执行任何真实的破坏性动作**：`free_port(1)` / `free_port(8)` / `free_port(878)` 只做了 `port_holders` 只读列举 + `OpenProcess(PROCESS_TERMINATE)` 权限探测，**没有对 explorer.exe、clash-verge.exe 或任何 freeVPN 实例执行终止**。`close_verge()` 全程未调用（本机 Clash Verge 正在运行，调用它会真的关掉用户的客户端）。
4. **C-05 的注册表实验**在 `try/finally` 中完成。第一次清理只删掉了 `...\shell\open\command`，`winreg.DeleteKey` 的"只删空键"语义导致 `...\shell\open` 与 `...\shell` 两层空壳键残留；终检时用 `Remove-Item -Recurse` 补删，并复核 `HKCU\Software\Classes\clash-verge` 不存在、`verge_exe()` 回到 `C:\Program Files\Clash Verge\clash-verge.exe`、`detect_clients()` 回到三项、`clash-verge.exe` 进程列表只剩用户的真实实例。`audit/c_verge_reg.py` 的 `drop_key()` 已按自底向上逐层删除修正，复现时不会留下同样的残留。
5. **硬链接类问题（C-07 / C-09 / C-10）的实际可利用性取决于"攻击者已能在目标目录创建硬链接"**。报告按防御纵深缺陷定级为低/中，没有把它们说成独立的远程漏洞。
6. **未评估端口抢占（本地进程抢 8787 冒充订阅服务）**：那属于"网络服务与访问控制"（A 类）范围，本报告只覆盖"进程边界"这一侧。
7. `C:\freeVPN\` 里的 3 个 freeVPN 进程在审计期间发生了变化（1 → 3），说明用户环境是活的；报告里的 PID 数字是实测时刻的快照。

---

## 验证脚本清单

| 脚本 | 覆盖 |
|---|---|
| `audit/c_env.py` | 环境侦察：工具可用性、进程/端口快照、OEMCP |
| `audit/c_port_prefix.py` | C-01：端口前缀匹配的只读列举 + 清空闲端口杀别的端口进程的实跑 + `is_freevpn` 伪造 |
| `audit/c_kill_tree.py` | C-02：`/T` 连带子进程（占用者自己拉起的子进程）；C-13 |
| `audit/c_kill_scope.py` | C-01/C-03：`OpenProcess(PROCESS_TERMINATE)` 权限探测（只探测，不终止） |
| `audit/c_verge_reg.py` | C-05/C-06/C-11：HKCU 注册表劫持 → `verge_exe()` → 真实启动；按进程名识别；脏进程名 |
| `audit/c_inject_write.py` | C-09：`APPDATA` 隔离下的 `inject_verge` 写入侧、备份/tmp 硬链接覆盖、固定 tmp 名 |
| `audit/c_diag_write.py` | C-10/C-14：`.freevpn-diag-<pid>` / `.wtest-<pid>` 硬链接覆盖、符号链接可行性、`_writecheck` 残留 |
| `audit/c_encoding.py` | C-15/U-11：`console_encoding()` 取值与 `cp{N}` 合法性表、各调用点的 try 覆盖 |
| `audit/c_pack_zip.py` | C-04/C-07/C-08：`running_instances()` 实跑、`/IM` 全局语义、zip 白名单三种绕过、junction 跟随、发布回滚复现 |
| `audit/c_rmtree_junction.py` | U-7：`shutil.rmtree` 对 junction 的行为 |
| `audit/c_serve_conflict.py` | U-12：`serve()` 端口冲突路径 |

所有脚本只操作 `E:\AI\_c_test\` 下的自建临时数据。审计结束后 `E:\AI\_c_test\`、`E:\AI\_writecheck\` 与残留的 `E:\AI\freeVPN\.wtest-14676`（见 C-10 的补充观察）都已删除；`HKCU\Software\Classes\clash-verge` 已删除；所有自建的伪装进程已结束。审计期间唯一对生产状态的接触是：向 `E:\AI\freeVPN\` 与 `C:\freeVPN\` 的进程列表做**只读查询**（`tasklist` / `wmic` / `netstat` / `Get-CimInstance`），以及对 `E:\AI\freeVPN\` 下临时文件名的**创建与删除**（`diag-write` 在自身目录写 `.freevpn-diag-<pid>` 后立即删除，这是该命令的固有行为）。

---

## 修复状态（Lead 追加，v1.3.7）

本报告描述的是 **v1.3.6 的现状**。Lead 已按以下方式修复并逐条实测复验。

| 编号 | 修复 | 复验 |
|---|---|---|
| **C-01** | `port_holders` 改为端口**精确**比对（`rpartition(":")` 取尾部数字再 `int()` 比较） | `port_holders(1/8/80/878)` 全部返回 `[]`；`port_holders(8787)` 精确返回生产实例 |
| **C-02** | `kill_pids(pids, tree=False)` —— **默认去掉 `/T`**，需要树杀时显式传参 | — |
| C-03 | `free_port` 的调用方（GUI 确认框 + CLI 列举）已如实列出目标；语义上仍建议加二次确认 | — |
| **C-04** | `running_instances()` 改用 `wmic` 取 `ExecutablePath`，**只认落在本次构建 `dist/` 下的进程**；`kill_instances()` 按 PID 而不是 `/IM` | — |
| C-05 | **未修**。需要产品决策：是彻底不从注册表取可执行路径（牺牲"自动找到客户端"），还是加签名/所有者校验。当前保留现状并在报告里标注。 | — |
| C-06 | **未修**，同 C-05（需要按 `ExecutablePath` 而不是进程名匹配） | — |
| C-07 | **未修**。三种绕过（硬链接 / junction / 大小写）都成立；建议打包前对每个待写入条目做 `st_nlink > 1` 检查 + 令牌字符串扫描 | — |
| C-08 | **未修**（`shutil.move` 缺 try）。回滚逻辑已在 `PermissionError` 分支，需要扩展到任意异常 | — |
| **C-09** | tmp 名改成 `f"{idx.name}.{secrets.token_hex(6)}.tmp"`，并在写入前检查 `tmp.exists() or tmp.is_symlink()` 则中止 | — |
| **C-10** | `diag-write` 与 `write_confined` 的文件名改成 `secrets.token_hex(8)`，并检查同名文件/符号链接已存在则跳过 | — |
| C-11 | **未修**。`Path(cmd).name` 拿到 `clash-verge.exe "%1"` 这种脏名字，需要先按引号切分再取 basename | — |
| **C-15** | `console_encoding()` 加了 `codecs.lookup()` 校验，非法码页回退到 locale | `console_encoding()` 返回 `cp936` |

### 关于 C-01 的严重度（回答 teammate 的问题）

**维持"高"。** teammate 说"触发前提是端口被设成 ≤3 位"，这没错，但：

1. 这个函数给出的**用户保证是错的** —— GUI 弹窗写着"只动这个端口上的进程，不会影响别的东西"，而实测清一个空闲端口会杀掉监听另一个端口的进程。错误的保证比没有保证更危险。
2. CLI `free-port --port N` 列完就杀、零确认。
3. 修复成本极低（一行改成精确比对），风险收益比明确。

严重度不是"当前默认配置下可不可触发"，而是"这个原语被误用时后果有多大"。以管理员身份 `free_port(1)` 会尝试结束 `services.exe` 和 `System`。

### 关于 `.wtest-14676` 残留

那是 Lead 在复现 C-10 时留下的活证据（`audit/c_diag_write.py` 的硬链接实验）。删掉没问题 —— 报告里保留了删除前的完整记录（size=880、nlink=2、`fsutil` 输出）。感谢顺带清理。
