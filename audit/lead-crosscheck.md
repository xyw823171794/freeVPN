# Lead 交叉验证记录

审计轮次：v1.3.6（2026-10-08）
Lead 亲自跑的部分，与两个 teammate 的范围不重叠或做交叉验证。

---

## L-1 · 访问日志的令牌脱敏漏了路径段形式　【中】

**位置**：`pool.py` `make_handler` → `_log()`

**现状**：

```python
safe = re.sub(r"([?&](?:token|t)=)[^&\s]*", r"\1***", path)
```

handler 支持**四种**令牌投递方式（不同客户端习惯不同）：

| 形式 | 脱敏 |
|---|---|
| `?token=xxx` | ✅ `?token=***` |
| `?t=xxx` | ✅ `?t=***` |
| `Authorization: Bearer xxx` | ✅ 本来就不进 URL |
| **路径段 `/t/<token>/<file>`** | ❌ **原样落盘** |

**实跑证据**（`audit/lead-token-redaction.py`）：

```
[OK]     GET 200 /sub/pool.yaml?token=***                ua=Python-urllib/3.13
[OK]     GET 200 /sub/pool.yaml?t=***                    ua=Python-urllib/3.13
[!! 泄露] GET 200 /t/<TOKEN>/pool.yaml                    ua=Python-urllib/3.13
[OK]     GET 200 /sub/pool.yaml                          ua=Python-urllib/3.13
```

四种形式各打一次，`/t/` 那条把完整令牌写进了 `state/access.log`。

**讽刺点**：`_log` 的 docstring 自己写着

> 令牌必须脱敏 —— 日志不该成为密钥的第二个落盘点。
> 之前这里写的是原始 self.path, 生产日志里 146/170 行都含完整令牌。

四种形式只堵了三种。

**影响**：`access.log` 的 ACL 是 `Authenticated Users:(M)`，任何本机用户可读。
拿到令牌就能以合法身份拉订阅（绕过 token.txt 的 ACL 收紧）。

**修复建议**：脱敏改成"按值替换"而不是"按参数名替换" —— 把当前令牌本身
从日志里抹掉，无论它出现在什么位置：

```python
safe = path.replace(token, "***")
safe = re.sub(r"([?&](?:token|t)=)[^&\s]*", r"\1***", safe)
```

这样以后新增投递形式也不会漏。

---

## L-2 · `state/` 与 `out/` 目录对本机其他用户可写　【中】

**位置**：目录 ACL（不是代码，是部署/加固缺失）

**实跑证据**：

```
C:\freeVPN\state   Authenticated Users:(I)(M)
                   Authenticated Users:(I)(OI)(CI)(IO)(M)
C:\freeVPN\out     同上（继承）
```

`tighten_file_perms` 只对**两个文件**调过：

```
pool.py:3249   sec.tighten_file_perms(ADDR_FILE)     # 订阅地址.txt
security.py:544/549  tighten_file_perms(tf)          # token.txt
```

其余全部继承父目录的宽松 ACL：

```
[宽松] access.log                         8140 字节
[宽松] daemon.log                        41297 字节
[宽松] gui.log                            8875 字节
[宽松] profiles.yaml.20261008-145503.bak  3748 字节   ← 含令牌
[宽松] out/pool.yaml                                   ← 订阅本身
[宽松] state/l1.json / pool.json / daemon.pid
[收紧] token.txt                          34 字节
[收紧] 订阅地址.txt
```

**两个后果**：

1. **密钥泄露**：`token.txt` 被保护，但同一个目录下至少 3 个文件里躺着明文令牌
   （`daemon.log` 45 行、`gui.log` 3 行、`profiles.yaml.*.bak`）。
   逐文件加固等于没加固。

2. **产物篡改**：`out/pool.yaml` 就是客户端要拉的订阅内容，别的本机用户可以
   直接改它 —— **往用户的 VPN 客户端里注入任意代理节点**。这比读令牌更严重，
   因为用户看不到（客户端只是拉了一份"正常"的订阅）。
   `state/pool.json`、`state/l1.json` 同理，会影响后续扫描的行为。

**修复建议**（任选，建议都做）：

- 启动时对整个 `state/` 和 `out/` 目录做一次 `icacls /inheritance:r`，
  而不是逐个文件 —— 新产生的文件自然继承收紧后的 ACL。
- 日志里的令牌一律不落盘（见 L-1 的修法 + daemon 横幅不要打印完整订阅地址）。
- `out/` 的产物写入前后校验完整性（至少别让外部改动无声生效）。

**注意**：这条的严重度取决于威胁模型。如果用户机器只有自己一个账户，
影响有限；但"本机其他用户"是 Windows 上很常见的场景（共享机、多账户、
服务账户），而且这个工具本身是常驻的。

---

## L-3 · 状态页 XSS —— 复验通过，无问题　【信息】

**位置**：`pool.py` `render_page()`

上一轮审计发现过（节点名来自公开订阅源，可被设为 `<img src=x onerror=...>`），
修复是 `html.escape` + nonce CSP。这一版代码改动很大，重新实测。

**方法**：19 个 payload（含 `javascript:`、`data:text/html`、大小写混淆、
`\t` 分隔、`{{7*7}}`、`{0.__class__}`、`<!--`、控制字符、超长），
塞进 report 的**每一个**字符串字段，然后用 `html.parser` 解析渲染结果。

**前两版脚本都是错的，值得记一下**：

- v1 只看"payload 在不在页面里" —— 但 payload 出现在**文本位置**是无害的，
  节点名显示成 `<script>` 只是文字。误报 5 条。
- v2 用正则抽属性 —— 把**转义后的文本**也当成了属性
  （`&lt;iframe src=javascript:...&gt;` 里的 `src=` 被误判成真属性）。误报 36 条。
- v3 用 `html.parser.HTMLParser` 才分得清"标签属性"和"文本"。

**结论**：

```
页面 9121 字符 / 293 个标签 / 43 个属性
落在真实属性里的 payload: 0/19
真实属性全部是我们自己的固定值：
  <meta charset>、<div class>、<a href="clash://install-config?url=x">、
  <input value="http://127.0.0.1:8787/sub/...">、<script nonce="...">
<script> 1 个，带正确 nonce
```

无问题。`href` 全页面只有一个，来自固定的 `clash://` 前缀（`import_link`），
且同样经过 `html.escape`。

**唯一的小问题**：`html.escape` 不清控制字符，`\x00\x01\x1b` 会原样进页面。
浏览器大多忽略，但 HTML 里不该出现 —— 建议渲染前过一遍节点管线里那个
`scrub()`，保持两条路径一致。　【低】

---

## L-4 · `verge_exe()` 从注册表取可执行路径　【低，待 A 确认】

```python
m = re.search(r'"([^"]+clash-verge\.exe)"', cmd, re.I)
if m and Path(m.group(1)).exists():
    return m.group(1)
```

`cmd` 来自 `detect_clients()` 读的注册表处理器命令。只要路径以
`clash-verge.exe` 结尾且文件存在就会被采纳，然后被 `relaunch_verge()`
拿去 `Popen`。

能写 `HKCU\Software\Classes\clash\shell\open\command` 的攻击者本来就能以当前
用户身份执行代码，所以**不构成提权**；但如果本程序以更高权限运行，
这就是一个执行任意程序的跳板。

留给 `sec-server-v2` 独立验证，我不重复。
