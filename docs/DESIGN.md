# 设计说明

## 一句话

在**不依赖完全磁盘访问**的前提下，用统一日志还原「哪个 App 最近真的用了哪个隐私权限」；
拿到完全磁盘访问时再补上精确授权清单。默认只读，收回需要显式开关，且执行前逐项重新校验。

## 为什么不能只做一个「需要 FDA 的 App」

我在 macOS 26.5 (Darwin 25.5) 上逐项验证过，结论如下（可用 `pvsaudit doctor` 复现）：

| 手段 | 结果 |
|---|---|
| 直接读 `~/Library/…/com.apple.TCC/TCC.db` | `authorization denied` |
| 私有 `TCCAccessCopyInformation` 系列 | 全部返回 nil / 崩溃 |
| 私有 `TCCAccessReset` | 对不存在的 service 也返回 0，空壳 |
| `/usr/bin/tccutil reset Service BundleID` | **可用，无需提权** |
| 统一日志 `subsystem == "com.apple.TCC"` | **零权限可读**，含完整归因 |
| 日志保留窗口 | 本机约 6 天，长期未清理的机器可达 18 天 |

结论：**授权清单**只能靠 FDA 拿，**使用证据**零权限就有。所以工具分成两层：

```
零权限层（永远可用）
  log show → 解析 AUTHREQ_* → 归因到 App → 多久没用 / 是否真用过
     ↓
FDA 层（可选，更精确）
  TCC.db → 精确授权集合 + 真实授权时间
     ↓
汇合 → 风险评分 → 建议 → 执行器（逐项重校验）→ tccutil / PPPC
```

## 日志怎么还原「谁用了什么」

一次 TCC 询问会写多条记录，共享一个 `msgID`：

```
AUTHREQ_CTX         service=kTCCServiceScreenCapture, preflight=yes|no
AUTHREQ_ATTRIBUTION accessing={identifier=com.bytedance.macos.feishu, binary_path=…}
                    requesting={identifier=com.apple.WindowServer, …}
AUTHREQ_SUBJECT     subject=com.bytedance.macos.feishu
AUTHREQ_RESULT      authValue=0|1|2
```

三个关键判断：

- **归因到谁**：屏幕录制等能力由 `WindowServer` 代问。`accessing` 才是用户关心的 App，
  `requesting` 只是代理。代码里维护了 broker 列表，避免把权限算到 WindowServer 头上。
- **是不是真用了**：`preflight=yes` 只是问「我有权限吗」，`preflight=no` 才是真正访问。
  只有后者计入「最近真正使用」。
- **有没有授权**：`authValue=2`（允许）才作为授权存在的证据。`0`（拒绝）绝不能当成授权。

`TCCDEvent: type=Create|Modify` 也落在日志里，但 category 是 `events` 而非 `access`——
早期版本按 `category == "access"` 过滤，会把所有授权变更静默丢掉。

## 证据分级

| 来源 | 可信度 | 能否自动收回 |
|---|---|---|
| TCC.db 行 | 已确认 | 可以 |
| 日志里的 Create 事件 | 较可信 | 否，转人工 |
| 日志里访问成功推断 | 推断 | 否，转人工 |

推断出来的授权虽然足够用来**提示**，但不足以支撑**自动**收回——因为「日志窗口内没看到」
不等于「没在用」，窗口只有几天。这条规则在评分层和执行层各实现一次，
所以即使有人手工把 plan 文件的 recommendation 改成 `revoke`，执行器依然会拒绝。

## 不误收的三道闸

1. **策略保护**：会议、IM、邮件、终端、开发工具、安全代理在 `Policy.protectedApps` 里，
   永远保留。可按公司实际软件清单增补。
2. **在用即保留**：最近 `activeUseWindowDays`（默认 30 天）内真正使用过 → 直接 `keep`，
   不参与评分。
3. **执行前重校验**：`apply` 不信任 plan 文件，会重新扫一遍 App、重新判断在用状态、
   重新检查策略。任何一条不满足就跳过并写明原因。

加上两类天然的「不可自动」：`Accessibility` / `PostEvent` / `AppleEvents` 一律转人工
（系统不提供可观测的「使用」信号，且收回体验很突兀）。

## 收回手段的选择

| 情况 | 手段 | 原因 |
|---|---|---|
| 已安装的 .app | `tccutil reset` | 无需提权，用户下次用时自然重新授权 |
| 已卸载的 .app | PPPC 描述文件 | `tccutil` 对未安装 bundle 返回 -10814 |
| 命令行工具 / JVM 授权 | 人工 | 既非 bundle，也无从 tccutil 定位 |

PPPC 必须按服务分组下发。早期版本把每个拒绝项同时写进 `ScreenCapture` 和 `Accessibility`，
会误删用户的辅助功能授权——测试里已锁死这个回归。

## 工具自身权限

- 默认**零 TCC 权限**，只读日志 + 调 `tccutil reset`。
- 想更精确时可以给宿主终端 FDA；不给也能用，只是清单不完整（报告里会明确写出来）。
- 不申请辅助功能、不申请屏幕录制、不安装内核扩展、常驻进程不需要。

## 已知边界

- 日志窗口有限（本机 6 天）：更早的「使用」不可观测，报告中如实标注。
- `Accessibility` 的实际使用无法从日志观测，只能看授权状态。
- 企业批量场景下，干净的落地方式是给每台机器授权**一个专用签名的小工具** FDA，
  而不是给终端 App 授权——终端下运行的任何脚本都会继承这份权限。

## 性能实测（本机 macOS 26.5，18 天窗口）

| 指标 | 数值 |
|---|---|
| 原始日志 | 134 MB / 12 万行 |
| 扫描耗时 | 约 26 秒 |
| 本工具常驻内存 | 约 156 MB（含 Swift 运行时基线） |
| `log show` 子进程内存 | 约 500 MB（系统工具，不属于本工具） |
| 聚合后摘要 | 174 条 (App, 服务) 组合 |

内存与日志量**解耦**：解析器逐行折叠成摘要，不保留单条事件
（`LogParser.keepObservations` 默认关闭，仅测试时打开）。
`wait`/`time -l` 看到的 500 MB 是 `log show` 自身占用，不是本工具。

## 为什么不写 TCC.db

1. 需要 FDA + 关 SIP，权限代价远大于收益；
2. 不同系统版本 schema 不同，直写极易损坏 tccd 状态；
3. `tccutil` 是 Apple 支持的路径，卸载重装后授权关系仍然正确。

读取 TCC.db 时用 `immutable=1` 只读打开，避免对 tccd 正在写的库加锁。
