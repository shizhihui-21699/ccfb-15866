# 权限与服务对照表

所有结论均在 macOS 26.5 (Darwin 25.5) 上实测。换系统版本后请用
`pvsaudit doctor` 与 `pvsaudit scan` 复核。

## 服务清单

| TCC service | tccutil 名称 | 中文 | 基础风险 | 可自动收回 | 可观测实际使用 |
|---|---|---|---|---|---|
| `kTCCServiceSystemPolicyAllFiles` | `SystemPolicyAllFiles` | 完全磁盘访问 | 95 | 是 | 是 |
| `kTCCServiceAccessibility` | `Accessibility` | 辅助功能 | 92 | **否** | **否** |
| `kTCCServiceScreenCapture` | `ScreenCapture` | 屏幕录制 | 88 | 是 | 是 |
| `kTCCServicePostEvent` | `PostEvent` | 模拟键鼠 | 84 | **否** | **否** |
| `kTCCServiceListenEvent` | `ListenEvent` | 输入监控 | 80 | 是 | 是 |
| `kTCCServiceSystemPolicySysAdminFiles` | `SystemPolicySysAdminFiles` | 系统管理文件 | 72 | 是 | 是 |
| `kTCCServiceMicrophone` | `Microphone` | 麦克风 | 62 | 是 | 是 |
| `kTCCServiceCamera` | `Camera` | 摄像头 | 60 | 是 | 是 |
| `kTCCServicePhotos` | `Photos` | 照片 | 58 | 是 | 是 |
| `kTCCServiceSystemPolicyDesktopFolder` | `SystemPolicyDesktopFolder` | 桌面 | 55 | 是 | 是 |
| `kTCCServiceSystemPolicyDocumentsFolder` | `SystemPolicyDocumentsFolder` | 文稿 | 55 | 是 | 是 |
| `kTCCServiceSystemPolicyDownloadsFolder` | `SystemPolicyDownloadsFolder` | 下载 | 52 | 是 | 是 |
| `kTCCServiceAddressBook` | `AddressBook` | 通讯录 | 50 | 是 | 是 |
| `kTCCServiceSpeechRecognition` | `SpeechRecognition` | 语音识别 | 50 | 是 | 是 |
| `kTCCServiceAppleEvents` | `AppleEvents` | 自动化 | 50 | **否** | 是 |
| `kTCCServiceSystemPolicyNetworkVolumes` | `SystemPolicyNetworkVolumes` | 网络卷 | 48 | 是 | 是 |
| `kTCCServiceSystemPolicyRemovableVolumes` | `SystemPolicyRemovableVolumes` | 可移动卷 | 48 | 是 | 是 |
| `kTCCServiceCalendar` | `Calendar` | 日历 | 45 | 是 | 是 |
| `kTCCServiceReminders` | `Reminders` | 提醒事项 | 40 | 是 | 是 |
| `kTCCServiceMediaLibrary` | `MediaLibrary` | 媒体库 | 38 | 是 | 是 |
| `kTCCServiceSystemPolicyAppBundles` | `SystemPolicyAppBundles` | 管理其他 App | 34 | 是 | 是 |
| `kTCCServiceDeveloperTool` | `DeveloperTool` | 开发者工具 | 20 | 是 | 是 |

“可观测实际使用”= 能从统一日志区分「真访问」与「只查状态」。

## tccutil 行为要点

```
# 有效服务名 + 已安装 bundle → 成功，退出码 0
$ tccutil reset Camera com.apple.Calculator
Successfully reset Camera approval status for com.apple.Calculator

# 不存在的 bundle → OSStatus -10814，退出码 64
$ tccutil reset Camera com.example.gone
tccutil: No such bundle identifier "com.example.gone": … (OSStatus error -10814.)

# 无效服务名 → 以“Failed to reset …”开头
$ tccutil reset Contacts com.apple.Terminal
tccutil: Failed to reset Contacts approval status for com.apple.Terminal
```

可以用第二条规律做**无损的服务名探测**：拿一个不存在的 bundle id 试服务名，
返回 “No such bundle identifier” 说明服务名合法，返回 “Failed to reset” 说明非法。
（`Contacts` 的正确名称是 `AddressBook`。）

其他实测：

- 不需要 sudo，普通用户即可执行 `tccutil reset`。
- 对从未授权的 App 执行也返回成功——无法据此判断「原本有没有授权」。
- 路径型标识（`/usr/local/bin/xxx`）、CLI 标识（`a.out`）、JVM 标识
  （`net.java.openjdk.java`）一律 -10814，`tccutil` 完全无法处理。

## 日志字段解读

| 字段 | 含义 |
|---|---|
| `preflight=yes` | 只查询权限状态 |
| `preflight=no` | 真正访问受保护资源 |
| `authValue=0` | 拒绝 |
| `authValue=1` | 未决定（尚未授权） |
| `authValue=2` | 允许 |
| `category=access` | TCC 访问记录所在分类 |
| `category=events` | `TCCDEvent` 授权变更记录所在分类（易被漏掉） |

## 权限获取建议（企业）

1. **默认零权限部署**，先跑 `scan` 看覆盖度。
2. 需要精确清单时，只给一个**专用签名的小工具**授予 FDA，不要给终端授予——
   终端下运行的任何脚本都会继承该权限。
3. 通过 MDM 下发 `Policy` 文件，把公司实际在用的软件加入 `protectedApps`。
4. `apply --apply` 建议只在人工确认过的机器上跑；批量场景用 `--profile` 生成 PPPC 描述文件，
   签名后由 MDM 下发，可审计、可回滚。
