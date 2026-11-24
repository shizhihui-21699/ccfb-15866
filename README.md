# PVSAudit

macOS 隐私权限审计与收回工具。面向几百到几千台 Mac 的 IT/安全团队：
找出哪些 App 拿了高风险权限、最近是否真的在用，给出收回建议，并支持一键处理。

## 核心设计

默认**零 TCC 权限**即可用：靠读取统一日志（`log show`）还原「哪个 App 何时真的用了
哪个权限」。获得完全磁盘访问后再补上精确授权清单。默认只读，收回需显式 `--apply`，
且执行前逐项重新校验。

详见 [docs/DESIGN.md](docs/DESIGN.md)、[docs/PERMISSIONS.md](docs/PERMISSIONS.md)。

## 构建

需要 Swift 5.9+（Command Line Tools 即可，不需要完整 Xcode）。

```bash
swift build -c release
swift run pvsaudit-selftest     # 34 项自测
```

## 使用

```bash
# 0. 看看本机能采到什么
.build/release/pvsaudit doctor

# 1. 只读审计（默认回溯 14 天日志）
.build/release/pvsaudit scan --days 14 --json state.json --report report.txt

# 2. 预览收回计划（默认 dry-run，绝不修改系统）
.build/release/pvsaudit apply --plan state.json

# 3. 确认后真正执行
.build/release/pvsaudit apply --plan state.json --apply

# 4. 对无法本地清除的项，生成 PPPC 描述文件（签名后由 MDM 下发）
.build/release/pvsaudit apply --plan state.json --profile deny.mobileconfig --org "公司名"
```

退出码：`0` 正常 / `1` 错误 / `2` 有建议但未执行（便于 CI 判断）/ `3` 部分失败。

## 策略文件

用 JSON 描述公司实际软件，避免误收。未指定的项一律偏向人工复核。

```json
{
  "name": "acme-2026",
  "version": 1,
  "protectedApps": [
    { "bundleIDPattern": "com.microsoft.teams*", "reason": "会议" },
    { "bundleIDPattern": "com.acme.internal.*",   "reason": "内部工具" }
  ],
  "trustedTeamIDs": ["ABCDE12345"],
  "activeUseWindowDays": 30,
  "warmWindowDays": 90,
  "dormantAppDays": 120,
  "unsignedPenalty": 25,
  "adhocPenalty": 15,
  "lookalikePenalty": 20
}
```

```bash
pvsaudit scan --policy acme.json --json state.json
```

## 安全默认

- `apply` 不加 `--apply` 时**不做任何修改**。
- 受策略保护的 App、Apple 组件、仍在使用的权限，执行器一律跳过。
- 辅助功能 / 模拟键鼠 / 自动化**永不自动收回**。
- 日志推断出的授权**永不自动收回**（证据强度不足，转人工）。
- 已卸载 App 走 PPPC 描述文件，不硬改本地数据库。
- 从不写 `TCC.db`，不关 SIP。

## 目录

```
Sources/PVSAuditCore/     核心库（模型、日志解析、TCC.db 读取、评分、执行器）
Sources/pvsaudit/         CLI
Sources/pvsaudit-selftest/ 自测（不依赖 XCTest）
docs/                     设计与权限对照
```
