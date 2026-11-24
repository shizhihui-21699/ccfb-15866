import Foundation

/// Human-readable report. Deliberately plain text so it pastes into a ticket
/// and diffs cleanly; JSON is available separately for automation.
public struct Reporter {

    public init() {}

    public func render(_ state: ScanState, limit: Int? = nil) -> String {
        var out: [String] = []
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm"
        f.timeZone = .current

        out.append("PVSAudit 隐私权限审计报告")
        out.append(String(repeating: "=", count: 52))
        out.append("主机      \(state.host.hostname)  (\(state.host.osVersion), \(state.host.osBuild))")
        out.append("用户      \(state.host.userName)")
        out.append("生成时间  \(f.string(from: state.generatedAt))")
        out.append("策略      \(state.policyName ?? "-")")
        out.append("")

        out.append("采集能力")
        out.append(String(repeating: "-", count: 52))
        out.append("完全磁盘访问  \(state.capability.hasFullDiskAccess ? "已授予" : "未授予")")
        out.append("日志可用      \(state.capability.canReadUnifiedLog ? "是" : "否")"
                   + (state.capability.logRetentionDays.map { "（可回溯约 \($0) 天）" } ?? ""))
        out.append("tccutil       \(state.capability.tccutilWorks ? "可用（无需提权）" : "不可用")")
        out.append("解析日志事件  \(state.diagnostics.logEventsParsed) 条")
        out.append("扫描 App      \(state.diagnostics.appsScanned) 个")
        for n in state.capability.notes { out.append("· \(n)") }
        out.append("")

        let actionable = state.findings.filter {
            $0.recommendation == .revoke || $0.recommendation == .remediateViaProfile
        }
        let review = state.findings.filter {
            $0.recommendation == .review || $0.recommendation == .reviewNonBundle
        }

        out.append("概览")
        out.append(String(repeating: "-", count: 52))
        out.append("高风险且可收回   \(actionable.count)")
        out.append("需人工复核       \(review.count)")
        out.append("在用 / 受保护    \(state.findings.filter { $0.recommendation == .keep }.count)")
        out.append("")

        if !actionable.isEmpty {
            out.append("建议收回（按风险排序）")
            out.append(String(repeating: "-", count: 52))
            for fnd in (limit.map { Array(actionable.prefix($0)) } ?? actionable) {
                out.append(contentsOf: block(fnd))
            }
            out.append("")
        }

        if !review.isEmpty {
            out.append("需人工复核")
            out.append(String(repeating: "-", count: 52))
            for fnd in (limit.map { Array(review.prefix($0)) } ?? review) {
                out.append(contentsOf: block(fnd))
            }
            out.append("")
        }

        if !state.diagnostics.warnings.isEmpty {
            out.append("警告")
            out.append(String(repeating: "-", count: 52))
            out.append(contentsOf: state.diagnostics.warnings.map { "· \($0)" })
            out.append("")
        }

        out.append("提示：本报告为只读结果。执行收回需运行 `pvsaudit apply`，")
        out.append("      默认 dry-run，确认无误后加 --apply。")
        return out.joined(separator: "\n")
    }

    private func block(_ f: Finding) -> [String] {
        let df = DateFormatter(); df.dateFormat = "MM-dd HH:mm"
        var lines: [String] = []
        let band = f.band.rawValue.uppercased()
        lines.append("[\(band) \(f.score)] \(f.app.displayName ?? f.app.key)  —  \(f.serviceDisplay)")
        lines.append("    标识      \(f.app.bundleID ?? f.app.path ?? "?")"
                     + (f.app.teamID.map { "  team \($0)" } ?? ""))
        switch f.app.signature {
        case .apple: lines.append("    签名      Apple")
        case .developerID: lines.append("    签名      Developer ID")
        case .adhoc: lines.append("    签名      自签名(ad-hoc)")
        case .unsigned: lines.append("    签名      未签名")
        case .unknown: lines.append("    签名      未知")
        }
        if let u = f.usage {
            let lastUse = u.lastActualUse.map { df.string(from: $0) } ?? "窗口内未观察到"
            var line = "    最近使用  \(lastUse)"
            if u.observedCount > 0 {
                line += "（窗口内查询 \(u.observedCount) 次，成功访问 \(u.accessRequestCount) 次）"
            } else {
                line += "（窗口内无任何记录）"
            }
            lines.append(line)
        } else {
            lines.append("    最近使用  窗口内无任何记录")
        }
        if let g = f.grant {
            if let m = g.lastModified {
                lines.append("    授权时间  \(df.string(from: m))（来源 \(g.source.rawValue)）")
            } else {
                lines.append("    授权证据  \(g.source.confidence.display)")
            }
        }
        if !f.reasons.isEmpty {
            lines.append("    判断依据  " + f.reasons.joined(separator: "；"))
        }
        if !f.blockers.isEmpty {
            lines.append("    注意      " + f.blockers.joined(separator: "；"))
        }
        switch f.recommendation {
        case .revoke:
            lines.append("    处置      建议收回 → tccutil reset \(f.serviceName) \(f.app.bundleID ?? "")")
        case .remediateViaProfile:
            lines.append("    处置      下发 PPPC 描述文件（本地无法清除）")
        case .review:
            lines.append("    处置      人工复核后决定")
        case .reviewNonBundle:
            lines.append("    处置      非 .app 授权，无法用 tccutil 清除；需人工移除或重装该工具")
        case .keep:
            lines.append("    处置      保留")
        case .noGrant:
            lines.append("    处置      无现存授权")
        }
        lines.append("")
        return lines
    }
}
