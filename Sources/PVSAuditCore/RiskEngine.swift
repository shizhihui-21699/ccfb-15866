import Foundation

/// Turns (grant set × observations × app identity × policy) into ranked findings.
///
/// Design rules, in priority order:
///   1. Never recommend revoking a protected app. Period.
///   2. Never recommend an *automatic* revoke of a service that is not
///      `autoRevocable` (Accessibility, PostEvent, AppleEvents) — those go to
///      human review even when they score high.
///   3. "In active use" always wins over any risk score.
///   4. Uncertainty (unknown signature) raises review priority, never lowers it.
public struct RiskEngine {

    public struct Input {
        public var grants: [Grant]
        public var usage: [UsageSummary]
        public var apps: [String: AppIdentity]
        public var policy: Policy
        public var now: Date
        public init(grants: [Grant], usage: [UsageSummary],
                    apps: [String: AppIdentity], policy: Policy, now: Date = Date()) {
            self.grants = grants; self.usage = usage; self.apps = apps
            self.policy = policy; self.now = now
        }
    }

    public init() {}

    public func evaluate(_ input: Input) -> [Finding] {
        let policy = input.policy
        let usageByKey = indexUsage(input.usage)

        // Group grants by (service, client). Log-derived grants and DB grants
        // for the same pair merge: the DB wins on detail, the log adds recency.
        var byPair: [PairKey: Grant] = [:]
        for g in input.grants {
            let key = PairKey(service: g.service, client: g.client)
            if let existing = byPair[key] {
                byPair[key] = merge(existing, g)
            } else {
                byPair[key] = g
            }
        }

        // Also surface strong signals where usage was seen but no grant is known
        // (e.g. revoked already, or DB unreadable). Useful, but not actionable.
        var extraClients: Set<String> = []
        if byPair.isEmpty {
            extraClients = Set(input.usage.map { $0.appKey })
        }

        var findings: [Finding] = []
        for (key, grant) in byPair {
            guard let spec = ServiceCatalog.spec(for: key.service) else { continue }
            let usage = usageByKey.exact[key] ?? usageByKey.appOnly(key.client)
            let app = enrich(resolveApp(client: key.client, apps: input.apps,
                                        clientType: grant.clientType), usage: usage)
            findings.append(makeFinding(app: app, spec: spec, grant: grant,
                                        usage: usage, policy: policy, now: input.now))
        }
        for client in extraClients {
            guard let app = input.apps[client] else { continue }
            for u in input.usage where u.appKey == client {
                guard let spec = ServiceCatalog.spec(for: u.service) else { continue }
                findings.append(makeFinding(app: app, spec: spec, grant: nil,
                                            usage: u, policy: policy, now: input.now))
            }
        }
        return findings.sorted { a, b in
            if a.score != b.score { return a.score > b.score }
            return a.app.key < b.app.key
        }
    }

    // MARK: - One finding

    private func makeFinding(app: AppIdentity, spec: ServiceSpec, grant: Grant?,
                             usage: UsageSummary?, policy: Policy, now: Date) -> Finding {
        var score = spec.risk
        var reasons: [String] = []
        var blockers: [String] = []
        var recommendation: Recommendation = .review

        // ---- Protected apps ----
        if let p = policy.protectedApps.first(where: { $0.matches(app.bundleID) }) {
            return Finding(
                app: app, serviceID: spec.id, serviceName: spec.tccutilName,
                serviceDisplay: spec.display, grant: grant, usage: usage,
                score: 0, band: .low, recommendation: .keep,
                reasons: ["受保护：\(p.reason)"],
                blockers: ["策略保护，不参与收回"], canResetLocally: spec.autoRevocable)
        }
        if app.isApple {
            return Finding(
                app: app, serviceID: spec.id, serviceName: spec.tccutilName,
                serviceDisplay: spec.display, grant: grant, usage: usage,
                score: 0, band: .low, recommendation: .keep,
                reasons: ["Apple 系统组件"],
                blockers: ["系统组件，不参与收回"], canResetLocally: false)
        }
        // OS daemons and CLIs (/usr/libexec/sharingd, /usr/bin/osascript) hold
        // many grants by design. Auditing them produces noise and can never
        // lead to an action, so they are out of scope — but say so explicitly
        // rather than silently dropping them.
        if app.isSystemBinary {
            return Finding(
                app: app, serviceID: spec.id, serviceName: spec.tccutilName,
                serviceDisplay: spec.display, grant: grant, usage: usage,
                score: 0, band: .low, recommendation: .keep,
                reasons: ["系统内置程序"],
                blockers: ["系统组件，不参与收回"], canResetLocally: false)
        }

        // ---- Usage modifiers ----
        // Be precise about what "no record" means: the log only reaches back a
        // bounded window (as little as a few days). "Not seen in the window" is
        // NOT "unused", and a tool that conflates them will revoke live grants.
        let lastActual = usage?.lastActualUse
        let activeDays = daysBetween(lastActual, and: now)
        let observedAny = (usage?.observedCount ?? 0) > 0

        if let d = activeDays {
            if d <= policy.activeUseWindowDays {
                return Finding(
                    app: app, serviceID: spec.id, serviceName: spec.tccutilName,
                    serviceDisplay: spec.display, grant: grant, usage: usage,
                    score: max(0, spec.risk - 70), band: .low, recommendation: .keep,
                    reasons: ["最近 \(d) 天真正使用过"],
                    blockers: ["在用，不建议收回"], canResetLocally: spec.autoRevocable)
            }
            if d > policy.warmWindowDays {
                score += 20
                reasons.append("已 \(d) 天没有真正使用")
            } else {
                reasons.append("最近一次真正使用在 \(d) 天前")
            }
        } else if observedAny {
            // The app asked TCC about this capability but never exercised it.
            score += 10
            reasons.append("仅查询过权限状态，未观察到真正使用")
        } else if grant != nil {
            score += 10
            reasons.append("日志窗口内未观察到该 App 访问此权限（窗口有限，不等于从未使用）")
        }

        // App dormancy adds weight: a permission on an app nobody launches is the
        // exact "forgotten grant" this tool exists to find.
        if let lu = app.lastUsed {
            let appDays = daysBetween(lu, and: now) ?? 0
            if appDays > policy.dormantAppDays {
                score += 20
                reasons.append("App 已 \(appDays) 天未启动")
            }
        }

        // ---- Signature trust ----
        switch app.signature {
        case .unsigned:
            score += policy.unsignedPenalty
            reasons.append("未签名，无法确认来源")
        case .adhoc:
            score += policy.adhocPenalty
            reasons.append("自签名（ad-hoc），无法确认来源")
        case .unknown:
            score += policy.lookalikePenalty
            reasons.append("签名信息不可读，身份存疑")
        case .developerID:
            if let team = app.teamID, policy.trustedTeamIDs.contains(team) {
                reasons.append("受信团队签名 (\(team))")
                score -= 10
            }
        case .apple:
            break
        }

        // An app declaring an Apple bundle id without an Apple signature is
        // actively trying to look like part of the OS. Treat it as hostile
        // evidence, not as an exemption.
        if app.claimsAppleIdentityUnverified {
            score += policy.lookalikePenalty
            reasons.append("声称 \(app.bundleID ?? "") 但无 Apple 签名，疑似伪装")
        }

        // ---- Evidence quality ----
        // An inferred grant (from a successful log request) is weaker evidence
        // than a TCC.db row. Do not let a weak grant drive an *automatic*
        // revoke; route those to human review instead. The executor enforces
        // this too, so a hand-edited plan cannot bypass it.
        if let g = grant, g.source.confidence != .confirmed {
            reasons.append("授权来源：" + g.source.confidence.display)
        }

        // ---- Addressability: .app bundle vs loose binary ----
        // A grant keyed by a CLI tool / JVM is invisible to tccutil and to a
        // bundleID PPPC profile, whether or not the binary still exists. Saying
        // "recommend revoke" for it would produce an action that cannot work.
        let isLoose = app.path != nil && !(app.path ?? "").hasSuffix(".app")
        var canResetLocally = spec.autoRevocable

        if isLoose {
            canResetLocally = false
            reasons.append("非 .app 包形式的授权（命令行工具 / JVM 等）")
            blockers.append("tccutil 与 bundleID 型 PPPC 均无法处理，需人工评估")
            recommendation = .reviewNonBundle
        } else if !app.installed {
            // The path was a .app (or unknown) but nothing is there any more:
            // a removed bundle. Its grant is still live, and a bundleID PPPC
            // profile can deny it even though it is gone.
            score += 15
            reasons.append("App 已不在常规位置（可能已卸载）")
            blockers.append("tccutil 无法处理已卸载的 bundle，需要下发 PPPC 描述文件")
            recommendation = .remediateViaProfile
            canResetLocally = false
        }

        // ---- Recommendation ----
        if app.installed && !isLoose {
            if !spec.autoRevocable {
                recommendation = .review
                blockers.append(spec.revokeEffect)
            } else if let g = grant, g.source.confidence == .inferred, score >= 55 {
                // Strong signal, weak evidence → a human should confirm.
                recommendation = .review
                blockers.append("授权系日志推断，建议开启完全磁盘访问确认后再收回")
            } else if score >= 55 {
                recommendation = .revoke
            } else if score >= 40 {
                recommendation = .review
            } else {
                recommendation = .keep
            }
        }

        if grant == nil {
            recommendation = .noGrant
            blockers = ["未发现现存授权，可能已被收回或仅被拒绝"]
        }

        score = min(100, max(0, score))
        return Finding(
            app: app, serviceID: spec.id, serviceName: spec.tccutilName,
            serviceDisplay: spec.display, grant: grant, usage: usage,
            score: score, band: band(for: score), recommendation: recommendation,
            reasons: reasons, blockers: blockers, canResetLocally: canResetLocally)
    }

    // MARK: - Helpers

    private struct PairKey: Hashable { var service: String; var client: String }

    private struct UsageIndex {
        var exact: [PairKey: UsageSummary] = [:]
        var byApp: [String: UsageSummary] = [:]
        func appOnly(_ client: String) -> UsageSummary? { byApp[client] }
    }

    private func indexUsage(_ usage: [UsageSummary]) -> UsageIndex {
        var idx = UsageIndex()
        for u in usage {
            let k = PairKey(service: u.service, client: u.appKey)
            if let e = idx.exact[k] {
                idx.exact[k] = mergeUsage(e, u)
            } else {
                idx.exact[k] = u
            }
            if let e = idx.byApp[u.appKey] {
                idx.byApp[u.appKey] = mergeUsage(e, u)
            } else {
                idx.byApp[u.appKey] = u
            }
        }
        return idx
    }

    private func mergeUsage(_ a: UsageSummary, _ b: UsageSummary) -> UsageSummary {
        UsageSummary(
            appKey: a.appKey, appPath: a.appPath ?? b.appPath, service: a.service,
            lastTouched: max(a.lastTouched, b.lastTouched),
            lastActualUse: [a.lastActualUse, b.lastActualUse].compactMap { $0 }.max(),
            observedCount: a.observedCount + b.observedCount,
            accessRequestCount: a.accessRequestCount + b.accessRequestCount)
    }

    private func merge(_ a: Grant, _ b: Grant) -> Grant {
        // Prefer DB rows (they carry last_modified); union the rest.
        let dbFirst = a.source == .userTCCDB || a.source == .systemTCCDB ? a : b
        let other = (dbFirst == a) ? b : a
        return Grant(
            service: dbFirst.service, client: dbFirst.client,
            clientType: dbFirst.clientType ?? other.clientType,
            allowed: dbFirst.allowed, authValue: dbFirst.authValue ?? other.authValue,
            authReason: dbFirst.authReason ?? other.authReason,
            lastModified: dbFirst.lastModified ?? other.lastModified,
            indirectObject: dbFirst.indirectObject ?? other.indirectObject,
            source: dbFirst.source)
    }

    /// The log usually tells us the executable path even when the grant is keyed
    /// by a bare identifier (CLI tool, JVM). Use it: it is the difference
    /// between "a.out, unknown" and "clidex at /usr/local/bin/clidex".
    private func enrich(_ app: AppIdentity, usage: UsageSummary?) -> AppIdentity {
        guard app.path == nil, let p = usage?.appPath, !p.isEmpty else { return app }
        var out = app
        out.path = p
        if !p.hasSuffix(".app") {
            out.displayName = (p as NSString).lastPathComponent
        }
        out.installed = FileManager.default.fileExists(atPath: p)
        // We just learned where this binary lives — resolve its signature too.
        // Otherwise an Apple-signed helper (e.g. com.apple.swift-frontend in
        // Command Line Tools) would be scored as an unidentifiable tool.
        if out.signature == .unknown {
            let sig = AppInventory().signatureInfo(at: p)
            out.signature = sig.kind
            out.teamID = sig.teamID
        }
        return out
    }

    private func resolveApp(client: String, apps: [String: AppIdentity],
                            clientType: Int?) -> AppIdentity {
        if let a = apps[client] { return a }
        // Regression: the audit must run on the machine it was taken from, so
        // resolve against this host's actual /Applications tree per request.
        let inv = AppInventory()
        for root in AppInventory.defaultRoots {
            let candidate = (root.path as NSString).appendingPathComponent(
                (client as NSString).lastPathComponent + ".app")
            if FileManager.default.fileExists(atPath: candidate),
               var id = inv.identity(forAppAt: candidate, system: root.system) {
                id.bundleID = id.bundleID ?? client
                return id
            }
        }
        // Grant may be keyed by a path to a loose binary (client_type 1) or by an
        // identifier whose executable the log told us about. Sign it too: an
        // Apple-signed compiler helper must not be mistaken for a rogue tool.
        if client.hasPrefix("/") {
            var id = AppIdentity(
                bundleID: nil, path: client, displayName: (client as NSString).lastPathComponent,
                version: nil, teamID: nil, signature: .unknown, installed: false,
                lastUsed: nil, running: false)
            let sig = AppInventory().signatureInfo(at: client)
            id.teamID = sig.teamID
            id.signature = sig.kind
            id.bundleID = client.contains("/") ? nil : client
            id.installed = FileManager.default.fileExists(atPath: client)
            return id
        }
        return AppIdentity(
            bundleID: client,
            path: nil,
            displayName: (client as NSString).lastPathComponent
                .replacingOccurrences(of: ".app", with: ""),
            version: nil, teamID: nil, signature: .unknown,
            installed: false, lastUsed: nil, running: false)
    }

    private func daysBetween(_ date: Date?, and now: Date) -> Int? {
        guard let date else { return nil }
        return Calendar.current.dateComponents([.day], from: date, to: now).day
    }

    private func band(for score: Int) -> RiskBand {
        switch score {
        case 85...: return .critical
        case 70..<85: return .high
        case 45..<70: return .medium
        default: return .low
        }
    }
}
