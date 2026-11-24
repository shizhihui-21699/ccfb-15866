import Foundation

/// Orchestrates a scan: capability probe → grants → usage → identity → findings.
public final class AuditEngine {

    public struct Options {
        public var sinceDays: Int
        public var policy: Policy
        public var policyWarning: String?
        public var includeSystemApps: Bool
        public init(sinceDays: Int = 14, policy: Policy = .default,
                    policyWarning: String? = nil, includeSystemApps: Bool = false) {
            self.sinceDays = sinceDays
            self.policy = policy
            self.policyWarning = policyWarning
            self.includeSystemApps = includeSystemApps
        }
    }

    private let apps = AppInventory()
    private let logReader: LogReader
    private let dbReader = TCCDatabaseReader()

    public init(logReader: LogReader = LogReader()) {
        self.logReader = logReader
    }

    public func scan(_ options: Options) throws -> ScanState {
        var warnings: [String] = []
        if let w = options.policyWarning { warnings.append(w) }

        // 1. Capability probe — never pretend we have more than we do.
        let readableUser = dbReader.canRead(path: TCCDatabaseReader.userDBPath)
        let readableSystem = dbReader.canRead(path: TCCDatabaseReader.systemDBPath)
        let hasFDA = readableUser || readableSystem
        let retention = logReader.retentionDays()
        let tccutilWorks = FileManager.default.isExecutableFile(atPath: "/usr/bin/tccutil")

        var notes: [String] = []
        if !hasFDA {
            notes.append("未获得完全磁盘访问：授权清单来自日志推断，可能不完整。")
            notes.append("如需精确清单，请在系统设置中为本工具开启“完全磁盘访问”。")
        }
        if let r = retention, r < options.sinceDays {
            notes.append("统一日志仅保留约 \(r) 天，早于该窗口的“使用”无法观测。")
        }

        // 2. Grants (DB if permitted; log lifecycle always).
        var grants: [Grant] = []
        var grantSources: [String] = []
        if hasFDA {
            let res = dbReader.readAll()
            grants = res.grants
            grantSources.append("TCC.db")
            warnings.append(contentsOf: res.errors)
        }

        // 3. Usage from the unified log — zero permission, always available.
        let parser = LogParser()
        var logOK = false
        do {
            let status = try logReader.stream(sinceDays: options.sinceDays) { parser.ingest(line: $0) }
            logOK = (status == 0)
            if !logOK { warnings.append("log show 退出码 \(status)，日志数据可能不完整") }
        } catch {
            warnings.append("无法读取统一日志：\(error)")
        }
        parser.finish()
        let parsed = parser.output
        grantSources.append(contentsOf: Set(parsed.lifecycle.map { $0.source.rawValue }))

        // Grants the log proves exist. A TCC request that *succeeded*
        // (authValue >= 2) is evidence a grant was in force at that moment —
        // either the app exercised the capability, or it checked and was told
        // "yes". Without this, the zero-permission tier would report every
        // touched permission as "no grant", which would make the tool useless
        // in its default configuration.
        if !parsed.inferredGrants.isEmpty {
            grantSources.append(GrantSource.logObservedGrant.rawValue)
        }
        grants.append(contentsOf: parsed.inferredGrants)
        grants.append(contentsOf: parsed.lifecycle)

        // 4. Usage aggregates come straight from the parser (already folded).
        let usage = parsed.usage

        // 5. Inventory.
        var roots = AppInventory.defaultRoots
        if !options.includeSystemApps {
            roots = roots.filter { !$0.system }
        }
        let inventory = apps.scan(roots: roots)

        // 6. Score.
        let engine = RiskEngine()
        let findings = engine.evaluate(.init(
            grants: grants, usage: usage, apps: inventory,
            policy: options.policy, now: Date()))

        // 7. Assemble.
        let cap = CapabilityReport(
            hasFullDiskAccess: hasFDA,
            canReadUserTCCDB: readableUser,
            canReadSystemTCCDB: readableSystem,
            canReadUnifiedLog: logOK,
            logRetentionDays: retention,
            tccutilPath: "/usr/bin/tccutil",
            tccutilWorks: tccutilWorks,
            notes: notes)

        let diag = Diagnostics(
            logEventsParsed: parsed.linesParsed,
            logWindowDays: options.sinceDays,
            unattributedEvents: parsed.unattributed,
            grantSourcesUsed: Array(Set(grantSources)).sorted(),
            appsScanned: inventory.count,
            warnings: warnings)

        return ScanState(
            schemaVersion: 1,
            generatedAt: Date(),
            host: Self.hostInfo(),
            capability: cap,
            policyName: options.policy.name,
            findings: findings,
            diagnostics: diag)
    }

    // MARK: - Grant inference (zero-permission tier)

    /// Derive the set of grants the log proves existed, from successful requests.
    ///
    /// We only use requests where TCC actually said "allowed". A *denied*
    /// request (authValue 0) must not create a grant. A status check that
    /// returned "allowed" is just as good a proof as an access: TCC only
    /// answers "allowed" when a grant row exists.
    public static func inferGrants(from observations: [Observation], now: Date) -> [Grant] {
        struct Key: Hashable { var service: String; var client: String }
        var lastAllowed: [Key: Date] = [:]
        var sawGranted: Set<Key> = []

        for o in observations where o.allowed == true {
            let k = Key(service: o.service, client: o.appKey)
            sawGranted.insert(k)
            lastAllowed[k] = max(lastAllowed[k] ?? .distantPast, o.at)
        }

        return sawGranted.map { k in
            Grant(service: k.service, client: k.client, clientType: nil,
                  allowed: true, authValue: 2, authReason: nil,
                  lastModified: nil,
                  indirectObject: nil, source: .logObservedGrant)
        }
    }

    // MARK: - Usage aggregation

    public static func summarizeUsage(_ observations: [Observation]) -> [UsageSummary] {
        struct Key: Hashable { var app: String; var service: String }
        var agg: [Key: (lastTouch: Date, lastUse: Date?, count: Int, access: Int, path: String?)] = [:]
        for o in observations {
            let k = Key(app: o.appKey, service: o.service)
            var e = agg[k] ?? (Date.distantPast, nil, 0, 0, nil)
            e.lastTouch = max(e.lastTouch, o.at)
            if o.kind == .accessRequest && o.allowed != false {
                e.lastUse = [e.lastUse, o.at].compactMap { $0 }.max()
                e.access += 1
            }
            e.count += 1
            if e.path == nil { e.path = o.appPath }
            agg[k] = e
        }
        return agg.map { k, v in
            UsageSummary(appKey: k.app, appPath: v.path, service: k.service,
                         lastTouched: v.lastTouch, lastActualUse: v.lastUse,
                         observedCount: v.count, accessRequestCount: v.access)
        }
    }

    public static func hostInfo() -> HostInfo {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        let build = (try? String(contentsOfFile: "/System/Library/CoreServices/SystemVersion.plist",
                                 encoding: .utf8))
            .flatMap { _ in
                (try? PropertyListSerialization.propertyList(
                    from: Data(contentsOf: URL(fileURLWithPath: "/System/Library/CoreServices/SystemVersion.plist")),
                    options: [], format: nil) as? [String: Any])?["ProductBuildVersion"] as? String
            } ?? "unknown"
        return HostInfo(
            osVersion: "macOS \(v.majorVersion).\(v.minorVersion).\(v.patchVersion)",
            osBuild: build,
            hostname: Host.current().localizedName ?? ProcessInfo.processInfo.hostName,
            userName: NSUserName(),
            timestamp: Date())
    }
}
