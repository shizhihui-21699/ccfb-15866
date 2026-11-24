import Foundation

// MARK: - Service catalog
//
// `id` is the raw TCC service identifier as it appears in TCC.db / the unified log.
// `tccutilName` is the spelling accepted by `/usr/bin/tccutil reset <name> <bundle>`.
// These were verified empirically on macOS 26.5; see docs/PERMISSIONS.md.

public enum ServiceCategory: String, Codable, CaseIterable {
    case screenSac, captureDevice, inputMonitoring, files, personalData, automation, developer
}

public struct ServiceSpec: Codable, Hashable {
    public let id: String
    public let tccutilName: String
    public let display: String
    public let risk: Int              // 0...100 base weight, before app/usage modifiers
    public let autoRevocable: Bool    // may the executor reset it without human review?
    public let observableUsage: Bool  // can we see actual *use* in the unified log?
    public let revokeEffect: String
    public let category: ServiceCategory

    public var isHighRisk: Bool { risk >= 70 }
}

public enum ServiceCatalog {
    /// Order matters only for report stability.
    public static let all: [ServiceSpec] = [
        .init(id: "kTCCServiceSystemPolicyAllFiles", tccutilName: "SystemPolicyAllFiles",
              display: "完全磁盘访问（读取全部文件）", risk: 95, autoRevocable: true,
              observableUsage: true, revokeEffect: "App 下次需要时会重新弹窗授权", category: .files),
        .init(id: "kTCCServiceAccessibility", tccutilName: "Accessibility",
              display: "辅助功能（控制键鼠/读取其他 App 内容）", risk: 92, autoRevocable: false,
              observableUsage: false, revokeEffect: "立即失效，不会弹窗；需用户手动重开", category: .inputMonitoring),
        .init(id: "kTCCServiceScreenCapture", tccutilName: "ScreenCapture",
              display: "屏幕录制", risk: 88, autoRevocable: true,
              observableUsage: true, revokeEffect: "录制中的 App 会中断，下次使用时重新弹窗", category: .screenSac),
        .init(id: "kTCCServicePostEvent", tccutilName: "PostEvent",
              display: "模拟键鼠事件（控制你的 Mac）", risk: 84, autoRevocable: false,
              observableUsage: false, revokeEffect: "立即失效；高风险，默认转人工复核", category: .inputMonitoring),
        .init(id: "kTCCServiceListenEvent", tccutilName: "ListenEvent",
              display: "输入监控（监听所有键盘/鼠标）", risk: 80, autoRevocable: true,
              observableUsage: true, revokeEffect: "立即失效，通常需重启 App 才恢复", category: .inputMonitoring),
        .init(id: "kTCCServiceSystemPolicySysAdminFiles", tccutilName: "SystemPolicySysAdminFiles",
              display: "系统管理文件访问", risk: 72, autoRevocable: true,
              observableUsage: true, revokeEffect: "App 下次需要时重新弹窗", category: .files),
        .init(id: "kTCCServiceMicrophone", tccutilName: "Microphone",
              display: "麦克风", risk: 62, autoRevocable: true,
              observableUsage: true, revokeEffect: "下次使用时重新弹窗", category: .captureDevice),
        .init(id: "kTCCServiceCamera", tccutilName: "Camera",
              display: "摄像头", risk: 60, autoRevocable: true,
              observableUsage: true, revokeEffect: "下次使用时重新弹窗", category: .captureDevice),
        .init(id: "kTCCServicePhotos", tccutilName: "Photos",
              display: "照片图库", risk: 58, autoRevocable: true,
              observableUsage: true, revokeEffect: "App 下次需要时重新弹窗", category: .personalData),
        .init(id: "kTCCServiceSystemPolicyDesktopFolder", tccutilName: "SystemPolicyDesktopFolder",
              display: "桌面文件夹", risk: 55, autoRevocable: true,
              observableUsage: true, revokeEffect: "下次访问该文件夹时重新弹窗", category: .files),
        .init(id: "kTCCServiceSystemPolicyDocumentsFolder", tccutilName: "SystemPolicyDocumentsFolder",
              display: "文稿文件夹", risk: 55, autoRevocable: true,
              observableUsage: true, revokeEffect: "下次访问该文件夹时重新弹窗", category: .files),
        .init(id: "kTCCServiceSystemPolicyDownloadsFolder", tccutilName: "SystemPolicyDownloadsFolder",
              display: "下载文件夹", risk: 52, autoRevocable: true,
              observableUsage: true, revokeEffect: "下次访问该文件夹时重新弹窗", category: .files),
        .init(id: "kTCCServiceAddressBook", tccutilName: "AddressBook",
              display: "通讯录", risk: 50, autoRevocable: true,
              observableUsage: true, revokeEffect: "App 下次需要时重新弹窗", category: .personalData),
        .init(id: "kTCCServiceSpeechRecognition", tccutilName: "SpeechRecognition",
              display: "语音识别", risk: 50, autoRevocable: true,
              observableUsage: true, revokeEffect: "App 下次需要时重新弹窗", category: .captureDevice),
        .init(id: "kTCCServiceAppleEvents", tccutilName: "AppleEvents",
              display: "自动化控制其他 App", risk: 50, autoRevocable: false,
              observableUsage: true, revokeEffect: "按目标 App 清零，粒度粗，默认转人工复核", category: .automation),
        .init(id: "kTCCServiceSystemPolicyNetworkVolumes", tccutilName: "SystemPolicyNetworkVolumes",
              display: "网络卷", risk: 48, autoRevocable: true,
              observableUsage: true, revokeEffect: "下次访问时重新弹窗", category: .files),
        .init(id: "kTCCServiceSystemPolicyRemovableVolumes", tccutilName: "SystemPolicyRemovableVolumes",
              display: "可移动卷", risk: 48, autoRevocable: true,
              observableUsage: true, revokeEffect: "下次访问时重新弹窗", category: .files),
        .init(id: "kTCCServiceCalendar", tccutilName: "Calendar",
              display: "日历", risk: 45, autoRevocable: true,
              observableUsage: true, revokeEffect: "App 下次需要时重新弹窗", category: .personalData),
        .init(id: "kTCCServiceReminders", tccutilName: "Reminders",
              display: "提醒事项", risk: 40, autoRevocable: true,
              observableUsage: true, revokeEffect: "App 下次需要时重新弹窗", category: .personalData),
        .init(id: "kTCCServiceMediaLibrary", tccutilName: "MediaLibrary",
              display: "媒体与 Apple Music", risk: 38, autoRevocable: true,
              observableUsage: true, revokeEffect: "App 下次需要时重新弹窗", category: .personalData),
        .init(id: "kTCCServiceSystemPolicyAppBundles", tccutilName: "SystemPolicyAppBundles",
              display: "管理其他 App", risk: 34, autoRevocable: true,
              observableUsage: true, revokeEffect: "下次操作时重新弹窗", category: .developer),
        .init(id: "kTCCServiceDeveloperTool", tccutilName: "DeveloperTool",
              display: "开发者工具", risk: 20, autoRevocable: true,
              observableUsage: true, revokeEffect: "下次使用时重新弹窗", category: .developer),
    ]

    private static let byID: [String: ServiceSpec] =
        Dictionary(uniqueKeysWithValues: all.map { ($0.id, $0) })
    private static let byTccutil: [String: ServiceSpec] =
        Dictionary(uniqueKeysWithValues: all.map { ($0.tccutilName, $0) })

    public static func spec(for id: String) -> ServiceSpec? { byID[id] }
    public static func spec(tccutilName: String) -> ServiceSpec? {
        byTccutil[tccutilName] ?? byID["kTCCService" + tccutilName]
    }
}

// MARK: - Signature / identity

public enum SignatureKind: String, Codable {
    case apple          // Apple platform binary or Apple-signed
    case developerID    // third-party signed with a Team ID
    case adhoc          // ad-hoc signed (local build / unsigned distribution)
    case unsigned
    case unknown

    public var isTrustedVendor: Bool { self == .apple || self == .developerID }
}

public struct AppIdentity: Codable, Hashable {
    public var bundleID: String?
    public var path: String?
    public var displayName: String?
    public var version: String?
    public var teamID: String?
    public var signature: SignatureKind
    public var installed: Bool
    public var lastUsed: Date?
    public var running: Bool

    public var key: String { bundleID ?? path ?? displayName ?? "unknown" }

    /// Is this genuinely Apple's own software?
    ///
    /// A `com.apple.*` bundle id alone is **not** proof: any ad-hoc-signed app
    /// can declare one. Trusting the prefix would let a third-party app exempt
    /// itself from the audit entirely — the worst possible false negative for
    /// this tool. Require a real Apple signature, or Apple's own system tree.
    public var isApple: Bool {
        if signature == .apple { return true }
        // Only a path under the sealed system volume counts; a lookalike in
        // /Applications or ~/Applications does not.
        if let p = path, p.hasPrefix("/System/"), signature != .adhoc, signature != .unsigned {
            return true
        }
        return false
    }

    /// A binary shipped by the OS itself (daemon, CLI, helper).
    ///
    /// These live outside `.app` bundles — /usr/libexec/sharingd, /usr/bin/osascript,
    /// /System/Library/… — and are TCC clients just like apps. They must be
    /// recognized from their *location*, because macOS 11+ signs them on the
    /// sealed system volume in a way `codesign -dvvv` from a plain shell does
    /// not always report as an Apple authority.
    ///
    /// Note this is deliberately narrower than "anything under /usr": a
    /// third-party tool in /usr/local/bin is *not* an OS binary.
    public var isSystemBinary: Bool {
        guard let p = path else { return false }
        if p.hasPrefix("/System/") { return true }
        if p.hasPrefix("/usr/libexec/") || p.hasPrefix("/usr/sbin/") { return true }
        if p.hasPrefix("/usr/bin/") || p.hasPrefix("/usr/lib/") { return true }
        if p.hasPrefix("/bin/") || p.hasPrefix("/sbin/") { return true }
        if p.hasPrefix("/Library/Apple/") { return true }
        return false
    }

    /// A bundle that claims an Apple identifier without an Apple signature.
    /// Worth surfacing, never worth exempting.
    public var claimsAppleIdentityUnverified: Bool {
        (bundleID?.hasPrefix("com.apple.") ?? false) && !isApple && !isSystemBinary
    }

    /// TCC rows can be keyed by a bundle id *or* by a bare code-signing
    /// identifier belonging to a command-line tool / JVM (e.g. "a.out",
    /// "net.java.openjdk.java"). Only the former is something tccutil or a
    /// bundleID-based PPPC profile can address.
    public var isBundleAddressed: Bool {
        guard installed, let path, path.hasSuffix(".app") else { return false }
        return bundleID != nil
    }

    /// Whether a `bundleID`-keyed PPPC profile could target this app.
    /// Unlike `isBundleAddressed`, this does **not** require the app to still be
    /// installed — denying a bundle that has since been removed is a primary
    /// use of PPPC, and the code requirement remains valid.
    public var isPPPCAddressable: Bool {
        guard bundleID != nil else { return false }
        // A path to a loose executable (CLI tool, JVM) is not a bundle. For such
        // grants `installed` came from "the file exists", which must not be read
        // as "a bundle exists". Only a .app path qualifies.
        return (path ?? "").hasSuffix(".app")
    }

    public init(bundleID: String?, path: String?, displayName: String?, version: String?,
                teamID: String?, signature: SignatureKind, installed: Bool,
                lastUsed: Date?, running: Bool) {
        self.bundleID = bundleID; self.path = path; self.displayName = displayName
        self.version = version; self.teamID = teamID; self.signature = signature
        self.installed = installed; self.lastUsed = lastUsed; self.running = running
    }
}

// MARK: - Grants (what permission exists)

public enum GrantSource: String, Codable {
    case userTCCDB          // ~/Library/Application Support/com.apple.TCC/TCC.db (needs FDA)
    case systemTCCDB        // /Library/Application Support/com.apple.TCC/TCC.db (needs FDA)
    case logLifecycle       // TCCDEvent Create/Modify seen in unified log (no permission)
    case logObservedGrant   // successful access (authValue=allows) implies a grant (no permission)

    /// How much weight to give this evidence when scoring and wording a finding.
    public var confidence: EvidenceConfidence {
        switch self {
        case .userTCCDB, .systemTCCDB: return .confirmed
        case .logLifecycle: return .probable
        case .logObservedGrant: return .inferred
        }
    }
}

public enum EvidenceConfidence: String, Codable {
    case confirmed   // read directly from TCC.db
    case probable    // grant lifecycle event in the log
    case inferred    // a successful request implies the grant existed
    var display: String {
        switch self {
        case .confirmed: return "已确认（TCC.db）"
        case .probable: return "较可信（日志授权事件）"
        case .inferred: return "推断（日志中访问成功）"
        }
    }
}

public struct Grant: Codable, Hashable {
    public var service: String
    public var client: String            // bundle id or path
    public var clientType: Int?          // TCC client_type (0=bundleID, 1=path, …)
    public var allowed: Bool?
    public var authValue: Int?
    public var authReason: Int?
    public var lastModified: Date?
    public var indirectObject: String?   // AppleEvents target app
    public var source: GrantSource

    public init(service: String, client: String, clientType: Int?, allowed: Bool?,
                authValue: Int?, authReason: Int?, lastModified: Date?,
                indirectObject: String?, source: GrantSource) {
        self.service = service; self.client = client; self.clientType = clientType
        self.allowed = allowed; self.authValue = authValue; self.authReason = authReason
        self.lastModified = lastModified; self.indirectObject = indirectObject
        self.source = source
    }
}

// MARK: - Usage (what actually happened)

public enum ObservationKind: String, Codable {
    case statusCheck    // preflight=yes: app asked "do I have permission?"
    case accessRequest  // preflight=no: app actually exercised the capability
}

public struct Observation: Codable, Hashable {
    public var appKey: String            // bundle id if known, else binary path
    public var appPath: String?
    public var service: String
    public var at: Date
    public var kind: ObservationKind
    public var allowed: Bool?

    public init(appKey: String, appPath: String?, service: String, at: Date,
                kind: ObservationKind, allowed: Bool?) {
        self.appKey = appKey; self.appPath = appPath; self.service = service
        self.at = at; self.kind = kind; self.allowed = allowed
    }
}

public struct UsageSummary: Codable, Hashable {
    public var appKey: String
    public var appPath: String?
    public var service: String
    public var lastTouched: Date
    public var lastActualUse: Date?
    public var observedCount: Int
    public var accessRequestCount: Int

    public init(appKey: String, appPath: String?, service: String, lastTouched: Date,
                lastActualUse: Date?, observedCount: Int, accessRequestCount: Int) {
        self.appKey = appKey; self.appPath = appPath; self.service = service
        self.lastTouched = lastTouched; self.lastActualUse = lastActualUse
        self.observedCount = observedCount; self.accessRequestCount = accessRequestCount
    }
}

// MARK: - Findings

public enum RiskBand: String, Codable, Comparable {
    case low, medium, high, critical
    public static func < (a: RiskBand, b: RiskBand) -> Bool { a.rank < b.rank }
    var rank: Int { switch self { case .low: 0; case .medium: 1; case .high: 2; case .critical: 3 } }
}

public enum Recommendation: String, Codable {
    case revoke              // safe to reset with tccutil now
    case remediateViaProfile // cannot reset locally (e.g. app uninstalled); emit PPPC deny
    case review              // needs a human (Accessibility, AppleEvents, coarse, ambiguous)
    case keep                // protected / actively used
    case noGrant             // usage seen but no grant known (denied or already cleared)
    case reviewNonBundle     // CLI/JVM binary grant: no tccutil, no bundleID PPPC
}

public struct Finding: Codable {
    public var app: AppIdentity
    public var serviceID: String
    public var serviceName: String
    public var serviceDisplay: String
    public var grant: Grant?
    public var usage: UsageSummary?
    public var score: Int
    public var band: RiskBand
    public var recommendation: Recommendation
    public var reasons: [String]
    public var blockers: [String]
    public var canResetLocally: Bool

    public init(app: AppIdentity, serviceID: String, serviceName: String,
                serviceDisplay: String, grant: Grant?, usage: UsageSummary?,
                score: Int, band: RiskBand, recommendation: Recommendation,
                reasons: [String], blockers: [String], canResetLocally: Bool) {
        self.app = app; self.serviceID = serviceID; self.serviceName = serviceName
        self.serviceDisplay = serviceDisplay; self.grant = grant; self.usage = usage
        self.score = score; self.band = band; self.recommendation = recommendation
        self.reasons = reasons; self.blockers = blockers
        self.canResetLocally = canResetLocally
    }
}

// MARK: - Scan state (the artifact passed between scan → apply)

public struct ScanState: Codable {
    public var schemaVersion: Int
    public var generatedAt: Date
    public var host: HostInfo
    public var capability: CapabilityReport
    public var policyName: String?
    public var findings: [Finding]
    public var diagnostics: Diagnostics

    public init(schemaVersion: Int, generatedAt: Date, host: HostInfo,
                capability: CapabilityReport, policyName: String?,
                findings: [Finding], diagnostics: Diagnostics) {
        self.schemaVersion = schemaVersion; self.generatedAt = generatedAt
        self.host = host; self.capability = capability; self.policyName = policyName
        self.findings = findings; self.diagnostics = diagnostics
    }
}

public struct HostInfo: Codable {
    public var osVersion: String
    public var osBuild: String
    public var hostname: String
    public var userName: String
    public var timestamp: Date

    public init(osVersion: String, osBuild: String, hostname: String,
                userName: String, timestamp: Date) {
        self.osVersion = osVersion; self.osBuild = osBuild; self.hostname = hostname
        self.userName = userName; self.timestamp = timestamp
    }
}

public struct CapabilityReport: Codable {
    public var hasFullDiskAccess: Bool
    public var canReadUserTCCDB: Bool
    public var canReadSystemTCCDB: Bool
    public var canReadUnifiedLog: Bool
    public var logRetentionDays: Int?
    public var tccutilPath: String
    public var tccutilWorks: Bool
    public var notes: [String]

    public init(hasFullDiskAccess: Bool, canReadUserTCCDB: Bool, canReadSystemTCCDB: Bool,
                canReadUnifiedLog: Bool, logRetentionDays: Int?, tccutilPath: String,
                tccutilWorks: Bool, notes: [String]) {
        self.hasFullDiskAccess = hasFullDiskAccess; self.canReadUserTCCDB = canReadUserTCCDB
        self.canReadSystemTCCDB = canReadSystemTCCDB; self.canReadUnifiedLog = canReadUnifiedLog
        self.logRetentionDays = logRetentionDays; self.tccutilPath = tccutilPath
        self.tccutilWorks = tccutilWorks; self.notes = notes
    }
}

public struct Diagnostics: Codable {
    public var logEventsParsed: Int
    public var logWindowDays: Int
    public var unattributedEvents: Int
    public var grantSourcesUsed: [String]
    public var appsScanned: Int
    public var warnings: [String]

    public init(logEventsParsed: Int, logWindowDays: Int, unattributedEvents: Int,
                grantSourcesUsed: [String], appsScanned: Int, warnings: [String]) {
        self.logEventsParsed = logEventsParsed; self.logWindowDays = logWindowDays
        self.unattributedEvents = unattributedEvents
        self.grantSourcesUsed = grantSourcesUsed; self.appsScanned = appsScanned
        self.warnings = warnings
    }
}
