import Foundation

// MARK: - Policy document
//
// The policy is the safety mechanism that stops the tool from revoking a
// permission an employee needs for their job. It is intentionally *deny*-biased:
// anything not explicitly cleared for automatic action goes to a human, and a
// protected app is never touched by the executor.

public struct ProtectedApp: Codable, Hashable {
    /// Glob-ish bundle id, e.g. "com.microsoft.teams*" or exact "com.apple.Safari".
    public var bundleIDPattern: String
    public var reason: String
    public init(bundleIDPattern: String, reason: String) {
        self.bundleIDPattern = bundleIDPattern
        self.reason = reason
    }

    public func matches(_ bundleID: String?) -> Bool {
        guard let bid = bundleID else { return false }
        if bundleIDPattern.hasSuffix("*") {
            return bid.hasPrefix(String(bundleIDPattern.dropLast()))
        }
        return bid.caseInsensitiveCompare(bundleIDPattern) == .orderedSame
    }
}

public struct Policy: Codable {
    public var name: String
    public var version: Int

    /// Never revoke, never even recommend revoke, for these.
    public var protectedApps: [ProtectedApp]

    /// Team IDs that are trusted to keep permissions when unused-but-recent.
    public var trustedTeamIDs: [String]

    /// A grant last *actually used* within this many days is "in use".
    public var activeUseWindowDays: Int
    /// A grant touched (incl. status checks) within this many days is "warm".
    public var warmWindowDays: Int
    /// An app not launched in this many days is treated as dormant.
    public var dormantAppDays: Int

    /// Extra score for apps whose signature we cannot verify.
    public var unsignedPenalty: Int
    public var adhocPenalty: Int
    /// Score bump if the app has no Team ID but claims a vendor-looking bundle id.
    public var lookalikePenalty: Int

    /// True when a policy explicitly allows automatic handling of `serviceID`.
    ///
    /// A service can only ever be auto-revocable if its own `ServiceSpec`
    /// says so. There is deliberately no policy switch to widen this: a
    /// mistyped policy file must not be able to mass-revoke Accessibility or
    /// Automation, which are the most disruptive to a working user.
    public func allowsAutoRevoke(_ serviceID: String) -> Bool {
        ServiceCatalog.spec(for: serviceID)?.autoRevocable ?? false
    }

    public static let `default` = Policy(
        name: "default",
        version: 1,
        protectedApps: [
            // Communication & meeting — a revoked camera/mic silently breaks calls.
            .init(bundleIDPattern: "com.microsoft.teams*", reason: "公司会议工具"),
            .init(bundleIDPattern: "com.zoom.xos", reason: "公司会议工具"),
            .init(bundleIDPattern: "us.zoom.xos", reason: "公司会议工具"),
            .init(bundleIDPattern: "com.tencent.meeting*", reason: "公司会议工具"),
            .init(bundleIDPattern: "com.bytedance.macos.feishu*", reason: "公司 IM"),
            .init(bundleIDPattern: "com.tencent.xinWeChat", reason: "公司 IM"),
            .init(bundleIDPattern: "com.microsoft.Outlook", reason: "公司邮件"),
            .init(bundleIDPattern: "com.apple.Safari", reason: "系统浏览器"),
            // Developer & IT tooling that breaks loudly if reset mid-task.
            .init(bundleIDPattern: "com.apple.Terminal", reason: "系统终端"),
            .init(bundleIDPattern: "com.googlecode.iterm2", reason: "终端"),
            .init(bundleIDPattern: "com.microsoft.VSCode", reason: "开发工具"),
            .init(bundleIDPattern: "com.apple.dt.Xcode", reason: "开发工具"),
            // Security agents — resetting these is an outage.
            .init(bundleIDPattern: "com.crowdstrike.*", reason: "安全代理"),
            .init(bundleIDPattern: "com.sentinelone.*", reason: "安全代理"),
            .init(bundleIDPattern: "com.jamf.*", reason: "MDM 代理"),
            .init(bundleIDPattern: "com.apple.MobileAsset.*", reason: "系统组件"),
        ],
        trustedTeamIDs: [],
        activeUseWindowDays: 30,
        warmWindowDays: 90,
        dormantAppDays: 120,
        unsignedPenalty: 25,
        adhocPenalty: 15,
        lookalikePenalty: 20
    )
}

// MARK: - Policy loading

public enum PolicyLoader {
    public static func load(from path: String) throws -> Policy {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let dec = JSONDecoder()
        return try dec.decode(Policy.self, from: data)
    }

    public static func loadIfPresent(_ path: String?) -> (Policy, String?) {
        guard let path else { return (.default, nil) }
        do { return (try load(from: path), nil) }
        catch { return (.default, "策略文件加载失败，已回退到内置默认策略: \(error)") }
    }
}
