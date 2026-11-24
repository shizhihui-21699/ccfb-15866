import Foundation

/// Executes revocations. Two hard rules:
///   * Dry run unless the caller explicitly applies (the CLI requires `--apply`).
///   * Re-validate every action against the live system right before doing it;
///     never trust the plan file alone (it may be stale or edited by hand).
public struct RevocationExecutor {

    public enum Mode { case dryRun, apply }

    public enum Outcome: String, Codable {
        case skippedProtected, skippedNotAutoRevocable, skippedActiveUse, skippedWeakEvidence
        , skippedNoGrant, resetOK, resetFailed, needsProfile, notInstalled
    }

    public struct ActionResult: Codable {
        public var appKey: String
        public var appName: String
        public var service: String
        public var serviceDisplay: String
        public var outcome: Outcome
        public var detail: String
    }

    public struct Report: Codable {
        public var mode: String
        public var startedAt: Date
        public var finishedAt: Date
        public var actions: [ActionResult]
        public var changed: Int { actions.filter { $0.outcome == .resetOK }.count }
    }

    public var policy: Policy
    public var tccutilPath: String
    public var now: Date

    public init(policy: Policy, tccutilPath: String = "/usr/bin/tccutil", now: Date = Date()) {
        self.policy = policy
        self.tccutilPath = tccutilPath
        self.now = now
    }

    /// Executes the revocations among `findings` that pass every gate.
    public func execute(_ findings: [Finding], mode: Mode) -> Report {
        let started = Date()
        var actions: [ActionResult] = []

        // Rebuild a fresh inventory so we judge against reality, not the scan file.
        let liveApps = AppInventory().scan()

        for f in findings {
            guard f.recommendation == .revoke
                || f.recommendation == .remediateViaProfile
                || f.recommendation == .reviewNonBundle
            else { continue }

            let service = f.serviceName
            let bundleID = f.app.bundleID

            // Gate 1: protected by policy.
            if let p = policy.protectedApps.first(where: { $0.matches(bundleID) }) {
                actions.append(.init(appKey: f.app.key, appName: f.app.displayName ?? f.app.key,
                                     service: f.serviceID, serviceDisplay: f.serviceDisplay,
                                     outcome: .skippedProtected, detail: "策略保护：\(p.reason)"))
                continue
            }
            // Gate 2: Apple/system.
            if f.app.isApple {
                actions.append(.init(appKey: f.app.key, appName: f.app.displayName ?? f.app.key,
                                     service: f.serviceID, serviceDisplay: f.serviceDisplay,
                                     outcome: .skippedProtected, detail: "Apple 系统组件"))
                continue
            }
            // Gate 3: still actively used (fresh evidence, not the scan's opinion).
            if let last = f.usage?.lastActualUse,
               let d = Calendar.current.dateComponents([.day], from: last, to: now).day,
               d <= policy.activeUseWindowDays {
                actions.append(.init(appKey: f.app.key, appName: f.app.displayName ?? f.app.key,
                                     service: f.serviceID, serviceDisplay: f.serviceDisplay,
                                     outcome: .skippedActiveUse, detail: "最近 \(d) 天仍在真正使用"))
                continue
            }
            // Gate 4: service may not be auto-revoked.
            guard let spec = ServiceCatalog.spec(for: f.serviceID), spec.autoRevocable else {
                actions.append(.init(appKey: f.app.key, appName: f.app.displayName ?? f.app.key,
                                     service: f.serviceID, serviceDisplay: f.serviceDisplay,
                                     outcome: .skippedNotAutoRevocable,
                                     detail: "该权限不允许自动收回，需人工复核"))
                continue
            }
            // Gate 4b: weak evidence must not trigger an automatic revoke.
            if let g = f.grant, g.source.confidence != .confirmed {
                actions.append(.init(appKey: f.app.key, appName: f.app.displayName ?? f.app.key,
                                     service: f.serviceID, serviceDisplay: f.serviceDisplay,
                                     outcome: .skippedWeakEvidence,
                                     detail: "授权来自日志推断，请先用完全磁盘访问确认"))
                continue
            }
            // Gate 5: the grant must be addressable the way we intend to act.
            // tccutil only accepts a bundle id for an installed .app; a grant
            // keyed by a CLI tool / JVM identifier cannot be reset by it at all.
            // tccutil resolves a bundle id against installed *bundle* copies only.
            // A file existing at some executable path does not make a grant
            // addressable — the inventory entry must be a real .app bundle.
            let liveApp = liveApps[bundleID ?? ""]
            let liveInstalled = liveApp != nil
            // "Was a bundle" vs "was never a bundle" decide the remedy: a
            // removed .app can still be denied by a bundleID PPPC profile, but
            // a CLI/JVM grant cannot be expressed that way at all.
            let bundleLike = (f.app.path ?? "").hasSuffix(".app") || liveInstalled
            if !bundleLike {
                actions.append(.init(appKey: f.app.key, appName: f.app.displayName ?? f.app.key,
                                     service: f.serviceID, serviceDisplay: f.serviceDisplay,
                                     outcome: .notInstalled,
                                     detail: "非 .app 包授权，tccutil 无法处理；需人工评估"))
                continue
            }
            guard liveInstalled, let bid = bundleID, !bid.isEmpty else {
                actions.append(.init(appKey: f.app.key, appName: f.app.displayName ?? f.app.key,
                                     service: f.serviceID, serviceDisplay: f.serviceDisplay,
                                     outcome: .needsProfile,
                                     detail: "App 已卸载，tccutil 无法处理；已生成 PPPC 建议"))
                continue
            }

            // Execute.
            switch mode {
            case .dryRun:
                actions.append(.init(appKey: f.app.key, appName: f.app.displayName ?? bid,
                                     service: f.serviceID, serviceDisplay: f.serviceDisplay,
                                     outcome: .resetOK, detail: "[dry-run] 将执行 tccutil reset \(service) \(bid)"))
            case .apply:
                let r = runTccutilReset(service: service, bundleID: bid)
                actions.append(.init(
                    appKey: f.app.key, appName: f.app.displayName ?? bid,
                    service: f.serviceID, serviceDisplay: f.serviceDisplay,
                    outcome: r.ok ? .resetOK : .resetFailed,
                    detail: r.message))
            }
        }

        return Report(mode: mode == .apply ? "apply" : "dry-run",
                      startedAt: started, finishedAt: Date(), actions: actions)
    }

    private func runTccutilReset(service: String, bundleID: String) -> (ok: Bool, message: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tccutilPath)
        p.arguments = ["reset", service, bundleID]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        do { try p.run() } catch { return (false, "无法启动 tccutil: \(error)") }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        let msg = String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return (p.terminationStatus == 0, msg)
    }
}

// MARK: - PPPC profile generation

/// For grants that cannot be cleared locally (app uninstalled, or a
/// system-scope grant), the durable fix is an MDM configuration profile with a
/// `com.apple.TCC.configuration-profile-policy` payload that denies the service
/// for that code requirement. We generate a ready-to-review profile rather than
/// touching the system directly.
public struct PPPCGenerator {

    public init() {}

    public func profile(denials: [Finding], organization: String) -> Data? {
        // Group by service: a denial for ScreenCapture must NOT be emitted under
        // Accessibility. The Services dictionary keys are TCC service names; one
        // entry per service, each holding only the apps denied *that* service.
        var byService: [String: [[String: Any]]] = [:]

        for f in denials {
            // A bundleID-addressed PPPC entry is meaningless for a grant keyed
            // by a CLI identifier — deploying it would silently do nothing.
            guard let bid = f.app.bundleID, f.app.isPPPCAddressable else { continue }
            // Only emit for services that actually accept a PPPC deny entry.
            guard let ppService = Self.pppcServiceName(for: f.serviceID) else { continue }

            let req = f.app.teamID.map {
                "identifier \"\(bid)\" and anchor apple generic and certificate leaf[subject.OU] = \"\($0)\""
            } ?? "identifier \"\(bid)\""
            byService[ppService, default: []].append([
                "Identifier": bid,
                "IdentifierType": "bundleID",
                "CodeRequirement": req,
                "StaticCode": false,
                "Comment": "PVSAudit: \(f.serviceDisplay)",
            ])
        }
        guard !byService.isEmpty else { return nil }

        let payload: [String: Any] = [
            "PayloadType": "com.apple.TCC.configuration-profile-policy",
            "PayloadVersion": 1,
            "PayloadIdentifier": "com.pvsaudit.pppc.\(UUID().uuidString)",
            "PayloadUUID": UUID().uuidString,
            "PayloadDisplayName": "PVSAudit 权限收紧",
            "Services": byService,
        ]
        let profile: [String: Any] = [
            "PayloadType": "Configuration",
            "PayloadVersion": 1,
            "PayloadIdentifier": "com.pvsaudit.profile.\(UUID().uuidString)",
            "PayloadUUID": UUID().uuidString,
            "PayloadDisplayName": "PVSAudit 隐私权限收紧",
            "PayloadOrganization": organization,
            "PayloadContent": [payload],
        ]
        // NOTE: unsigned — must be signed by the org's MDM before deployment.
        return try? PropertyListSerialization.data(
            fromPropertyList: profile, format: .xml, options: 0)
    }

    /// Map an internal TCC service id to the name used as a key in a PPPC
    /// payload's `Services` dictionary. Returns nil for services that have no
    /// meaningful bundleID-based deny (e.g. app-managed or session services).
    static func pppcServiceName(for serviceID: String) -> String? {
        switch serviceID {
        case "kTCCServiceScreenCapture": return "ScreenCapture"
        case "kTCCServiceAccessibility": return "Accessibility"
        case "kTCCServiceCamera": return "Camera"
        case "kTCCServiceMicrophone": return "Microphone"
        case "kTCCServiceSystemPolicyAllFiles": return "SystemPolicyAllFiles"
        case "kTCCServiceSystemPolicyDesktopFolder": return "SystemPolicyDesktopFolder"
        case "kTCCServiceSystemPolicyDocumentsFolder": return "SystemPolicyDocumentsFolder"
        case "kTCCServiceSystemPolicyDownloadsFolder": return "SystemPolicyDownloadsFolder"
        case "kTCCServiceSystemPolicyNetworkVolumes": return "SystemPolicyNetworkVolumes"
        case "kTCCServiceSystemPolicyRemovableVolumes": return "SystemPolicyRemovableVolumes"
        case "kTCCServiceListenEvent": return "ListenEvent"
        case "kTCCServicePostEvent": return "PostEvent"
        case "kTCCServiceAppleEvents": return "AppleEvents"
        case "kTCCServicePhotos": return "Photos"
        case "kTCCServiceCalendar": return "Calendar"
        case "kTCCServiceAddressBook": return "AddressBook"
        case "kTCCServiceReminders": return "Reminders"
        case "kTCCServiceMediaLibrary": return "MediaLibrary"
        case "kTCCServiceSpeechRecognition": return "SpeechRecognition"
        default: return nil
        }
    }
}
