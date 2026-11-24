import Foundation
import PVSAuditCore

// A tiny assertion harness. Runs with `swift run pvsaudit-selftest`.
// Exits non-zero on failure so CI (or a Makefile) can gate on it.

final class Harness {
    private(set) var passed = 0
    private(set) var failed = 0
    private var failures: [String] = []
    private var currentTest = ""

    /// Assertions record against the current test instead of throwing, so test
    /// bodies stay linear and a single failure does not mask later checks.
    func test(_ name: String, _ body: () -> Void) {
        currentTest = name
        let before = failed
        body()
        if failed == before { passed += 1 }
    }

    func expect(_ cond: Bool, _ msg: @autoclosure () -> String,
                file: StaticString = #file, line: UInt = #line) {
        if !cond { record(msg(), file: file, line: line) }
    }

    func expectEqual<T: Equatable>(_ a: T, _ b: T, _ msg: @autoclosure () -> String,
                                   file: StaticString = #file, line: UInt = #line) {
        if a != b { record("\(msg()) — 期望 \(b)，实际 \(a)", file: file, line: line) }
    }

    private func record(_ text: String, file: StaticString, line: UInt) {
        failed += 1
        failures.append("[\(currentTest)] \(text)")
    }

    func finish() -> Int32 {
        print("")
        if failed == 0 {
            print("✓ 全部通过：\(passed) 项")
            return 0
        }
        print("✗ \(failed) 处断言失败，\(passed) 个测试通过")
        for f in failures { print("  · \(f)") }
        return 1
    }
}

private func fixture(_ lines: [String]) -> LogParser {
    let p = LogParser(); p.keepObservations = true
    for l in lines { p.ingest(line: Data(l.utf8)) }
    p.finish()
    return p
}

// MARK: - Real log fixtures (captured on macOS 26.5, identifiers preserved)

// Screen capture from Lark, brokered by WindowServer.
let screenCapture = [
    #"{"timestamp":"2026-11-24 07:13:54.100000+0800","eventMessage":"REQUEST: tccd_uid=0, sender_pid=403, sender_uid=88, sender_auid=-1, function=TCCAccessRequest, msgID=403.463"}"#,
    #"{"timestamp":"2026-11-24 07:13:54.120000+0800","eventMessage":"AUTHREQ_CTX: msgID=403.463, function=<private>, service=kTCCServiceScreenCapture, preflight=yes, query=1, client_dict=(null), daemon_dict=<private>"}"#,
    #"{"timestamp":"2026-11-24 07:13:54.130000+0800","eventMessage":"AUTHREQ_ATTRIBUTION: msgID=403.463, attribution={accessing={TCCDProcess: identifier=com.bytedance.macos.feishu, pid=638, auid=501, euid=501, binary_path=/Applications/Lark.app/Contents/MacOS/Feishu}, requesting={TCCDProcess: identifier=com.apple.WindowServer, pid=403, auid=88, euid=88, binary_path=/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/Resources/WindowServer}, }"}"#,
    #"{"timestamp":"2026-11-24 07:13:54.140000+0800","eventMessage":"AUTHREQ_SUBJECT: msgID=403.463, subject=com.bytedance.macos.feishu,"}"#,
    #"{"timestamp":"2026-11-24 07:13:54.150000+0800","eventMessage":"AUTHREQ_RESULT: msgID=403.463, authValue=2, authReason=4, authVersion=1, desired_auth=0, error=(null),"}"#,
]

let h = Harness()

// MARK: - Parser

h.test("代理进程应归因到真正的 App") {
    let p = fixture(screenCapture)
    h.expectEqual(p.output.observations.count, 1, "应恰好一条观测")
    let o = p.output.observations[0]
    h.expectEqual(o.appKey, "com.bytedance.macos.feishu", "WindowServer 只是代理")
    h.expectEqual(o.appPath, "/Applications/Lark.app/Contents/MacOS/Feishu", "应保留二进制路径")
    h.expectEqual(o.service, "kTCCServiceScreenCapture", "服务识别")
    h.expectEqual(o.kind, .statusCheck, "preflight=yes 是状态查询")
    h.expectEqual(o.allowed, true, "authValue=2 表示已授权")
}

h.test("preflight=no 代表真正使用") {
    let lines = screenCapture.map { $0.replacingOccurrences(of: "preflight=yes", with: "preflight=no") }
    h.expectEqual(fixture(lines).output.observations.first?.kind, .accessRequest, "应判定为真实访问")
}

h.test("拒绝记录应标记为未授权") {
    let lines = screenCapture.map { $0.replacingOccurrences(of: "authValue=2", with: "authValue=0") }
    h.expectEqual(fixture(lines).output.observations.first?.allowed, false, "authValue=0")
}

h.test("脱敏记录应忽略而非猜测") {
    let lines = [
        #"{"timestamp":"2026-11-24 07:13:54.120000+0800","eventMessage":"AUTHREQ_CTX: msgID=1.1, function=<private>, service=kTCCServiceCamera, preflight=yes, query=1"}"#,
        #"{"timestamp":"2026-11-24 07:13:54.130000+0800","eventMessage":"AUTHREQ_ATTRIBUTION: msgID=1.1, attribution={accessing={TCCDProcess: identifier=<private>, pid=1}, }"}"#,
        #"{"timestamp":"2026-11-24 07:13:54.150000+0800","eventMessage":"AUTHREQ_RESULT: msgID=1.1, authValue=2, authReason=4"}"#,
    ]
    let p = fixture(lines)
    h.expect(p.output.observations.isEmpty, "脱敏数据不应产出观测")
    h.expectEqual(p.output.unattributed, 1, "应计入未归因")
}

h.test("未编目服务应丢弃") {
    let lines = screenCapture.map {
        $0.replacingOccurrences(of: "kTCCServiceScreenCapture", with: "kTCCServiceSomethingNew")
    }
    h.expect(fixture(lines).output.observations.isEmpty, "未知服务不应产出发现")
}

h.test("生命周期 Create 变授权，Delete 不变") {
    let lines = [
        #"{"timestamp":"2026-11-25 02:21:00.000000+0800","eventMessage":"Publishing <TCCDEvent: type=Create, service=kTCCServiceSystemPolicyAllFiles, identifier_type=Bundle ID, identifier=com.example.corp.tool> to 0 subscribers: {}"}"#,
        #"{"timestamp":"2026-11-25 02:22:00.000000+0800","eventMessage":"Publishing <TCCDEvent: type=Delete, service=kTCCServiceAccessibility, identifier_type=Bundle ID, identifier=com.example.corp.tool> to 0 subscribers: {}"}"#,
    ]
    let p = fixture(lines)
    h.expectEqual(p.output.lifecycle.count, 1, "只应保留 Create")
    h.expectEqual(p.output.lifecycle.first?.client, "com.example.corp.tool", "客户端识别")
}

h.test("畸形日志不应崩溃") {
    let p = fixture(["not json", "{}", #"{"eventMessage":123}"#, ""])
    h.expect(p.output.observations.isEmpty, "无观测")
    h.expect(p.output.malformedLines > 0, "应统计畸形行")
}

h.test("路径型客户端应保留") {
    let lines = screenCapture.map {
        $0.replacingOccurrences(of: "identifier=com.bytedance.macos.feishu",
                                with: "identifier=/Users/x/Projects/MyTool/build/MyTool")
    }
    h.expectEqual(fixture(lines).output.observations.first?.appKey,
                  "/Users/x/Projects/MyTool/build/MyTool", "路径应被当作标识")
}

// MARK: - Usage aggregation

h.test("用量汇总区分状态查询与真实访问") {
    let obs = [
        Observation(appKey: "com.x.a", appPath: nil, service: "kTCCServiceCamera",
                    at: Date(timeIntervalSince1970: 1_000), kind: .statusCheck, allowed: nil),
        Observation(appKey: "com.x.a", appPath: nil, service: "kTCCServiceCamera",
                    at: Date(timeIntervalSince1970: 2_000), kind: .accessRequest, allowed: true),
        Observation(appKey: "com.x.a", appPath: nil, service: "kTCCServiceCamera",
                    at: Date(timeIntervalSince1970: 3_000), kind: .accessRequest, allowed: false),
    ]
    let s = AuditEngine.summarizeUsage(obs)
    h.expectEqual(s.count, 1, "应聚合成一条")
    h.expectEqual(s[0].observedCount, 3, "观测总数")
    h.expectEqual(s[0].accessRequestCount, 1, "只统计成功的真实访问")
    h.expectEqual(s[0].lastActualUse, Date(timeIntervalSince1970: 2_000), "最后真实使用时间")
    h.expectEqual(s[0].lastTouched, Date(timeIntervalSince1970: 3_000), "最后触达时间")
}

// MARK: - Risk engine: the "don't break people's work" guarantees

let now = Date(timeIntervalSince1970: 1_800_000_000)
func daysAgo(_ d: Double) -> Date { now.addingTimeInterval(-d * 86_400) }

func app(_ bid: String, team: String? = "TEAM123", sig: SignatureKind = .developerID,
         installed: Bool = true, lastUsed: Date? = nil, apple: Bool = false) -> AppIdentity {
    AppIdentity(bundleID: bid, path: "/Applications/\(bid).app",
                displayName: bid, version: "1.0", teamID: team,
                signature: apple ? .apple : sig,
                installed: installed, lastUsed: lastUsed, running: false)
}

func grant(_ bid: String, _ svc: String) -> Grant {
    Grant(service: svc, client: bid, clientType: 0, allowed: true,
          authValue: 2, authReason: 4, lastModified: daysAgo(400),
          indirectObject: nil, source: .userTCCDB)
}

func run(_ gs: [Grant], _ us: [UsageSummary], _ apps: [AppIdentity],
         policy: Policy = .default) -> [Finding] {
    RiskEngine().evaluate(.init(grants: gs, usage: us, apps: Dictionary(
        uniqueKeysWithValues: apps.map { ($0.bundleID ?? $0.key, $0) }),
        policy: policy, now: now))
}

h.test("受保护 App 永不建议收回（即使风险项）") {
    let f = run([grant("com.microsoft.teams", "kTCCServiceScreenCapture")], [],
                [app("com.microsoft.teams")])
    h.expectEqual(f[0].recommendation, .keep, "Teams 应受保护")
    h.expectEqual(f[0].score, 0, "受保护项不应有风险分")
}

h.test("Apple 组件永不收回") {
    let f = run([grant("com.apple.finder", "kTCCServiceSystemPolicyAllFiles")], [],
                [app("com.apple.finder", team: nil, sig: .apple, apple: true)])
    h.expectEqual(f[0].recommendation, .keep, "Apple 组件保留")
}

h.test("伪造 com.apple.* 的自签名 App 不得被豁免") {
    // Security regression: `isApple` must not trust the bundle-id prefix.
    // Otherwise any ad-hoc-signed app can name itself com.apple.* and be
    // permanently skipped by the audit.
    let spoof = AppIdentity(bundleID: "com.apple.NotesHelper",
                            path: "/Applications/NotesHelper.app",
                            displayName: "NotesHelper", version: "1", teamID: nil,
                            signature: .adhoc, installed: true,
                            lastUsed: daysAgo(200), running: false)
    h.expect(!spoof.isApple, "仅凭 com.apple.* 前缀不能判定为 Apple")
    h.expect(spoof.claimsAppleIdentityUnverified, "应标记为可疑伪装")

    let f = run([grant("com.apple.NotesHelper", "kTCCServiceScreenCapture")],
                [UsageSummary(appKey: "com.apple.NotesHelper", appPath: nil,
                              service: "kTCCServiceScreenCapture",
                              lastTouched: daysAgo(300), lastActualUse: daysAgo(300),
                              observedCount: 3, accessRequestCount: 3)],
                [spoof])
    h.expect(f[0].recommendation != .keep, "伪装 App 不得被保留")
    h.expect(f[0].reasons.contains { $0.contains("伪装") }, "应写明疑似伪装")
}

h.test("真正的 Apple 签名仍被识别") {
    let real = AppIdentity(bundleID: "com.apple.Safari", path: "/Applications/Safari.app",
                           displayName: "Safari", version: "1", teamID: nil,
                           signature: .apple, installed: true, lastUsed: nil, running: false)
    h.expect(real.isApple, "Apple 签名应被识别")
    h.expect(!real.claimsAppleIdentityUnverified, "不应误报伪装")
}

h.test("系统内置守护进程识别为系统程序而非三方工具") {
    for p in ["/usr/libexec/sharingd", "/usr/bin/osascript", "/System/x/y"] {
        let a = AppIdentity(bundleID: "com.apple.x", path: p, displayName: "x", version: nil,
                            teamID: nil, signature: .unknown, installed: true,
                            lastUsed: nil, running: false)
        h.expect(a.isSystemBinary, "\(p) 应识别为系统程序")
        h.expect(!a.claimsAppleIdentityUnverified, "系统程序不应被当成伪装")
        let f = run([grant("com.apple.x", "kTCCServiceAddressBook")], [], [a])
        h.expectEqual(f[0].recommendation, .keep, "\(p) 应被排除在审计外")
    }
}

h.test("用户装在 /usr/local 的三方工具不算系统程序") {
    let cli = AppIdentity(bundleID: "a.out", path: "/usr/local/bin/clidex",
                          displayName: "clidex", version: nil, teamID: nil,
                          signature: .unknown, installed: true, lastUsed: nil, running: false)
    h.expect(!cli.isSystemBinary, "/usr/local 不属于系统卷")
}

h.test("近期真实使用的权限不收回") {
    let usage = [UsageSummary(appKey: "com.x.tool", appPath: nil,
                              service: "kTCCServiceScreenCapture",
                              lastTouched: daysAgo(1), lastActualUse: daysAgo(1),
                              observedCount: 5, accessRequestCount: 5)]
    let f = run([grant("com.x.tool", "kTCCServiceScreenCapture")], usage, [app("com.x.tool")])
    h.expectEqual(f[0].recommendation, .keep, "在用即保留")
}

h.test("长期未用 + 未签名 → 建议收回") {
    let usage = [UsageSummary(appKey: "com.acquired.tool", appPath: nil,
                              service: "kTCCServiceScreenCapture",
                              lastTouched: daysAgo(300), lastActualUse: daysAgo(300),
                              observedCount: 3, accessRequestCount: 3)]
    let f = run([grant("com.acquired.tool", "kTCCServiceScreenCapture")], usage,
                [app("com.acquired.tool", sig: .unsigned, lastUsed: daysAgo(200))])
    h.expectEqual(f[0].recommendation, .revoke, "应收")
    h.expect(f[0].score >= 70, "分数应偏高，实际 \(f[0].score)")
}

h.test("辅助功能永不自动收回，转人工复核") {
    let usage = [UsageSummary(appKey: "com.acquired.tool", appPath: nil,
                              service: "kTCCServiceAccessibility",
                              lastTouched: daysAgo(300), lastActualUse: nil,
                              observedCount: 1, accessRequestCount: 0)]
    let f = run([grant("com.acquired.tool", "kTCCServiceAccessibility")], usage,
                [app("com.acquired.tool", sig: .unsigned, lastUsed: daysAgo(200))])
    h.expectEqual(f[0].recommendation, .review, "必须人工复核")
    h.expectEqual(f[0].canResetLocally, false, "不可本地 reset")
}

h.test("已卸载 App 转为 PPPC 下发建议") {
    let usage = [UsageSummary(appKey: "com.gone.app", appPath: nil,
                              service: "kTCCServiceCamera",
                              lastTouched: daysAgo(300), lastActualUse: daysAgo(300),
                              observedCount: 3, accessRequestCount: 3)]
    let f = run([grant("com.gone.app", "kTCCServiceCamera")], usage,
                [app("com.gone.app", installed: false, lastUsed: daysAgo(300))])
    h.expectEqual(f[0].recommendation, .remediateViaProfile, "应走描述文件")
    h.expectEqual(f[0].canResetLocally, false, "tccutil 无法处理")
}

h.test("结果按风险分降序") {
    let gs = [grant("com.a.low", "kTCCServiceMediaLibrary"),
              grant("com.b.high", "kTCCServiceSystemPolicyAllFiles")]
    let f = run(gs, [], [app("com.a.low"), app("com.b.high")])
    h.expect(f[0].score >= f[1].score, "必须降序")
}

// MARK: - Executor gates

h.test("executor dry-run 绝不调用 tccutil") {
    // Point tccutil at a path that does not exist: if dry-run ever shells out,
    // it will surface as a failure. This proves dry-run is truly inert.
    let f = run([grant("com.x.tool", "kTCCServiceScreenCapture")],
                [UsageSummary(appKey: "com.x.tool", appPath: nil,
                              service: "kTCCServiceScreenCapture",
                              lastTouched: daysAgo(300), lastActualUse: daysAgo(300),
                              observedCount: 3, accessRequestCount: 3)],
                [app("com.x.tool", sig: .unsigned, lastUsed: daysAgo(200))])
    let exec = RevocationExecutor(policy: .default,
                                  tccutilPath: "/nonexistent/tccutil", now: now)
    let r = exec.execute(f, mode: .dryRun)
    h.expect(r.actions.allSatisfy { $0.outcome != .resetFailed },
             "dry-run 不应尝试执行")
    h.expect(r.actions.contains { $0.outcome == .resetOK || $0.outcome == .needsProfile },
             "应产出计划项")
}

h.test("executor 对已卸载 .app 走 PPPC 而非 reset") {
    // An .app bundle that is no longer on disk: tccutil refuses these, so the
    // durable fix is a profile.
    let gone = AppIdentity(bundleID: "com.gone.app", path: "/Applications/com.gone.app.app",
                           displayName: "gone", version: nil, teamID: "T", signature: .developerID,
                           installed: false, lastUsed: daysAgo(300), running: false)
    let f = [Finding(app: gone, serviceID: "kTCCServiceCamera", serviceName: "Camera",
                     serviceDisplay: "摄像头", grant: grant("com.gone.app", "kTCCServiceCamera"),
                     usage: nil, score: 80, band: .high,
                     recommendation: .remediateViaProfile, reasons: [], blockers: [],
                     canResetLocally: false)]
    let r = RevocationExecutor(policy: .default, now: now).execute(f, mode: .apply)
    h.expectEqual(r.actions.first?.outcome, .needsProfile, "已卸载 .app 应转 PPPC")
}

h.test("executor 对命令行工具授权拒绝并提示人工") {
    let cli = AppIdentity(bundleID: "a.out", path: "/usr/local/bin/clidex",
                          displayName: "clidex", version: nil, teamID: nil,
                          signature: .unknown, installed: true, lastUsed: nil, running: false)
    let f = [Finding(app: cli, serviceID: "kTCCServiceListenEvent",
                     serviceName: "ListenEvent", serviceDisplay: "输入监控",
                     grant: grant("a.out", "kTCCServiceListenEvent"),
                     usage: nil, score: 95, band: .critical,
                     recommendation: .reviewNonBundle, reasons: [], blockers: [],
                     canResetLocally: false)]
    let r = RevocationExecutor(policy: .default, now: now).execute(f, mode: .apply)
    h.expectEqual(r.actions.first?.outcome, .notInstalled,
                  "非 .app 授权 tccutil 无法处理")
}

h.test("PPPC 不为非 bundle 授权生成无效条目") {
    let cli = AppIdentity(bundleID: "a.out", path: "/usr/local/bin/clidex",
                          displayName: "clidex", version: nil, teamID: nil,
                          signature: .unknown, installed: true, lastUsed: nil, running: false)
    let f = Finding(app: cli, serviceID: "kTCCServiceListenEvent", serviceName: "ListenEvent",
                    serviceDisplay: "输入监控", grant: nil, usage: nil, score: 95,
                    band: .critical, recommendation: .reviewNonBundle,
                    reasons: [], blockers: [], canResetLocally: false)
    let data = PPPCGenerator().profile(denials: [f], organization: "Acme")
    h.expect(data == nil, "不应为无法生效的目标生成描述文件")
}

h.test("executor 跳过仍在使用的权限") {
    let f = [Finding(app: app("com.x.tool"), serviceID: "kTCCServiceCamera",
                     serviceName: "Camera", serviceDisplay: "摄像头",
                     grant: grant("com.x.tool", "kTCCServiceCamera"),
                     usage: UsageSummary(appKey: "com.x.tool", appPath: nil,
                                         service: "kTCCServiceCamera",
                                         lastTouched: daysAgo(1), lastActualUse: daysAgo(1),
                                         observedCount: 2, accessRequestCount: 2),
                     score: 90, band: .critical, recommendation: .revoke,
                     reasons: [], blockers: [], canResetLocally: true)]
    let r = RevocationExecutor(policy: .default, now: now).execute(f, mode: .apply)
    h.expectEqual(r.actions.first?.outcome, .skippedActiveUse, "执行前必须再次校验在用状态")
}

// MARK: - Policy

h.test("策略通配匹配") {
    let p = ProtectedApp(bundleIDPattern: "com.microsoft.teams*", reason: "会议")
    h.expect(p.matches("com.microsoft.teams2"), "前缀应匹配")
    h.expect(p.matches("com.microsoft.teams"), "精确应匹配")
    h.expect(!p.matches("com.evil.teams"), "不应误匹配")
}

h.test("默认策略覆盖常见工作软件") {
    let must = ["com.microsoft.teams", "com.zoom.xos", "com.bytedance.macos.feishu",
                "com.googlecode.iterm2", "com.crowdstrike.falcon"]
    for bid in must {
        h.expect(Policy.default.protectedApps.contains { $0.matches(bid) }, "\(bid) 应受保护")
    }
}

// MARK: - TCC.db reader (against a synthetic database with a known schema)

h.test("TCC.db 读取：只保留已授权、已编目的服务") {
    let path = NSTemporaryDirectory() + "pvsaudit-fake-\(getpid()).db"
    defer { try? FileManager.default.removeItem(atPath: path) }
    let sql = """
    CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER,
      auth_value INTEGER, auth_reason INTEGER, last_modified INTEGER,
      indirect_object_identifier TEXT);
    INSERT INTO access VALUES ('kTCCServiceScreenCapture','com.acquired.app',0,2,4,1700000000,'UNUSED');
    INSERT INTO access VALUES ('kTCCServiceCamera','com.denied.app',0,0,2,1720000000,'UNUSED');
    INSERT INTO access VALUES ('kTCCServiceAppleEvents','com.script.app',0,2,4,1730000000,'com.apple.finder');
    INSERT INTO access VALUES ('kTCCServiceUnknownNew','com.x.app',0,2,4,1740000000,'UNUSED');
    INSERT INTO access VALUES ('kTCCServiceMicrophone','/opt/tool/bin/rec',1,2,4,1750000000,'UNUSED');
    """
    let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/sqlite3")
    p.arguments = [path, sql]
    try? p.run(); p.waitUntilExit()

    guard let grants = try? TCCDatabaseReader().readGrants(path: path, source: .userTCCDB) else {
        h.expect(false, "读取应成功"); return
    }
    h.expectEqual(grants.count, 3, "应保留 3 条（丢弃拒绝项与未编目服务）")
    h.expect(grants.contains { $0.client == "com.acquired.app" }, "应含屏幕录制授权")
    h.expect(grants.contains { $0.client == "/opt/tool/bin/rec" && $0.clientType == 1 },
             "路径型客户端应保留")
    h.expect(!grants.contains { $0.client == "com.denied.app" }, "拒绝项不应出现")
    h.expect(!grants.contains { $0.service == "kTCCServiceUnknownNew" }, "未编目服务应丢弃")
    let ae = grants.first { $0.client == "com.script.app" }
    h.expectEqual(ae?.indirectObject, "com.apple.finder", "应读出自变量目标")
}

h.test("TCC.db 打开失败时报告无权限而非伪造数据") {
    let reader = TCCDatabaseReader()
    h.expect(!reader.canRead(path: "/nonexistent/TCC.db"), "不存在的库应判为不可读")
    do {
        _ = try reader.readGrants(path: "/nonexistent/TCC.db", source: .userTCCDB)
        h.expect(false, "应抛错")
    } catch { /* expected */ }
}

// MARK: - Reporting & serialization

h.test("扫描结果可 JSON 往返") {
    let state = ScanState(
        schemaVersion: 1, generatedAt: now,
        host: HostInfo(osVersion: "macOS 26.5", osBuild: "25F80", hostname: "h",
                       userName: "u", timestamp: now),
        capability: CapabilityReport(hasFullDiskAccess: false, canReadUserTCCDB: false,
                                     canReadSystemTCCDB: false, canReadUnifiedLog: true,
                                     logRetentionDays: 14, tccutilPath: "/usr/bin/tccutil",
                                     tccutilWorks: true, notes: []),
        policyName: "default", findings: [], diagnostics: Diagnostics(
            logEventsParsed: 0, logWindowDays: 14, unattributedEvents: 0,
            grantSourcesUsed: [], appsScanned: 0, warnings: []))
    let e = JSONEncoder(); e.dateEncodingStrategy = .iso8601
    let d = (try? e.encode(state)) ?? Data()
    let de = JSONDecoder(); de.dateDecodingStrategy = .iso8601
    let back = try? de.decode(ScanState.self, from: d)
    h.expect(back != nil, "应能解码")
    h.expectEqual(back?.host.osVersion, "macOS 26.5", "往返一致")
}

h.test("报告包含关键提示") {
    let f = Finding(app: app("com.acquired.tool", sig: .unsigned),
                    serviceID: "kTCCServiceScreenCapture", serviceName: "ScreenCapture",
                    serviceDisplay: "屏幕录制",
                    grant: grant("com.acquired.tool", "kTCCServiceScreenCapture"),
                    usage: nil, score: 92, band: .critical, recommendation: .revoke,
                    reasons: ["已 300 天没有真正使用"], blockers: [], canResetLocally: true)
    let state = ScanState(
        schemaVersion: 1, generatedAt: now,
        host: HostInfo(osVersion: "macOS 26.5", osBuild: "25F80", hostname: "h",
                       userName: "u", timestamp: now),
        capability: CapabilityReport(hasFullDiskAccess: false, canReadUserTCCDB: false,
                                     canReadSystemTCCDB: false, canReadUnifiedLog: true,
                                     logRetentionDays: 14, tccutilPath: "/usr/bin/tccutil",
                                     tccutilWorks: true, notes: ["未获得完全磁盘访问"]),
        policyName: "default", findings: [f],
        diagnostics: Diagnostics(logEventsParsed: 0, logWindowDays: 14,
                                 unattributedEvents: 0, grantSourcesUsed: [],
                                 appsScanned: 1, warnings: []))
    let text = Reporter().render(state)
    h.expect(text.contains("屏幕录制"), "应显示服务")
    h.expect(text.contains("tccutil reset ScreenCapture"), "应给出可执行命令")
    h.expect(text.contains("只读结果"), "应声明未做修改")
}

// MARK: - PPPC

h.test("PPPC 描述文件含代码要求") {
    let f = Finding(app: app("com.gone.app", team: "ABC123"),
                    serviceID: "kTCCServiceCamera", serviceName: "Camera",
                    serviceDisplay: "摄像头", grant: nil, usage: nil, score: 80,
                    band: .high, recommendation: .remediateViaProfile,
                    reasons: [], blockers: [], canResetLocally: false)
    let data = PPPCGenerator().profile(denials: [f], organization: "Acme")
    h.expect(data != nil, "应生成描述文件")
    let s = String(data: data!, encoding: .utf8) ?? ""
    h.expect(s.contains("ABC123"), "应包含 Team ID 约束")
    h.expect(s.contains("com.apple.TCC.configuration-profile-policy"), "应为 TCC payload")
    h.expect(s.contains("Camera"), "应写入正确的服务键")
}

h.test("PPPC 不得把某服务的拒绝项写到别的服务下") {
    // Regression: an earlier version emitted every denial under BOTH
    // ScreenCapture and Accessibility, which would silently strip a live
    // Accessibility grant — the worst kind of false positive.
    let screen = Finding(app: app("com.gone.app", team: "ABC123"),
                         serviceID: "kTCCServiceScreenCapture", serviceName: "ScreenCapture",
                         serviceDisplay: "屏幕录制", grant: nil, usage: nil, score: 80,
                         band: .high, recommendation: .remediateViaProfile,
                         reasons: [], blockers: [], canResetLocally: false)
    let data = PPPCGenerator().profile(denials: [screen], organization: "Acme")
    let s = String(data: data!, encoding: .utf8) ?? ""
    h.expect(s.contains("ScreenCapture"), "应包含屏幕录制")
    h.expect(!s.contains("Accessibility"), "绝不能出现未请求的辅助功能")
}

h.test("PPPC 保留已安装状态无关的 bundle 目标") {
    // Denying an already-removed bundle is a primary PPPC use; it must not be
    // skipped just because the app is gone from disk.
    let gone = AppIdentity(bundleID: "com.gone.app", path: "/Applications/com.gone.app.app",
                           displayName: "Gone", version: nil, teamID: "T", signature: .developerID,
                           installed: false, lastUsed: nil, running: false)
    let f = Finding(app: gone, serviceID: "kTCCServiceCamera", serviceName: "Camera",
                    serviceDisplay: "摄像头", grant: nil, usage: nil, score: 80,
                    band: .high, recommendation: .remediateViaProfile,
                    reasons: [], blockers: [], canResetLocally: false)
    h.expect(PPPCGenerator().profile(denials: [f], organization: "A") != nil,
             "已卸载的 bundle 仍应可下发")
}

exit(h.finish())
