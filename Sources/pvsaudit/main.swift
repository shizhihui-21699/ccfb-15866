import Foundation
import PVSAuditCore

// MARK: - Minimal argument parsing (no external deps)

struct Args {
    var command: String = "scan"
    var jsonPath: String? = nil
    var reportPath: String? = nil
    var policyPath: String? = nil
    var sinceDays: Int = 14
    var limit: Int? = nil
    var apply = false
    var planPath: String? = nil
    var profilePath: String? = nil
    var organization: String = "Your Company"
    var includeSystem = false
    var quiet = false

    static func parse(_ argv: [String]) -> Args {
        var a = Args()
        var i = 1
        if argv.count > 1, !argv[1].hasPrefix("-") {
            a.command = argv[1]; i = 2
        }
        while i < argv.count {
            let k = argv[i]
            func next() -> String? { i + 1 < argv.count ? argv[i+1] : nil }
            switch k {
            case "--json": a.jsonPath = next(); i += 1
            case "--report": a.reportPath = next(); i += 1
            case "--policy": a.policyPath = next(); i += 1
            case "--days": if let v = next() { a.sinceDays = Int(v) ?? a.sinceDays }; i += 1
            case "--limit": if let v = next() { a.limit = Int(v) }; i += 1
            case "--apply": a.apply = true
            case "--plan": a.planPath = next(); i += 1
            case "--profile": a.profilePath = next(); i += 1
            case "--org": a.organization = next() ?? a.organization; i += 1
            case "--include-system": a.includeSystem = true
            case "--quiet": a.quiet = true
            case "-h", "--help": printHelp(); exit(0)
            default:
                FileHandle.standardError.write(Data("未知参数: \(k)\n".utf8))
                exit(64)
            }
            i += 1
        }
        return a
    }
}

func printHelp() {
    print("""
    pvsaudit — macOS 隐私权限审计与收回

    用法:
      pvsaudit scan   [--days N] [--policy FILE] [--json OUT] [--report OUT]
                      [--limit N] [--include-system]
      pvsaudit apply  [--plan STATE.json | --json STATE.json] [--apply]
                      [--profile OUT] [--org NAME] [--policy FILE]
      pvsaudit doctor

    说明:
      scan    只读审计，不做任何修改。默认回溯 14 天日志。
      apply   依据审计结果收回权限。默认 dry-run；加 --apply 才真正执行。
      doctor  检查本机的采集能力（FDA / 日志 / tccutil）。

    安全默认:
      · 未加 --apply 时绝不改动系统。
      · 受策略保护的 App、Apple 组件、仍在使用的权限不会被收回。
      · 辅助功能 / 模拟键鼠 / 自动化 永不自动收回，只做提示。

    退出码: 0 正常；1 运行错误；2 有建议但未执行；3 部分操作失败。
    """)
}

// MARK: - Helpers

func fail(_ msg: String, code: Int32 = 1) -> Never {
    FileHandle.standardError.write(Data(("错误: " + msg + "\n").utf8))
    exit(code)
}

let encoder: JSONEncoder = {
    let e = JSONEncoder()
    e.outputFormatting = [.prettyPrinted, .sortedKeys]
    e.dateEncodingStrategy = .iso8601
    return e
}()
let decoder: JSONDecoder = {
    let d = JSONDecoder()
    d.dateDecodingStrategy = .iso8601
    return d
}()

func write(_ data: Data, to path: String, what: String) {
    do {
        let url = URL(fileURLWithPath: path)
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: url)
        print("已写入\(what): \(path)")
    } catch {
        fail("写入 \(path) 失败: \(error)")
    }
}

// MARK: - Commands

let args = Args.parse(CommandLine.arguments)

switch args.command {

case "doctor":
    let reader = LogReader()
    let db = TCCDatabaseReader()
    let userOK = db.canRead(path: TCCDatabaseReader.userDBPath)
    let sysOK = db.canRead(path: TCCDatabaseReader.systemDBPath)
    print("macOS 采集能力检查")
    print("--------------------------------------")
    print("用户 TCC.db 可读     \(userOK ? "是" : "否（缺完全磁盘访问）")")
    print("系统 TCC.db 可读     \(sysOK ? "是" : "否（缺完全磁盘访问）")")
    print("统一日志可读         \(reader.retentionDays() != nil ? "是" : "否")"
          + (reader.retentionDays().map { "，回溯约 \($0) 天" } ?? ""))
    print("tccutil              \(FileManager.default.isExecutableFile(atPath: "/usr/bin/tccutil") ? "可用" : "缺失")")
    print("")
    if !(userOK || sysOK) {
        print("当前为“零权限模式”：授权清单由日志推断，覆盖不完整。")
        print("如需精确清单，可在 系统设置 → 隐私与安全性 → 完全磁盘访问 中授权本工具的宿主终端。")
    }

case "scan":
    let (policy, warn) = PolicyLoader.loadIfPresent(args.policyPath)
    let engine = AuditEngine()
    let state: ScanState
    do {
        state = try engine.scan(.init(sinceDays: args.sinceDays, policy: policy,
                                      policyWarning: warn, includeSystemApps: args.includeSystem))
    } catch { fail("\(error)") }

    if let out = args.jsonPath {
        guard let data = try? encoder.encode(state) else { fail("序列化失败") }
        write(data, to: out, what: "审计数据")
        // A standalone state file is also the input to `apply`.
    } else {
        let data = (try? encoder.encode(state)) ?? Data()
        write(data, to: "pvsaudit-state.json", what: "审计数据")
    }

    if !args.quiet {
        print(Reporter().render(state, limit: args.limit))
    }
    if let rp = args.reportPath {
        write(Data(Reporter().render(state, limit: args.limit).utf8), to: rp, what: "文本报告")
    }

    let actionable = state.findings.filter {
        $0.recommendation == .revoke || $0.recommendation == .remediateViaProfile
    }
    exit(actionable.isEmpty ? 0 : 2)

case "apply":
    let planPath = args.planPath ?? args.jsonPath ?? "pvsaudit-state.json"
    guard let data = FileManager.default.contents(atPath: planPath) else {
        fail("找不到审计数据 \(planPath)，请先运行 scan")
    }
    let state: ScanState
    do { state = try decoder.decode(ScanState.self, from: data) }
    catch { fail("解析 \(planPath) 失败: \(error)") }

    let (policy, _) = PolicyLoader.loadIfPresent(args.policyPath)
    let exec = RevocationExecutor(policy: policy)
    let report = exec.execute(state.findings, mode: args.apply ? .apply : .dryRun)

    print("收回执行（\(report.mode)）")
    print("--------------------------------------")
    for a in report.actions {
        let mark: String
        switch a.outcome {
        case .resetOK: mark = args.apply ? "✓" : "·"
        case .resetFailed: mark = "✗"
        case .needsProfile: mark = "→"
        default: mark = "–"
        }
        print("\(mark) \(a.appName) / \(a.serviceDisplay)")
        print("    \(a.detail)")
    }
    if report.actions.isEmpty {
        print("没有符合条件的收回项。")
    } else {
        print("")
        print("本次\(args.apply ? "已收回" : "计划收回") \(report.changed) 项。")
        if !args.apply {
            print("这是 dry-run，未做任何修改。确认后加 --apply 执行。")
        }
    }

    // PPPC profile for the ones we cannot fix locally.
    let needsProfile = state.findings.filter { $0.recommendation == .remediateViaProfile }
    if let pp = args.profilePath, !needsProfile.isEmpty,
       let prof = PPPCGenerator().profile(denials: needsProfile, organization: args.organization) {
        write(prof, to: pp, what: "PPPC 描述文件（需签名后下发）")
    }

    if let jp = args.jsonPath {
        if let d = try? encoder.encode(report) { write(d, to: jp, what: "执行记录") }
    }

    let failed = report.actions.filter { $0.outcome == .resetFailed }.count
    exit(failed > 0 ? 3 : 0)

default:
    FileHandle.standardError.write(Data("未知命令: \(args.command)\n".utf8))
    printHelp()
    exit(64)
}
