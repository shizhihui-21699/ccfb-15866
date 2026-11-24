import Foundation

/// Parses `log show --style ndjson` output for the TCC subsystem.
///
/// The unified log is readable with **no** TCC permission, and it carries enough
/// to reconstruct "which app touched which capability, and when":
///
///   AUTHREQ_CTX          service + preflight=yes|no
///   AUTHREQ_ATTRIBUTION  accessing/requesting process (bundle id + binary path)
///   AUTHREQ_SUBJECT      the subject identity for the request
///   AUTHREQ_RESULT       authValue (0 denied / 1 undetermined / 2 granted)
///   TCCDEvent            grant lifecycle: type=Create|Modify|Delete
///
/// All records of a single request share a `msgID`, so we join on it.
/// The parser is incremental: feed it one NDJSON line at a time, call `finish()`.
public final class LogParser {

    public struct Output {
        public var observations: [Observation] = []
        /// Incremental aggregates. Kept as running state so a multi-week scan
        /// holds one small struct per (app, service) instead of one object per
        /// log record — memory then scales with apps, not with event volume.
        public var usage: [UsageSummary] = []
        public var inferredGrants: [Grant] = []
        public var lifecycle: [Grant] = []
        public var linesParsed = 0
        public var unattributed = 0
        public var earliest: Date?
        public var malformedLines = 0
    }

    /// Running state for usage aggregation, keyed by (app, service).
    private struct UsageKey: Hashable { var app: String; var service: String }
    private struct UsageAcc {
        var appPath: String?
        var lastTouch: Date
        var lastUse: Date?
        var count = 0
        var access = 0
    }
    private var usageAcc: [UsageKey: UsageAcc] = [:]
    private var inferringGrants: Set<UsageKey> = []

    /// Retain every individual observation in `output.observations`.
    /// Off by default: production only needs the aggregates, and keeping one
    /// object per record costs hundreds of MB on a multi-week window.
    public var keepObservations = false

    public private(set) var output = Output()

    private struct Pending {
        var at: Date
        var service: String?
        var preflight: Bool?
        var accessingID: String?
        var accessingPath: String?
        var requestingID: String?
        var requestingPath: String?
        var subject: String?
        var authValue: Int?
    }

    private var pending: [String: Pending] = [:]
    private var order: [String] = []

    public init() {}

    // MARK: - Incremental ingest

    public func ingest(line: Data) {
        // One pool per line. Without this, the temporary NSDictionary / NSString
        // objects JSONSerialization creates are autoreleased into the *outer*
        // pool and accumulate for the whole scan — measured at ~600 MB for a
        // 120k-line window. Wrapping the line releases them immediately.
        autoreleasepool {
            ingestInner(line: line)
        }
    }

    private func ingestInner(line: Data) {
        guard !line.isEmpty else { return }
        output.linesParsed += 1
        guard let obj = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any],
              let msg = obj["eventMessage"] as? String
        else { output.malformedLines += 1; return }

        let at = parseTimestamp(obj["timestamp"] as? String)
        if let d = at, output.earliest.map({ d < $0 }) ?? true { output.earliest = d }

        if msg.contains("TCCDEvent:") {
            if let g = Self.parseLifecycle(msg) { output.lifecycle.append(g) }
            return
        }

        guard let msgID = Self.firstMatch(msg, #"msgID=(\d+\.\d+)"#) else { return }

        if pending[msgID] == nil {
            pending[msgID] = Pending(at: at ?? Date())
            order.append(msgID)
            if order.count > 8192 {          // bounded memory on long scans
                for k in order.prefix(2048) { flush(k) }
                order.removeFirst(2048)
            }
        }
        var p = pending[msgID]!

        if msg.hasPrefix("AUTHREQ_CTX") {
            if let s = Self.firstMatch(msg, #"service=(kTCCService\w+)"#) { p.service = s }
            if let pf = Self.firstMatch(msg, #"preflight=(\w+)"#) { p.preflight = (pf == "yes") }
            if let t = at { p.at = t }
        } else if msg.hasPrefix("AUTHREQ_ATTRIBUTION") {
            if let block = Self.firstMatch(msg, #"accessing=\{(.*?)\}"#) {
                p.accessingID = Self.firstMatch(block, #"identifier=([^,}]+)"#).flatMap(Self.sanitizeIdent)
                p.accessingPath = Self.firstMatch(block, #"binary_path=([^,}]+)"#)
            }
            if let block = Self.firstMatch(msg, #"requesting=\{(.*?)\}"#) {
                p.requestingID = Self.firstMatch(block, #"identifier=([^,}]+)"#).flatMap(Self.sanitizeIdent)
                p.requestingPath = Self.firstMatch(block, #"binary_path=([^,}]+)"#)
            }
        } else if msg.hasPrefix("AUTHREQ_SUBJECT") {
            if let s = Self.firstMatch(msg, #"subject=([^,\s}]+)"#) { p.subject = Self.sanitizeIdent(s) }
        } else if msg.hasPrefix("AUTHREQ_RESULT") {
            if let v = Self.firstMatch(msg, #"authValue=(\d+)"#) { p.authValue = Int(v) }
        }
        pending[msgID] = p

        if msg.hasPrefix("AUTHREQ_RESULT") {
            flush(msgID)
            if let i = order.firstIndex(of: msgID) { order.remove(at: i) }
        }
    }

    /// Flush anything still open (requests whose RESULT fell outside the window)
    /// and materialise the incremental aggregates into `output`.
    public func finish() {
        for k in order { flush(k) }
        pending.removeAll()
        order.removeAll()

        output.usage = usageAcc.map { k, v in
            UsageSummary(appKey: k.app, appPath: v.appPath, service: k.service,
                         lastTouched: v.lastTouch, lastActualUse: v.lastUse,
                         observedCount: v.count, accessRequestCount: v.access)
        }
        output.inferredGrants = inferringGrants.map { k in
            Grant(service: k.service, client: k.app, clientType: nil, allowed: true,
                  authValue: 2, authReason: nil, lastModified: nil,
                  indirectObject: nil, source: .logObservedGrant)
        }
    }

    // MARK: - Attribution

    private func flush(_ key: String) {
        guard let p = pending.removeValue(forKey: key) else { return }
        guard let (actorID, actorPath) = Self.pickActor(p) else {
            output.unattributed += 1
            return
        }
        guard let svc = p.service, ServiceCatalog.spec(for: svc) != nil else { return }
        let kind: ObservationKind = (p.preflight == true) ? .statusCheck : .accessRequest
        let allowed: Bool? = p.authValue.map { $0 >= 2 }
        record(appKey: actorID, appPath: actorPath, service: svc,
               at: p.at, kind: kind, allowed: allowed)
    }

    /// Fold one resolved request into the running aggregates. Deliberately does
    /// not keep the individual record: consumers only need the summary.
    private func record(appKey: String, appPath: String?, service: String,
                        at: Date, kind: ObservationKind, allowed: Bool?) {
        let k = UsageKey(app: appKey, service: service)
        var a = usageAcc[k] ?? UsageAcc(appPath: appPath, lastTouch: at)
        a.lastTouch = max(a.lastTouch, at)
        if a.appPath == nil { a.appPath = appPath }
        a.count += 1
        if kind == .accessRequest && allowed != false {
            a.lastUse = [a.lastUse, at].compactMap { $0 }.max()
            a.access += 1
            inferringGrants.insert(k)
        } else if allowed == true {
            // A status check answered "yes" also proves a grant exists.
            inferringGrants.insert(k)
        }
        usageAcc[k] = a
        if keepObservations {
            output.observations.append(Observation(
                appKey: appKey, appPath: appPath, service: service,
                at: at, kind: kind, allowed: allowed))
        }
    }

    private static func pickActor(_ p: Pending) -> (String, String?)? {
        if let id = p.accessingID {
            if isSystemBroker(id), let rid = p.requestingID, !isSystemBroker(rid) {
                return (rid, p.requestingPath)
            }
            return (id, p.accessingPath)
        }
        if let rid = p.requestingID { return (rid, p.requestingPath) }
        if let s = p.subject { return (s, nil) }
        return nil
    }

    private static let brokerIDs: Set<String> = [
        "com.apple.WindowServer", "com.apple.tccd", "com.apple.replayd",
        "com.apple.ScreenCaptureKit", "com.apple.coreservices.UASharedPasteboardProgressUI",
        "com.apple.xpc.launchd",
    ]
    static func isSystemBroker(_ id: String) -> Bool {
        brokerIDs.contains(id) || id == "headless_shell" || id.hasPrefix("com.apple.WindowServer")
    }

    static func sanitizeIdent(_ s: String) -> String? {
        let t = s.trimmingCharacters(in: .whitespaces)
        guard !t.isEmpty, t != "-", t != "unknown", t != "(null)" else { return nil }
        if t.hasPrefix("/") { return t }
        if t.contains("."), !t.contains(" ") { return t }
        return nil
    }

    // MARK: - Lifecycle

    private static func parseLifecycle(_ msg: String) -> Grant? {
        guard let type = firstMatch(msg, #"type=(\w+)"#), type == "Create" || type == "Modify" else {
            return nil
        }
        guard let svc = firstMatch(msg, #"service=(kTCCService\w+)"#),
              ServiceCatalog.spec(for: svc) != nil,
              let ident = firstMatch(msg, #"identifier=([^,}>\s]+)"#).flatMap(sanitizeIdent)
        else { return nil }
        return Grant(service: svc, client: ident, clientType: nil, allowed: true,
                     authValue: nil, authReason: nil, lastModified: nil,
                     indirectObject: nil, source: .logLifecycle)
    }

    private func parseTimestamp(_ s: String?) -> Date? { LogTimestamp.parse(s) }

    // MARK: - Regex
    //
    // Compiled once. Constructing an NSRegularExpression per call was the
    // dominant cost on a multi-week scan (12× memory amplification, seconds of
    // CPU) — every record runs 3–6 of these.

    private static let regexCache: [String: NSRegularExpression] = {
        var m: [String: NSRegularExpression] = [:]
        for p in [
            #"msgID=(\d+\.\d+)"#,
            #"service=(kTCCService\w+)"#,
            #"preflight=(\w+)"#,
            #"accessing=\{(.*?)\}"#,
            #"requesting=\{(.*?)\}"#,
            #"identifier=([^,}]+)"#,
            #"binary_path=([^,}]+)"#,
            #"subject=([^,\s}]+)"#,
            #"authValue=(\d+)"#,
            #"type=(\w+)"#,
            #"identifier=([^,}>\s]+)"#,
        ] {
            if let re = try? NSRegularExpression(pattern: p, options: [.dotMatchesLineSeparators]) {
                m[p] = re
            }
        }
        return m
    }()

    static func firstMatch(_ s: String, _ pattern: String) -> String? {
        guard let re = regexCache[pattern] else { return nil }
        let range = NSRange(s.startIndex..<s.endIndex, in: s)
        guard let m = re.firstMatch(in: s, range: range), m.numberOfRanges > 1,
              let r = Range(m.range(at: 1), in: s) else { return nil }
        return String(s[r])
    }
}
