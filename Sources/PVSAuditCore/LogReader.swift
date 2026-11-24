import Foundation

/// Streams `log show` output line-by-line so a multi-day window never has to be
/// held in memory as one large string.
public struct LogReader {

    public enum LogReaderError: Error, CustomStringConvertible {
        case launchFailed(String)
        case noLogTool
        public var description: String {
            switch self {
            case .launchFailed(let m): return "无法运行 log 命令：\(m)"
            case .noLogTool: return "找不到 /usr/bin/log"
            }
        }
    }

    public var logToolPath: String

    public init(logToolPath: String = "/usr/bin/log") {
        self.logToolPath = logToolPath
    }

    /// Predicate limited to the TCC subsystem and the record families we need.
    /// Note: TCC access records sit in category "access", but grant lifecycle
    /// (`TCCDEvent`) records are published under category "events" — filtering
    /// on `category == "access"` alone silently drops every grant change.
    /// Narrowing here is what keeps an 18-day scan down to a few seconds.
    public static let predicate = """
    subsystem == "com.apple.TCC" AND (\
    eventMessage CONTAINS "AUTHREQ_CTX" OR \
    eventMessage CONTAINS "AUTHREQ_ATTRIBUTION" OR \
    eventMessage CONTAINS "AUTHREQ_SUBJECT" OR \
    eventMessage CONTAINS "AUTHREQ_RESULT" OR \
    eventMessage CONTAINS "TCCDEvent")
    """

    public func arguments(sinceDays: Int) -> [String] {
        ["show", "--last", "\(sinceDays)d", "--style", "ndjson", "--predicate", Self.predicate]
    }

    /// Runs the scan, handing each NDJSON line to `body` as it arrives.
    /// Returns the process exit status.
    @discardableResult
    public func stream(sinceDays: Int, body: (Data) -> Void) throws -> Int32 {
        guard FileManager.default.isExecutableFile(atPath: logToolPath) else {
            throw LogReaderError.noLogTool
        }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: logToolPath)
        p.arguments = arguments(sinceDays: sinceDays)
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice

        do { try p.run() } catch { throw LogReaderError.launchFailed("\(error)") }

        let handle = out.fileHandleForReading
        // Read in bounded chunks and carry over only the incomplete tail line.
        // `availableData` can hand back tens of MB in one call (it drains the
        // whole pipe), which showed up as a ~290 MB floor on a 134 MB scan.
        let chunkSize = 1 << 18
        var carry = Data()
        while true {
            let chunk: Data?
            do { chunk = try handle.read(upToCount: chunkSize) }
            catch { break }
            guard let chunk, !chunk.isEmpty else { break }

            var start = chunk.startIndex
            while let nl = chunk[start...].firstIndex(of: 0x0A) {
                if carry.isEmpty {
                    if nl > start { body(Data(chunk[start..<nl])) }
                } else {
                    carry.append(chunk[start..<nl])
                    body(carry)
                    carry.removeAll(keepingCapacity: true)
                }
                start = chunk.index(after: nl)
            }
            if start < chunk.endIndex { carry.append(chunk[start...]) }
            // A pathological line with no newline must not grow unbounded.
            if carry.count > 8 << 20 { body(carry); carry.removeAll(keepingCapacity: true) }
        }
        if !carry.isEmpty { body(carry) }
        p.waitUntilExit()
        return p.terminationStatus
    }

    /// How far back the unified log actually reaches, in whole days.
    /// Used to label "recently used" honestly instead of implying more history.
    public func retentionDays(probeSubsystem: String = "com.apple.TCC") -> Int? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: logToolPath)
        p.arguments = ["show", "--style", "ndjson", "--predicate",
                       "subsystem == \"\(probeSubsystem)\""]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return nil }

        defer { p.terminate() }
        // Read only the first chunk — we want the oldest record, which comes first.
        var chunk = out.fileHandleForReading.availableData
        // availableData may return a short read; keep pulling until we have one line.
        while !chunk.contains(0x0A) {
            let more = out.fileHandleForReading.availableData
            if more.isEmpty { break }
            chunk.append(more)
        }
        guard let nl = chunk.firstIndex(of: 0x0A) else { p.waitUntilExit(); return nil }
        let first = chunk[chunk.startIndex..<nl]
        p.terminate()
        guard let obj = (try? JSONSerialization.jsonObject(with: Data(first))) as? [String: Any],
              let d = LogTimestamp.parse(obj["timestamp"] as? String) else { return nil }
        let days = Calendar.current.dateComponents([.day], from: d, to: Date()).day
        return days
    }
}
