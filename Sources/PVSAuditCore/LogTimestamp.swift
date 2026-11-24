import Foundation

/// Unified-log timestamps come in several shapes depending on `log` version and
/// locale, e.g.:
///   2026-11-24T18:48:03.123456Z        (ISO, with T)
///   2026-11-24 07:13:54.100000+0800    (space + microseconds + offset)
///   2026-11-24 07:13:54.100+08:00
///   2026-11-24 07:13:54                (space, no fraction)
/// Getting this wrong silently makes "last used" look ancient, which would
/// mislabel a live app as dormant — exactly the failure we cannot afford.
public enum LogTimestamp {

    private static let isoFrac: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]; return f
    }()
    private static let isoPlain: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime]; return f
    }()

    // Space-separated forms need DateFormatter; cache the variants.
    private static let spaceFormatters: [DateFormatter] = [
        "yyyy-MM-dd HH:mm:ss.SSSSSSZZZZZ",
        "yyyy-MM-dd HH:mm:ss.SSSSSSZ",
        "yyyy-MM-dd HH:mm:ss.SSSZZZZZ",
        "yyyy-MM-dd HH:mm:ss.SSSZ",
        "yyyy-MM-dd HH:mm:ssZZZZZ",
        "yyyy-MM-dd HH:mm:ssZ",
        "yyyy-MM-dd HH:mm:ss",
    ].map { fmt in
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = fmt
        return f
    }

    public static func parse(_ s: String?) -> Date? {
        guard let s, !s.isEmpty else { return nil }
        if let d = isoFrac.date(from: s) { return d }
        if let d = isoPlain.date(from: s) { return d }
        for f in spaceFormatters {
            if let d = f.date(from: s) { return d }
        }
        return nil
    }
}
