import Foundation
import SQLite3

/// Reads grants out of TCC.db — **only works with Full Disk Access**.
///
/// This is deliberately optional. The tool is fully useful without it (log tier),
/// and merely *more precise* with it (exact grant set + real last-modified dates).
///
/// We open read-only with `immutable=1` so we never take a lock on a database
/// that tccd is actively writing, and so a stale WAL cannot corrupt our view.
public struct TCCDatabaseReader {

    public enum DBError: Error, CustomStringConvertible {
        case notPermitted(String)
        case openFailed(String)
        case queryFailed(String)
        public var description: String {
            switch self {
            case .notPermitted(let p): return "无权限读取 \(p)（需要完全磁盘访问）"
            case .openFailed(let m): return "无法打开 TCC.db：\(m)"
            case .queryFailed(let m): return "查询 TCC.db 失败：\(m)"
            }
        }
    }

    public static var userDBPath: String {
        // Overridable for testing and for reading an offline copy taken from a
        // managed Mac (e.g. a forensic snapshot).
        ProcessInfo.processInfo.environment["PVSAUDIT_USER_TCCDB"]
            ?? NSHomeDirectory() + "/Library/Application Support/com.apple.TCC/TCC.db"
    }
    public static var systemDBPath: String {
        ProcessInfo.processInfo.environment["PVSAUDIT_SYSTEM_TCCDB"]
            ?? "/Library/Application Support/com.apple.TCC/TCC.db"
    }

    public init() {}

    /// Cheap, honest capability check: can we open the user DB read-only?
    public func canRead(path: String) -> Bool {
        guard let db = openReadOnly(path) else { return false }
        sqlite3_close(db)
        return true
    }

    private func openReadOnly(_ path: String) -> OpaquePointer? {
        var db: OpaquePointer?
        let uri = "file:\(path)?immutable=1"
        let rc = sqlite3_open_v2(uri, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nil)
        guard rc == SQLITE_OK else {
            if let db { sqlite3_close(db) }
            return nil
        }
        return db
    }

    /// Read all grants we understand from one database.
    public func readGrants(path: String, source: GrantSource) throws -> [Grant] {
        guard let db = openReadOnly(path) else { throw DBError.notPermitted(path) }
        defer { sqlite3_close(db) }

        // Columns differ across OS versions (indirect_object_identifier appeared
        // in 10.14; last_reminded/pid/… are noise). Introspect instead of assuming.
        let cols = try columns(db: db, table: "access")
        guard cols.contains("service"), cols.contains("client") else {
            throw DBError.queryFailed("access 表结构与预期不符: \(cols.sorted())")
        }
        let hasAllowed = cols.contains("auth_value")
        let hasAuthReason = cols.contains("auth_reason")
        let hasClientType = cols.contains("client_type")
        let hasIndirect = cols.contains("indirect_object_identifier")
        let hasModified = cols.contains("last_modified") || cols.contains("last_modified_date")
        let modifiedCol = cols.contains("last_modified") ? "last_modified" : "last_modified_date"

        var sql = "SELECT service, client"
        sql += hasClientType ? ", client_type" : ", NULL"
        sql += hasAllowed ? ", auth_value" : ", NULL"
        sql += hasAuthReason ? ", auth_reason" : ", NULL"
        sql += hasModified ? ", \(modifiedCol)" : ", NULL"
        sql += hasIndirect ? ", indirect_object_identifier" : ", NULL"
        sql += " FROM access"

        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw DBError.queryFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }

        var grants: [Grant] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let service = text(stmt, 0)
            let client = text(stmt, 1)
            guard let service, let client else { continue }
            guard ServiceCatalog.spec(for: service) != nil else { continue }

            let clientType = sqlite3_column_type(stmt, 2) == SQLITE_NULL ? nil : Int(sqlite3_column_int(stmt, 2))
            let authValue = sqlite3_column_type(stmt, 3) == SQLITE_NULL ? nil : Int(sqlite3_column_int(stmt, 3))
            let authReason = sqlite3_column_type(stmt, 4) == SQLITE_NULL ? nil : Int(sqlite3_column_int(stmt, 4))
            let modifiedRaw = sqlite3_column_type(stmt, 5) == SQLITE_NULL ? nil : sqlite3_column_double(stmt, 5)
            let indirect = text(stmt, 6)

            // auth_value: 0 = denied, 2 = allowed. Only surface grants.
            guard let av = authValue, av != 0 else { continue }

            grants.append(Grant(
                service: service,
                client: client,
                clientType: clientType,
                allowed: true,
                authValue: av,
                authReason: authReason,
                lastModified: modifiedRaw.flatMap { $0 > 0 ? Date(timeIntervalSince1970: $0) : nil },
                indirectObject: (indirect == "UNUSED" || indirect?.isEmpty == true) ? nil : indirect,
                source: source))
        }
        return grants
    }

    public func readAll() -> (grants: [Grant], readableUser: Bool, readableSystem: Bool, errors: [String]) {
        var grants: [Grant] = []
        var errors: [String] = []
        let readableUser = canRead(path: Self.userDBPath)
        let readableSystem = canRead(path: Self.systemDBPath)

        if readableUser, let g = try? readGrants(path: Self.userDBPath, source: .userTCCDB) {
            grants += g
        } else if !readableUser {
            errors.append("用户 TCC.db 不可读（缺完全磁盘访问）")
        }
        if readableSystem, let g = try? readGrants(path: Self.systemDBPath, source: .systemTCCDB) {
            grants += g
        } else if !readableSystem {
            errors.append("系统 TCC.db 不可读（缺完全磁盘访问）")
        }
        return (grants, readableUser, readableSystem, errors)
    }

    // MARK: - SQLite helpers

    private func columns(db: OpaquePointer, table: String) throws -> Set<String> {
        var stmt: OpaquePointer?
        let sql = "PRAGMA table_info(\(table))"
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw DBError.queryFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        var out = Set<String>()
        while sqlite3_step(stmt) == SQLITE_ROW {
            out.insert(text(stmt, 1) ?? "")
        }
        return out
    }

    private func text(_ stmt: OpaquePointer?, _ i: Int32) -> String? {
        guard let c = sqlite3_column_text(stmt, i) else { return nil }
        return String(cString: c)
    }
}
