//! tz.zig -- local UTC offset, resolved without libc.
//!
//! WHY THIS EXISTS: `localtime_r` is a libc function and this miner links no
//! libc on Linux/Android (that is the point of the pure-Zig build), while Zig
//! 0.14's std has no timezone facility at all -- `std.time.epoch` breaks a Unix
//! timestamp into UTC fields and stops there. So log lines were UTC on POSIX
//! while the C++, Rust and Go siblings printed local wall-clock in the very
//! same format: a Zig line silently read hours off with nothing marking it.
//! This resolves the offset ourselves, and `offsetAt` returns null wherever it
//! genuinely cannot -- console.zig then marks that line `Z` rather than
//! pretending. A wrong offset would be worse than an honest UTC.
//!
//! Sources, first hit wins: the TZ environment variable, then /etc/localtime.
//! Android usually has neither (bionic resolves zones through a system property
//! and a tzdata container), which is exactly the case the marker is for.

const std = @import("std");
const builtin = @import("builtin");

/// Caps keep this allocation-free, matching the rest of the codebase. Real
/// zone files carry a few hundred transitions; anything past these limits
/// resolves to null rather than to a half-parsed answer.
const max_transitions = 1200;
const max_types = 64;

const Ttinfo = struct { utoff: i32 = 0, isdst: bool = false };

const Zone = struct {
    /// Transition instants (UTC seconds), ascending.
    times: [max_transitions]i64 = undefined,
    /// Index into `types` effective from the matching transition onwards.
    idx: [max_transitions]u8 = undefined,
    n: usize = 0,
    types: [max_types]Ttinfo = undefined,
    ntypes: usize = 0,
    /// Offset before the first transition (or the whole answer for a fixed
    /// zone parsed from a TZ string with no DST rule).
    initial: i32 = 0,

    fn offsetAt(self: *const Zone, utc_secs: i64) i32 {
        if (self.n == 0) return self.initial;
        // Last transition at or before the instant. Ascending, so binary search.
        var lo: usize = 0;
        var hi: usize = self.n;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (self.times[mid] <= utc_secs) lo = mid + 1 else hi = mid;
        }
        if (lo == 0) return self.initial;
        const t = self.idx[lo - 1];
        if (t >= self.ntypes) return self.initial;
        return self.types[t].utoff;
    }
};

/// A POSIX TZ rule ("EST5EDT,M3.2.0,M11.1.0"): two offsets and the M-form
/// dates they switch on. Evaluated per instant rather than baked in, so a
/// long-running miner follows a DST change instead of freezing at startup.
const PosixRule = struct {
    std_off: i32,
    dst_off: i32,
    start: MRule,
    end: MRule,

    const MRule = struct { month: u8, week: u8, day: u8, secs: i32 };

    fn offsetAt(self: *const PosixRule, utc_secs: i64) i32 {
        // Transition instants are given in local time; using the standard
        // offset for both comparisons is off by an hour for the few hours
        // around each switch, which is immaterial for a log timestamp.
        const local = utc_secs + self.std_off;
        const year = yearOf(local);
        const s = instantOf(self.start, year);
        const e = instantOf(self.end, year);
        const in_dst = if (s <= e) (local >= s and local < e) else (local >= s or local < e);
        return if (in_dst) self.dst_off else self.std_off;
    }
};

var zone: Zone = .{};
var posix: ?PosixRule = null;
var resolved = false;
var once = std.once(resolve);

/// Seconds east of UTC for `utc_secs`, or null when no zone data could be
/// found or trusted. Cheap after the first call: the zone is parsed once and
/// only the lookup runs per line.
pub fn offsetAt(utc_secs: i64) ?i32 {
    if (is_windows_target) return null; // Windows uses GetLocalTime directly.
    once.call();
    if (!resolved) return null;
    if (posix) |p| return p.offsetAt(utc_secs);
    return zone.offsetAt(utc_secs);
}

const is_windows_target = builtin.os.tag == .windows;

fn resolve() void {
    if (is_windows_target) return;

    if (std.posix.getenv("TZ")) |tz| {
        if (resolveTz(tz)) resolved = true;
        // An explicitly set but unparseable TZ is NOT silently replaced by
        // /etc/localtime: the user asked for something specific, and guessing
        // differently would be the wrong kind of helpful.
        return;
    }
    if (loadFile("/etc/localtime")) resolved = true;
}

fn resolveTz(tz_in: []const u8) bool {
    var tz = tz_in;
    if (tz.len > 0 and tz[0] == ':') tz = tz[1..];
    if (tz.len == 0) {
        zone = .{ .initial = 0 };
        return true; // POSIX: empty TZ means UTC.
    }
    // A zone name -- look it up in the usual roots, including Termux's prefix.
    if (std.mem.indexOfScalar(u8, tz, '/') != null) return loadZoneName(tz);
    if (std.ascii.eqlIgnoreCase(tz, "UTC") or std.ascii.eqlIgnoreCase(tz, "GMT")) {
        zone = .{ .initial = 0 };
        return true;
    }
    // Otherwise a POSIX rule string; a bare name that is not a rule (e.g. a
    // single-file zone like "EST") is also tried as a file.
    if (parsePosix(tz)) return true;
    return loadZoneName(tz);
}

fn loadZoneName(name: []const u8) bool {
    // Reject traversal: the name indexes a system database, not the filesystem.
    if (std.mem.startsWith(u8, name, "/")) return loadFile(name);
    if (std.mem.indexOf(u8, name, "..") != null) return false;

    var buf: [std.fs.max_path_bytes]u8 = undefined;
    if (std.posix.getenv("TZDIR")) |dir| {
        if (std.fmt.bufPrint(&buf, "{s}/{s}", .{ dir, name })) |p| {
            if (loadFile(p)) return true;
        } else |_| {}
    }
    const roots = [_][]const u8{
        "/usr/share/zoneinfo",
        "/etc/zoneinfo",
        "/system/usr/share/zoneinfo", // Android, when present
    };
    for (roots) |root| {
        if (std.fmt.bufPrint(&buf, "{s}/{s}", .{ root, name })) |p| {
            if (loadFile(p)) return true;
        } else |_| {}
    }
    // Termux installs its own zoneinfo under $PREFIX.
    if (std.posix.getenv("PREFIX")) |prefix| {
        if (std.fmt.bufPrint(&buf, "{s}/share/zoneinfo/{s}", .{ prefix, name })) |p| {
            if (loadFile(p)) return true;
        } else |_| {}
    }
    return false;
}

fn loadFile(path: []const u8) bool {
    const f = std.fs.openFileAbsolute(path, .{}) catch return false;
    defer f.close();
    var buf: [64 * 1024]u8 = undefined;
    const n = f.readAll(&buf) catch return false;
    return parseTzif(buf[0..n]);
}

// ---------------------------------------------------------------------------
// TZif (RFC 8536)
// ---------------------------------------------------------------------------

const Counts = struct { isutcnt: u32, isstdcnt: u32, leapcnt: u32, timecnt: u32, typecnt: u32, charcnt: u32 };

fn readCounts(b: []const u8) Counts {
    return .{
        .isutcnt = std.mem.readInt(u32, b[20..24], .big),
        .isstdcnt = std.mem.readInt(u32, b[24..28], .big),
        .leapcnt = std.mem.readInt(u32, b[28..32], .big),
        .timecnt = std.mem.readInt(u32, b[32..36], .big),
        .typecnt = std.mem.readInt(u32, b[36..40], .big),
        .charcnt = std.mem.readInt(u32, b[40..44], .big),
    };
}

/// Parse a TZif image into `zone`. Prefers the 64-bit v2+ block when present.
/// Returns false on anything malformed -- callers then fall through to UTC.
pub fn parseTzif(buf: []const u8) bool {
    if (buf.len < 44 or !std.mem.eql(u8, buf[0..4], "TZif")) return false;
    const version = buf[4];

    const c1 = readCounts(buf);
    if (c1.typecnt == 0) return false;
    const v1_body = 44 + c1.timecnt * 4 + c1.timecnt + c1.typecnt * 6 +
        c1.charcnt + c1.leapcnt * 8 + c1.isstdcnt + c1.isutcnt;

    if (version != 0 and buf.len >= 44 + v1_body + 44) {
        // v2/v3: a second header + 64-bit block follows the v1 block.
        const h2 = buf[44 + v1_body ..];
        if (h2.len >= 44 and std.mem.eql(u8, h2[0..4], "TZif")) {
            const c2 = readCounts(h2);
            if (c2.typecnt == 0) return false;
            return parseBlock(h2[44..], c2, 8);
        }
    }
    return parseBlock(buf[44..], c1, 4);
}

fn parseBlock(b: []const u8, c: Counts, time_size: usize) bool {
    if (c.timecnt > max_transitions or c.typecnt > max_types) return false;

    const times_len = c.timecnt * time_size;
    const idx_len = c.timecnt;
    const types_len = c.typecnt * 6;
    if (b.len < times_len + idx_len + types_len + c.charcnt) return false;

    var z: Zone = .{};
    z.n = c.timecnt;
    z.ntypes = c.typecnt;

    var i: usize = 0;
    while (i < c.timecnt) : (i += 1) {
        const off = i * time_size;
        z.times[i] = if (time_size == 8)
            std.mem.readInt(i64, b[off..][0..8], .big)
        else
            std.mem.readInt(i32, b[off..][0..4], .big);
        if (i > 0 and z.times[i] < z.times[i - 1]) return false; // must ascend
    }

    const idx_base = times_len;
    i = 0;
    while (i < c.timecnt) : (i += 1) {
        const t = b[idx_base + i];
        if (t >= c.typecnt) return false;
        z.idx[i] = t;
    }

    const types_base = idx_base + idx_len;
    i = 0;
    while (i < c.typecnt) : (i += 1) {
        const off = types_base + i * 6;
        z.types[i] = .{
            .utoff = std.mem.readInt(i32, b[off..][0..4], .big),
            .isdst = b[off + 4] != 0,
        };
    }

    // Before the first transition, prefer the first non-DST type (RFC 8536 §4).
    z.initial = z.types[0].utoff;
    i = 0;
    while (i < c.typecnt) : (i += 1) {
        if (!z.types[i].isdst) {
            z.initial = z.types[i].utoff;
            break;
        }
    }

    zone = z;
    posix = null;
    return true;
}

// ---------------------------------------------------------------------------
// POSIX TZ strings
// ---------------------------------------------------------------------------

/// "std offset[dst[offset]][,start,end]". Returns false for forms we do not
/// evaluate (J<n> / bare <n> day rules), so they fall through rather than
/// producing a confidently wrong time.
fn parsePosix(s: []const u8) bool {
    var i: usize = 0;
    const std_name = scanName(s, &i) orelse return false;
    _ = std_name;
    const std_off = scanOffset(s, &i) orelse return false;
    // POSIX offsets are "west of UTC" -- invert to seconds east.
    const std_east = -std_off;

    if (i >= s.len) {
        zone = .{ .initial = std_east };
        posix = null;
        return true;
    }

    const dst_name = scanName(s, &i) orelse return false;
    _ = dst_name;
    // DST offset defaults to one hour ahead of standard.
    var dst_east = std_east + 3600;
    if (i < s.len and s[i] != ',') {
        const d = scanOffset(s, &i) orelse return false;
        dst_east = -d;
    }
    if (i >= s.len or s[i] != ',') return false;
    i += 1;
    const start = scanMRule(s, &i) orelse return false;
    if (i >= s.len or s[i] != ',') return false;
    i += 1;
    const end = scanMRule(s, &i) orelse return false;

    posix = .{ .std_off = std_east, .dst_off = dst_east, .start = start, .end = end };
    return true;
}

fn scanName(s: []const u8, i: *usize) ?[]const u8 {
    const start = i.*;
    if (start < s.len and s[start] == '<') { // quoted form: <+05>
        var j = start + 1;
        while (j < s.len and s[j] != '>') j += 1;
        if (j >= s.len) return null;
        i.* = j + 1;
        return s[start + 1 .. j];
    }
    var j = start;
    while (j < s.len and std.ascii.isAlphabetic(s[j])) j += 1;
    if (j - start < 3) return null;
    i.* = j;
    return s[start..j];
}

/// "[+|-]hh[:mm[:ss]]" -> seconds (POSIX sign convention: positive is west).
fn scanOffset(s: []const u8, i: *usize) ?i32 {
    var j = i.*;
    if (j >= s.len) return null;
    var neg = false;
    if (s[j] == '+' or s[j] == '-') {
        neg = s[j] == '-';
        j += 1;
    }
    const h = scanInt(s, &j) orelse return null;
    var total: i32 = h * 3600;
    if (j < s.len and s[j] == ':') {
        j += 1;
        const m = scanInt(s, &j) orelse return null;
        total += m * 60;
        if (j < s.len and s[j] == ':') {
            j += 1;
            const sec = scanInt(s, &j) orelse return null;
            total += sec;
        }
    }
    i.* = j;
    return if (neg) -total else total;
}

fn scanInt(s: []const u8, i: *usize) ?i32 {
    const start = i.*;
    var j = start;
    while (j < s.len and std.ascii.isDigit(s[j])) j += 1;
    if (j == start) return null;
    const v = std.fmt.parseInt(i32, s[start..j], 10) catch return null;
    i.* = j;
    return v;
}

/// "M<month>.<week>.<day>[/<time>]" only. J<n> and bare <n> are rejected.
fn scanMRule(s: []const u8, i: *usize) ?PosixRule.MRule {
    var j = i.*;
    if (j >= s.len or s[j] != 'M') return null;
    j += 1;
    const month = scanInt(s, &j) orelse return null;
    if (j >= s.len or s[j] != '.') return null;
    j += 1;
    const week = scanInt(s, &j) orelse return null;
    if (j >= s.len or s[j] != '.') return null;
    j += 1;
    const day = scanInt(s, &j) orelse return null;
    if (month < 1 or month > 12 or week < 1 or week > 5 or day < 0 or day > 6) return null;

    var secs: i32 = 2 * 3600; // POSIX default switch time
    if (j < s.len and s[j] == '/') {
        j += 1;
        secs = scanOffset(s, &j) orelse return null;
    }
    i.* = j;
    return .{ .month = @intCast(month), .week = @intCast(week), .day = @intCast(day), .secs = secs };
}

// ---------------------------------------------------------------------------
// Civil-date helpers (UTC only -- the offset is applied by the caller)
// ---------------------------------------------------------------------------

fn isLeap(y: i32) bool {
    return (@mod(y, 4) == 0 and @mod(y, 100) != 0) or @mod(y, 400) == 0;
}

const cum_days = [12]i32{ 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };

fn daysFromCivil(y: i32, m: i32, d: i32) i64 {
    var days: i64 = 0;
    var yy: i32 = 1970;
    while (yy < y) : (yy += 1) days += if (isLeap(yy)) 366 else 365;
    while (yy > y) : (yy -= 1) days -= if (isLeap(yy - 1)) 366 else 365;
    days += cum_days[@intCast(m - 1)];
    if (m > 2 and isLeap(y)) days += 1;
    return days + (d - 1);
}

fn yearOf(local_secs: i64) i32 {
    const days = @divFloor(local_secs, 86400);
    var y: i32 = 1970;
    var rem = days;
    while (true) {
        const len: i64 = if (isLeap(y)) 366 else 365;
        if (rem >= len) {
            rem -= len;
            y += 1;
        } else if (rem < 0) {
            y -= 1;
            rem += if (isLeap(y)) 366 else 365;
        } else break;
    }
    return y;
}

/// Day-of-week for a civil date, 0 = Sunday (1970-01-01 was a Thursday).
fn weekday(y: i32, m: i32, d: i32) i32 {
    return @intCast(@mod(daysFromCivil(y, m, d) + 4, 7));
}

/// Local-time instant of an M-rule in a given year, as seconds since epoch.
fn instantOf(r: PosixRule.MRule, year: i32) i64 {
    const month: i32 = r.month;
    const want: i32 = r.day;
    const first_dow = weekday(year, month, 1);
    // Day-of-month of the first `want` weekday, then advance whole weeks.
    var dom: i32 = 1 + @mod(want - first_dow + 7, 7);
    var w: u8 = 1;
    const dim = daysInMonth(year, month);
    while (w < r.week) : (w += 1) {
        if (dom + 7 > dim) break; // week 5 means "the last one"
        dom += 7;
    }
    return daysFromCivil(year, month, dom) * 86400 + r.secs;
}

fn daysInMonth(y: i32, m: i32) i32 {
    return switch (m) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        else => if (isLeap(y)) @as(i32, 29) else 28,
    };
}

// ---------------------------------------------------------------------------
// Tests -- offline; no clock, filesystem or network dependence.
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Build a minimal TZif v1 image: one transition, two types.
fn fixtureV1(transition: i32, before: i32, after: i32) [
    44 + 4 + 1 + 12 + 1
]u8 {
    var b: [44 + 4 + 1 + 12 + 1]u8 = [_]u8{0} ** (44 + 4 + 1 + 12 + 1);
    @memcpy(b[0..4], "TZif");
    b[4] = 0; // version 1
    std.mem.writeInt(u32, b[32..36], 1, .big); // timecnt
    std.mem.writeInt(u32, b[36..40], 2, .big); // typecnt
    std.mem.writeInt(u32, b[40..44], 1, .big); // charcnt
    std.mem.writeInt(i32, b[44..48], transition, .big);
    b[48] = 1; // the transition selects type 1
    std.mem.writeInt(i32, b[49..53], before, .big); // type 0
    b[53] = 0;
    b[54] = 0;
    std.mem.writeInt(i32, b[55..59], after, .big); // type 1
    b[59] = 1; // isdst
    b[60] = 0;
    return b;
}

test "TZif: offset before and after a transition" {
    const b = fixtureV1(1000, -18000, -14400); // -5h then -4h
    try testing.expect(parseTzif(&b));
    try testing.expectEqual(@as(i32, -18000), zone.offsetAt(999));
    try testing.expectEqual(@as(i32, -14400), zone.offsetAt(1000));
    try testing.expectEqual(@as(i32, -14400), zone.offsetAt(1_000_000_000));
}

test "TZif: garbage and truncation are rejected, never guessed" {
    try testing.expect(!parseTzif("not a tzif file at all"));
    try testing.expect(!parseTzif(""));
    const b = fixtureV1(1000, -18000, -14400);
    try testing.expect(!parseTzif(b[0..50])); // truncated mid-body
}

test "POSIX TZ: fixed offset, no DST" {
    try testing.expect(parsePosix("EST5"));
    try testing.expectEqual(@as(?PosixRule, null), posix);
    try testing.expectEqual(@as(i32, -5 * 3600), zone.offsetAt(0));
}

test "POSIX TZ: DST rule evaluated on both sides of the boundary" {
    try testing.expect(parsePosix("EST5EDT,M3.2.0,M11.1.0"));
    const p = posix.?;
    // 2026: DST starts Sun 8 Mar, ends Sun 1 Nov (US rules).
    const jan = daysFromCivil(2026, 1, 15) * 86400;
    const jul = daysFromCivil(2026, 7, 15) * 86400;
    try testing.expectEqual(@as(i32, -5 * 3600), p.offsetAt(jan));
    try testing.expectEqual(@as(i32, -4 * 3600), p.offsetAt(jul));
}

test "POSIX TZ: unsupported J-form is rejected rather than guessed" {
    try testing.expect(!parsePosix("EST5EDT,J60,J300"));
}

test "weekday and M-rule land on the right day" {
    try testing.expectEqual(@as(i32, 4), weekday(1970, 1, 1)); // Thursday
    // Second Sunday of March 2026 is the 8th.
    const r = PosixRule.MRule{ .month = 3, .week = 2, .day = 0, .secs = 0 };
    try testing.expectEqual(daysFromCivil(2026, 3, 8) * 86400, instantOf(r, 2026));
    // "Week 5" means the last such weekday: last Sunday of March 2026 is the 29th.
    const last = PosixRule.MRule{ .month = 3, .week = 5, .day = 0, .secs = 0 };
    try testing.expectEqual(daysFromCivil(2026, 3, 29) * 86400, instantOf(last, 2026));
}
