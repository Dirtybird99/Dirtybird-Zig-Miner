//! tz.zig -- local UTC offset, resolved without libc.
//!
//! WHY THIS EXISTS: `localtime_r` is libc and this miner links none on
//! Linux/Android, so log lines were UTC on POSIX while the C++, Rust and Go
//! siblings printed local wall-clock in the very same format -- a Zig line
//! silently read hours off with nothing marking it.
//!
//! Zig's std ships a TZif *parser* (`std.tz`, RFC 9636/8536) but no zone
//! *resolution*: nothing maps "now" to an offset, and nothing finds the zone
//! file in the first place. That gap is what this file fills. The binary
//! format is std's problem, deliberately -- an earlier version of this file
//! hand-rolled the parser and got it wrong in the way the format punishes
//! (see the note on slim files below).
//!
//! Sources, first hit wins: the TZ environment variable, then /etc/localtime.
//! `offsetAt` returns null wherever the zone genuinely cannot be resolved, and
//! console.zig then marks that line `Z`. A wrong offset is worse than an
//! honest UTC, so every unparseable input resolves to null rather than a guess.
//!
//! ANDROID: bionic reads a single concatenated `tzdata` container (under
//! /apex/com.android.tzdata/etc/tz/ or /system/usr/share/zoneinfo/) and never
//! consults TZDIR or a per-zone file tree, so none of the lookups below can
//! succeed there. Android is expected to fall through to the `Z` marker.

const std = @import("std");
const builtin = @import("builtin");

const is_windows_target = builtin.os.tag == .windows;

/// RFC 9636 §3.2 bounds on a UT offset. Anything outside is a corrupt file, and
/// a corrupt offset must not reach the clock arithmetic in console.zig.
const min_utoff: i32 = -89999;
const max_utoff: i32 = 93599;

/// Zone data is parsed once at first use and lives for the process, so it is
/// carved out of a fixed buffer rather than the heap: no allocator plumbing,
/// no steady-state allocation. Real zone files are a few KiB.
var arena_buf: [96 * 1024]u8 = undefined;

const Resolved = union(enum) {
    /// Transition table plus the trailing POSIX rule, which is the sole
    /// authority for instants after the last stored transition.
    tzif: struct { tz: std.tz.Tz, footer: ?PosixRule },
    /// A TZ value that was itself a POSIX rule, or a fixed offset.
    rule: PosixRule,
    fixed: i32,
};

var resolved: ?Resolved = null;
var once = std.once(resolve);

/// Seconds east of UTC for `utc_secs`, or null when no zone data could be
/// found or trusted. Parsing happens once; only the lookup runs per line.
pub fn offsetAt(utc_secs: i64) ?i32 {
    if (is_windows_target) return null; // Windows uses GetLocalTime directly.
    once.call();
    const r = resolved orelse return null;
    const off: i32 = switch (r) {
        .fixed => |f| f,
        .rule => |p| p.offsetAt(utc_secs),
        .tzif => |t| tzifOffset(t.tz, t.footer, utc_secs),
    };
    // Belt and braces: std.tz does not range-check `offset`, and console.zig
    // must never be handed something that makes its clock arithmetic negative.
    if (off < min_utoff or off > max_utoff) return null;
    return off;
}

/// Offset from a parsed zone: the last transition at or before the instant,
/// except past the final transition, where the footer rule takes over. Slim
/// TZif files (zic's default since tzcode 2020b) stop their table decades ago
/// and rely on that footer entirely -- America/New_York's last transition is
/// in 2007 -- so ignoring it means reporting a permanently stale offset.
fn tzifOffset(tz: std.tz.Tz, footer: ?PosixRule, utc_secs: i64) i32 {
    const ts = tz.transitions;
    if (ts.len == 0) return if (footer) |f| f.offsetAt(utc_secs) else firstStandard(tz);
    if (utc_secs >= ts[ts.len - 1].ts) {
        if (footer) |f| return f.offsetAt(utc_secs);
        return ts[ts.len - 1].timetype.offset;
    }
    if (utc_secs < ts[0].ts) return firstStandard(tz);

    var lo: usize = 0;
    var hi: usize = ts.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (ts[mid].ts <= utc_secs) lo = mid + 1 else hi = mid;
    }
    return ts[lo - 1].timetype.offset;
}

/// Before the first transition, RFC 9636 §4 says to use the first timetype
/// that is not DST, falling back to the first one.
fn firstStandard(tz: std.tz.Tz) i32 {
    for (tz.timetypes) |t| {
        if (!t.isDst()) return t.offset;
    }
    return if (tz.timetypes.len > 0) tz.timetypes[0].offset else 0;
}

fn resolve() void {
    if (is_windows_target) return;

    if (std.posix.getenv("TZ")) |tz_env| {
        // A TZ the user set explicitly is never silently replaced by
        // /etc/localtime: guessing differently is the wrong kind of helpful.
        resolveTz(tz_env);
        return;
    }
    _ = loadFile("/etc/localtime");
}

fn resolveTz(tz_in: []const u8) void {
    var tz = tz_in;
    if (tz.len > 0 and tz[0] == ':') tz = tz[1..];
    if (tz.len == 0) {
        resolved = .{ .fixed = 0 }; // POSIX: empty TZ means UTC.
        return;
    }
    if (std.ascii.eqlIgnoreCase(tz, "UTC") or std.ascii.eqlIgnoreCase(tz, "GMT")) {
        resolved = .{ .fixed = 0 };
        return;
    }
    // Try the POSIX rule form FIRST. Testing for '/' first would misroute every
    // rule carrying an explicit transition time -- CET-1CEST,M3.5.0,M10.5.0/3
    // and GMT0BST,M3.5.0/1,M10.5.0 among them, i.e. most of Europe.
    if (parsePosix(tz)) |p| {
        resolved = p;
        return;
    }
    _ = loadZoneName(tz);
}

fn loadZoneName(name: []const u8) bool {
    // A zone name indexes a system database; it is not a path to follow.
    // Reject traversal and absolute paths outright rather than opening them.
    if (name.len == 0 or name[0] == '/') return false;
    if (std.mem.indexOf(u8, name, "..") != null) return false;

    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const roots = [_]?[]const u8{
        std.posix.getenv("TZDIR"),
        "/usr/share/zoneinfo",
        "/etc/zoneinfo",
    };
    for (roots) |maybe_root| {
        const root = maybe_root orelse continue;
        const p = std.fmt.bufPrint(&buf, "{s}/{s}", .{ root, name }) catch continue;
        if (loadFile(p)) return true;
    }
    if (std.posix.getenv("PREFIX")) |prefix| { // Termux
        const p = std.fmt.bufPrint(&buf, "{s}/share/zoneinfo/{s}", .{ prefix, name }) catch return false;
        if (loadFile(p)) return true;
    }
    return false;
}

fn loadFile(path: []const u8) bool {
    const f = std.fs.openFileAbsolute(path, .{}) catch return false;
    defer f.close();

    // A FIFO would block this thread forever inside std.once, taking every
    // logging thread with it. Only ever read a regular file.
    const st = f.stat() catch return false;
    if (st.kind != .file) return false;

    var fba = std.heap.FixedBufferAllocator.init(&arena_buf);
    const tz = std.tz.Tz.parse(fba.allocator(), f.reader()) catch return false;

    var footer: ?PosixRule = null;
    if (tz.footer) |ft| footer = parsePosixRule(ft);

    resolved = .{ .tzif = .{ .tz = tz, .footer = footer } };
    return true;
}

// ---------------------------------------------------------------------------
// POSIX TZ strings -- "std offset[dst[offset]][,start,end]"
// ---------------------------------------------------------------------------

const PosixRule = struct {
    std_off: i32,
    dst_off: i32,
    start: ?MRule = null,
    end: ?MRule = null,

    const MRule = struct { month: u8, week: u8, day: u8, secs: i32 };

    fn offsetAt(self: PosixRule, utc_secs: i64) i32 {
        const s_rule = self.start orelse return self.std_off;
        const e_rule = self.end orelse return self.std_off;
        // Transition instants are local; using the standard offset for both
        // comparisons is off by an hour for the few hours either side of a
        // switch, which is immaterial for a log timestamp.
        const local = utc_secs + self.std_off;
        const year = yearOf(local);
        const s = instantOf(s_rule, year);
        const e = instantOf(e_rule, year);
        const in_dst = if (s <= e) (local >= s and local < e) else (local >= s or local < e);
        return if (in_dst) self.dst_off else self.std_off;
    }
};

fn parsePosix(s: []const u8) ?Resolved {
    const r = parsePosixRule(s) orelse return null;
    if (r.start == null) return .{ .fixed = r.std_off };
    return .{ .rule = r };
}

/// Returns null for anything not fully understood -- J<n> and bare <n> day
/// forms included -- so an unsupported rule degrades to a marked UTC rather
/// than a confidently wrong offset.
fn parsePosixRule(s: []const u8) ?PosixRule {
    var i: usize = 0;
    _ = scanName(s, &i) orelse return null;
    const std_off = scanOffset(s, &i) orelse return null;
    const std_east = -std_off; // POSIX offsets are west-positive.
    if (std_east < min_utoff or std_east > max_utoff) return null;

    if (i >= s.len) return .{ .std_off = std_east, .dst_off = std_east };

    _ = scanName(s, &i) orelse return null;
    var dst_east = std_east + 3600;
    if (i < s.len and s[i] != ',') {
        const d = scanOffset(s, &i) orelse return null;
        dst_east = -d;
    }
    if (dst_east < min_utoff or dst_east > max_utoff) return null;
    if (i >= s.len or s[i] != ',') return null;
    i += 1;
    const start = scanMRule(s, &i) orelse return null;
    if (i >= s.len or s[i] != ',') return null;
    i += 1;
    const end = scanMRule(s, &i) orelse return null;
    if (i != s.len) return null; // trailing junk means we did not understand it

    return .{ .std_off = std_east, .dst_off = dst_east, .start = start, .end = end };
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

/// "[+|-]hh[:mm[:ss]]" -> seconds, POSIX sign convention (positive is west).
/// Each field is range-checked before it is multiplied, so a hostile TZ cannot
/// overflow the arithmetic (which is UB in the ReleaseFast build we ship).
fn scanOffset(s: []const u8, i: *usize) ?i32 {
    var j = i.*;
    if (j >= s.len) return null;
    var neg = false;
    if (s[j] == '+' or s[j] == '-') {
        neg = s[j] == '-';
        j += 1;
    }
    const h = scanInt(s, &j, 24) orelse return null;
    var total: i32 = h * 3600;
    if (j < s.len and s[j] == ':') {
        j += 1;
        const m = scanInt(s, &j, 59) orelse return null;
        total += m * 60;
        if (j < s.len and s[j] == ':') {
            j += 1;
            const sec = scanInt(s, &j, 59) orelse return null;
            total += sec;
        }
    }
    i.* = j;
    return if (neg) -total else total;
}

fn scanInt(s: []const u8, i: *usize, max: i32) ?i32 {
    const start = i.*;
    var j = start;
    while (j < s.len and std.ascii.isDigit(s[j])) j += 1;
    if (j == start or j - start > 3) return null;
    const v = std.fmt.parseInt(i32, s[start..j], 10) catch return null;
    if (v > max) return null;
    i.* = j;
    return v;
}

/// "M<month>.<week>.<day>[/<time>]" only.
fn scanMRule(s: []const u8, i: *usize) ?PosixRule.MRule {
    var j = i.*;
    if (j >= s.len or s[j] != 'M') return null;
    j += 1;
    const month = scanInt(s, &j, 12) orelse return null;
    if (j >= s.len or s[j] != '.') return null;
    j += 1;
    const week = scanInt(s, &j, 5) orelse return null;
    if (j >= s.len or s[j] != '.') return null;
    j += 1;
    const day = scanInt(s, &j, 6) orelse return null;
    if (month < 1 or week < 1) return null;

    var secs: i32 = 2 * 3600; // POSIX default switch time
    if (j < s.len and s[j] == '/') {
        j += 1;
        secs = scanOffset(s, &j) orelse return null;
    }
    i.* = j;
    return .{ .month = @intCast(month), .week = @intCast(week), .day = @intCast(day), .secs = secs };
}

// ---------------------------------------------------------------------------
// Civil-date helpers (UTC; the offset is applied by the caller)
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

/// Day of week for a civil date, 0 = Sunday (1970-01-01 was a Thursday).
fn weekday(y: i32, m: i32, d: i32) i32 {
    return @intCast(@mod(daysFromCivil(y, m, d) + 4, 7));
}

/// Local instant of an M-rule in a given year, seconds since epoch.
fn instantOf(r: PosixRule.MRule, year: i32) i64 {
    const month: i32 = r.month;
    const want: i32 = r.day;
    const first_dow = weekday(year, month, 1);
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

test "POSIX: fixed offset, no DST rule" {
    const r = parsePosixRule("EST5").?;
    try testing.expectEqual(@as(i32, -5 * 3600), r.std_off);
    try testing.expectEqual(@as(?PosixRule.MRule, null), r.start);
    try testing.expectEqual(@as(i32, -5 * 3600), r.offsetAt(0));
}

test "POSIX: DST evaluated on both sides of the boundary" {
    const r = parsePosixRule("EST5EDT,M3.2.0,M11.1.0").?;
    const jan = daysFromCivil(2026, 1, 15) * 86400;
    const jul = daysFromCivil(2026, 7, 15) * 86400;
    try testing.expectEqual(@as(i32, -5 * 3600), r.offsetAt(jan));
    try testing.expectEqual(@as(i32, -4 * 3600), r.offsetAt(jul));
}

test "POSIX: rules carrying an explicit transition time are accepted" {
    // These all contain '/', which an earlier version misrouted to a file
    // lookup -- taking most of Europe, the UK, Australia and NZ with it.
    const uk = parsePosixRule("GMT0BST,M3.5.0/1,M10.5.0").?;
    const jul = daysFromCivil(2026, 7, 15) * 86400;
    try testing.expectEqual(@as(i32, 3600), uk.offsetAt(jul));

    const cet = parsePosixRule("CET-1CEST,M3.5.0,M10.5.0/3").?;
    try testing.expectEqual(@as(i32, 2 * 3600), cet.offsetAt(jul));

    // Southern hemisphere: DST spans the year boundary.
    const syd = parsePosixRule("AEST-10AEDT,M10.1.0,M4.1.0/3").?;
    const jan = daysFromCivil(2026, 1, 15) * 86400;
    try testing.expectEqual(@as(i32, 11 * 3600), syd.offsetAt(jan));
    try testing.expectEqual(@as(i32, 10 * 3600), syd.offsetAt(jul));
}

test "POSIX: unparseable forms yield null, never a guess" {
    try testing.expectEqual(@as(?PosixRule, null), parsePosixRule("EST5EDT,J60,J300")); // J-form
    try testing.expectEqual(@as(?PosixRule, null), parsePosixRule("XYZ500000")); // hours out of range
    try testing.expectEqual(@as(?PosixRule, null), parsePosixRule("XYZ600000")); // would overflow i32
    try testing.expectEqual(@as(?PosixRule, null), parsePosixRule("%%%"));
    try testing.expectEqual(@as(?PosixRule, null), parsePosixRule("America/Chicago")); // a zone name
    try testing.expectEqual(@as(?PosixRule, null), parsePosixRule("EST5EDT,M3.2.0,M11.1.0junk"));
}

test "POSIX: offsets stay inside the RFC range" {
    const r = parsePosixRule("XYZ24").?; // 24h west is the extreme legal value
    try testing.expect(r.std_off >= min_utoff and r.std_off <= max_utoff);
}

test "civil date helpers" {
    try testing.expectEqual(@as(i32, 4), weekday(1970, 1, 1)); // Thursday
    try testing.expectEqual(@as(i64, -365), daysFromCivil(1969, 1, 1));
    try testing.expectEqual(@as(i32, 1969), yearOf(-1));
    // Second Sunday of March 2026 is the 8th; the last is the 29th.
    const second = PosixRule.MRule{ .month = 3, .week = 2, .day = 0, .secs = 0 };
    const last = PosixRule.MRule{ .month = 3, .week = 5, .day = 0, .secs = 0 };
    try testing.expectEqual(daysFromCivil(2026, 3, 8) * 86400, instantOf(second, 2026));
    try testing.expectEqual(daysFromCivil(2026, 3, 29) * 86400, instantOf(last, 2026));
}

test "slim TZif: the footer rule governs instants past the last transition" {
    // The shape that broke the previous implementation: a table whose last
    // transition is decades old, plus a footer that carries the live rule.
    // America/New_York's real table ends in 2007.
    var timetypes = [_]std.tz.Timetype{
        .{ .offset = -18000, .flags = 0, .name_data = "EST\x00\x00\x00".* },
        .{ .offset = -14400, .flags = 1, .name_data = "EDT\x00\x00\x00".* },
    };
    var transitions = [_]std.tz.Transition{
        .{ .ts = daysFromCivil(2007, 3, 11) * 86400, .timetype = &timetypes[1] },
    };
    const tz = std.tz.Tz{
        .allocator = testing.allocator,
        .transitions = &transitions,
        .timetypes = &timetypes,
        .leapseconds = &.{},
        .footer = null,
    };
    const footer = parsePosixRule("EST5EDT,M3.2.0,M11.1.0");
    const jan_2026 = daysFromCivil(2026, 1, 15) * 86400;
    const jul_2026 = daysFromCivil(2026, 7, 15) * 86400;

    // Without the footer the stale DST transition wins forever -- the bug.
    try testing.expectEqual(@as(i32, -14400), tzifOffset(tz, null, jan_2026));
    // With it, January is correctly EST and July correctly EDT.
    try testing.expectEqual(@as(i32, -18000), tzifOffset(tz, footer, jan_2026));
    try testing.expectEqual(@as(i32, -14400), tzifOffset(tz, footer, jul_2026));
}

test "TZif lookup: before the first transition uses the first standard type" {
    var timetypes = [_]std.tz.Timetype{
        .{ .offset = -14400, .flags = 1, .name_data = "EDT\x00\x00\x00".* },
        .{ .offset = -18000, .flags = 0, .name_data = "EST\x00\x00\x00".* },
    };
    var transitions = [_]std.tz.Transition{
        .{ .ts = 1000, .timetype = &timetypes[0] },
    };
    const tz = std.tz.Tz{
        .allocator = testing.allocator,
        .transitions = &transitions,
        .timetypes = &timetypes,
        .leapseconds = &.{},
        .footer = null,
    };
    try testing.expectEqual(@as(i32, -18000), tzifOffset(tz, null, 999)); // first non-DST
    try testing.expectEqual(@as(i32, -14400), tzifOffset(tz, null, 1000)); // at the transition
}
