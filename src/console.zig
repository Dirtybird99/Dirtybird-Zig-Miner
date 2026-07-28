//! console.zig -- timestamped INFO/WARN/ERROR log lines matching the Dirtybird C
//! miner's `console.cpp::log_line`. Imported by main.zig ONLY; net.zig stays portable
//! and reaches logging through the net.Hooks `log` callback instead of importing this.
//!
//! C reference (src/console.cpp):
//!   TTY:      printf("\r%s%s.%03d  %-5s %s\n", clr_eol, ts, ms, level, msg)
//!   non-TTY:  printf("%s.%03d  %-5s %s\n", ts, ms, level, msg)
//!   ts = strftime("%d/%m %H:%M:%S", localtime), clr_eol = "\x1b[K".
//! The C writes to stdout; we use stderr (std.debug.print) to share the one stream --
//! and lock -- the reporter already uses (main.zig). Visually identical.
//! Interactive logs clear the live status row; redirected logs stay plain.
const std = @import("std");
const builtin = @import("builtin");
const tz = @import("tz.zig");

const is_windows = builtin.os.tag == .windows;
const A_CLREOL = "\x1b[K"; // ANSI erase-to-end-of-line (C's dluna_clr_eol)
var is_tty = false;

pub fn setTty(value: bool) void {
    is_tty = value;
}

/// Broken-down LOCAL wall-clock time to the millisecond (C: localtime + .%03d ms).
/// `utc` is set when no timezone could be resolved and the fields are therefore
/// UTC; the formatter marks those lines so they cannot be misread as local.
const LocalTime = struct { month: u8, day: u8, hour: u8, minute: u8, second: u8, millis: u16, utc: bool = false };

// Windows GetLocalTime gives every field (incl. milliseconds) directly. Declared at top
// level but referenced only in the is_windows branch, so the POSIX build prunes it.
const SYSTEMTIME = extern struct {
    wYear: u16,
    wMonth: u16,
    wDayOfWeek: u16,
    wDay: u16,
    wHour: u16,
    wMinute: u16,
    wSecond: u16,
    wMilliseconds: u16,
};
extern "kernel32" fn GetLocalTime(lpSystemTime: *SYSTEMTIME) callconv(.winapi) void;

fn nowLocal() LocalTime {
    if (is_windows) {
        var st: SYSTEMTIME = undefined;
        GetLocalTime(&st);
        return .{
            .month = @intCast(st.wMonth),
            .day = @intCast(st.wDay),
            .hour = @intCast(st.wHour),
            .minute = @intCast(st.wMinute),
            .second = @intCast(st.wSecond),
            .millis = @intCast(st.wMilliseconds),
        };
    } else {
        // POSIX: no libc, so no localtime_r, and std has no timezone facility.
        // tz.zig resolves the offset itself (TZ, then /etc/localtime) so these
        // line up with the C/Rust/Go siblings when logs sit side by side. Where
        // no zone data exists -- Android typically has none -- the fields stay
        // UTC and the formatter appends 'Z' rather than implying local time.
        const ms_total = std.time.milliTimestamp();
        const utc_secs = @divFloor(ms_total, 1000);
        var off: ?i32 = tz.offsetAt(utc_secs);
        // std.time.epoch is epoch-relative and unsigned: a pre-1970 instant
        // would make @intCast illegal behaviour (UB in the ReleaseFast build
        // we ship). An unsynced RTC on a freshly booted phone or SBC reports
        // ~0, which any western offset pushes negative -- so drop the offset
        // and mark the line rather than trusting the arithmetic.
        var shifted = utc_secs + (off orelse 0);
        if (shifted < 0) {
            off = null;
            shifted = utc_secs;
        }
        if (shifted < 0) shifted = 0;
        const secs: u64 = @intCast(shifted);
        const es = std.time.epoch.EpochSeconds{ .secs = secs };
        const yd = es.getEpochDay().calculateYearDay();
        const md = yd.calculateMonthDay();
        const ds = es.getDaySeconds();
        return .{
            .month = @intFromEnum(md.month),
            .day = @as(u8, md.day_index) + 1,
            .hour = ds.getHoursIntoDay(),
            .minute = ds.getMinutesIntoHour(),
            .second = ds.getSecondsIntoMinute(),
            .millis = @intCast(@mod(ms_total, 1000)),
            .utc = off == null,
        };
    }
}

fn formatLogLine(buf: []u8, lt: LocalTime, level: []const u8, msg: []const u8, tty: bool) []const u8 {
    var lvl: [5]u8 = .{ ' ', ' ', ' ', ' ', ' ' };
    const n = @min(level.len, lvl.len);
    @memcpy(lvl[0..n], level[0..n]);

    // 'Z' marks a line whose clock could not be resolved to local time. The two
    // spaces before the level are preserved either way, so the level column
    // stays aligned within a session (a host is consistently one or the other).
    return std.fmt.bufPrint(buf, "{s}{d:0>2}/{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}{s}  {s} {s}\n", .{
        if (tty) "\r" ++ A_CLREOL else "", lt.day, lt.month, lt.hour, lt.minute, lt.second, lt.millis, if (lt.utc) "Z" else "", lvl[0..], msg,
    }) catch buf[0..0];
}

/// Print one timestamped log line for a pre-formatted message. `level` is left-padded
/// to width 5 (C's `%-5s`): "INFO "/"WARN "/"ERROR", giving two spaces after "INFO".
/// The leading `\r\x1b[K` overwrites the reporter's in-place stats line.
pub fn logLineRaw(level: []const u8, msg: []const u8) void {
    const lt = nowLocal();
    var buf: [1024]u8 = undefined;
    std.debug.print("{s}", .{formatLogLine(&buf, lt, level, msg, is_tty)});
}

/// Convenience for callers with a comptime format (the startup banner). Formats into a
/// stack buffer then delegates to logLineRaw. 512 bytes covers a wallet (~66) + label.
pub fn logLine(level: []const u8, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch buf[0..0];
    logLineRaw(level, msg);
}

test "formatLogLine clears any live status row before logging" {
    var buf: [128]u8 = undefined;
    const line = formatLogLine(&buf, .{
        .month = 6,
        .day = 19,
        .hour = 13,
        .minute = 27,
        .second = 12,
        .millis = 466,
    }, "INFO", "Connected", true);

    try std.testing.expectEqualStrings("\r\x1b[K19/06 13:27:12.466  INFO  Connected\n", line);

    const plain = formatLogLine(&buf, .{
        .month = 6,
        .day = 19,
        .hour = 13,
        .minute = 27,
        .second = 12,
        .millis = 466,
    }, "INFO", "Connected", false);
    try std.testing.expectEqualStrings("19/06 13:27:12.466  INFO  Connected\n", plain);
}

test "formatLogLine marks a line whose clock could not be resolved to local time" {
    var buf: [128]u8 = undefined;
    const fields = LocalTime{
        .month = 6,
        .day = 19,
        .hour = 13,
        .minute = 27,
        .second = 12,
        .millis = 466,
        .utc = true,
    };
    const line = formatLogLine(&buf, fields, "INFO", "Connected", false);
    // 'Z' immediately after the milliseconds; the two-space gap before the
    // level is unchanged, so the level column still lines up.
    try std.testing.expectEqualStrings("19/06 13:27:12.466Z  INFO  Connected\n", line);

    // ERROR fills the 5-column level field, leaving a single space -- the same
    // rule the C miner's %-5s produces. Verify the marker doesn't disturb it.
    const err_line = formatLogLine(&buf, fields, "ERROR", "connection lost", false);
    try std.testing.expectEqualStrings("19/06 13:27:12.466Z  ERROR connection lost\n", err_line);
}
