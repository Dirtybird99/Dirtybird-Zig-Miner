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
//! The Zig miner forces the leading CR+clear sequence for every log line so a later
//! INFO/WARN/ERROR line never lands in the middle of the live status banner.
const std = @import("std");
const builtin = @import("builtin");

const is_windows = builtin.os.tag == .windows;
const A_CLREOL = "\x1b[K"; // ANSI erase-to-end-of-line (C's dluna_clr_eol)

/// Broken-down LOCAL wall-clock time to the millisecond (C: localtime + .%03d ms).
const LocalTime = struct { month: u8, day: u8, hour: u8, minute: u8, second: u8, millis: u16 };

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
        // POSIX: pure-Zig UTC breakdown via std.time.epoch (no libc localtime_r,
        // so the miner links no libc on Linux/Android). Timestamps are UTC rather
        // than local wall-clock -- a deliberate trade for a fully pure-Zig build;
        // Windows still shows local time via GetLocalTime.
        const ms_total = std.time.milliTimestamp();
        const secs: u64 = @intCast(@divFloor(ms_total, 1000));
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
        };
    }
}

fn formatLogLine(buf: []u8, lt: LocalTime, level: []const u8, msg: []const u8) []const u8 {
    var lvl: [5]u8 = .{ ' ', ' ', ' ', ' ', ' ' };
    const n = @min(level.len, lvl.len);
    @memcpy(lvl[0..n], level[0..n]);

    return std.fmt.bufPrint(buf, "\r{s}{d:0>2}/{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}  {s} {s}\n", .{
        A_CLREOL, lt.day, lt.month, lt.hour, lt.minute, lt.second, lt.millis, lvl[0..], msg,
    }) catch buf[0..0];
}

/// Print one timestamped log line for a pre-formatted message. `level` is left-padded
/// to width 5 (C's `%-5s`): "INFO "/"WARN "/"ERROR", giving two spaces after "INFO".
/// The leading `\r\x1b[K` overwrites the reporter's in-place stats line.
pub fn logLineRaw(level: []const u8, msg: []const u8) void {
    const lt = nowLocal();
    var buf: [1024]u8 = undefined;
    std.debug.print("{s}", .{formatLogLine(&buf, lt, level, msg)});
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
    }, "INFO", "Connected");

    try std.testing.expectEqualStrings("\r\x1b[K19/06 13:27:12.466  INFO  Connected\n", line);
}
