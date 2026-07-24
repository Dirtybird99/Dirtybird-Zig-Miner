//! Golden-vector access: parses testdata/checkpoints.txt (emitted by oracle.exe).
//! Format: blocks introduced by "## case=NAME", each followed by "KEY=hexvalue" lines.
const std = @import("std");

pub const text = @embedFile("testdata/checkpoints.txt");

pub const cases = [_][]const u8{ "a", "zero48", "pat48" };

fn hexNibble(c: u8) u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => 0,
    };
}

/// Decode hex `s` into `out`, returning the number of bytes written.
pub fn hexDecode(s: []const u8, out: []u8) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i + 1 < s.len + 1 and i + 1 <= s.len) : (i += 2) {
        if (i + 1 >= s.len) break;
        out[n] = (hexNibble(s[i]) << 4) | hexNibble(s[i + 1]);
        n += 1;
    }
    return n;
}

/// Return the raw hex string for `key` within case `case`, or null.
pub fn field(case: []const u8, key: []const u8) ?[]const u8 {
    var marker_buf: [64]u8 = undefined;
    const marker = std.fmt.bufPrint(&marker_buf, "## case={s}", .{case}) catch return null;

    var in_case = false;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimRight(u8, raw, "\r");
        if (std.mem.startsWith(u8, line, "## case=")) {
            in_case = std.mem.eql(u8, line, marker);
            continue;
        }
        if (!in_case) continue;
        if (line.len > key.len and std.mem.startsWith(u8, line, key) and line[key.len] == '=') {
            return line[key.len + 1 ..];
        }
    }
    return null;
}

pub fn u64Field(case: []const u8, key: []const u8) ?u64 {
    const s = field(case, key) orelse return null;
    return std.fmt.parseInt(u64, s, 16) catch null;
}

pub fn u32Field(case: []const u8, key: []const u8) ?u32 {
    const s = field(case, key) orelse return null;
    return std.fmt.parseInt(u32, s, 10) catch null;
}

test "parser finds known fields" {
    try std.testing.expectEqualStrings(
        "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
        field("a", "SHA").?,
    );
    try std.testing.expectEqual(@as(u64, 0x11e0770a7f976603), u64Field("a", "LHASH0").?);
    try std.testing.expectEqual(@as(u32, 70318), u32Field("a", "DATALEN").?);
}
