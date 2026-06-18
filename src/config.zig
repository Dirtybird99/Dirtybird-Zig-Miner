//! config.zig -- optional config.json read at startup. Uses the same keys as the
//! DeroLuna miner (`daemon-address`, `wallet`, `threads`) so a familiar config.json
//! "just works". Precedence: explicit CLI flags > config.json > compiled-in defaults.
const std = @import("std");

pub const Config = struct {
    daemon_address: ?[]const u8 = null,
    wallet: ?[]const u8 = null,
    threads: ?i64 = null,
};

/// Parse a JSON config. Unknown keys are ignored and any missing key stays null, so a
/// partial or fuller DeroLuna-style config.json is accepted. Returned strings are duped
/// with `allocator` (program-lifetime; freed at process exit).
pub fn parseConfig(allocator: std.mem.Allocator, bytes: []const u8) !Config {
    const Raw = struct {
        @"daemon-address": ?[]const u8 = null,
        wallet: ?[]const u8 = null,
        threads: ?i64 = null,
    };
    var parsed = try std.json.parseFromSlice(Raw, allocator, bytes, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const r = parsed.value;
    return .{
        .daemon_address = if (r.@"daemon-address") |s| try allocator.dupe(u8, s) else null,
        .wallet = if (r.wallet) |s| try allocator.dupe(u8, s) else null,
        .threads = r.threads,
    };
}

test "parseConfig: reads keys, ignores unknown, missing -> null" {
    const a = std.testing.allocator;
    const json =
        \\{
        \\  "daemon-address": "host.example:1234",
        \\  "wallet": "dero1qexample",
        \\  "threads": -1,
        \\  "lock-threads": true,
        \\  "period": 10
        \\}
    ;
    const c = try parseConfig(a, json);
    defer {
        if (c.daemon_address) |s| a.free(s);
        if (c.wallet) |s| a.free(s);
    }
    try std.testing.expectEqualStrings("host.example:1234", c.daemon_address.?);
    try std.testing.expectEqualStrings("dero1qexample", c.wallet.?);
    try std.testing.expectEqual(@as(i64, -1), c.threads.?);

    const c2 = try parseConfig(a, "{}");
    try std.testing.expect(c2.daemon_address == null);
    try std.testing.expect(c2.wallet == null);
    try std.testing.expect(c2.threads == null);
}
