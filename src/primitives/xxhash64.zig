//! XXHash64 (canonical XXH64), seed 0 in the pipeline. Thin wrapper over std.
const std = @import("std");

pub fn hash(seed: u64, data: []const u8) u64 {
    return std.hash.XxHash64.hash(seed, data);
}

test "xxhash64 canonical vectors (seed 0) vs oracle" {
    try std.testing.expectEqual(@as(u64, 0xef46db3751d8e999), hash(0, ""));
    try std.testing.expectEqual(@as(u64, 0x44bc2cf5ad770999), hash(0, "abc"));
    var pat: [48]u8 = undefined;
    for (&pat, 0..) |*p, i| p.* = @intCast(i);
    try std.testing.expectEqual(@as(u64, 0x8fe437632da06964), hash(0, &pat));
}
