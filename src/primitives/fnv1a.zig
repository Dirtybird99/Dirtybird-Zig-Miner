//! FNV-1a 64-bit. basis 0xcbf29ce484222325, prime 0x100000001b3. Wrapping multiply.
const std = @import("std");

const BASIS: u64 = 0xcbf29ce484222325;
const PRIME: u64 = 0x100000001b3;

pub fn hash(data: []const u8) u64 {
    var h: u64 = BASIS;
    for (data) |b| {
        h ^= @as(u64, b);
        h *%= PRIME;
    }
    return h;
}

/// Fixed 256-byte variant (the post-RC4 lhash seed).
pub fn hash256(data: *const [256]u8) u64 {
    return hash(data);
}

test "fnv1a-64 known vector" {
    // FNV-1a 64 of "" is the basis; of "a" is 0xaf63dc4c8601ec8c
    try std.testing.expectEqual(@as(u64, BASIS), hash(""));
    try std.testing.expectEqual(@as(u64, 0xaf63dc4c8601ec8c), hash("a"));
}
