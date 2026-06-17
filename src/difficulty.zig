//! difficulty.zig -- target = floor(2^256 / difficulty) as 32-byte big-endian, and
//! the hash<=target check. Ported from difficulty.cpp (u128 long division, no bigint).
const std = @import("std");

pub fn computeTarget(difficulty: u64, target: *[32]u8) void {
    @memset(target, 0);
    // Degenerate/invalid difficulty: an all-zero target accepts no hash. This is
    // strictly safer than the C's all-0xFF ("everything passes") behavior — a
    // garbage daemon value can neither crash us (no signed cast) nor make us flood
    // the pool with bogus shares.
    if (difficulty == 0) return;
    // 2^256 as a 33-byte big-endian number: [1, 0, 0, ..., 0]
    var dividend = [_]u8{0} ** 33;
    dividend[0] = 1;

    var rem: u128 = 0;
    const d: u64 = difficulty;
    var i: usize = 0;
    while (i < 33) : (i += 1) {
        rem = (rem << 8) | dividend[i];
        if (i > 0) target[i - 1] = @intCast(rem / d);
        rem = rem % d;
    }
}

/// hash is SHA256 output interpreted little-endian; target is big-endian (MSB first).
pub fn checkHash(hash: *const [32]u8, target: *const [32]u8) bool {
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        const h = hash[31 - i];
        const t = target[i];
        if (h < t) return true;
        if (h > t) return false;
    }
    return true; // exact match counts
}

test "computeTarget known values" {
    var t: [32]u8 = undefined;
    computeTarget(256, &t); // 2^248
    try std.testing.expectEqual(@as(u8, 1), t[0]);
    for (t[1..]) |b| try std.testing.expectEqual(@as(u8, 0), b);

    computeTarget(2, &t); // 2^255
    try std.testing.expectEqual(@as(u8, 0x80), t[0]);
    for (t[1..]) |b| try std.testing.expectEqual(@as(u8, 0), b);

    computeTarget(0, &t); // degenerate -> all zero (nothing passes; safe)
    for (t) |b| try std.testing.expectEqual(@as(u8, 0), b);

    // Adversarial near-u64-max difficulty must not panic and yields a tiny target.
    computeTarget(std.math.maxInt(u64), &t);
    try std.testing.expectEqual(@as(u8, 0), t[0]); // ~ 2^256/2^64 = 2^192, high bytes zero
}

test "checkHash ordering" {
    var target: [32]u8 = undefined;
    computeTarget(256, &target); // target = 2^248 (big-endian [1,0,...])

    // hash value 0 (LE) -> passes
    var zero = [_]u8{0} ** 32;
    try std.testing.expect(checkHash(&zero, &target));

    // hash just above target: little-endian value = 2^248 + 1 -> fails.
    // LE value 2^248 means byte index 31 (MSB) = 0x01. +1 sets byte 0.
    var above = [_]u8{0} ** 32;
    above[31] = 0x01; // == target
    above[0] = 0x01; // +1 -> strictly greater
    try std.testing.expect(!checkHash(&above, &target));

    // exactly equal passes
    var eq = [_]u8{0} ** 32;
    eq[31] = 0x01;
    try std.testing.expect(checkHash(&eq, &target));
}
