//! SipHash-2-4, byte-faithful to HighwayHash's sip_hash.h as the C miner calls it:
//! `SipHash({k0, k1}, data, len)` where the key is two u64 words used DIRECTLY
//! (k0 = tries, k1 = prev_lhash) — not reinterpreted from key bytes.
const std = @import("std");

inline fn rotl(x: u64, comptime b: u6) u64 {
    return (x << b) | (x >> (64 - @as(u7, b)));
}

pub fn hash(k0: u64, k1: u64, data: []const u8) u64 {
    var v0: u64 = 0x736f6d6570736575 ^ k0;
    var v1: u64 = 0x646f72616e646f6d ^ k1;
    var v2: u64 = 0x6c7967656e657261 ^ k0;
    var v3: u64 = 0x7465646279746573 ^ k1;

    const round = struct {
        inline fn r(a: *u64, b: *u64, c: *u64, d: *u64) void {
            a.* +%= b.*;
            b.* = rotl(b.*, 13);
            b.* ^= a.*;
            a.* = rotl(a.*, 32);
            c.* +%= d.*;
            d.* = rotl(d.*, 16);
            d.* ^= c.*;
            a.* +%= d.*;
            d.* = rotl(d.*, 21);
            d.* ^= a.*;
            c.* +%= b.*;
            b.* = rotl(b.*, 17);
            b.* ^= c.*;
            c.* = rotl(c.*, 32);
        }
    }.r;

    const full = data.len - (data.len % 8);
    var i: usize = 0;
    while (i < full) : (i += 8) {
        const m = std.mem.readInt(u64, data[i..][0..8], .little);
        v3 ^= m;
        round(&v0, &v1, &v2, &v3);
        round(&v0, &v1, &v2, &v3);
        v0 ^= m;
    }

    // final 8-byte packet: trailing bytes in low positions, (len & 0xff) in top byte
    var b: u64 = @as(u64, @as(u8, @truncate(data.len))) << 56;
    var j: usize = 0;
    while (full + j < data.len) : (j += 1) {
        b |= @as(u64, data[full + j]) << @intCast(8 * j);
    }
    v3 ^= b;
    round(&v0, &v1, &v2, &v3);
    round(&v0, &v1, &v2, &v3);
    v0 ^= b;

    v2 ^= 0xff;
    round(&v0, &v1, &v2, &v3);
    round(&v0, &v1, &v2, &v3);
    round(&v0, &v1, &v2, &v3);
    round(&v0, &v1, &v2, &v3);

    return v0 ^ v1 ^ v2 ^ v3;
}

test "siphash-2-4 vs oracle (highwayhash variant)" {
    try std.testing.expectEqual(@as(u64, 0x54e761ac4b1ca3de), hash(1, 0, ""));
    try std.testing.expectEqual(@as(u64, 0xd15ad05b2871319d), hash(1, 2, "abc"));
    var pat: [48]u8 = undefined;
    for (&pat, 0..) |*p, idx| p.* = @intCast(idx);
    try std.testing.expectEqual(@as(u64, 0xfdfd6564cd6cb327), hash(7, 0xdeadbeef, &pat));
    var p15: [15]u8 = undefined;
    for (&p15, 0..) |*p, idx| p.* = @intCast(idx);
    try std.testing.expectEqual(@as(u64, 0x71bfad869ecfeeca), hash(0xabcdef, 0x12345, &p15));
}
