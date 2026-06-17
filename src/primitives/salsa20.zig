//! Salsa20/20 keystream expansion, byte-faithful to the upstream ucstk::Salsa20.
//! Key = 32 bytes, IV = 0 (8 bytes), block counter starts at 0. Emits 256 bytes
//! (4 blocks) of keystream. Little-endian words throughout.
const std = @import("std");

inline fn rotl(v: u32, comptime n: u5) u32 {
    return std.math.rotl(u32, v, n);
}
inline fn rd(b: *const [4]u8) u32 {
    return std.mem.readInt(u32, b, .little);
}

/// Expand a 32-byte key into 256 bytes of Salsa20/20 keystream (IV=0, counter=0).
pub fn expand(key: *const [32]u8, out: *[256]u8) void {
    const sigma = "expand 32-byte k";
    var v: [16]u32 = .{
        rd(sigma[0..4]), rd(key[0..4]),   rd(key[4..8]),    rd(key[8..12]),
        rd(key[12..16]), rd(sigma[4..8]), 0,                0,
        0,               0,               rd(sigma[8..12]), rd(key[16..20]),
        rd(key[20..24]), rd(key[24..28]), rd(key[28..32]),  rd(sigma[12..16]),
    };

    var off: usize = 0;
    var block: usize = 0;
    while (block < 4) : (block += 1) {
        var x: [16]u32 = v;
        var i: i32 = 20;
        while (i > 0) : (i -= 2) {
            x[4] ^= rotl(x[0] +% x[12], 7);
            x[8] ^= rotl(x[4] +% x[0], 9);
            x[12] ^= rotl(x[8] +% x[4], 13);
            x[0] ^= rotl(x[12] +% x[8], 18);
            x[9] ^= rotl(x[5] +% x[1], 7);
            x[13] ^= rotl(x[9] +% x[5], 9);
            x[1] ^= rotl(x[13] +% x[9], 13);
            x[5] ^= rotl(x[1] +% x[13], 18);
            x[14] ^= rotl(x[10] +% x[6], 7);
            x[2] ^= rotl(x[14] +% x[10], 9);
            x[6] ^= rotl(x[2] +% x[14], 13);
            x[10] ^= rotl(x[6] +% x[2], 18);
            x[3] ^= rotl(x[15] +% x[11], 7);
            x[7] ^= rotl(x[3] +% x[15], 9);
            x[11] ^= rotl(x[7] +% x[3], 13);
            x[15] ^= rotl(x[11] +% x[7], 18);
            x[1] ^= rotl(x[0] +% x[3], 7);
            x[2] ^= rotl(x[1] +% x[0], 9);
            x[3] ^= rotl(x[2] +% x[1], 13);
            x[0] ^= rotl(x[3] +% x[2], 18);
            x[6] ^= rotl(x[5] +% x[4], 7);
            x[7] ^= rotl(x[6] +% x[5], 9);
            x[4] ^= rotl(x[7] +% x[6], 13);
            x[5] ^= rotl(x[4] +% x[7], 18);
            x[11] ^= rotl(x[10] +% x[9], 7);
            x[8] ^= rotl(x[11] +% x[10], 9);
            x[9] ^= rotl(x[8] +% x[11], 13);
            x[10] ^= rotl(x[9] +% x[8], 18);
            x[12] ^= rotl(x[15] +% x[14], 7);
            x[13] ^= rotl(x[12] +% x[15], 9);
            x[14] ^= rotl(x[13] +% x[12], 13);
            x[15] ^= rotl(x[14] +% x[13], 18);
        }
        var j: usize = 0;
        while (j < 16) : (j += 1) {
            std.mem.writeInt(u32, out[off..][0..4], x[j] +% v[j], .little);
            off += 4;
        }
        // increment 64-bit block counter (words 8 low, 9 high)
        v[8] +%= 1;
        if (v[8] == 0) v[9] +%= 1;
    }
}
