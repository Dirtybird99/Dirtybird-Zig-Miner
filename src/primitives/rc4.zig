//! RC4 (Rivest) — byte-identical to OpenSSL's RC4 as used by the C miner.
//! State persists across `process` calls within one hash; `setKey` (initial keying
//! and op>=254 re-key in wolfCompute) resets the permutation and the x/y cursors.
const std = @import("std");

pub const Rc4 = struct {
    x: u32 = 0,
    y: u32 = 0,
    s: [256]u32 = undefined,

    pub fn setKey(self: *Rc4, key: []const u8) void {
        self.x = 0;
        self.y = 0;
        var i: usize = 0;
        while (i < 256) : (i += 1) self.s[i] = @intCast(i);
        var j: u32 = 0;
        i = 0;
        while (i < 256) : (i += 1) {
            j = (j + self.s[i] + key[i % key.len]) & 0xff;
            const t = self.s[i];
            self.s[i] = self.s[j];
            self.s[j] = t;
        }
    }

    /// Encrypt/decrypt in place is allowed (in and out may alias).
    pub fn process(self: *Rc4, in: []const u8, out: []u8) void {
        var x = self.x;
        var y = self.y;
        var n: usize = 0;
        while (n < in.len) : (n += 1) {
            x = (x + 1) & 0xff;
            y = (y + self.s[x]) & 0xff;
            const t = self.s[x];
            self.s[x] = self.s[y];
            self.s[y] = t;
            const k = self.s[(self.s[x] + self.s[y]) & 0xff];
            out[n] = in[n] ^ @as(u8, @intCast(k));
        }
        self.x = x;
        self.y = y;
    }
};

test "rc4 standard KAT key=Key pt=Plaintext" {
    var rc4: Rc4 = .{};
    rc4.setKey("Key");
    var ct: [9]u8 = undefined;
    rc4.process("Plaintext", &ct);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3 }, &ct);
}
