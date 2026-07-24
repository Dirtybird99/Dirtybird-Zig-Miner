//! Per-stage parity: each pipeline stage must match the oracle checkpoints for
//! every golden case. Localises any divergence to a single stage.
const std = @import("std");
const tv = @import("testvec.zig");
const sha256 = @import("primitives/sha256.zig");
const salsa20 = @import("primitives/salsa20.zig");
const fnv1a = @import("primitives/fnv1a.zig");
const Rc4 = @import("primitives/rc4.zig").Rc4;

test "stage parity: sha -> salsa -> rc4 -> fnv1a across all golden cases" {
    for (tv.cases) |case| {
        // input
        var input_buf: [256]u8 = undefined;
        const input_hex = tv.field(case, "INPUT").?;
        const input_len = tv.hexDecode(input_hex, &input_buf);
        const input = input_buf[0..input_len];

        // stage 1: SHA256(input) == SHA
        var sha: [32]u8 = undefined;
        sha256.hash(input, &sha);
        var sha_exp: [32]u8 = undefined;
        _ = tv.hexDecode(tv.field(case, "SHA").?, &sha_exp);
        try std.testing.expectEqualSlices(u8, &sha_exp, &sha);

        // stage 2: Salsa20 expand(SHA) == SALSA
        var salsa: [256]u8 = undefined;
        salsa20.expand(&sha, &salsa);
        var salsa_exp: [256]u8 = undefined;
        _ = tv.hexDecode(tv.field(case, "SALSA").?, &salsa_exp);
        try std.testing.expectEqualSlices(u8, &salsa_exp, &salsa);

        // stage 3: RC4(key=salsa) over salsa, in place == RC4
        var rc4: Rc4 = .{};
        rc4.setKey(&salsa);
        var rc4out: [256]u8 = salsa;
        rc4.process(&rc4out, &rc4out);
        var rc4_exp: [256]u8 = undefined;
        _ = tv.hexDecode(tv.field(case, "RC4").?, &rc4_exp);
        try std.testing.expectEqualSlices(u8, &rc4_exp, &rc4out);

        // stage 4: FNV1a-64(rc4) == LHASH0
        try std.testing.expectEqual(tv.u64Field(case, "LHASH0").?, fnv1a.hash256(&rc4out));
    }
}
