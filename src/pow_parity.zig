//! Full-pipeline parity vs oracle: data_len, lhash/prev_lhash, SDATA, SA bytes, and
//! the final OUT must all match for every golden case. Requires libsais (run via
//! `zig build test`).
const std = @import("std");
const tv = @import("testvec.zig");
const pow = @import("pow.zig");

test "full pipeline parity across all golden cases" {
    const alloc = std.testing.allocator;
    const w = try alloc.create(pow.Worker);
    defer alloc.destroy(w);
    defer w.deinitSA();

    for (tv.cases) |case| {
        w.* = .{};
        var input_buf: [256]u8 = undefined;
        const input_len = tv.hexDecode(tv.field(case, "INPUT").?, &input_buf);
        var out: [32]u8 = undefined;
        try pow.hash(input_buf[0..input_len], &out, w);

        try std.testing.expectEqual(tv.u32Field(case, "DATALEN").?, w.data_len);
        try std.testing.expectEqual(tv.u64Field(case, "LHASH").?, w.lhash);
        try std.testing.expectEqual(tv.u64Field(case, "PREVLHASH").?, w.prev_lhash);

        const sdata_exp = try alloc.alloc(u8, w.data_len);
        defer alloc.free(sdata_exp);
        _ = tv.hexDecode(tv.field(case, "SDATA").?, sdata_exp);
        try std.testing.expectEqualSlices(u8, sdata_exp, w.sData[0..w.data_len]);

        const sa_exp = try alloc.alloc(u8, w.data_len * 4);
        defer alloc.free(sa_exp);
        _ = tv.hexDecode(tv.field(case, "SA").?, sa_exp);
        try std.testing.expectEqualSlices(u8, sa_exp, std.mem.sliceAsBytes(w.sa[0..w.data_len]));

        var out_exp: [32]u8 = undefined;
        _ = tv.hexDecode(tv.field(case, "OUT").?, &out_exp);
        try std.testing.expectEqualSlices(u8, &out_exp, &out);
    }
}
