//! astrobwt.zig -- the AstroBWTv3 branch-compute core (wolfCompute) + the Worker
//! scratch. Ported byte-faithfully from astrobwt.cpp's wolfCompute (scalar dispatch,
//! which is provably identical to the LUT/AVX2 paths since regular ops ignore pos2val).
//!
//! Every byte/u64 operation that wraps in C uses Zig wrapping operators (+% -% *%);
//! develop in ReleaseSafe so a missed wrap panics at the exact site.
const std = @import("std");
const CodeLUT = @import("codelut.zig").CodeLUT;
const sa_mod = @import("suffix_array.zig");
const sa_fast = @import("sa_fast.zig");
const Rc4 = @import("primitives/rc4.zig").Rc4;
const xxhash64 = @import("primitives/xxhash64.zig");
const fnv1a = @import("primitives/fnv1a.zig");
const siphash = @import("primitives/siphash.zig");

pub const SCRATCH: usize = 72000 + 64; // MAX_LENGTH + 64

pub const Worker = struct {
    sData: [SCRATCH]u8 = undefined,
    sa: [SCRATCH]i32 = undefined,
    key: Rc4 = .{},
    op: u8 = 0,
    A: u8 = 0,
    pos1: u8 = 0,
    pos2: u8 = 0,
    data_len: u32 = 0,
    random_switcher: u64 = 0,
    lhash: u64 = 0,
    prev_lhash: u64 = 0,
    tries: u16 = 0,
    template_idx: i32 = 0,
    /// Per-template group markers (posData = (firstChunk<<7)|chunkCount) recorded
    /// during wolfCompute; consumed by the v1.14 descriptor SA to exploit the
    /// repeat structure. n_templates is the count after the final flush.
    template_markers: [320]u16 = undefined,
    n_templates: u32 = 0,
    /// Lazily-created reusable libsais context (per thread). Free with deinitSA().
    sa_ctx: ?*anyopaque = null,
    /// Lazily-allocated scratch for the experimental fast SA backends. Kept as
    /// heap pointers so the libsais path's Worker stays lean (~360 KB).
    sa_scratch: ?*sa_fast.Scratch = null,
    sa_radix: ?*sa_fast.Radix8 = null,

    /// Release the libsais context + any SA scratch. Safe to call repeatedly.
    pub fn deinitSA(self: *Worker) void {
        if (self.sa_ctx) |c| {
            sa_mod.freeCtx(c);
            self.sa_ctx = null;
        }
        if (self.sa_scratch) |p| {
            std.heap.page_allocator.destroy(p);
            self.sa_scratch = null;
        }
        if (self.sa_radix) |p| {
            std.heap.page_allocator.destroy(p);
            self.sa_radix = null;
        }
    }
};

inline fn rl8(x: u8, d: u8) u8 {
    return std.math.rotl(u8, x, @as(u3, @intCast(d & 7)));
}

/// Ops whose 4 micro-ops reference pos2val (state-dependent) -- these cannot be
/// table-driven. Everything else is a pure byte->byte map (a "regular" op) and is
/// served from a precomputed 1D LUT. List from the dirtybird reference (verified
/// byte-identical to the per-byte wolfBranch path by the oracle fuzz).
const BRANCHED_OPS = [_]u8{
    1,   3,   5,   9,   11,  13,  15,  17,  20,  21,  23,  27,  29,  30,  35,  39,
    40,  43,  45,  47,  51,  54,  58,  60,  62,  64,  68,  70,  72,  74,  75,  80,
    82,  85,  91,  92,  93,  94,  103, 108, 109, 115, 116, 117, 119, 120, 123, 124,
    127, 132, 133, 134, 136, 138, 140, 142, 143, 146, 148, 149, 150, 154, 155, 159,
    161, 165, 168, 169, 176, 177, 178, 180, 182, 184, 187, 189, 190, 193, 194, 195,
    199, 202, 203, 204, 212, 214, 215, 216, 219, 221, 222, 223, 226, 227, 230, 231,
    234, 236, 239, 240, 241, 242, 250, 253,
};

/// Comptime 1D LUT: reg_idx[op]=0xFF for branched ops, else a compact index into
/// `lut` (152 regular ops x 256 = 38912 bytes, L1-friendly). lut[idx*256+v] =
/// wolfBranch(v, 0, CodeLUT[op]).
const RegLut = struct { reg_idx: [256]u8, lut: [152 * 256]u8 };
const REGLUT: RegLut = blk: {
    @setEvalBranchQuota(5_000_000);
    var rl: RegLut = .{ .reg_idx = [_]u8{0xFF} ** 256, .lut = undefined };
    var branched = [_]bool{false} ** 256;
    for (BRANCHED_OPS) |op| branched[op] = true;
    var rc: u8 = 0;
    for (0..256) |op| {
        if (branched[op]) continue;
        rl.reg_idx[op] = rc;
        const opc = CodeLUT[op];
        for (0..256) |v| rl.lut[@as(usize, rc) * 256 + v] = wolfBranch(@intCast(v), 0, opc);
        rc += 1;
    }
    break :blk rl;
};

/// wolfBranch: 4 micro-ops packed in `opcode`, executed MSB-first.
pub fn wolfBranch(val_in: u8, pos2val: u8, opcode: u32) u8 {
    var val = val_in;
    var i: u5 = 3;
    while (true) : (i -%= 1) {
        const insn: u8 = @truncate(opcode >> @as(u5, @intCast(@as(u32, i) * 8)));
        switch (insn) {
            0 => val +%= val,
            1 => val -%= (val ^ 97),
            2 => val *%= val,
            3 => val ^= pos2val,
            4 => val = ~val,
            5 => val &= pos2val,
            6 => val = @truncate(@as(u16, val) << @as(u4, @intCast(val & 3))),
            7 => val >>= @as(u3, @intCast(val & 3)),
            8 => val = @bitReverse(val),
            9 => val ^= @popCount(val),
            10 => val = rl8(val, val),
            11 => val = rl8(val, 1),
            12 => val ^= rl8(val, 2),
            13 => val = rl8(val, 3),
            14 => val ^= rl8(val, 4),
            15 => val = rl8(val, 5),
            else => {},
        }
        if (i == 0) break;
    }
    return val;
}

// ---- AVX2 wolfPermute for branched (pos2val-dependent) ops: 32 bytes/op via
// @Vector, byte-identical to the scalar wolfBranch (validated by the oracle fuzz).
// Port of the dirtybird reference's simd_wolf.h.
const V32u8 = @Vector(32, u8);
const V32u3 = @Vector(32, u3);

inline fn vrolc(x: V32u8, comptime n: u3) V32u8 {
    if (n == 0) return x;
    const l: V32u3 = @splat(n);
    const r: V32u3 = @splat(@intCast(8 - @as(u8, n)));
    return (x << l) | (x >> r);
}
inline fn vrolv(x: V32u8) V32u8 { // rotate each byte left by (byte & 7)
    const amt: V32u8 = x & @as(V32u8, @splat(7));
    const l: V32u3 = @truncate(amt);
    const r: V32u3 = @truncate((@as(V32u8, @splat(8)) -% amt) & @as(V32u8, @splat(7)));
    return (x << l) | (x >> r);
}

/// out[p1..p2) = wolfBranch(in[i], in[p2], op) for i in [p1,p2), via 32-byte SIMD.
/// Touches 32 bytes from p1 (blended so only [p1,p2) commits) -- the caller's
/// buffer must have >=32 bytes after p1 (sData does), matching the C++ exactly.
fn wolfPermuteAvx2(in: [*]const u8, out: [*]u8, op: u8, p1: u8, p2: u8) void {
    const opc = CodeLUT[op];
    var data: V32u8 = in[p1..][0..32].*;
    const old = data;
    const pos2val: V32u8 = @splat(in[p2]);
    const v3: V32u8 = @splat(3);
    var i: i32 = 3;
    while (i >= 0) : (i -= 1) {
        const insn: u8 = @truncate(opc >> @intCast(@as(u32, @intCast(i)) * 8));
        switch (insn) {
            0 => data = data +% data,
            1 => data = data -% (data ^ @as(V32u8, @splat(97))),
            2 => data = data *% data,
            3 => data = data ^ pos2val,
            4 => data = ~data,
            5 => data = data & pos2val,
            6 => data = data << @as(V32u3, @truncate(data & v3)),
            7 => data = data >> @as(V32u3, @truncate(data & v3)),
            8 => data = @bitReverse(data),
            9 => data = data ^ @popCount(data),
            10 => data = vrolv(data),
            11 => data = vrolc(data, 1),
            12 => data = data ^ vrolc(data, 2),
            13 => data = vrolc(data, 3),
            14 => data = data ^ vrolc(data, 4),
            15 => data = vrolc(data, 5),
            else => {},
        }
    }
    const len: u8 = p2 - p1;
    const idx: V32u8 = std.simd.iota(u8, 32);
    const mask = idx < @as(V32u8, @splat(len));
    out[p1..][0..32].* = @select(u8, mask, data, old);
}

/// The 278-iteration branch-compute loop. Fills w.sData[0..w.data_len].
pub fn wolfCompute(w: *Worker) void {
    w.template_idx = 0;
    var chunk_count: u32 = 1; // C++ chunkCount is int (no u8 wrap); must match for markers
    var first_chunk: i32 = 0;
    var lp1: u8 = 0;
    var lp2: u8 = 255;
    w.tries = 0;

    var chunk_off: usize = 0;

    var it: u32 = 0;
    while (it < 278) : (it += 1) {
        w.tries +%= 1;
        w.random_switcher = w.prev_lhash ^ w.lhash ^ @as(u64, w.tries);
        w.op = @truncate(w.random_switcher);
        var p1: u8 = @truncate(w.random_switcher >> 8);
        var p2: u8 = @truncate(w.random_switcher >> 16);

        if (p1 > p2) {
            const t = p1;
            p1 = p2;
            p2 = t;
        }
        if (p2 - p1 > 32) p2 = p1 +% ((p2 - p1) & 0x1f);

        lp1 = @min(lp1, p1);
        lp2 = @max(lp2, p2);
        w.pos1 = p1;
        w.pos2 = p2;

        chunk_off = @as(usize, w.tries - 1) * 256;
        const chunk = w.sData[chunk_off..][0..256];
        var prev_chunk: *[256]u8 = chunk;
        if (w.tries != 1) {
            prev_chunk = w.sData[(@as(usize, w.tries - 2) * 256)..][0..256];
            @memcpy(chunk, prev_chunk);
        }

        op_blk: {
            if (w.op == 253) {
                var i: usize = p1;
                while (i < p2) : (i += 1) {
                    chunk[i] = rl8(chunk[i], 3);
                    chunk[i] ^= rl8(chunk[i], 2);
                    chunk[i] ^= prev_chunk[p2];
                    chunk[i] = rl8(chunk[i], 3);
                    w.prev_lhash = w.lhash +% w.prev_lhash;
                    w.lhash = xxhash64.hash(0, chunk[0..p2]);
                }
                break :op_blk;
            }
            if (w.op == 53 or w.op == 55 or w.op == 188 or w.op == 249) {
                var i: usize = p1;
                while (i < p2) : (i += 1) chunk[i] = 0;
                break :op_blk;
            }
            if (w.op >= 254) w.key.setKey(prev_chunk);

            const ridx = REGLUT.reg_idx[w.op];
            if (ridx != 0xFF) {
                // regular op: one table load per byte instead of the 4-op wolfBranch
                const row = REGLUT.lut[@as(usize, ridx) * 256 ..][0..256];
                var i: usize = p1;
                while (i < p2) : (i += 1) chunk[i] = row[prev_chunk[i]];
            } else {
                // branched (pos2val-dependent) op: 32-byte AVX2 permute
                wolfPermuteAvx2(@as([*]const u8, prev_chunk), @as([*]u8, chunk), w.op, p1, p2);
            }

            if (w.op == 0) {
                if ((p2 - p1) % 2 == 1) {
                    const t1 = chunk[p1];
                    const t2 = chunk[p2];
                    chunk[p1] = @bitReverse(t2);
                    chunk[p2] = @bitReverse(t1);
                }
            }
        }

        // after_op
        w.A = chunk[p1] -% chunk[p2];
        if (w.A < 0x10) {
            w.prev_lhash = w.lhash +% w.prev_lhash;
            w.lhash = xxhash64.hash(0, chunk[0..p2]);
        }
        if (w.A < 0x20) {
            w.prev_lhash = w.lhash +% w.prev_lhash;
            w.lhash = fnv1a.hash(chunk[0..p2]);
        }
        if (w.A < 0x30) {
            w.prev_lhash = w.lhash +% w.prev_lhash;
            w.lhash = siphash.hash(@as(u64, w.tries), w.prev_lhash, chunk[0..p2]);
        }

        if (w.A <= 0x40) {
            w.key.process(chunk, chunk);
            // Record the template marker (posData) BEFORE the reset, exactly as
            // the C++ wolfCompute does: astroTemplate[templateIdx] = (firstChunk<<7)|chunkCount,
            // then templateIdx += (tries>1).
            w.template_markers[@intCast(w.template_idx)] =
                @truncate((@as(u32, @intCast(first_chunk)) << 7) | chunk_count);
            w.template_idx += @intFromBool(w.tries > 1);
            first_chunk = @as(i32, w.tries) - 1;
            lp1 = 255;
            lp2 = 0;
            chunk_count = 1;
        } else {
            chunk_count += 1;
        }

        chunk[255] = chunk[255] ^ chunk[p1] ^ chunk[p2];

        if (w.tries > 276 or (chunk[255] >= 0xf0 and w.tries > 260)) break;
    }
    // Flush the final template marker (C++: chunkCount > 0 always holds here),
    // then record the template count for the v1.14 descriptor SA.
    w.template_markers[@intCast(w.template_idx)] =
        @truncate((@as(u32, @intCast(first_chunk)) << 7) | chunk_count);
    w.template_idx += 1;
    w.n_templates = @intCast(w.template_idx);
    _ = .{ lp1, lp2 };

    const last = w.sData[chunk_off..][0..256];
    const tail: u64 = (@as(u64, last[253]) << 8 | @as(u64, last[254])) & 0x3ff;
    w.data_len = @intCast((@as(i64, w.tries) - 4) * 256 + @as(i64, @intCast(tail)));
    while (w.data_len > 0 and w.sData[w.data_len - 1] == 0) w.data_len -= 1;
}
