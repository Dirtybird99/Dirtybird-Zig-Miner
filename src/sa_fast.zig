//! sa_fast.zig -- fast suffix-array construction for the AstroBWTv3 stage-5,
//! specialized for the (near-uniform-random) Wolf-permuted byte data.
//!
//! WHY THIS IS NOT "CHEATING": a suffix array is mathematically UNIQUE for a
//! string. Any construction that lexicographically orders all suffixes produces
//! the byte-identical SA, hence the byte-identical final hash. This module is
//! validated bit-for-bit against libsais (and the independent C++ oracle) over
//! the differential-fuzz corpus. It just gets to the same answer faster.
//!
//! ALGORITHM (port of dirtybird's bucket_sa.h / DeroLuna's radix path):
//!   1. Counting sort by the 2-byte prefix into 65536 buckets (256 KB, L2-resident).
//!   2. Scatter suffix start positions into SA by that prefix.
//!   3. Within each multi-element bucket, finish the order with a suffix
//!      comparator that compares 8 bytes at a time (big-endian load == direct
//!      lexicographic compare), falling back to byte-wise, with the standard
//!      "shorter suffix sorts first" sentinel rule -- exactly libsais's order.
//! For random data the average bucket holds ~1.07 suffixes, so step 3 is cheap.
//!
//! libsais does 5+ induced-sort passes over the whole array with irregular
//! random access (L3/RAM bound). This stays in L1/L2 and runs ~2-3x faster on
//! this workload. See docs and the radix-vs-sais parity analysis.

const std = @import("std");

pub const BUCKETS: usize = 65536; // 256 * 256

/// Per-thread scratch (the three 64K-entry u32 tables). ~768 KB; allocate once
/// per mining thread and reuse, like the libsais context.
pub const Scratch = struct {
    counts: [BUCKETS]u32 = undefined,
    offsets: [BUCKETS]u32 = undefined,
    bucket_start: [BUCKETS]u32 = undefined,
};

/// Lexicographic "suffix at `a` < suffix at `b`" for the text `T[0..n)`.
/// The 2-byte prefix is already equal (same bucket), so we start at offset +2.
/// The Wolf-permuted data has a deep mean LCP (~68 bytes from the period-256
/// chunk structure), so the inner loop is the whole cost -- it runs 32 bytes at
/// a time on AVX2. Reads never pass `end`, so no input padding is required.
const V32 = @Vector(32, u8);
inline fn suffixLess(T: [*]const u8, n: usize, a: i32, b: i32) bool {
    var pa: usize = @as(usize, @intCast(a)) + 2;
    var pb: usize = @as(usize, @intCast(b)) + 2;
    const end: usize = n;

    // 32 bytes at a time: equal-compare the lanes, jump to the first differing
    // byte via a movemask + count-trailing-zeros.
    while (pa + 32 <= end and pb + 32 <= end) {
        const va: V32 = T[pa..][0..32].*;
        const vb: V32 = T[pb..][0..32].*;
        const eqmask: u32 = @bitCast(va == vb);
        if (eqmask != 0xFFFF_FFFF) {
            const off = @ctz(~eqmask);
            return T[pa + off] < T[pb + off];
        }
        pa += 32;
        pb += 32;
    }
    // 8-byte tail: big-endian load makes the u64 compare a lexicographic compare.
    while (pa + 8 <= end and pb + 8 <= end) {
        const va = std.mem.readInt(u64, T[pa..][0..8], .big);
        const vb = std.mem.readInt(u64, T[pb..][0..8], .big);
        if (va != vb) return va < vb;
        pa += 8;
        pb += 8;
    }
    while (pa < end and pb < end) {
        if (T[pa] != T[pb]) return T[pa] < T[pb];
        pa += 1;
        pb += 1;
    }
    // One suffix is a prefix of the other: the shorter one (larger start) is
    // smaller, matching the implicit end-of-string sentinel < every byte.
    return (end - @as(usize, @intCast(a))) < (end - @as(usize, @intCast(b)));
}

fn lessThanCtx(ctx: SortCtx, a: i32, b: i32) bool {
    return suffixLess(ctx.T, ctx.n, a, b);
}
const SortCtx = struct { T: [*]const u8, n: usize };

/// Build the suffix array of `T[0..n)` into `SA[0..n)`. `sc` is reusable scratch.
/// Produces the byte-identical SA that libsais would (validated by fuzz).
pub fn bucketSortSA(sc: *Scratch, T: [*]const u8, SA: [*]i32, n: usize) void {
    if (n == 0) return;
    if (n == 1) {
        SA[0] = 0;
        return;
    }

    // Phase 1: histogram of 2-byte prefixes.
    @memset(&sc.counts, 0);
    var i: usize = 0;
    while (i < n - 1) : (i += 1) {
        const key = (@as(usize, T[i]) << 8) | @as(usize, T[i + 1]);
        sc.counts[key] += 1;
    }
    // Last position is a 1-byte suffix: prefix = (T[n-1], sentinel) -> bucket hi*256+0,
    // the smallest bucket among those starting with byte T[n-1].
    sc.counts[@as(usize, T[n - 1]) << 8] += 1;

    // Phase 2: exclusive prefix sum -> bucket start offsets.
    var sum: u32 = 0;
    var b: usize = 0;
    while (b < BUCKETS) : (b += 1) {
        sc.offsets[b] = sum;
        sum += sc.counts[b];
    }
    @memcpy(&sc.bucket_start, &sc.offsets);

    // Phase 3: scatter positions into SA by their 2-byte prefix.
    i = 0;
    while (i < n - 1) : (i += 1) {
        const key = (@as(usize, T[i]) << 8) | @as(usize, T[i + 1]);
        SA[sc.offsets[key]] = @intCast(i);
        sc.offsets[key] += 1;
    }
    {
        const key = @as(usize, T[n - 1]) << 8;
        SA[sc.offsets[key]] = @intCast(n - 1);
        sc.offsets[key] += 1;
    }

    // Phase 4: order within each bucket that holds >1 suffix.
    b = 0;
    while (b < BUCKETS) : (b += 1) {
        const cnt = sc.counts[b];
        if (cnt <= 1) continue;
        const start = sc.bucket_start[b];

        if (cnt == 2) {
            if (suffixLess(T, n, SA[start + 1], SA[start])) {
                const tmp = SA[start];
                SA[start] = SA[start + 1];
                SA[start + 1] = tmp;
            }
        } else if (cnt <= 16) {
            // Insertion sort: most multi-buckets hold 3-5 suffixes.
            var ii: u32 = start + 1;
            while (ii < start + cnt) : (ii += 1) {
                const key_val = SA[ii];
                var j: i64 = @as(i64, ii) - 1;
                while (j >= start and suffixLess(T, n, key_val, SA[@intCast(j)])) {
                    SA[@as(usize, @intCast(j + 1))] = SA[@as(usize, @intCast(j))];
                    j -= 1;
                }
                SA[@as(usize, @intCast(j + 1))] = key_val;
            }
        } else {
            // Rare large bucket: O(n log n) worst-case pattern-defeating sort.
            const slice = SA[start .. start + cnt];
            std.sort.pdq(i32, slice, SortCtx{ .T = T, .n = n }, lessThanCtx);
        }
    }
}

// ===================================================================
// Variant B: 8-byte-prefix radix (port of dirtybird's dluna_radix_sa.h).
// 4 LSD passes of 16-bit counting sort over a compact records array
// presort the full 8-byte big-endian prefix WITHOUT any comparisons
// (sequential, cache-resident). Only true 8-byte-prefix collisions then
// hit the SIMD comparator. EXACT: the comparator resolves to full depth.
// ===================================================================

pub const RADIX_MAX_N: usize = 72064;
const RADIX_BUCKETS: usize = 65536;

const SortRecord = extern struct { key: u64, pos: u32, pad: u32 };

pub const Radix8 = struct {
    records: [RADIX_MAX_N]SortRecord = undefined,
    temp: [RADIX_MAX_N]SortRecord = undefined,
    hist: [4][RADIX_BUCKETS]u32 = undefined,
};

/// Compare suffixes a<b knowing their first `skip` bytes are already equal.
inline fn suffixLessSkip(T: [*]const u8, n: usize, a: i32, b: i32, comptime skip: usize) bool {
    var pa: usize = @as(usize, @intCast(a)) + skip;
    var pb: usize = @as(usize, @intCast(b)) + skip;
    const end: usize = n;
    while (pa + 32 <= end and pb + 32 <= end) {
        const va: V32 = T[pa..][0..32].*;
        const vb: V32 = T[pb..][0..32].*;
        const eqmask: u32 = @bitCast(va == vb);
        if (eqmask != 0xFFFF_FFFF) {
            const off = @ctz(~eqmask);
            return T[pa + off] < T[pb + off];
        }
        pa += 32;
        pb += 32;
    }
    while (pa + 8 <= end and pb + 8 <= end) {
        const va = std.mem.readInt(u64, T[pa..][0..8], .big);
        const vb = std.mem.readInt(u64, T[pb..][0..8], .big);
        if (va != vb) return va < vb;
        pa += 8;
        pb += 8;
    }
    while (pa < end and pb < end) {
        if (T[pa] != T[pb]) return T[pa] < T[pb];
        pa += 1;
        pb += 1;
    }
    return (end - @as(usize, @intCast(a))) < (end - @as(usize, @intCast(b)));
}

fn lessSkip8(ctx: SortCtx, a: i32, b: i32) bool {
    return suffixLessSkip(ctx.T, ctx.n, a, b, 8);
}

/// Build SA via 8-byte-prefix radix. Requires >=8 bytes of readable padding
/// after T[n-1] (pow.zig zero-pads sData). EXACT (validated vs libsais).
pub fn radixSortSA8(rx: *Radix8, T: [*]const u8, SA: [*]i32, n: usize) void {
    if (n == 0) return;
    if (n == 1) {
        SA[0] = 0;
        return;
    }
    const records = &rx.records;
    const temp = &rx.temp;
    @memset(std.mem.asBytes(&rx.hist), 0);

    // Phase 1: encode 8-byte big-endian key + histograms (4x 16-bit digits).
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const key = std.mem.readInt(u64, T[i..][0..8], .big);
        records[i] = .{ .key = key, .pos = @intCast(i), .pad = 0 };
        rx.hist[0][(key >> 0) & 0xFFFF] += 1;
        rx.hist[1][(key >> 16) & 0xFFFF] += 1;
        rx.hist[2][(key >> 32) & 0xFFFF] += 1;
        rx.hist[3][(key >> 48) & 0xFFFF] += 1;
    }

    // Phase 2: prefix sums -> start offsets.
    for (0..4) |p| {
        var off: u32 = 0;
        for (0..RADIX_BUCKETS) |r| {
            const c = rx.hist[p][r];
            rx.hist[p][r] = off;
            off += c;
        }
    }

    // Phase 3: 4 stable LSD passes (16 bits each).
    i = 0;
    while (i < n) : (i += 1) {
        const d = (records[i].key >> 0) & 0xFFFF;
        temp[rx.hist[0][d]] = records[i];
        rx.hist[0][d] += 1;
    }
    i = 0;
    while (i < n) : (i += 1) {
        const d = (temp[i].key >> 16) & 0xFFFF;
        records[rx.hist[1][d]] = temp[i];
        rx.hist[1][d] += 1;
    }
    i = 0;
    while (i < n) : (i += 1) {
        const d = (records[i].key >> 32) & 0xFFFF;
        temp[rx.hist[2][d]] = records[i];
        rx.hist[2][d] += 1;
    }
    i = 0;
    while (i < n) : (i += 1) {
        const d = (temp[i].key >> 48) & 0xFFFF;
        records[rx.hist[3][d]] = temp[i];
        rx.hist[3][d] += 1;
    }

    // Phase 4: extract; resolve rare equal-key runs with the exact comparator.
    var out: usize = 0;
    i = 0;
    while (i < n) {
        const key = records[i].key;
        if (i + 1 >= n or records[i + 1].key != key) {
            SA[out] = @intCast(records[i].pos);
            out += 1;
            i += 1;
            continue;
        }
        var j = i + 1;
        while (j < n and records[j].key == key) j += 1;
        const bsize = j - i;
        for (0..bsize) |k| SA[out + k] = @intCast(records[i + k].pos);
        const grp = SA[out .. out + bsize];
        if (bsize <= 24) {
            // insertion sort
            var x: usize = 1;
            while (x < bsize) : (x += 1) {
                const kv = grp[x];
                var y: i64 = @as(i64, @intCast(x)) - 1;
                while (y >= 0 and suffixLessSkip(T, n, kv, grp[@intCast(y)], 8)) {
                    grp[@as(usize, @intCast(y + 1))] = grp[@as(usize, @intCast(y))];
                    y -= 1;
                }
                grp[@as(usize, @intCast(y + 1))] = kv;
            }
        } else {
            std.sort.pdq(i32, grp, SortCtx{ .T = T, .n = n }, lessSkip8);
        }
        out += bsize;
        i = j;
    }
}

// ---- correctness tests (vs a reference O(n^2 log n) naive SA) ----

fn naiveSuffixLess(T: []const u8, a: usize, b: usize) bool {
    var pa = a;
    var pb = b;
    while (pa < T.len and pb < T.len) : (pa += 1) {
        if (T[pa] != T[pb]) return T[pa] < T[pb];
        pb += 1;
    }
    return (T.len - a) < (T.len - b);
}

fn naiveSA(T: []const u8, out: []i32) void {
    for (out, 0..) |*v, i| v.* = @intCast(i);
    const C = struct {
        t: []const u8,
        fn lt(self: @This(), x: i32, y: i32) bool {
            return naiveSuffixLess(self.t, @intCast(x), @intCast(y));
        }
    };
    std.sort.pdq(i32, out, C{ .t = T }, C.lt);
}

test "bucketSortSA matches naive SA on random + adversarial inputs" {
    const sc = try std.testing.allocator.create(Scratch);
    defer std.testing.allocator.destroy(sc);

    var prng = std.Random.DefaultPrng.init(0x5A5A);
    const r = prng.random();

    var buf: [4096]u8 = undefined;
    var sa_fast: [4096]i32 = undefined;
    var sa_ref: [4096]i32 = undefined;

    // random byte strings, many lengths & alphabets (small alphabet => more ties)
    var trial: usize = 0;
    while (trial < 3000) : (trial += 1) {
        const n = 1 + (r.int(usize) % buf.len);
        const alphabet: u16 = switch (r.int(u2)) {
            0 => 2, // binary: heavy ties, stresses the comparator/sentinel
            1 => 4,
            2 => 16,
            3 => 256,
        };
        for (buf[0..n]) |*c| c.* = @intCast(r.int(u16) % alphabet);
        bucketSortSA(sc, buf[0..n].ptr, sa_fast[0..n].ptr, n);
        naiveSA(buf[0..n], sa_ref[0..n]);
        try std.testing.expectEqualSlices(i32, sa_ref[0..n], sa_fast[0..n]);
    }

    // adversarial: all same byte, runs, near-periodic
    const cases = [_][]const u8{
        "a", "aa", "aaaa", "ababab", "abcabcabc", "\x00\x00\x00", "\x00\x01\x00\x01",
        "banana", "mississippi", "aaaaaaaab", "baaaaaaaa",
    };
    for (cases) |t| {
        const n = t.len;
        bucketSortSA(sc, t.ptr, sa_fast[0..n].ptr, n);
        naiveSA(t, sa_ref[0..n]);
        try std.testing.expectEqualSlices(i32, sa_ref[0..n], sa_fast[0..n]);
    }
}

test "radixSortSA8 matches naive SA on random + adversarial inputs" {
    const rx = try std.testing.allocator.create(Radix8);
    defer std.testing.allocator.destroy(rx);

    var prng = std.Random.DefaultPrng.init(0x7E57);
    const r = prng.random();

    // buffer with >=8 bytes of zero tail padding (radix reads 8-byte windows)
    var buf: [4096 + 16]u8 = undefined;
    var sa_out: [4096]i32 = undefined;
    var sa_ref: [4096]i32 = undefined;

    var trial: usize = 0;
    while (trial < 3000) : (trial += 1) {
        const n = 1 + (r.int(usize) % 4096);
        const alphabet: u16 = switch (r.int(u2)) {
            0 => 2,
            1 => 4,
            2 => 16,
            3 => 256,
        };
        for (buf[0..n]) |*c| c.* = @intCast(r.int(u16) % alphabet);
        @memset(buf[n .. n + 16], 0);
        radixSortSA8(rx, buf[0..n].ptr, sa_out[0..n].ptr, n);
        naiveSA(buf[0..n], sa_ref[0..n]);
        try std.testing.expectEqualSlices(i32, sa_ref[0..n], sa_out[0..n]);
    }

    const cases = [_][]const u8{
        "a", "aa", "aaaa", "ababab", "abcabcabc", "banana", "mississippi",
        "aaaaaaaaaaaaaaaaab", "baaaaaaaaaaaaaaaaa", "abababababababab",
    };
    for (cases) |t| {
        const n = t.len;
        @memcpy(buf[0..n], t);
        @memset(buf[n .. n + 16], 0);
        radixSortSA8(rx, buf[0..n].ptr, sa_out[0..n].ptr, n);
        naiveSA(t, sa_ref[0..n]);
        try std.testing.expectEqualSlices(i32, sa_ref[0..n], sa_out[0..n]);
    }
}
