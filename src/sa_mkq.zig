//! sa_mkq.zig -- EXACT suffix-array construction via recursive MSD radix /
//! multikey quicksort (three-way radix quicksort), specialized for the deep-LCP
//! Wolf-permuted byte data of AstroBWTv3 stage 5.
//!
//! WHY THIS SHAPE (vs the earlier bucket/LSD-radix attempts in sa_fast.zig):
//! Those attempts re-scanned shared prefixes on collision groups (the data has
//! mean LCP ~68, p99 ~416), so the comparator dominated and they lost to libsais.
//! MSD radix RECURSES into the next byte depth on each collision group instead of
//! re-comparing from the start: every byte position is touched at most once per
//! suffix. This is the approach deroluna's decompiled SA core uses (256-way MSD
//! counting radix + recursive partition + an 8-way uint64 comparator tail).
//!
//! EXACTNESS: a suffix array is mathematically UNIQUE for a string, so any correct
//! lexicographic ordering reproduces libsais's bytes exactly. Validated bit-for-bit
//! against a naive O(n^2 log n) reference (unit tests below) and against libsais on
//! real wolfCompute outputs (src/sa_mkq_check.zig).
//!
//! THE SENTINEL RULE (load-bearing for exactness): a suffix whose start `pos`
//! satisfies `pos+d >= n` has ENDED at depth d. An ended suffix is lexicographically
//! smaller than every byte value (implicit end-of-string sentinel < any byte), so it
//! is placed in a dedicated slot BEFORE byte-bucket 0 -- NOT folded into bucket 0,
//! which would intermix it with real `\x00`-continuing suffixes and sort wrong.
//! Within any equal-prefix group at depth d, at most one suffix can have ended (two
//! would be identical strings), so that slot holds <=1 element and is already sorted.
//! This is exactly the "shorter suffix (larger start index) sorts first" convention.

const std = @import("std");

const V32 = @Vector(32, u8);

// ---------------------------------------------------------------------------
// Comparator (copied from sa_fast.zig's `suffixLessSkip`, which is an `inline fn`
// and not `pub`, so it cannot be imported; copying is required and intended).
// `skip` is a RUNTIME depth here (the shared-prefix length the radix already
// resolved) so insertion sort never re-scans bytes the radix already ordered.
// Needs >=32 readable bytes of padding after T[n-1] for the 32-byte SIMD reads;
// the pipeline zero-pads sData, and the unit tests below pad their buffers.
// ---------------------------------------------------------------------------
inline fn suffixLessSkip(T: [*]const u8, n: usize, a: i32, b: i32, skip: usize) bool {
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
    // One suffix is a prefix of the other: the shorter (larger start) is smaller.
    return (end - @as(usize, @intCast(a))) < (end - @as(usize, @intCast(b)));
}

const SortCtx = struct { T: [*]const u8, n: usize, depth: usize };
fn lessThanCtx(ctx: SortCtx, a: i32, b: i32) bool {
    return suffixLessSkip(ctx.T, ctx.n, a, b, ctx.depth);
}

/// Max input length: AstroBWTv3 SCRATCH is 72000+64; round up for safety.
pub const MKQ_MAX_N: usize = 72064;

/// Default: below this range size, finish with insertion sort at the current
/// depth instead of another 256-entry counting pass. This is make-or-break on
/// deep-LCP data: the per-node count-clear is pure overhead on the many small
/// deep groups that mean-LCP-68 produces, and the insertion sort starts at
/// `depth` so it never re-scans the shared prefix the radix already resolved.
/// Overridable per-call via Scratch.insertion_cutoff for tuning sweeps.
///
/// TUNED on real wolfCompute data via the robust min-of-8 sweep in
/// src/sa_mkq_check.zig: the curve is flat for cutoffs ~48-192 (all ~0.75x of
/// libsais), with 96 the consistent best. Cutoffs >=256 risk O(k^2) insertion
/// blow-up on pathological deep-LCP groups, so we stay at 96.
/// (NOTE: on THIS deep-LCP data buildSA is ~1.3x SLOWER than libsais even tuned;
/// see the validator's verdict. This constant only minimizes that gap.)
pub const INSERTION_CUTOFF: usize = 96;

/// One entry of the explicit work stack: a still-unsorted sub-range of SA that
/// shares the first `depth` bytes. The stack only ever holds pairwise-disjoint
/// ranges of size >=2 (children live inside the popped parent; siblings disjoint),
/// so at most n/2 entries -- sizing the stack to MKQ_MAX_N cannot overflow.
const Frame = struct { start: u32, len: u32, depth: u32 };

/// Per-thread reusable scratch. Allocate once per mining thread and reuse across
/// hashes (do NOT allocate per call). ~290 KB temp + ~580 KB stack + 256 KB for
/// the depth-0 two-byte histogram.
pub const Scratch = struct {
    /// Scatter target for the counting-sort pass (one range at a time).
    temp: [MKQ_MAX_N]i32 = undefined,
    /// Explicit DFS work stack.
    stack: [MKQ_MAX_N]Frame = undefined,
    /// 256-bucket histogram + scattering cursors, reused per node.
    count: [256]u32 = undefined,
    offset: [256]u32 = undefined,
    /// 65536-bucket histogram for the one-time 2-byte depth-0 radix pass.
    count16: [65536]u32 = undefined,
    offset16: [65536]u32 = undefined,
    /// Tunable insertion-sort cutoff (0 => use the default INSERTION_CUTOFF).
    /// Exposed for the validator's cutoff sweep; production callers leave it 0.
    insertion_cutoff: usize = 0,
};

/// Insertion sort of SA[start..start+len) using the suffix comparator at `depth`.
inline fn insertionSort(T: [*]const u8, n: usize, SA: [*]i32, start: usize, len: usize, depth: usize) void {
    var i: usize = start + 1;
    while (i < start + len) : (i += 1) {
        const kv = SA[i];
        var j: i64 = @as(i64, @intCast(i)) - 1;
        while (j >= @as(i64, @intCast(start)) and suffixLessSkip(T, n, kv, SA[@intCast(j)], depth)) {
            SA[@as(usize, @intCast(j + 1))] = SA[@as(usize, @intCast(j))];
            j -= 1;
        }
        SA[@as(usize, @intCast(j + 1))] = kv;
    }
}

/// Build the suffix array of `T[0..n)` into `SA[0..n)`.
/// `sc` is reusable per-thread scratch. Produces the byte-identical SA libsais does.
pub fn buildSA(sc: *Scratch, T: [*]const u8, SA: [*]i32, n: usize) void {
    if (n == 0) return;
    if (n == 1) {
        SA[0] = 0;
        return;
    }
    std.debug.assert(n <= MKQ_MAX_N);

    const cutoff: usize = if (sc.insertion_cutoff != 0) sc.insertion_cutoff else INSERTION_CUTOFF;

    var sp: usize = 0;

    // ---- One-time depth-0 two-byte (65536-bucket) counting radix ----
    // Replaces the largest top-level node and a full byte-level in one cache-
    // resident pass (the big count array is cleared ONCE, never per-node). Each
    // resulting bucket shares its first 2 bytes, so we hand it to the 1-byte
    // recursion at depth 2. EXACT: a suffix at pos=n-1 reads T[n] (zero padding)
    // as its 2nd byte and lands in bucket (T[n-1]<<8); the depth-2 recursion's
    // sentinel rule (pos+2 >= n => ended => placed first) then orders it
    // correctly. The lone 1-byte suffix is the unique smallest in that bucket, so
    // even within a multi-element bucket the sentinel handling is exact.
    {
        @memset(&sc.count16, 0);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const key = (@as(usize, T[i]) << 8) | @as(usize, T[i + 1]);
            sc.count16[key] += 1;
        }
        var sum: u32 = 0;
        var b: usize = 0;
        while (b < 65536) : (b += 1) {
            sc.offset16[b] = sum;
            sum += sc.count16[b];
        }
        // Scatter directly into SA by 2-byte prefix.
        i = 0;
        while (i < n) : (i += 1) {
            const key = (@as(usize, T[i]) << 8) | @as(usize, T[i + 1]);
            SA[sc.offset16[key]] = @intCast(i);
            sc.offset16[key] += 1;
        }
        // Seed the work stack with every multi-element 2-byte bucket at depth 2.
        var off: usize = 0;
        b = 0;
        while (b < 65536) : (b += 1) {
            const c: usize = sc.count16[b];
            if (c >= 2) {
                sc.stack[sp] = .{ .start = @intCast(off), .len = @intCast(c), .depth = 2 };
                sp += 1;
            }
            off += c;
        }
    }

    while (sp > 0) {
        sp -= 1;
        const f = sc.stack[sp];
        const start: usize = f.start;
        const len: usize = f.len;
        const depth: usize = f.depth;

        if (len <= 1) continue;
        if (len <= cutoff) {
            insertionSort(T, n, SA, start, len, depth);
            continue;
        }

        // ---- 256-way MSD counting sort by byte T[pos+depth] ----
        // Ended suffixes (pos+depth >= n) are lexicographically smaller than every
        // byte value, so they go FIRST, in [start, start+num_ended), ordered
        // shorter-first (descending pos: a larger start = shorter suffix = smaller).
        // Because the depth-0 front peels TWO byte levels at once, a depth-2 group
        // can contain up to TWO ended suffixes (pos=n-1 and pos=n-2 when the last
        // two bytes are equal); every deeper level has at most one. We collect ALL
        // of them into temp[start..start+num_ended) and sort that tiny run.
        @memset(&sc.count, 0);
        var num_ended: usize = 0;

        var k: usize = start;
        while (k < start + len) : (k += 1) {
            const pos: usize = @intCast(SA[k]);
            if (pos + depth >= n) {
                sc.temp[start + num_ended] = SA[k];
                num_ended += 1;
            } else {
                sc.count[T[pos + depth]] += 1;
            }
        }
        // Order the (<=2) ended suffixes descending by pos (shorter suffix first).
        if (num_ended == 2) {
            if (sc.temp[start] < sc.temp[start + 1]) {
                const t = sc.temp[start];
                sc.temp[start] = sc.temp[start + 1];
                sc.temp[start + 1] = t;
            }
        } else if (num_ended > 2) {
            // Defensive: not reachable given the depth bounds above, but keep exact.
            std.sort.pdq(i32, sc.temp[start .. start + num_ended], {}, struct {
                fn gt(_: void, a: i32, b: i32) bool {
                    return a > b;
                }
            }.gt);
        }

        // Exclusive prefix sum -> bucket start offsets within [base .. start+len),
        // where base = start + num_ended (the ended suffixes occupy the front).
        const base: usize = start + num_ended;
        var sum: u32 = @intCast(base);
        var b: usize = 0;
        while (b < 256) : (b += 1) {
            sc.offset[b] = sum;
            sum += sc.count[b];
        }

        // Scatter the (non-ended) positions into temp by their byte at `depth`.
        k = start;
        while (k < start + len) : (k += 1) {
            const v = SA[k];
            const pos: usize = @intCast(v);
            if (pos + depth >= n) continue; // ended ones already in temp[start..]
            const byte = T[pos + depth];
            sc.temp[sc.offset[byte]] = v;
            sc.offset[byte] += 1;
        }

        // One copy back: ended suffixes (already ordered) + the bucketed bytes.
        @memcpy(SA[start .. start + len], sc.temp[start .. start + len]);

        // Push each multi-element bucket to recurse at depth+1. (Single-element
        // buckets and the ended-suffix front are already final.)
        var off: usize = base;
        b = 0;
        while (b < 256) : (b += 1) {
            const c: usize = sc.count[b];
            if (c >= 2) {
                sc.stack[sp] = .{
                    .start = @intCast(off),
                    .len = @intCast(c),
                    .depth = @intCast(depth + 1),
                };
                sp += 1;
            }
            off += c;
        }
    }
}

// ===========================================================================
// Correctness tests vs a naive O(n^2 log n) reference SA.
// The naive reference uses the SAME sentinel convention that sa_fast.zig already
// validated bit-for-bit against libsais, so reference and libsais agree by
// construction; matching it proves buildSA matches libsais.
// ===========================================================================

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

test "buildSA matches naive SA on random + adversarial inputs" {
    const sc = try std.testing.allocator.create(Scratch);
    defer std.testing.allocator.destroy(sc);

    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    const r = prng.random();

    // buffer with >=32 bytes of zero tail padding (comparator reads 32-byte windows)
    var buf: [4096 + 64]u8 = undefined;
    var sa_out: [4096]i32 = undefined;
    var sa_ref: [4096]i32 = undefined;

    var trial: usize = 0;
    while (trial < 20000) : (trial += 1) {
        const n = 1 + (r.int(usize) % 4096);
        const alphabet: u16 = switch (r.int(u2)) {
            0 => 2, // binary: heavy ties, deepest recursion -> stresses sentinel
            1 => 4,
            2 => 16,
            3 => 256,
        };
        for (buf[0..n]) |*c| c.* = @intCast(r.int(u16) % alphabet);
        @memset(buf[n .. n + 64], 0);
        buildSA(sc, buf[0..n].ptr, sa_out[0..n].ptr, n);
        naiveSA(buf[0..n], sa_ref[0..n]);
        if (!std.mem.eql(i32, sa_ref[0..n], sa_out[0..n])) {
            std.debug.print("MISMATCH trial={d} n={d} alphabet={d}\n", .{ trial, n, alphabet });
            for (0..n) |idx| {
                if (sa_ref[idx] != sa_out[idx]) {
                    std.debug.print("  first diff at SA[{d}]: ref={d} got={d}\n", .{ idx, sa_ref[idx], sa_out[idx] });
                    break;
                }
            }
            return error.TestUnexpectedResult;
        }
    }

    // adversarial: all same byte, runs, near-periodic, deep-LCP
    const cases = [_][]const u8{
        "a",                  "aa",                   "aaaa",
        "ababab",             "abcabcabc",            "\x00\x00\x00",
        "\x00\x01\x00\x01",   "banana",               "mississippi",
        "aaaaaaaab",          "baaaaaaaa",            "abababababababab",
        "aaaaaaaaaaaaaaaaab", "baaaaaaaaaaaaaaaaa",   "zzzzzzzzzzzzzzzzzzzz",
        "\x00",               "\xff\xff\xff\xff\x00", "abcabcabcabcabcabcd",
        // Last TWO bytes zero: with the 2-byte depth-0 front, suffixes pos=n-1
        // and pos=n-2 both land in the same depth-2 bucket and BOTH have ended.
        // Stresses the multi-ended-suffix sentinel handling.
        "\x01\x02\x00\x00",   "\x03\x01\x02\x00\x00", "\x00\x00",
        "\x05\x00\x00",       "abc\x00\x00",          "\x00\x00\x00\x00",
    };
    for (cases) |t| {
        const n = t.len;
        @memcpy(buf[0..n], t);
        @memset(buf[n .. n + 64], 0);
        buildSA(sc, buf[0..n].ptr, sa_out[0..n].ptr, n);
        naiveSA(t, sa_ref[0..n]);
        try std.testing.expectEqualSlices(i32, sa_ref[0..n], sa_out[0..n]);
    }
}

test "buildSA handles long all-same-byte (max recursion depth)" {
    const sc = try std.testing.allocator.create(Scratch);
    defer std.testing.allocator.destroy(sc);

    // All-same-byte is the worst case for recursion depth: every suffix shares the
    // whole prefix, so the radix recurses ~n levels deep. Proves the explicit stack
    // and sentinel handling survive maximal depth.
    const n: usize = 4096;
    var buf: [4096 + 64]u8 = undefined;
    @memset(&buf, 0);
    for (buf[0..n]) |*c| c.* = 'q';
    @memset(buf[n .. n + 64], 0);

    var sa_out: [4096]i32 = undefined;
    var sa_ref: [4096]i32 = undefined;
    buildSA(sc, buf[0..n].ptr, sa_out[0..n].ptr, n);
    naiveSA(buf[0..n], sa_ref[0..n]);
    try std.testing.expectEqualSlices(i32, sa_ref[0..n], sa_out[0..n]);
}
