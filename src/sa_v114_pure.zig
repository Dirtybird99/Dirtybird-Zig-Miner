//! sa_v114_pure.zig -- pure-Zig, clean-room reimplementation of the v1.14
//! "descriptor" suffix array (AstroBWTv3 stage 5). Byte-identical to libsais /
//! the vendored C++ descriptor because the suffix array of a string is UNIQUE;
//! this exploits wolfCompute's period-256 group structure (via the stage-5
//! flags) to build that unique SA faster than a general suffix sort.
//!
//! This is NOT a transcription of vendor/v114/v114_stubs.cpp -- only the
//! algorithmic idea is ported; the C++ arena / Stage5Run bit-packing / fused
//! representation was not carried over. (The run descriptor here IS packed
//! into a u64 for memory bandwidth, but with an independent 24/30/10
//! key/begin/len layout unrelated to the C++ Stage5Run {key; count<<17|begin}
//! encoding.) The layout in plain Zig arrays:
//!
//!   * The flags partition the full 256-byte chunks into "group-runs" of
//!     near-identical consecutive chunks. Within a group-run of G chunks the G
//!     suffixes at a fixed within-chunk offset `rel` are sorted once at rel=255;
//!     for rel=254..0 each position gains one leading byte, and because the
//!     tails (the rel+1 suffixes) are already ordered, a stable insertion by the
//!     single new byte re-derives the exact order in O(G).
//!   * Each per-rel sorted list is chopped into runs sharing a 3-byte prefix.
//!     All runs are sorted by that prefix; within a shared-prefix bucket the
//!     members are ordered by full suffix. Suffixes are distinct (a total order
//!     with the standard shorter-suffix-first rule), so any correct sort
//!     reproduces the unique SA -- there is no tie-order to match.
//!
//! Validated element-for-element vs libsais over real wolfCompute inputs by
//! src/sa_v114_check.zig.

const std = @import("std");
const builtin = @import("builtin");

// Max suffix-array length. Must equal astrobwt.SCRATCH; a comptime check in
// astrobwt.zig enforces it. Kept as a local constant so this module does NOT
// import astrobwt -- astrobwt imports THIS (for the Scratch type + the Worker
// SA field), and a mutual import would be a cycle.
pub const SCRATCH: usize = 72000 + 64;

/// True on x86-64 builds that carry full AVX-512 (F+BW). The widened kernels
/// below (64-byte suffix compares, 16-wide arena copies) pay off there: the
/// 64-byte compare lowers to a single vpcmpb + kmovq pair, and the 16-wide
/// copies to one zmm load/store. On AVX2-only targets LLVM would split every
/// 64-byte vector into YMM halves (no gain, extra instructions), so the wide
/// path is gated OFF there and the codegen stays byte-identical to the shipped
/// x86_64_v3+sha baseline. Non-x86 targets keep the narrow path too (NEON
/// splits are correct but untested here). The miner never mixes the wide SA
/// kernels with the legacy-SSE SHA-NI asm on a non-AVX-512 build.
const wide_ok = builtin.cpu.arch == .x86_64 and
    std.Target.x86.featureSetHasAll(builtin.cpu.features, .{ .avx512f, .avx512bw });
const MAX_GROUP: u32 = 512; // kStage4MaxGroupCount; actual group_count <= data_len>>8

// A run packed into one u64 -- 24-bit big-endian 3-byte key in bits [40..63],
// arena begin in bits [10..39] (begin < SCRATCH < 2^17), length in bits [0..9]
// (len <= MAX_GROUP = 512). 8 bytes/run instead of a 12-byte struct, so the
// radix passes and the materialize table walk stream 33% fewer bytes.

/// 64-byte vector used by the suffix comparator and the 16-wide arena copies
/// on +avx512 builds only (see `wide_ok`).
const V64u8 = @Vector(64, u8);
const V16u32 = @Vector(16, u32);
const Run = u64;
const RUN_KEY_SHIFT: u6 = 40;
const RUN_BEGIN_SHIFT: u6 = 10;
const RUN_BEGIN_MASK: u64 = 0x3FFF_FFFF;
const RUN_LEN_MASK: u64 = 0x3FF;

inline fn packRun(key: u32, begin: u32, len: u32) Run {
    return (@as(u64, key) << RUN_KEY_SHIFT) | (@as(u64, begin) << RUN_BEGIN_SHIFT) | @as(u64, len);
}

inline fn runBegin(r: Run) u32 {
    return @intCast((r >> RUN_BEGIN_SHIFT) & RUN_BEGIN_MASK);
}

inline fn runLen(r: Run) u32 {
    return @intCast(r & RUN_LEN_MASK);
}

/// Per-thread reusable scratch. Allocate once (page_allocator) and reuse.
pub const Scratch = struct {
    arena: [SCRATCH]u32 = undefined, // every position, laid out run-by-run
    runs: [SCRATCH]Run = undefined, // worst case: `n` singleton runs
    runs_tmp: [SCRATCH]Run = undefined, // radix scratch for the run sort
};

/// 3-pass LSD byte radix sort of `runs` by the 24-bit key in the top field
/// (ascending; stable, so equal-key runs keep emit order -- the payload bits
/// below the key never influence the order). The three histograms are built by
/// emit (see Builder.countKey) rather than by a counting pass here, so `runs`
/// is walked 3 times instead of 4.
/// `tmp` must be at least runs.len long. Returns whichever buffer the sorted
/// result landed in -- an odd pass count leaves it in `tmp`, so copying it back
/// into `runs` would cost a full extra read+write of the array (~636 KB/hash at
/// 19.9k runs) for nothing. The caller reads the returned slice instead.
fn radixSortRuns(runs: []Run, tmp: []Run, counts: *[3][256]u32) []Run {
    var count = counts.*;
    for (&count) |*hist| {
        var sum: u32 = 0;
        for (hist) |*c| {
            const cc = c.*;
            c.* = sum;
            sum += cc;
        }
    }
    var src = runs;
    var dst = tmp[0..runs.len];
    var pass: u32 = 0;
    while (pass < 3) : (pass += 1) {
        // Computed per pass: a running `shift += 8` counter would overflow u6
        // on the (dead) post-final-pass increment (40 -> 48 -> 56 -> 64).
        const shift: u6 = @intCast(RUN_KEY_SHIFT + 8 * pass);
        const hist = &count[pass];
        var i: usize = 0;
        while (i + 4 <= src.len) : (i += 4) {
            const r0 = src[i];
            const r1 = src[i + 1];
            const r2 = src[i + 2];
            const r3 = src[i + 3];

            const b0 = (r0 >> shift) & 0xff;
            const b1 = (r1 >> shift) & 0xff;
            const b2 = (r2 >> shift) & 0xff;
            const b3 = (r3 >> shift) & 0xff;

            const p0 = hist[b0]; hist[b0] += 1;
            dst[p0] = r0;

            const p1 = hist[b1]; hist[b1] += 1;
            dst[p1] = r1;

            const p2 = hist[b2]; hist[b2] += 1;
            dst[p2] = r2;

            const p3 = hist[b3]; hist[b3] += 1;
            dst[p3] = r3;
        }
        while (i < src.len) : (i += 1) {
            const r = src[i];
            const bkt = (r >> shift) & 0xff;
            const p = hist[bkt];
            hist[bkt] += 1;
            dst[p] = r;
        }
        const t = src;
        src = dst;
        dst = t;
    }
    // `src` is the buffer the last pass wrote into. On runs.len == 0 the passes
    // are no-ops but the swaps still run, so this is `tmp[0..0]` -- correct, and
    // the caller's bucket walk never enters.
    return src;
}

/// Width of the bucket prefix key, in bytes. Elements sharing a bucket agree on
/// this many leading bytes, which is exactly what `lessAfterKey` may skip. It is
/// not a free parameter: `load24`/`keyBE`/`radixSortRuns` and the 24-bit key field
/// in `Run` all encode the same 3, so changing it here alone would be wrong.
const KEY_BYTES: u32 = 3;

/// Little-endian 3-byte load. Requires >=3 readable bytes at `pos` (the caller
/// zero-pads >=3 bytes past the last suffix position). The padding value does
/// not affect the SA: it only influences the intermediate 3-byte bucketing, and
/// within a bucket positions are ordered by their real suffix (bounded by n).
inline fn load24(data: [*]const u8, pos: u32) u32 {
    return @as(u32, data[pos]) |
        (@as(u32, data[pos + 1]) << 8) |
        (@as(u32, data[pos + 2]) << 16);
}

/// Big-endian 3-byte key from a little-endian load24, so ascending numeric
/// order == lexicographic order of the 3-byte prefix.
inline fn keyBE(k: u32) u32 {
    return ((k & 0xff) << 16) | (k & 0xff00) | ((k >> 16) & 0xff);
}

/// Standard suffix-array order over data[0..n): lexicographic by unsigned byte,
/// shorter suffix (larger start position) sorts first. Matches libsais and the
/// C++ compare_suffixes exactly.
const SuffixCtx = struct {
    data: [*]const u8,
    n: u32,
    /// `skip` bytes at the front are already known equal, so the scan starts there
    /// instead of at 0. No `common <= skip` guard is needed: every loop below is
    /// bounded by `common`, so when the shorter suffix is no longer than `skip` all
    /// three fall through to the length tiebreak, which is the right answer. (The
    /// C++ `compare_suffixes_after_key` spells that guard out explicitly; the loop
    /// bounds here give the same result.) This matters because `load24` may read the
    /// zero padding past `data_len`, so two positions near the end can share a
    /// *padded* key without sharing three real bytes.
    inline fn lessSkip(ctx: SuffixCtx, a: u32, b: u32, comptime skip: u32) bool {
        const alen = ctx.n - a;
        const blen = ctx.n - b;
        const common = @min(alen, blen);
        var i: u32 = skip;
        // 64 bytes at a time (AVX-512 only, see `wide_ok`): equal-compare the
        // lanes, jump to the first differing byte via a movemask +
        // count-trailing-zeros (one bit per byte). This lowers to a single
        // vpcmpb + kmovq pair per 64 bytes.
        //
        // The Wolf-permuted data has a mean LCP of ~68 bytes, but DO NOT read that
        // as the length these compares run -- see the dead-end note below the
        // block. `skip` already covers the shared key, and the surviving compare
        // is far shorter than the global mean.
        if (comptime wide_ok) {
            while (i + 64 <= common) : (i += 64) {
                const va: V64u8 = ctx.data[a + i ..][0..64].*;
                const vb: V64u8 = ctx.data[b + i ..][0..64].*;
                const eqbits: u64 = @bitCast(va == vb);
                if (eqbits != 0xFFFF_FFFF_FFFF_FFFF) {
                    const off: u32 = @ctz(~eqbits);
                    if (comptime INSTRUMENT) noteCmp(i + off - skip);
                    return ctx.data[a + i + off] < ctx.data[b + i + off];
                }
            }
        }
        // NO 32-BYTE AVX2 PATH HERE, AND THAT IS DELIBERATE. Adding one looks
        // obvious -- this host has AVX2, `wide_ok` is false because Raptor Lake
        // fuses off AVX-512, so the comparator "drops to" the 8-byte scalar loop
        // below. MEASURED 2026-08-07: a 32-byte @Vector(32,u8) compare here cost
        // -2.03% at 20 threads (0/8 paired runs won). The optimize-loop had
        // already recorded the same sign at iteration 2 ("SIMD 32B prefix scan in
        // SuffixCtx.less - 12.2pct worse, compares diverge early").
        //
        // WHY: the global mean LCP is ~68 bytes, but that is NOT the length these
        // compares run. Measured with the compare-length histogram in prof.zig
        // (n = 354M comparisons) -- bytes scanned past `skip` before resolving:
        //      0-7  61.27%    8-15  19.60%   16-23  6.79%
        //     24-31  1.16%   32-63   2.06%     64+  9.12%
        // 61% resolve inside the FIRST 8-byte load and 88.8% inside 32 bytes, so a
        // 32-byte step pays vector setup on every comparison to help only 11.2%.
        //
        // REGIME-DEPENDENT, and that is the trap. At 1 thread the wide load is
        // nearly free and the 9.12% long tail pays for it: AVX2 measured +1.08%
        // (p95bench aggregate, 3/4) and +1.17% (bench2, 6/6). At the 20-22 thread
        // operating point it LOSES -- the extra bytes touched cost more in
        // E-cluster L2 contention than the saved iterations. Screen this at 20T+
        // or it will look like a win.
        //
        // THE GATED HYBRID WAS ALSO TRIED AND IS ALSO A NULL. Escalating to the
        // 32-byte step only after 16 scalar bytes -- chosen because 80.9% resolve
        // inside 16, and 58.5% of the survivors then run past 32 -- measured
        // median +0.04% at 22 threads (4/7 pairs, one pair discarded as
        // contaminated) and, at 1 thread, +0.37% on bench2 against +0.45% SLOWER
        // on p95bench aggregate. Both regimes sit under the harness's ~0.5%
        // resolution and the two 1T harnesses disagree in sign. The gate works --
        // it removes the -2.03% penalty of the unconditional path -- but it also
        // gates away the gain: only 19.1% of comparisons ever reach the vector
        // loop. Not merged; a second comparator path is not worth zero.
        // 8-byte tail: big-endian load makes the u64 compare a lexicographic compare.
        while (i + 8 <= common) : (i += 8) {
            const av = std.mem.readInt(u64, ctx.data[a + i ..][0..8], .big);
            const bv = std.mem.readInt(u64, ctx.data[b + i ..][0..8], .big);
            if (av != bv) {
                if (comptime INSTRUMENT) noteCmp(i - skip + (@clz(av ^ bv) >> 3));
                return av < bv;
            }
        }
        while (i < common) : (i += 1) {
            const av = ctx.data[a + i];
            const bv = ctx.data[b + i];
            if (av != bv) {
                if (comptime INSTRUMENT) noteCmp(i - skip);
                return av < bv;
            }
        }
        if (comptime INSTRUMENT) noteCmp(i - skip);
        return alen < blen;
    }

    /// No prefix known equal -- the rel=255 seed sort.
    fn less(ctx: SuffixCtx, a: u32, b: u32) bool {
        return lessSkip(ctx, a, b, 0);
    }

    /// Multi-run bucket: every element shares the bucket's 3-byte prefix key by
    /// construction, so the first three bytes are already resolved. Mirrors the C++
    /// `compare_suffixes_after_key` (vendor/v114/v114_stubs.cpp), which the pure-Zig
    /// port had collapsed back into a from-zero compare.
    fn lessAfterKey(ctx: SuffixCtx, a: u32, b: u32) bool {
        return lessSkip(ctx, a, b, KEY_BYTES);
    }
};

// Diagnostic instrumentation. Only src/prof.zig declares the root flag; normal
// miner/bench roots leave this false, so all global writes/timers disappear.
pub const INSTRUMENT = if (@hasDecl(@import("root"), "astrobwt_profile_enabled"))
    @import("root").astrobwt_profile_enabled
else
    false;
pub var stat_runs: u32 = 0;
pub var stat_multi_pos: u32 = 0; // positions in multi-run buckets (re-sorted)
pub var stat_single_pos: u32 = 0; // positions copied directly (single-run buckets)
pub var ns_emit: u64 = 0;
pub var ns_sort: u64 = 0;
pub var ns_mat: u64 = 0;
// Time spent inside the multi-run bucket re-sort alone, a subset of ns_mat. This
// is the only work a suffix-comparator change can reach, so it is the ceiling for
// any such change; the rest of ns_mat is single-run wide copies.
pub var ns_msort: u64 = 0;
// stat_* describe the LAST hash only -- they are reset per buildSA call, not
// accumulated. ns_* accumulate.
pub var acc_multi_pos: u64 = 0;
pub var acc_single_pos: u64 = 0;
// Multi-run buckets and the runs inside them. m/bucket sets how much a k-way merge
// of the (already sorted) runs could save over re-sorting the concatenation.
pub var acc_multi_buckets: u64 = 0;
pub var acc_multi_runs: u64 = 0;
/// Single-run bucket length distribution. The materialize copy width is only
/// worth narrowing if most runs fit inside the narrow store.
/// Bytes scanned past `skip` before a suffix comparison resolves, bucketed
/// 0-7 / 8-15 / 16-23 / 24-31 / 32-63 / 64+. Bucket 0 is the population a
/// 32-byte vector step could never help: it resolves inside one 8-byte load.
pub var cmp_hist: [6]u64 = .{0} ** 6;
pub var cmp_total: u64 = 0;

inline fn noteCmp(bytes: u32) void {
    cmp_total += 1;
    const b: usize = if (bytes < 8) 0 else if (bytes < 16) 1 else if (bytes < 24) 2 else if (bytes < 32) 3 else if (bytes < 64) 4 else 5;
    cmp_hist[b] += 1;
}

pub var acc_rl_le4: u64 = 0;
pub var acc_rl_5to8: u64 = 0;
pub var acc_rl_gt8: u64 = 0;
// Work units inside the emit phase, counted rather than timed: a timer around a
// loop entered 256x per group-run would cost more than the loop. `emit_key_loads`
// counts load24 calls in run formation; `emit_shifts` counts element moves in the
// per-rel single-byte insertion. Their ratio says which half of emit to attack.
pub var emit_key_loads: u64 = 0;
pub var emit_shifts: u64 = 0;
pub var emit_seed_elems: u64 = 0;

const Builder = struct {
    sc: *Scratch,
    data: [*]const u8,
    ctx: SuffixCtx,
    arena_len: u32 = 0,
    runs_len: u32 = 0,
    /// Radix histograms for the three key bytes, accumulated here instead of in
    /// a separate counting pass over `runs`. Emit already holds the key in a
    /// register when it packs the Run, so the three increments are free here,
    /// whereas the counting pass had to stream all of `runs` (159 KB at 19.9k
    /// runs) back in from L2 before pass 0 streamed it in again.
    count: [3][256]u32 = .{ [_]u32{0} ** 256, [_]u32{0} ** 256, [_]u32{0} ** 256 },

    /// Fold one run's key into the histograms. `key` is the big-endian 3-byte
    /// prefix and MUST be < 2^24: the three passes read bytes 0..2 of it, so a
    /// wider key would desync the prefix sums from the scatter and corrupt the
    /// SA silently.
    inline fn countKey(self: *Builder, key: u32) void {
        std.debug.assert(key < (1 << 24));
        self.count[0][key & 0xff] += 1;
        self.count[1][(key >> 8) & 0xff] += 1;
        self.count[2][(key >> 16) & 0xff] += 1;
    }

    /// Record a run of already-suffix-sorted positions sharing one 3-byte prefix.
    inline fn appendRun(self: *Builder, positions: []const u32) void {
        const begin = self.arena_len;
        @memcpy(self.sc.arena[begin .. begin + positions.len], positions);
        self.arena_len = begin + @as(u32, @intCast(positions.len));
        const key = keyBE(load24(self.data, positions[0]));
        self.countKey(key);
        self.sc.runs[self.runs_len] = packRun(key, begin, @intCast(positions.len));
        self.runs_len += 1;
    }

    /// Emit `count` positions starting at `start` as singleton runs (used for
    /// single-chunk group-runs and the final partial chunk).
    fn emitLiterals(self: *Builder, start: u32, count: u32) void {
        var rel: u32 = 0;
        while (rel < count) : (rel += 1) {
            const pos = start + rel;
            const begin = self.arena_len;
            self.sc.arena[begin] = pos;
            const key = keyBE(load24(self.data, pos));
            self.countKey(key);
            self.sc.runs[self.runs_len] = packRun(key, begin, 1);
            self.arena_len = begin + 1;
            self.runs_len += 1;
        }
    }

    /// Emit a group-run spanning chunks [start_group, end_group).
    fn emitGroupRun(self: *Builder, start_group: u32, end_group: u32, order: []u32) void {
        const g = end_group - start_group;
        if (g == 0) return;
        const base = start_group << 8;
        if (g == 1) {
            self.emitLiterals(base, 256);
            return;
        }

        // rel = 255: the G same-offset suffixes, sorted once by full suffix.
        var c: u32 = 0;
        while (c < g) : (c += 1) order[c] = base + (c << 8) + 255;
        if (comptime INSTRUMENT) emit_seed_elems += g;
        std.sort.pdq(u32, order[0..g], self.ctx, SuffixCtx.less);

        var rel: i32 = 255;
        while (rel >= 0) : (rel -= 1) {
            // Group the sorted order[] into maximal same-3-byte-prefix runs.
            var i: u32 = 0;
            while (i < g) {
                const key = load24(self.data, order[i]);
                var j = i + 1;
                while (j < g and load24(self.data, order[j]) == key) : (j += 1) {}
                if (comptime INSTRUMENT) emit_key_loads += (j - i) + 1;
                self.appendRun(order[i..j]);
                i = j;
            }
            if (rel > 0) {
                // Prepend one byte to every suffix, then stable-insert by that
                // new leading byte -- the tails (rel+1 order) are already sorted.
                c = 0;
                while (c < g) : (c += 1) order[c] -= 1;
                var ii: u32 = 1;
                while (ii < g) : (ii += 1) {
                    const pos = order[ii];
                    const k = self.data[pos];
                    var m = ii;
                    while (m > 0 and self.data[order[m - 1]] > k) : (m -= 1) {
                        order[m] = order[m - 1];
                        if (comptime INSTRUMENT) emit_shifts += 1;
                    }
                    order[m] = pos;
                }
            }
        }
    }
};

/// Build the suffix array of data[0..n) into sa_out[0..n) using the group-run
/// structure encoded in `flags` ((n>>8)+1 bytes; flags[g]!=0 starts a new
/// group-run). `data` must be zero-padded >=3 bytes past n-1. `sa_out` must
/// have capacity for at least n + copy_width elements (a SCRATCH-sized buffer
/// like Worker.sa satisfies this; copy_width is 8 on the narrow path, 16 on
/// AVX-512 builds): the materialize stage's unconditional wide stores leave up
/// to copy_width-1 scratch lanes past sa_out[n-1] on the final bucket.
/// sa_out[0..n) is the canonical SA (byte-identical to libsais).
pub fn buildSA(sc: *Scratch, data: [*]const u8, n: u32, flags: [*]const u8, sa_out: [*]i32) void {
    std.debug.assert(n + (if (comptime wide_ok) @as(usize, 16) else 8) <= SCRATCH); // wide copies need tail slack in every buffer
    var b = Builder{ .sc = sc, .data = data, .ctx = .{ .data = data, .n = n } };
    const full_groups: u32 = n >> 8;
    var order: [MAX_GROUP]u32 = undefined;
    var tmr: std.time.Timer = if (INSTRUMENT) (std.time.Timer.start() catch unreachable) else undefined;

    var run_start_group: u32 = 0;
    var group: u32 = 1;
    while (group <= full_groups) : (group += 1) {
        if (flags[group] != 0 or group == full_groups) {
            b.emitGroupRun(run_start_group, group, order[0..]);
            run_start_group = group;
        }
    }
    // Trailing partial chunk (n & 0xff positions) as singletons.
    b.emitLiterals(full_groups << 8, n & 0xff);
    if (INSTRUMENT) ns_emit += tmr.lap();

    // Global order by 3-byte prefix (O(runs) radix; dominated the profile as pdq).
    // The sorted runs may land in either buffer -- read them through `sorted`.
    const sorted = radixSortRuns(sc.runs[0..b.runs_len], sc.runs_tmp[0..], &b.count);
    // 3 passes with a swap after each => the result is ALWAYS in runs_tmp. The
    // in-place bucket sort below assumes `sc.runs` is dead from here on; if the
    // pass count ever changes, this catches it instead of corrupting the SA.
    std.debug.assert(b.runs_len == 0 or sorted.ptr == @as([*]Run, &sc.runs_tmp));
    if (INSTRUMENT) {
        ns_sort += tmr.lap();
        stat_runs = b.runs_len;
        stat_multi_pos = 0;
        stat_single_pos = 0;
    }

    // Materialize: within each prefix bucket, single run copies directly
    // (already suffix-sorted); multiple runs are ordered by full suffix.
    var out_pos: u32 = 0;
    var i: u32 = 0;
    while (i < b.runs_len) {
        // Hold the run in a register across the bucket-boundary scan: the
        // single-run branch below used to re-load sorted[i] that this line
        // already fetched.
        const r_i = sorted[i];
        const key_i = r_i >> RUN_KEY_SHIFT;
        var j = i + 1;
        while (j < b.runs_len and (sorted[j] >> RUN_KEY_SHIFT) == key_i) : (j += 1) {}
        if (j == i + 1) {
            const r = r_i;
            const rl = runLen(r);
            const rb = runBegin(r);
            if (INSTRUMENT) {
                stat_single_pos += rl;
                acc_single_pos += rl;
            }
            // One unconditional wide copy covers rl <= copy_width (the common
            // case, avg run len ~3.5) with no data-dependent branch; out_pos
            // only advances by rl, so over-copied lanes are overwritten by the
            // next run -- except after the FINAL bucket, which leaves up to
            // copy_width-1 scratch lanes past sa_out[n-1] (hence the documented
            // tail-slack requirement; n <= 70911 < SCRATCH-copy_width).
            if (comptime INSTRUMENT) {
                if (rl <= 4) acc_rl_le4 += 1 else if (rl <= 8) acc_rl_5to8 += 1 else acc_rl_gt8 += 1;
            }
            if (comptime wide_ok) {
                const v: V16u32 = sc.arena[rb..][0..16].*;
                @as([*]u32, @ptrCast(sa_out))[out_pos..][0..16].* = v;
                var k: u32 = 16;
                while (k < rl) : (k += 1) sa_out[out_pos + k] = @intCast(sc.arena[rb + k]);
            } else {
                const v: @Vector(8, u32) = sc.arena[rb..][0..8].*;
                @as([*]u32, @ptrCast(sa_out))[out_pos..][0..8].* = v;
                var k: u32 = 8;
                while (k < rl) : (k += 1) sa_out[out_pos + k] = @intCast(sc.arena[rb + k]);
            }
            out_pos += rl;
        } else {
            // Gather the bucket's runs straight into `sa_out` and sort them there,
            // rather than staging through a separate scratch buffer and copying
            // back. `sa_out` is [*]i32 and positions are u32 below 2^17, so the
            // reinterpret is value-preserving and the later @intCast disappears.
            // The over-copy bound is identical to the single-run path above, so
            // the tail-slack requirement is unchanged.
            const dst: [*]u32 = @ptrCast(sa_out);
            var m: u32 = 0;
            var t = i;
            while (t < j) : (t += 1) {
                const r = sorted[t];
                const rl = runLen(r);
                const rb = runBegin(r);
                if (comptime wide_ok) {
                    const v: V16u32 = sc.arena[rb..][0..16].*;
                    dst[out_pos + m ..][0..16].* = v;
                } else {
                    const v: @Vector(8, u32) = sc.arena[rb..][0..8].*;
                    dst[out_pos + m ..][0..8].* = v;
                }
                var k: u32 = if (comptime wide_ok) 16 else 8;
                while (k < rl) : (k += 1) dst[out_pos + m + k] = sc.arena[rb + k];
                m += rl;
            }
            const bucket = dst[out_pos..][0..m];
            if (comptime INSTRUMENT) {
                var st = std.time.Timer.start() catch unreachable;
                std.sort.pdq(u32, bucket, b.ctx, SuffixCtx.lessAfterKey);
                ns_msort += st.read();
                stat_multi_pos += m;
                acc_multi_pos += m;
                acc_multi_buckets += 1;
                acc_multi_runs += j - i;
            } else {
                std.sort.pdq(u32, bucket, b.ctx, SuffixCtx.lessAfterKey);
            }
            out_pos += m;
        }
        i = j;
    }
    if (INSTRUMENT) ns_mat += tmr.lap();
    std.debug.assert(out_pos == n);
}

/// Port of build_v114_stage5_flags: write group-boundary flags from wolfCompute's
/// per-template group markers. Returns the flag count (0 on failure). Identical
/// to sa_v114.buildStage5Flags (the pure part already shared by the C++ path).
pub fn buildStage5Flags(markers: []const u16, n_templates: u32, logical_len: u32, flags: []u8) u32 {
    if (logical_len == 0) return 0;
    const flags_len: u32 = (logical_len >> 8) + 1;
    if (flags.len < flags_len) return 0;
    @memset(flags[0..flags_len], 0);
    flags[0] = 1;
    const limit = @min(n_templates, 277);
    var i: u32 = 0;
    while (i < limit) : (i += 1) {
        const pos_data: u32 = markers[i];
        const start_group = pos_data >> 7;
        const group_count = pos_data & 0x7f;
        const boundary = start_group + group_count;
        if (group_count != 0 and boundary > 0 and boundary < flags_len) {
            flags[boundary] = 1;
        }
    }
    return flags_len;
}

/// Convenience entry: build the stage-5 flags from wolfCompute's per-template
/// markers, then the SA. Takes explicit params (no astrobwt dependency).
/// `data` must be zero-padded >=3 bytes past n-1, and `sa_out` needs n+7
/// elements of capacity (see buildSA). Returns true on success; false
/// (degenerate input) => caller should use a fallback backend. n <= 72000 always
/// keeps flag_len <= 320.
pub fn build(sc: *Scratch, data: [*]const u8, n: u32, markers: []const u16, n_templates: u32, sa_out: [*]i32) bool {
    if (n == 0) return false;
    var flags: [320]u8 = undefined;
    const flag_len = buildStage5Flags(markers, n_templates, n, &flags);
    if (flag_len == 0) return false;
    buildSA(sc, data, n, &flags, sa_out);
    return true;
}
