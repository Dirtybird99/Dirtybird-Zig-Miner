//! sa_v114_pure.zig -- pure-Zig, clean-room reimplementation of the v1.14
//! "descriptor" suffix array (AstroBWTv3 stage 5). Byte-identical to libsais /
//! the vendored C++ descriptor because the suffix array of a string is UNIQUE;
//! this exploits wolfCompute's period-256 group structure (via the stage-5
//! flags) to build that unique SA faster than a general suffix sort.
//!
//! This is NOT a transcription of vendor/v114/v114_stubs.cpp -- only the
//! algorithmic idea is ported; the C++ arena / Stage5Run bit-packing / fused
//! representation is dropped in favour of plain Zig arrays:
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

// Max suffix-array length. Must equal astrobwt.SCRATCH; a comptime check in
// astrobwt.zig enforces it. Kept as a local constant so this module does NOT
// import astrobwt -- astrobwt imports THIS (for the Scratch type + the Worker
// SA field), and a mutual import would be a cycle.
pub const SCRATCH: usize = 72000 + 64;
const MAX_GROUP: u32 = 512; // kStage4MaxGroupCount; actual group_count <= data_len>>8

const Run = struct { key: u32, begin: u32, len: u32 };

/// Per-thread reusable scratch. Allocate once (page_allocator) and reuse.
pub const Scratch = struct {
    arena: [SCRATCH]u32 = undefined, // every position, laid out run-by-run
    runs: [SCRATCH]Run = undefined, // worst case: `n` singleton runs
    runs_tmp: [SCRATCH]Run = undefined, // radix scratch for the run sort
    tmp: [SCRATCH]u32 = undefined, // per-bucket merge buffer
};

/// 3-pass LSD byte radix sort of `runs` by the 24-bit big-endian key (ascending).
/// O(runs), replacing a comparison sort that dominated the profile. `tmp` must be
/// at least runs.len long; result ends up back in `runs`.
fn radixSortRuns(runs: []Run, tmp: []Run) void {
    var src = runs;
    var dst = tmp[0..runs.len];
    var shift: u5 = 0;
    var pass: u32 = 0;
    while (pass < 3) : (pass += 1) {
        var count = [_]u32{0} ** 256;
        for (src) |r| count[(r.key >> shift) & 0xff] += 1;
        var sum: u32 = 0;
        for (&count) |*c| {
            const cc = c.*;
            c.* = sum;
            sum += cc;
        }
        for (src) |r| {
            const bkt = (r.key >> shift) & 0xff;
            dst[count[bkt]] = r;
            count[bkt] += 1;
        }
        const t = src;
        src = dst;
        dst = t;
        shift += 8;
    }
    // 3 passes (odd) leave the sorted result in `tmp`; copy back to `runs`.
    if (src.ptr != runs.ptr) @memcpy(runs, src);
}

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
    fn less(ctx: SuffixCtx, a: u32, b: u32) bool {
        const alen = ctx.n - a;
        const blen = ctx.n - b;
        const common = @min(alen, blen);
        var i: u32 = 0;
        // 8 bytes at a time, big-endian so numeric order == lexicographic.
        while (i + 8 <= common) : (i += 8) {
            const av = std.mem.readInt(u64, ctx.data[a + i ..][0..8], .big);
            const bv = std.mem.readInt(u64, ctx.data[b + i ..][0..8], .big);
            if (av != bv) return av < bv;
        }
        while (i < common) : (i += 1) {
            const av = ctx.data[a + i];
            const bv = ctx.data[b + i];
            if (av != bv) return av < bv;
        }
        return alen < blen;
    }
};

// Diagnostic instrumentation. When false (default) all of it is dead-code
// eliminated, so the hot path has no global writes / timer calls (required for
// the multi-threaded miner). Flip to true + rebuild sa_v114_check to re-profile.
pub const INSTRUMENT = false;
pub var stat_runs: u32 = 0;
pub var stat_multi_pos: u32 = 0; // positions in multi-run buckets (re-sorted)
pub var stat_single_pos: u32 = 0; // positions copied directly (single-run buckets)
pub var ns_emit: u64 = 0;
pub var ns_sort: u64 = 0;
pub var ns_mat: u64 = 0;

const Builder = struct {
    sc: *Scratch,
    data: [*]const u8,
    ctx: SuffixCtx,
    arena_len: u32 = 0,
    runs_len: u32 = 0,

    /// Record a run of already-suffix-sorted positions sharing one 3-byte prefix.
    inline fn appendRun(self: *Builder, positions: []const u32) void {
        const begin = self.arena_len;
        @memcpy(self.sc.arena[begin .. begin + positions.len], positions);
        self.arena_len = begin + @as(u32, @intCast(positions.len));
        self.sc.runs[self.runs_len] = .{
            .key = keyBE(load24(self.data, positions[0])),
            .begin = begin,
            .len = @intCast(positions.len),
        };
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
            self.sc.runs[self.runs_len] = .{ .key = keyBE(load24(self.data, pos)), .begin = begin, .len = 1 };
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
        std.sort.pdq(u32, order[0..g], self.ctx, SuffixCtx.less);

        var rel: i32 = 255;
        while (rel >= 0) : (rel -= 1) {
            // Group the sorted order[] into maximal same-3-byte-prefix runs.
            var i: u32 = 0;
            while (i < g) {
                const key = load24(self.data, order[i]);
                var j = i + 1;
                while (j < g and load24(self.data, order[j]) == key) : (j += 1) {}
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
                    }
                    order[m] = pos;
                }
            }
        }
    }
};

/// Build the suffix array of data[0..n) into sa_out[0..n) using the group-run
/// structure encoded in `flags` ((n>>8)+1 bytes; flags[g]!=0 starts a new
/// group-run). `data` must be zero-padded >=3 bytes past n-1. Output is the
/// canonical SA (byte-identical to libsais).
pub fn buildSA(sc: *Scratch, data: [*]const u8, n: u32, flags: [*]const u8, sa_out: [*]i32) void {
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
    radixSortRuns(sc.runs[0..b.runs_len], sc.runs_tmp[0..]);
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
        var j = i + 1;
        while (j < b.runs_len and sc.runs[j].key == sc.runs[i].key) : (j += 1) {}
        if (j == i + 1) {
            const r = sc.runs[i];
            if (INSTRUMENT) stat_single_pos += r.len;
            var k: u32 = 0;
            while (k < r.len) : (k += 1) sa_out[out_pos + k] = @intCast(sc.arena[r.begin + k]);
            out_pos += r.len;
        } else {
            var m: u32 = 0;
            var t = i;
            while (t < j) : (t += 1) {
                const r = sc.runs[t];
                @memcpy(sc.tmp[m .. m + r.len], sc.arena[r.begin .. r.begin + r.len]);
                m += r.len;
            }
            std.sort.pdq(u32, sc.tmp[0..m], b.ctx, SuffixCtx.less);
            if (INSTRUMENT) stat_multi_pos += m;
            var k: u32 = 0;
            while (k < m) : (k += 1) sa_out[out_pos + k] = @intCast(sc.tmp[k]);
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
/// `data` must be zero-padded >=3 bytes past n-1. Returns true on success; false
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
