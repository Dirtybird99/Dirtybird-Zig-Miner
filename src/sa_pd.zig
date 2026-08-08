//! sa_pd.zig -- exact suffix array by prefix-doubling (Manber-Myers /
//! Larsson-Sadakane style). O(n log n), driven entirely by integer counting
//! sorts over rank pairs -- so its cost is INDEPENDENT of the LCP depth, unlike
//! comparison/byte-radix methods. On the deep-LCP Wolf data (median LCP ~43)
//! that matters: no byte re-scanning. All access is sequential integer arrays
//! (cache-resident), the hypothesis being it scales better than libsais's
//! random-access induced sort under 10-thread memory contention.
//!
//! Byte-identical to libsais (the SA is unique); validated vs naive + oracle.

const std = @import("std");

pub const PD_MAX_N: usize = 72064;

pub const Scratch = struct {
    rank: [PD_MAX_N + 1]i32 = undefined, // rank of suffix i this round (+1 guard)
    tmp: [PD_MAX_N]i32 = undefined, // next-round ranks
    sa2: [PD_MAX_N]i32 = undefined, // SA sorted by 2nd key
    cnt: [PD_MAX_N + 1]i32 = undefined, // counting-sort histogram
};

/// Build SA of T[0..n) into SA[0..n). `sc` is reusable scratch.
pub fn prefixDoubleSA(sc: *Scratch, T: [*]const u8, SA: [*]i32, n: usize) void {
    if (n == 0) return;
    if (n == 1) {
        SA[0] = 0;
        return;
    }
    const rank = sc.rank[0 .. n + 1];
    const tmp = sc.tmp[0..n];
    const sa2 = sc.sa2[0..n];

    // ---- initial: rank by first byte (counting sort over 256 + place) ----
    var c0 = [_]i32{0} ** 257;
    for (0..n) |i| c0[@as(usize, T[i]) + 1] += 1;
    for (1..257) |i| c0[i] += c0[i - 1];
    for (0..n) |i| {
        const b = T[i];
        SA[@intCast(c0[b])] = @intCast(i);
        c0[b] += 1;
    }
    // dense ranks from the byte order
    rank[@intCast(SA[0])] = 0;
    var r: i32 = 0;
    for (1..n) |i| {
        if (T[@intCast(SA[i])] != T[@intCast(SA[i - 1])]) r += 1;
        rank[@intCast(SA[i])] = r;
    }
    if (r == @as(i32, @intCast(n - 1))) return; // already all distinct

    // ---- doubling rounds ----
    var k: usize = 1;
    while (true) : (k *= 2) {
        // sort by 2nd key: rank[i+k] (or -1 if i+k>=n) using counting sort.
        // Suffixes with i+k>=n have empty 2nd half -> smallest -> go first.
        // Stable bucket by (2nd key + 1) in [0..n]; index 0 = the "-1" group.
        const m = n + 1;
        const cnt = sc.cnt[0..m];
        @memset(cnt, 0);
        for (0..n) |i| {
            const key: usize = if (i + k < n) @as(usize, @intCast(rank[i + k] + 1)) else 0;
            cnt[key] += 1;
        }
        var sum: i32 = 0;
        for (0..m) |i| {
            const cc = cnt[i];
            cnt[i] = sum;
            sum += cc;
        }
        // place positions into sa2 by 2nd key, in input order (stable)
        for (0..n) |i| {
            const key: usize = if (i + k < n) @as(usize, @intCast(rank[i + k] + 1)) else 0;
            sa2[@intCast(cnt[key])] = @intCast(i);
            cnt[key] += 1;
        }

        // sort by 1st key: rank[i] using counting sort, stable over sa2 order.
        const cnt1 = sc.cnt[0 .. n + 1];
        @memset(cnt1[0 .. n + 1], 0);
        for (0..n) |i| cnt1[@as(usize, @intCast(rank[i])) + 1] += 1;
        for (1..n + 1) |i| cnt1[i] += cnt1[i - 1];
        for (0..n) |i| {
            const s: usize = @intCast(sa2[i]);
            const rr: usize = @intCast(rank[s]);
            SA[@intCast(cnt1[rr])] = @intCast(s);
            cnt1[rr] += 1;
        }

        // recompute ranks from the new (rank[i], rank[i+k]) order
        const key2 = struct {
            inline fn at(rk: []const i32, nn: usize, kk: usize, idx: i32) i64 {
                const x: usize = @intCast(idx);
                return if (x + kk < nn) rk[x + kk] else -1;
            }
        };
        tmp[@intCast(SA[0])] = 0;
        r = 0;
        for (1..n) |i| {
            const a = SA[i - 1];
            const b = SA[i];
            const ra = rank[@intCast(a)];
            const rb = rank[@intCast(b)];
            if (ra != rb or
                key2.at(rank, n, k, a) != key2.at(rank, n, k, b)) r += 1;
            tmp[@intCast(b)] = r;
        }
        @memcpy(rank[0..n], tmp);
        if (r == @as(i32, @intCast(n - 1))) break; // all distinct -> done
    }
}

// ---- correctness test vs naive SA ----
fn naiveLess(T: []const u8, a: usize, b: usize) bool {
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
            return naiveLess(self.t, @intCast(x), @intCast(y));
        }
    };
    std.sort.pdq(i32, out, C{ .t = T }, C.lt);
}

test "prefixDoubleSA matches naive SA" {
    const sc = try std.testing.allocator.create(Scratch);
    defer std.testing.allocator.destroy(sc);
    var prng = std.Random.DefaultPrng.init(0xD0D0);
    const rnd = prng.random();
    var buf: [4096]u8 = undefined;
    var a1: [4096]i32 = undefined;
    var a2: [4096]i32 = undefined;
    var trial: usize = 0;
    while (trial < 2500) : (trial += 1) {
        const n = 1 + (rnd.int(usize) % buf.len);
        const alpha: u16 = switch (rnd.int(u2)) {
            0 => 2,
            1 => 4,
            2 => 16,
            3 => 256,
        };
        for (buf[0..n]) |*c| c.* = @intCast(rnd.int(u16) % alpha);
        prefixDoubleSA(sc, buf[0..n].ptr, a1[0..n].ptr, n);
        naiveSA(buf[0..n], a2[0..n]);
        try std.testing.expectEqualSlices(i32, a2[0..n], a1[0..n]);
    }
}
