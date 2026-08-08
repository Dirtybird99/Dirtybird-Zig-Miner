//! sadiag.zig -- diagnostics on the suffix-array INPUT (wolfCompute output).
//! Measures LCP distribution (how deep suffix comparisons must go) and bucket
//! collision stats, to decide which SA construction can beat libsais here.
const std = @import("std");
const sha256 = @import("primitives/sha256.zig");
const salsa20 = @import("primitives/salsa20.zig");
const fnv1a = @import("primitives/fnv1a.zig");
const astrobwt = @import("astrobwt.zig");
const sa = @import("suffix_array.zig");

fn buildSData(w: *astrobwt.Worker, blob: []const u8) void {
    var scratch: [384]u8 = [_]u8{0} ** 384;
    sha256.hash(blob, scratch[320..][0..32]);
    salsa20.expand(scratch[320..][0..32], scratch[0..][0..256]);
    w.key.setKey(scratch[0..256]);
    w.key.process(scratch[0..256], scratch[0..256]);
    w.lhash = fnv1a.hash256(scratch[0..256]);
    w.prev_lhash = w.lhash;
    w.tries = 0;
    @memcpy(w.sData[0..256], scratch[0..256]);
    astrobwt.wolfCompute(w);
    @memset(w.sData[w.data_len..][0..16], 0);
}

pub fn main() !void {
    const a = std.heap.page_allocator;
    const w = try a.create(astrobwt.Worker);
    defer a.destroy(w);
    w.* = .{};
    w.sa_ctx = sa.createCtx();
    defer w.deinitSA();

    const rank = try a.alloc(i32, astrobwt.SCRATCH);
    defer a.free(rank);
    const lcp = try a.alloc(i32, astrobwt.SCRATCH);
    defer a.free(lcp);

    var blob: [48]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xABCDEF);
    prng.random().bytes(&blob);

    const SAMPLES = 40;
    var sum_avg_lcp: f64 = 0;
    var global_max_lcp: i64 = 0;
    var sum_p99: f64 = 0;
    var sum_buckets_gt1: f64 = 0;
    var sum_maxbucket: f64 = 0;
    var sum_n: f64 = 0;
    var sum_p50: f64 = 0;
    var sum_p90: f64 = 0;
    var sum_gt8: f64 = 0;
    var sum_gt32: f64 = 0;
    var sum_gt256: f64 = 0;

    var s: usize = 0;
    while (s < SAMPLES) : (s += 1) {
        std.mem.writeInt(u32, blob[43..47], @intCast(s), .big);
        buildSData(w, &blob);
        const n: usize = w.data_len;
        const T = w.sData[0..n];
        const SA = w.sa[0..n];
        sa.suffixArrayCtx(w.sa_ctx, T, SA) catch {};

        // Kasai LCP
        for (0..n) |i| rank[@intCast(SA[i])] = @intCast(i);
        var h: i64 = 0;
        var total_lcp: i64 = 0;
        var maxl: i64 = 0;
        // histogram of lcp values (cap 4096)
        var hist = [_]u32{0} ** 4097;
        for (0..n) |i| {
            if (rank[i] > 0) {
                const j: usize = @intCast(SA[@as(usize, @intCast(rank[i])) - 1]);
                while (i + @as(usize, @intCast(h)) < n and j + @as(usize, @intCast(h)) < n and
                    T[i + @as(usize, @intCast(h))] == T[j + @as(usize, @intCast(h))]) h += 1;
                total_lcp += h;
                if (h > maxl) maxl = h;
                hist[@intCast(@min(h, 4096))] += 1;
                if (h > 0) h -= 1;
            } else h = 0;
        }
        const avg_lcp = @as(f64, @floatFromInt(total_lcp)) / @as(f64, @floatFromInt(n));
        // percentiles from hist
        const pct = struct {
            fn at(hg: []const u32, nn: usize, p: f64) i64 {
                var c: u64 = 0;
                const th: u64 = @intFromFloat(p * @as(f64, @floatFromInt(nn)));
                for (hg, 0..) |cc, val| {
                    c += cc;
                    if (c >= th) return @intCast(val);
                }
                return @intCast(hg.len - 1);
            }
        };
        const p50 = pct.at(&hist, n, 0.50);
        const p90 = pct.at(&hist, n, 0.90);
        const p99 = pct.at(&hist, n, 0.99);
        var gt8: u32 = 0;
        var gt32: u32 = 0;
        var gt256: u32 = 0;
        for (hist, 0..) |c, val| {
            if (val > 8) gt8 += c;
            if (val > 32) gt32 += c;
            if (val > 256) gt256 += c;
        }
        _ = .{ p50, p90, gt8, gt32, gt256 };
        sum_p50 += @floatFromInt(p50);
        sum_p90 += @floatFromInt(p90);
        sum_gt8 += @floatFromInt(gt8);
        sum_gt32 += @floatFromInt(gt32);
        sum_gt256 += @floatFromInt(gt256);

        // 2-byte bucket stats
        var bcounts = try a.alloc(u32, 65536);
        defer a.free(bcounts);
        @memset(bcounts, 0);
        for (0..n - 1) |i| bcounts[(@as(usize, T[i]) << 8) | T[i + 1]] += 1;
        bcounts[@as(usize, T[n - 1]) << 8] += 1;
        var gt1: u32 = 0;
        var maxb: u32 = 0;
        for (bcounts) |c| {
            if (c > 1) gt1 += 1;
            if (c > maxb) maxb = c;
        }

        sum_avg_lcp += avg_lcp;
        if (maxl > global_max_lcp) global_max_lcp = maxl;
        sum_p99 += @floatFromInt(p99);
        sum_buckets_gt1 += @floatFromInt(gt1);
        sum_maxbucket += @floatFromInt(maxb);
        sum_n += @floatFromInt(n);
    }

    const f: f64 = @floatFromInt(SAMPLES);
    std.debug.print("\n=== SA input (wolfCompute output) diagnostics, {d} samples ===\n", .{SAMPLES});
    std.debug.print("  avg n (data_len)      = {d:.0}\n", .{sum_n / f});
    std.debug.print("  avg LCP               = {d:.1} bytes  <-- mean comparison depth\n", .{sum_avg_lcp / f});
    std.debug.print("  median(p50) LCP       = {d:.0} bytes\n", .{sum_p50 / f});
    std.debug.print("  p90 LCP               = {d:.0} bytes\n", .{sum_p90 / f});
    std.debug.print("  p99 LCP               = {d:.0} bytes\n", .{sum_p99 / f});
    std.debug.print("  global max LCP        = {d}\n", .{global_max_lcp});
    std.debug.print("  suffixes w/ LCP>8     = {d:.0} ({d:.1}%)\n", .{ sum_gt8 / f, 100.0 * sum_gt8 / sum_n });
    std.debug.print("  suffixes w/ LCP>32    = {d:.0} ({d:.1}%)\n", .{ sum_gt32 / f, 100.0 * sum_gt32 / sum_n });
    std.debug.print("  suffixes w/ LCP>256   = {d:.0} ({d:.1}%)\n", .{ sum_gt256 / f, 100.0 * sum_gt256 / sum_n });
    std.debug.print("  2-byte buckets >1     = {d:.0}\n", .{sum_buckets_gt1 / f});
    std.debug.print("  max 2-byte bucket     = {d:.0}\n", .{sum_maxbucket / f});
    std.debug.print("  => total comparison work ~ n*avgLCP = {d:.0} byte-cmps/hash\n", .{(sum_n / f) * (sum_avg_lcp / f)});
}
