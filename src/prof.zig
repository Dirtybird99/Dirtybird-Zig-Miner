//! prof.zig -- matched stage profiler for the production pure-Zig pow.hash2 path.
//! Usage: prof [pairs] [repeats] [pin] (defaults: 2500 5 2)
const std = @import("std");
const builtin = @import("builtin");

// pow.zig, sa_v114_pure.zig and astrobwt.zig see this root declaration at compile
// time. It is absent from the miner and benchmarks, leaving their production paths
// untouched. The nanosecond profile is portable and runs on every target; only the
// wolfCompute cycle split needs x86 RDTSC, and astrobwt.zig gates that itself.
pub const astrobwt_profile_enabled = true;

const pow = @import("pow.zig");
const astrobwt = @import("astrobwt.zig");
const sa_pure = @import("sa_v114_pure.zig");
const system = @import("system.zig");

fn setPair(blob0: *[48]u8, blob1: *[48]u8, pair: usize) void {
    const nonce: u32 = @intCast(pair * 2);
    std.mem.writeInt(u32, blob0[43..47], nonce, .big);
    std.mem.writeInt(u32, blob1[43..47], nonce + 1, .big);
}

pub fn main() !void {
    const a = std.heap.page_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    const pairs = if (args.len > 1) try std.fmt.parseInt(usize, args[1], 10) else 2500;
    const repeats = if (args.len > 2) try std.fmt.parseInt(usize, args[2], 10) else 5;
    const pin: u6 = if (args.len > 3) try std.fmt.parseInt(u6, args[3], 10) else 2;
    if (pairs == 0 or repeats == 0 or pairs > @as(usize, std.math.maxInt(u32) / 2)) {
        std.debug.print("prof: pairs/repeats must be >= 1 and pairs <= {d}\n", .{std.math.maxInt(u32) / 2});
        std.process.exit(2);
    }

    if (comptime builtin.os.tag == .windows) {
        system.setProcessHighPriority();
        system.pinThreadToLogical(pin);
        system.setThreadHighPriority();
    }

    const w0 = try a.create(pow.Worker);
    defer a.destroy(w0);
    const w1 = try a.create(pow.Worker);
    defer a.destroy(w1);
    w0.* = .{};
    w1.* = .{};
    defer w0.deinitSA();
    defer w1.deinitSA();

    // Exact bench2 tid=0 corpus: DefaultPrng(12345), one 48-byte base blob,
    // big-endian nonces 0/1, 2/3, ... at bytes [43..47].
    var prng = std.Random.DefaultPrng.init(12345);
    var blob0: [48]u8 = undefined;
    prng.random().bytes(&blob0);
    blob0[47] = 0;
    var blob1 = blob0;
    var out0: [32]u8 = undefined;
    var out1: [32]u8 = undefined;

    // One untimed sweep faults in the lazily allocated pure-Zig SA scratch and
    // produces the same output checksum Rust can use as its correctness gate.
    var checksum: u64 = 0xcbf29ce484222325;
    var sum_data_len: u64 = 0;
    var i: usize = 0;
    while (i < pairs) : (i += 1) {
        setPair(&blob0, &blob1, i);
        try pow.hash2(&blob0, &blob1, &out0, &out1, w0, w1);
        for ([_]*const [32]u8{ &out0, &out1 }) |out| {
            for (out) |byte| checksum = (checksum ^ byte) *% 0x100000001b3;
        }
        sum_data_len += w0.data_len + w1.data_len;
    }

    pow.resetProfile();
    astrobwt.resetWolfProfile();
    sa_pure.ns_emit = 0;
    sa_pure.ns_sort = 0;
    sa_pure.ns_mat = 0;

    var total_timer = try std.time.Timer.start();
    var rep: usize = 0;
    while (rep < repeats) : (rep += 1) {
        i = 0;
        while (i < pairs) : (i += 1) {
            setPair(&blob0, &blob1, i);
            try pow.hash2(&blob0, &blob1, &out0, &out1, w0, w1);
            std.mem.doNotOptimizeAway(&out0);
            std.mem.doNotOptimizeAway(&out1);
        }
    }
    const total_ns = total_timer.read();

    const counters = pow.profile_counters;
    const sa_inner_ns = sa_pure.ns_emit + sa_pure.ns_sort + sa_pure.ns_mat;
    const sa_overhead_ns = if (counters.sa_ns > sa_inner_ns) counters.sa_ns - sa_inner_ns else 0;
    const accounted_ns = counters.prepare_ns + counters.op_loop_ns + counters.sa_ns + counters.final_hash2_ns;
    const hashes = 2.0 * @as(f64, @floatFromInt(pairs)) * @as(f64, @floatFromInt(repeats));
    const total_f: f64 = @floatFromInt(total_ns);
    const row = struct {
        fn print(name: []const u8, ns: u64, n_hashes: f64, total: f64) void {
            const value: f64 = @floatFromInt(ns);
            std.debug.print("  {s:<24} {d:>8.1} us/hash  {d:>5.1}%\n", .{ name, value / n_hashes / 1000.0, value / total * 100.0 });
        }
    };

    std.debug.print("\n=== pure-Zig production hash2 profile ===\n", .{});
    std.debug.print("  corpus: seed=12345 pairs={d} repeats={d} pin={d} pages=4K\n", .{ pairs, repeats, pin });
    row.print("prepare", counters.prepare_ns, hashes, total_f);
    row.print("op-loop", counters.op_loop_ns, hashes, total_f);
    row.print("descriptor emit", sa_pure.ns_emit, hashes, total_f);
    row.print("radix", sa_pure.ns_sort, hashes, total_f);
    row.print("materialize/collision", sa_pure.ns_mat, hashes, total_f);
    row.print("SA flags/call overhead", sa_overhead_ns, hashes, total_f);
    row.print("final SHA-256 x2", counters.final_hash2_ns, hashes, total_f);
    std.debug.print("  {s:<24} {d:>8.1} us/hash  100.0%\n", .{ "TOTAL measured", total_f / hashes / 1000.0 });
    std.debug.print("  accounted={d:.1}%  avg_data_len={d:.0}  checksum={x:0>16}\n", .{
        @as(f64, @floatFromInt(accounted_ns)) / total_f * 100.0,
        @as(f64, @floatFromInt(sum_data_len)) / (2.0 * @as(f64, @floatFromInt(pairs))),
        checksum,
    });

    if (comptime !astrobwt.profile_cycles_supported) {
        std.debug.print("\n  wolfCompute cycle split: unavailable on {s} (needs x86-64 RDTSC).\n", .{@tagName(builtin.cpu.arch)});
        std.debug.print("  The nanosecond table above is unaffected.\n", .{});
        return;
    }

    // Each profiled iteration carries exactly one bare rdtsc pair. The minimum over
    // many samples is the cleanest estimator for a fixed instruction cost.
    var pair_cost: u64 = std.math.maxInt(u64);
    var cal: usize = 0;
    while (cal < 2000) : (cal += 1) pair_cost = @min(pair_cost, astrobwt.profileRdtscPair());

    // One pass per bucket over the one-lane corpus (same base blob, nonces
    // 0..pairs-1). Splitting the passes holds a profiled iteration to two rdtsc
    // reads instead of five, so a bucket is not dominated by its own probe.
    var bucket_cycles = [4]f64{ 0, 0, 0, 0 };
    var cycles_per_ns_sum: f64 = 0;
    var total_corrected: f64 = 0;
    var clamped = false;
    for (0..4) |bi| {
        const b: u2 = @intCast(bi);
        pow.resetProfile();
        astrobwt.resetWolfProfile();
        astrobwt.profile_wolf_bucket = b;
        astrobwt.profile_wolf_collect = true;
        i = 0;
        while (i < pairs) : (i += 1) {
            std.mem.writeInt(u32, blob0[43..47], @intCast(i), .big);
            try pow.hash(&blob0, &out0, w0);
            std.mem.doNotOptimizeAway(&out0);
        }
        astrobwt.profile_wolf_collect = false;

        const raw: f64 = @floatFromInt(astrobwt.profile_wolf_cycles[b]);
        const total_raw: f64 = @floatFromInt(astrobwt.profile_wolf_total);
        const probe: f64 = @floatFromInt(pair_cost *% astrobwt.profile_wolf_iters);
        const op_ns: f64 = @floatFromInt(pow.profile_counters.op_loop_ns);

        // Scale from the *uncorrected* pair: numerator and denominator span the same
        // work and carry the same probe overhead, so the ratio recovers the clock.
        // Unlike op_loop_ns/sum(buckets) this does not force the rows to sum to the
        // wall time -- the denominator is the total, not the sum of the parts.
        if (op_ns > 0) cycles_per_ns_sum += total_raw / op_ns;

        if (raw > probe) {
            bucket_cycles[b] = raw - probe;
        } else {
            bucket_cycles[b] = 0;
            clamped = true;
        }
        total_corrected += if (total_raw > probe) total_raw - probe else 0;
    }

    const cycles_per_ns = cycles_per_ns_sum / 4.0;
    const total_mean = total_corrected / 4.0;
    const wolf_hashes: f64 = @floatFromInt(pairs);
    const measured = bucket_cycles[0] + bucket_cycles[1] + bucket_cycles[2] + bucket_cycles[3];
    const unattributed = if (total_mean > measured) total_mean - measured else 0;

    std.debug.print("\n  one-lane wolfCompute RDTSC breakdown (one bucket per pass, probe cost removed):\n", .{});
    std.debug.print("    probe calibration: {d} cycles per rdtsc pair, {d:.2} GHz\n", .{ pair_cost, cycles_per_ns });
    const names = [_][]const u8{ "byte-op + chunk copy", "loop hashes", "RC4 + template", "chunk[255] fold" };
    for (names, bucket_cycles) |name, cycles| printCycleRow(name, cycles, wolf_hashes, cycles_per_ns);
    // p1/p2 arithmetic, the loop-exit test, the template flush and data_len.
    printCycleRow("unattributed", unattributed, wolf_hashes, cycles_per_ns);
    printCycleRow("TOTAL wolfCompute", total_mean, wolf_hashes, cycles_per_ns);
    if (clamped) std.debug.print("    note: a bucket fell below its calibrated probe cost and was clamped to zero\n", .{});
}

fn printCycleRow(name: []const u8, cycles: f64, n_hashes: f64, cycles_per_ns: f64) void {
    const ns = if (cycles_per_ns > 0) cycles / cycles_per_ns / n_hashes else 0;
    std.debug.print("    {s:<22} {d:>10.0} cycles/hash  {d:>8.1} ns/hash\n", .{ name, cycles / n_hashes, ns });
}
