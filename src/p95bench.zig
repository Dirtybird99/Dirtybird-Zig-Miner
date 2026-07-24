//! p95bench.zig -- p95 per-hash tail-latency harness for the production batched
//! pow.hash2 path. Metric ground truth for the optimize loop: FROZEN once the
//! loop starts (editing what measures you invalidates the run).
//!
//! Method: bench2's tid=0 blob stream (seed 12345, nonce big-endian at [43..47]),
//! `pairs` FIXED nonce pairs (pair i = nonces 2i, 2i+1 -- pairing matters: hash2's
//! multi-buffer SHA cost depends on both lanes). One untimed warmup sweep (faults
//! in Worker + SA scratch, accumulates an FNV checksum of every output), then
//! `repeats` timed sweeps over all pairs, keeping the per-pair MIN (repeat-major
//! order preserves production cache state between calls; min discards OS spikes).
//! p95 is index (pairs*95)/100 of the ascending per-pair mins, reported per-hash
//! (pair/2).
//!
//! Output contract: stdout is exactly one line `p95_ns=<integer>`; everything
//! else (percentiles, sweep times, data_len stats, checksum) goes to stderr.
//! Usage: p95bench [pin] [repeats] [pairs] [hp]   (defaults 2, 5, 2500, 0)
const std = @import("std");
const builtin = @import("builtin");
const pow = @import("pow.zig");
const system = @import("system.zig");
const pages = @import("pages.zig");

pub fn main() !void {
    const a = std.heap.page_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    const pin: u6 = if (args.len > 1) try std.fmt.parseInt(u6, args[1], 10) else 2;
    const repeats: usize = if (args.len > 2) try std.fmt.parseInt(usize, args[2], 10) else 5;
    const pairs: usize = if (args.len > 3) try std.fmt.parseInt(usize, args[3], 10) else 2500;
    const hp = if (args.len > 4) (args[4][0] != '0') else false;
    if (repeats == 0 or pairs == 0) {
        std.debug.print("p95bench: repeats and pairs must be >= 1\n", .{});
        std.process.exit(2);
    }

    // Measure on the main thread: HIGH priority class, pinned to one P-core
    // (logical 2 = physical #1 -- off logical 0's kernel DPC traffic, idle HT
    // sibling), HIGHEST thread priority + power throttling off.
    if (comptime builtin.os.tag == .windows) {
        if (hp) _ = system.enableLockMemoryPrivilege();
        system.setProcessHighPriority();
        system.pinThreadToLogical(pin);
        system.setThreadHighPriority();
    }

    // Both workers, optionally packed into one large-page backing exactly like
    // bench2's production layout. Default is hp=0: allocHugeBacking can silently
    // fall back run-to-run (error 1450), and a mode flip mid-loop would read as a
    // fake 2-4% code effect.
    var large_backing: ?pages.PageBacking = null;
    const ws: [2]*pow.Worker = blk: {
        if (hp) {
            if (pages.allocHugeBacking(2 * @sizeOf(pow.Worker))) |backing| {
                large_backing = backing;
                const buf = backing.bytes;
                const p0: *pow.Worker = @ptrCast(@alignCast(buf.ptr));
                const p1: *pow.Worker = @ptrCast(@alignCast(buf.ptr + @sizeOf(pow.Worker)));
                break :blk .{ p0, p1 };
            }
        }
        break :blk .{
            try std.heap.page_allocator.create(pow.Worker),
            try std.heap.page_allocator.create(pow.Worker),
        };
    };
    const w0 = ws[0];
    const w1 = ws[1];
    w0.* = .{};
    w1.* = .{};
    defer {
        w0.deinitSA();
        w1.deinitSA();
        if (large_backing) |backing| {
            pages.freeHugeBacking(backing);
        } else {
            std.heap.page_allocator.destroy(w0);
            std.heap.page_allocator.destroy(w1);
        }
    }

    var prng = std.Random.DefaultPrng.init(12345);
    var blob0: [48]u8 = undefined;
    prng.random().bytes(&blob0);
    blob0[47] = 0;
    var blob1: [48]u8 = blob0;
    var out0: [32]u8 = undefined;
    var out1: [32]u8 = undefined;

    const mins = try a.alloc(u64, pairs);
    defer a.free(mins);
    @memset(mins, std.math.maxInt(u64));

    // Warmup sweep: untimed; faults in the lazily-created SA scratch, trains
    // predictors, and folds every output byte into an FNV-1a checksum -- a free
    // tripwire the loop compares against baseline (it must never change).
    var checksum: u64 = 0xcbf29ce484222325;
    var sum_dlen: u64 = 0;
    var max_dlen: u64 = 0;
    var i: usize = 0;
    while (i < pairs) : (i += 1) {
        std.mem.writeInt(u32, blob0[43..47], @intCast(2 * i), .big);
        std.mem.writeInt(u32, blob1[43..47], @intCast(2 * i + 1), .big);
        try pow.hash2(&blob0, &blob1, &out0, &out1, w0, w1);
        for (out0) |byte| checksum = (checksum ^ byte) *% 0x100000001b3;
        for (out1) |byte| checksum = (checksum ^ byte) *% 0x100000001b3;
        sum_dlen += w0.data_len + w1.data_len;
        max_dlen = @max(max_dlen, @max(w0.data_len, w1.data_len));
    }

    // Timed sweeps: per-pair min across repeats.
    const sweep_ns = try a.alloc(u64, repeats);
    defer a.free(sweep_ns);
    var timer = try std.time.Timer.start();
    var sweep_timer = try std.time.Timer.start();
    var rep: usize = 0;
    while (rep < repeats) : (rep += 1) {
        sweep_timer.reset();
        i = 0;
        while (i < pairs) : (i += 1) {
            std.mem.writeInt(u32, blob0[43..47], @intCast(2 * i), .big);
            std.mem.writeInt(u32, blob1[43..47], @intCast(2 * i + 1), .big);
            timer.reset();
            try pow.hash2(&blob0, &blob1, &out0, &out1, w0, w1);
            const dt = timer.read();
            std.mem.doNotOptimizeAway(&out0);
            std.mem.doNotOptimizeAway(&out1);
            if (dt < mins[i]) mins[i] = dt;
        }
        sweep_ns[rep] = sweep_timer.read();
    }

    const sorted = try a.alloc(u64, pairs);
    defer a.free(sorted);
    @memcpy(sorted, mins);
    std.mem.sort(u64, sorted, {}, comptime std.sort.asc(u64));

    var sum: u64 = 0;
    for (sorted) |v| sum += v;
    const per_hash = struct {
        fn at(s: []const u64, idx: usize) u64 {
            return s[idx] / 2;
        }
    };
    const p50 = per_hash.at(sorted, pairs * 50 / 100);
    const p90 = per_hash.at(sorted, pairs * 90 / 100);
    const p95 = per_hash.at(sorted, pairs * 95 / 100);
    const p99 = per_hash.at(sorted, pairs * 99 / 100);
    const worst = sorted[pairs - 1] / 2;
    const mean = sum / pairs / 2;

    std.debug.print("p95bench: pin={d} hp={} pairs={d} repeats={d}\n", .{ pin, hp, pairs, repeats });
    std.debug.print("  per-hash ns: p50={d} p90={d} p95={d} p99={d} max={d} mean={d}\n", .{ p50, p90, p95, p99, worst, mean });
    std.debug.print("  data_len: max={d} avg={d}\n", .{ max_dlen, sum_dlen / (2 * pairs) });
    for (sweep_ns, 0..) |ns, s| {
        std.debug.print("  sweep{d}: {d:.1} ms\n", .{ s, @as(f64, @floatFromInt(ns)) / 1e6 });
    }
    std.debug.print("  checksum={x:0>16}\n", .{checksum});

    try std.io.getStdOut().writer().print("p95_ns={d}\n", .{p95});
}
