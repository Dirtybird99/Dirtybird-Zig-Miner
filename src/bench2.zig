//! bench2.zig -- batched (2-nonce) hashrate benchmark. Processes two nonces per
//! iteration via pow.hash2, so the final SHA-256 can run multi-buffer (2-way,
//! latency-hiding). Usage: bench2 [threads] [seconds] [aff 0/1] [affmode]
const std = @import("std");
const builtin = @import("builtin");
const pow = @import("pow.zig");
const system = @import("system.zig");
const pages = @import("pages.zig");

const Ctx = struct {
    count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    seed: u64 = 12345,
    aff: bool = false,
    affmode: u8 = 0,
    hp: bool = false,
    nthreads: usize = 1,
};

const AFF_MAPS = [_][10]u6{
    .{ 0, 2, 4, 6, 8, 10, 12, 14, 16, 17 },
    .{ 0, 2, 4, 6, 8, 10, 12, 14, 1, 3 },
    .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 },
    .{ 0, 2, 4, 6, 8, 10, 12, 14, 16, 18 },
};

fn worker(ctx: *Ctx, tid: usize) void {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .linux) {
        if (ctx.aff) {
            const cpu: u7 = if (ctx.nthreads == 10 and builtin.os.tag == .windows)
                AFF_MAPS[ctx.affmode][tid]
            else
                system.recommendedAffinityForThreads(ctx.nthreads)[@min(tid, system.MAX_AFFINITY - 1)];
            system.pinThreadToLogical(cpu);
            system.setThreadHighPriority();
        }
    }
    // Both private workers, optionally packed into ONE 2MB large page (hp) so the
    // hot sData/sa buffers (~360KB each) get large-page TLB coverage on the
    // production hash2 path. Falls back to page_allocator if large pages decline.
    var large_backing: ?pages.PageBacking = null;
    const ws: [2]*pow.Worker = blk: {
        if (ctx.hp) {
            if (pages.allocHugeBacking(2 * @sizeOf(pow.Worker))) |backing| {
                large_backing = backing;
                const buf = backing.bytes;
                const p0: *pow.Worker = @ptrCast(@alignCast(buf.ptr));
                const p1: *pow.Worker = @ptrCast(@alignCast(buf.ptr + @sizeOf(pow.Worker)));
                break :blk .{ p0, p1 };
            }
        }
        break :blk .{
            std.heap.page_allocator.create(pow.Worker) catch return,
            std.heap.page_allocator.create(pow.Worker) catch return,
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
    var prng = std.Random.DefaultPrng.init(ctx.seed +% tid);
    var blob0: [48]u8 = undefined;
    prng.random().bytes(&blob0);
    blob0[47] = @truncate(tid);
    var blob1: [48]u8 = blob0;
    var out0: [32]u8 = undefined;
    var out1: [32]u8 = undefined;
    var nonce: u32 = 0;
    var local: u64 = 0;
    while (!ctx.stop.load(.monotonic)) {
        std.mem.writeInt(u32, blob0[43..47], nonce, .big);
        std.mem.writeInt(u32, blob1[43..47], nonce +% 1, .big);
        pow.hash2(&blob0, &blob1, &out0, &out1, w0, w1) catch {};
        nonce +%= 2;
        local += 2;
        if (local & 63 == 0) _ = ctx.count.fetchAdd(64, .monotonic);
    }
    _ = ctx.count.fetchAdd(local & 63, .monotonic);
}

pub fn main() !void {
    const a = std.heap.page_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    const nthreads = if (args.len > 1) try std.fmt.parseInt(usize, args[1], 10) else 10;
    const secs = if (args.len > 2) try std.fmt.parseInt(u64, args[2], 10) else 10;
    const aff = if (args.len > 3) (args[3][0] != '0') else false;
    const affmode: u8 = if (args.len > 4) (std.fmt.parseInt(u8, args[4], 10) catch 0) else 0;
    const hp = if (args.len > 5) (args[5][0] != '0') else false;

    var ctx = Ctx{ .aff = aff, .affmode = affmode, .hp = hp, .nthreads = nthreads };
    if (comptime builtin.os.tag == .windows) {
        if (aff or hp) {
            _ = system.enableLockMemoryPrivilege();
            if (hp) std.debug.print("[large-pages ON]\n", .{});
        }
    }
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .linux) {
        if (aff) system.setProcessHighPriority();
    }
    if (hp and builtin.os.tag == .linux) std.debug.print("[huge-pages THP requested]\n", .{});
    const threads = try a.alloc(std.Thread, nthreads);
    defer a.free(threads);

    const t0 = std.time.milliTimestamp();
    for (threads, 0..) |*t, i| t.* = try std.Thread.spawn(.{}, worker, .{ &ctx, i });
    std.time.sleep(secs * std.time.ns_per_s);
    ctx.stop.store(true, .monotonic);
    for (threads) |t| t.join();

    const dt = @as(f64, @floatFromInt(std.time.milliTimestamp() - t0)) / 1000.0;
    const total = ctx.count.load(.monotonic);
    const khs = @as(f64, @floatFromInt(total)) / dt / 1000.0;
    std.debug.print("bench2: {d} threads, {d:.1}s, {d} hashes -> {d:.2} KH/s total ({d:.3}/thr)\n", .{ nthreads, dt, total, khs, khs / @as(f64, @floatFromInt(nthreads)) });
}
