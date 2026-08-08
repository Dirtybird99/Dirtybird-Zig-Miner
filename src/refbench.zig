//! refbench.zig -- A/B the reference EXACT suffix-array backends (custom_sa_70kb,
//! divsufsort) against libsais on REAL wolfCompute data, to find the fastest
//! exact SA. All three must produce byte-identical SAs (the SA is unique).
const std = @import("std");
const sha256 = @import("primitives/sha256.zig");
const salsa20 = @import("primitives/salsa20.zig");
const fnv1a = @import("primitives/fnv1a.zig");
const astrobwt = @import("astrobwt.zig");
const sa = @import("suffix_array.zig");

extern fn custom_sa_70kb(T: [*]const u8, SA: [*]i32, n: i32, bA: [*]i32, bB: [*]i32) i32;
extern fn divsufsort(T: [*]const u8, SA: [*]i32, n: i32, bA: [*]i32, bB: [*]i32) i32;
extern fn radix_sa_bounded(T: [*]const u8, SA: [*]i32, n: i32) i32;

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
    @memset(w.sData[w.data_len..][0..32], 0);
}

pub fn main() !void {
    const a = std.heap.page_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    const iters: u64 = if (args.len > 1) try std.fmt.parseInt(u64, args[1], 10) else 5000;

    const w = try a.create(astrobwt.Worker);
    defer a.destroy(w);
    w.* = .{};
    w.sa_ctx = sa.createCtx();
    defer w.deinitSA();

    const sa_lib = try a.alloc(i32, astrobwt.SCRATCH);
    const sa_dss = try a.alloc(i32, astrobwt.SCRATCH);
    const sa_cus = try a.alloc(i32, astrobwt.SCRATCH);
    const bA = try a.alloc(i32, 256);
    const bB = try a.alloc(i32, 256 * 256);
    defer a.free(sa_lib);
    defer a.free(sa_dss);
    defer a.free(sa_cus);
    defer a.free(bA);
    defer a.free(bB);

    var blob: [48]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xBEEF11);
    prng.random().bytes(&blob);

    const sa_rdx = try a.alloc(i32, astrobwt.SCRATCH);
    defer a.free(sa_rdx);

    var t_lib: u64 = 0;
    var t_dss: u64 = 0;
    var t_cus: u64 = 0;
    var t_rdx: u64 = 0;
    var mism_dss: u64 = 0;
    var mism_cus: u64 = 0;
    var mism_rdx: u64 = 0;
    var rdx_tested: u64 = 0;
    var sum_n: u64 = 0;
    var timer = try std.time.Timer.start();

    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        std.mem.writeInt(u32, blob[43..47], @truncate(i), .big);
        buildSData(w, &blob);
        const n = w.data_len;
        const ni: i32 = @intCast(n);
        sum_n += n;

        timer.reset();
        sa.suffixArrayCtx(w.sa_ctx, w.sData[0..n], sa_lib[0..n]) catch {};
        t_lib += timer.read();

        timer.reset();
        _ = divsufsort(w.sData[0..n].ptr, sa_dss[0..n].ptr, ni, bA.ptr, bB.ptr);
        t_dss += timer.read();

        timer.reset();
        _ = custom_sa_70kb(w.sData[0..n].ptr, sa_cus[0..n].ptr, ni, bA.ptr, bB.ptr);
        t_cus += timer.read();

        // bounded radix (DERO sort_indices2) -- the consensus-correctness test
        timer.reset();
        const rc = radix_sa_bounded(w.sData[0..n].ptr, sa_rdx[0..n].ptr, ni);
        t_rdx += timer.read();

        if (!std.mem.eql(i32, sa_lib[0..n], sa_dss[0..n])) mism_dss += 1;
        if (!std.mem.eql(i32, sa_lib[0..n], sa_cus[0..n])) mism_cus += 1;
        if (rc == 0) {
            rdx_tested += 1;
            if (!std.mem.eql(i32, sa_lib[0..n], sa_rdx[0..n])) mism_rdx += 1;
        }
    }

    const fi: f64 = @floatFromInt(iters);
    std.debug.print("\n=== EXACT SA backend A/B on real wolfCompute data ({d} iters) ===\n", .{iters});
    std.debug.print("  avg n = {d:.0}\n", .{@as(f64, @floatFromInt(sum_n)) / fi});
    std.debug.print("  libsais        {d:>8.1} us/hash   (baseline)\n", .{@as(f64, @floatFromInt(t_lib)) / fi / 1000.0});
    std.debug.print("  divsufsort     {d:>8.1} us/hash   ({d:.2}x)   mismatches={d}\n", .{ @as(f64, @floatFromInt(t_dss)) / fi / 1000.0, @as(f64, @floatFromInt(t_lib)) / @as(f64, @floatFromInt(t_dss)), mism_dss });
    std.debug.print("  custom_sa_70kb {d:>8.1} us/hash   ({d:.2}x)   mismatches={d}\n", .{ @as(f64, @floatFromInt(t_cus)) / fi / 1000.0, @as(f64, @floatFromInt(t_lib)) / @as(f64, @floatFromInt(t_cus)), mism_cus });
    const fr: f64 = @floatFromInt(@max(rdx_tested, 1));
    std.debug.print("  radix_bounded  {d:>8.1} us/hash   ({d:.2}x)   mismatches={d}/{d}  <-- DERO sort_indices2 (bounded)\n", .{ @as(f64, @floatFromInt(t_rdx)) / fr / 1000.0, @as(f64, @floatFromInt(t_lib)) / @as(f64, @floatFromInt(@max(t_rdx, 1))), mism_rdx, rdx_tested });
    std.debug.print("\n  *** If radix_bounded mismatches>0, its hash differs from consensus -> REJECTED shares -> off-limits.\n", .{});
}
