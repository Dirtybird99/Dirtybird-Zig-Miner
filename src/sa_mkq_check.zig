//! sa_mkq_check.zig -- differential validator + timer for src/sa_mkq.zig (buildSA)
//! against libsais, on REAL wolfCompute outputs (the actual SA inputs the miner
//! sees). Modeled on src/sadiag.zig's buildSData pipeline.
//!
//! Build:
//!   .tools\zig\zig.exe build-exe src\sa_mkq_check.zig vendor\libsais\libsais.c ^
//!     -Ivendor\libsais -lc -O ReleaseFast -mcpu=native ^
//!     -femit-bin=zig-out\bin\sa_mkq_check.exe
//! Run:
//!   zig-out\bin\sa_mkq_check.exe [num_nonces]
//!
//! Asserts SA arrays are byte-identical for every nonce (mismatches must be 0),
//! and reports single-thread microseconds/hash for buildSA vs libsais.

const std = @import("std");
const sha256 = @import("primitives/sha256.zig");
const salsa20 = @import("primitives/salsa20.zig");
const fnv1a = @import("primitives/fnv1a.zig");
const astrobwt = @import("astrobwt.zig");
const sa = @import("suffix_array.zig");
const sa_mkq = @import("sa_mkq.zig");

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
    // Zero-pad >=32 bytes after data_len so the 32-byte SIMD reads in the
    // comparator (and any future u64 key reads) are safe and read zeros.
    @memset(w.sData[w.data_len..][0..64], 0);
}

pub fn main() !void {
    const a = std.heap.page_allocator;

    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    var num_nonces: usize = 5000;
    if (args.len >= 2) num_nonces = try std.fmt.parseInt(usize, args[1], 10);

    const w = try a.create(astrobwt.Worker);
    defer a.destroy(w);
    w.* = .{};
    w.sa_ctx = sa.createCtx();
    defer w.deinitSA();

    const sc = try a.create(sa_mkq.Scratch);
    defer a.destroy(sc);

    // Output SA buffers (separate so we can compare).
    const sa_lib = try a.alloc(i32, astrobwt.SCRATCH);
    defer a.free(sa_lib);
    const sa_mk = try a.alloc(i32, astrobwt.SCRATCH);
    defer a.free(sa_mk);

    var blob: [48]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x1234_5678_9ABC_DEF0);
    prng.random().bytes(&blob);

    var mismatches: usize = 0;
    var sum_n: u64 = 0;
    var timer = try std.time.Timer.start();

    // ---- Precompute all SA inputs ONCE into a flat arena ----
    // This takes buildSData (and its variance) entirely out of the timed loops, so
    // we measure ONLY suffix-array construction. Each input is the real wolfCompute
    // output, zero-padded >=64 bytes after data_len.
    const PAD = 64;
    const inputs = try a.alloc(u8, num_nonces * astrobwt.SCRATCH);
    defer a.free(inputs);
    const lens = try a.alloc(u32, num_nonces);
    defer a.free(lens);

    var s: usize = 0;
    while (s < num_nonces) : (s += 1) {
        std.mem.writeInt(u32, blob[43..47], @intCast(s & 0xFFFF_FFFF), .big);
        buildSData(w, &blob);
        const n: usize = w.data_len;
        lens[s] = @intCast(n);
        sum_n += n;
        @memcpy(inputs[s * astrobwt.SCRATCH ..][0..n], w.sData[0..n]);
        @memset(inputs[s * astrobwt.SCRATCH + n ..][0..PAD], 0);
    }
    const fn_nonces: f64 = @floatFromInt(num_nonces);

    // ---- Correctness: buildSA vs libsais on every input (untimed) ----
    s = 0;
    while (s < num_nonces) : (s += 1) {
        const n: usize = lens[s];
        const T = inputs[s * astrobwt.SCRATCH ..][0..n];
        sa.suffixArrayCtx(w.sa_ctx, T, sa_lib[0..n]) catch return error.SuffixArrayFailed;
        sa_mkq.buildSA(sc, T.ptr, sa_mk[0..n].ptr, n);
        if (!std.mem.eql(i32, sa_lib[0..n], sa_mk[0..n])) {
            mismatches += 1;
            if (mismatches == 1) {
                std.debug.print("\n!!! MISMATCH at nonce {d} (n={d})\n", .{ s, n });
                for (0..n) |idx| {
                    if (sa_lib[idx] != sa_mk[idx]) {
                        std.debug.print("  first diff SA[{d}]: libsais={d} buildSA={d}\n", .{ idx, sa_lib[idx], sa_mk[idx] });
                        break;
                    }
                }
            }
        }
    }

    std.debug.print("\n=== sa_mkq buildSA vs libsais on real wolfCompute inputs ===\n", .{});
    std.debug.print("  nonces tested      = {d}\n", .{num_nonces});
    std.debug.print("  avg n (data_len)   = {d:.0}\n", .{@as(f64, @floatFromInt(sum_n)) / fn_nonces});
    std.debug.print("  MISMATCHES         = {d}  {s}\n", .{ mismatches, if (mismatches == 0) "(EXACT)" else "(!!! FAIL)" });

    // ---- Robust timing: min-of-R full passes per backend ----
    // The MINIMUM total time across repetitions is the best estimate of true
    // compute cost: OS scheduling/contention can only ADD time, never subtract.
    // Reporting min (not mean) suppresses the upward noise that plagued earlier
    // runs. We interleave one libsais min-pass and one buildSA min-pass per cutoff
    // so both see identical thermal state.
    const R: usize = 8;
    const cutoffs = [_]usize{ 32, 48, 64, 96, 128, 192 };

    // libsais min-of-R.
    var lib_min_ns: u64 = std.math.maxInt(u64);
    var rep: usize = 0;
    while (rep < R) : (rep += 1) {
        timer.reset();
        s = 0;
        while (s < num_nonces) : (s += 1) {
            const n: usize = lens[s];
            const T = inputs[s * astrobwt.SCRATCH ..][0..n];
            sa.suffixArrayCtx(w.sa_ctx, T, sa_lib[0..n]) catch {};
        }
        const t = timer.read();
        if (t < lib_min_ns) lib_min_ns = t;
    }
    const lib_us = @as(f64, @floatFromInt(lib_min_ns)) / 1000.0 / fn_nonces;
    std.debug.print("\n  --- robust timing (min of {d} passes, {d} nonces each) ---\n", .{ R, num_nonces });
    std.debug.print("  libsais  us/hash   = {d:.1}  (best-case, least-contended)\n", .{lib_us});

    for (cutoffs) |co| {
        sc.insertion_cutoff = co;
        var mkq_min_ns: u64 = std.math.maxInt(u64);
        rep = 0;
        while (rep < R) : (rep += 1) {
            timer.reset();
            s = 0;
            while (s < num_nonces) : (s += 1) {
                const n: usize = lens[s];
                const T = inputs[s * astrobwt.SCRATCH ..][0..n];
                sa_mkq.buildSA(sc, T.ptr, sa_mk[0..n].ptr, n);
            }
            const t = timer.read();
            if (t < mkq_min_ns) mkq_min_ns = t;
        }
        const mkq_us = @as(f64, @floatFromInt(mkq_min_ns)) / 1000.0 / fn_nonces;
        std.debug.print("    cutoff={d:>4}  buildSA={d:>7.1} us/hash  speedup(lib/mkq)={d:.2}x  {s}\n", .{
            co,                                          mkq_us, lib_us / mkq_us,
            if (mkq_us < lib_us) "FASTER" else "slower",
        });
    }
    sc.insertion_cutoff = 0;

    if (mismatches != 0) {
        std.process.exit(1);
    }
}
