//! sa_v114_check.zig -- differential validator + timer for src/sa_v114_pure.zig
//! (buildSA) against libsais, on REAL wolfCompute outputs (the actual SA inputs
//! the miner sees). Modeled on src/sa_mkq_check.zig.
//!
//! Build:
//!   .tools\zig\zig.exe build-exe src\sa_v114_check.zig vendor\libsais\libsais.c ^
//!     -Ivendor\libsais -lc -O ReleaseFast -mcpu=native ^
//!     -femit-bin=zig-out\bin\sa_v114_check.exe
//! Run:
//!   zig-out\bin\sa_v114_check.exe [num_nonces]
//!
//! Asserts SA arrays are byte-identical to libsais for every nonce (mismatches
//! must be 0), and reports single-thread microseconds/hash for buildSA vs libsais.

const std = @import("std");
const sha256 = @import("primitives/sha256.zig");
const salsa20 = @import("primitives/salsa20.zig");
const fnv1a = @import("primitives/fnv1a.zig");
const astrobwt = @import("astrobwt.zig");
const sa = @import("suffix_array.zig");
const sa_pure = @import("sa_v114_pure.zig");

const FLAG_CAP = 320; // (72000>>8)+1 = 282 <= 320

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
    // Zero-pad past data_len so load24 (reads pos+2) and any u64 comparator
    // reads are safe and see zeros.
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

    const sc = try a.create(sa_pure.Scratch);
    defer a.destroy(sc);

    const sa_lib = try a.alloc(i32, astrobwt.SCRATCH);
    defer a.free(sa_lib);
    const sa_pu = try a.alloc(i32, astrobwt.SCRATCH);
    defer a.free(sa_pu);

    var blob: [48]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x1234_5678_9ABC_DEF0);
    prng.random().bytes(&blob);

    // Streaming gate: `sa_v114_check <count> stream [seed]` -- build+check one
    // nonce at a time (no precompute storage), so millions of nonces fit in RAM.
    // Correctness only (no timing). Used for the large pre-ship differential gate.
    if (args.len >= 3 and std.mem.eql(u8, args[2], "stream")) {
        var seed: u64 = 1;
        if (args.len >= 4) seed = try std.fmt.parseInt(u64, args[3], 10);
        std.mem.writeInt(u64, blob[0..8], seed, .big);
        var flags: [FLAG_CAP]u8 = undefined;
        var sm: u64 = 0;
        var s2: u64 = 0;
        while (s2 < num_nonces) : (s2 += 1) {
            std.mem.writeInt(u64, blob[40..48], s2, .big);
            buildSData(w, &blob);
            const n: usize = w.data_len;
            const T = w.sData[0..n];
            sa.suffixArrayCtx(w.sa_ctx, T, sa_lib[0..n]) catch return error.SuffixArrayFailed;
            const flen = sa_pure.buildStage5Flags(&w.template_markers, w.n_templates, @intCast(n), &flags);
            if (flen == 0) {
                std.debug.print("!!! buildStage5Flags==0 at nonce {d} (n={d})\n", .{ s2, n });
                std.process.exit(3);
            }
            sa_pure.buildSA(sc, T.ptr, @intCast(n), &flags, sa_pu[0..n].ptr);
            if (!std.mem.eql(i32, sa_lib[0..n], sa_pu[0..n])) {
                sm += 1;
                if (sm <= 3) std.debug.print("!!! MISMATCH at nonce {d} (n={d})\n", .{ s2, n });
            }
            if (s2 != 0 and s2 % 250000 == 0) std.debug.print("  ...{d} checked, {d} mismatches\n", .{ s2, sm });
        }
        std.debug.print("STREAM: checked={d} mismatches={d} -> {s}\n", .{ num_nonces, sm, if (sm == 0) "PASS" else "FAIL" });
        if (sm != 0) std.process.exit(1);
        return;
    }

    var mismatches: usize = 0;
    var sum_n: u64 = 0;
    var timer = try std.time.Timer.start();

    // ---- Precompute all SA inputs + flags ONCE into flat arenas ----
    const PAD = 64;
    const inputs = try a.alloc(u8, num_nonces * astrobwt.SCRATCH);
    defer a.free(inputs);
    const lens = try a.alloc(u32, num_nonces);
    defer a.free(lens);
    const flags_all = try a.alloc(u8, num_nonces * FLAG_CAP);
    defer a.free(flags_all);

    var s: usize = 0;
    while (s < num_nonces) : (s += 1) {
        std.mem.writeInt(u32, blob[43..47], @intCast(s & 0xFFFF_FFFF), .big);
        buildSData(w, &blob);
        const n: usize = w.data_len;
        lens[s] = @intCast(n);
        sum_n += n;
        @memcpy(inputs[s * astrobwt.SCRATCH ..][0..n], w.sData[0..n]);
        @memset(inputs[s * astrobwt.SCRATCH + n ..][0..PAD], 0);
        const fl = flags_all[s * FLAG_CAP ..][0..FLAG_CAP];
        const flen = sa_pure.buildStage5Flags(&w.template_markers, w.n_templates, @intCast(n), fl);
        if (flen == 0) {
            std.debug.print("!!! buildStage5Flags returned 0 at nonce {d} (n={d})\n", .{ s, n });
            std.process.exit(3);
        }
    }
    const fn_nonces: f64 = @floatFromInt(num_nonces);

    // ---- Correctness: buildSA vs libsais on every input (untimed) ----
    var tot_runs: u64 = 0;
    var tot_multi: u64 = 0;
    var tot_single: u64 = 0;
    sa_pure.ns_emit = 0;
    sa_pure.ns_sort = 0;
    sa_pure.ns_mat = 0;
    s = 0;
    while (s < num_nonces) : (s += 1) {
        const n: usize = lens[s];
        const T = inputs[s * astrobwt.SCRATCH ..][0..n];
        const fl = flags_all[s * FLAG_CAP ..];
        sa.suffixArrayCtx(w.sa_ctx, T, sa_lib[0..n]) catch return error.SuffixArrayFailed;
        sa_pure.buildSA(sc, T.ptr, @intCast(n), fl.ptr, sa_pu[0..n].ptr);
        tot_runs += sa_pure.stat_runs;
        tot_multi += sa_pure.stat_multi_pos;
        tot_single += sa_pure.stat_single_pos;
        if (!std.mem.eql(i32, sa_lib[0..n], sa_pu[0..n])) {
            mismatches += 1;
            if (mismatches <= 3) {
                std.debug.print("\n!!! MISMATCH at nonce {d} (n={d})\n", .{ s, n });
                for (0..n) |idx| {
                    if (sa_lib[idx] != sa_pu[idx]) {
                        std.debug.print("  first diff SA[{d}]: libsais={d} buildSA={d}\n", .{ idx, sa_lib[idx], sa_pu[idx] });
                        break;
                    }
                }
            }
        }
    }

    std.debug.print("\n=== sa_v114_pure buildSA vs libsais on real wolfCompute inputs ===\n", .{});
    std.debug.print("  nonces tested      = {d}\n", .{num_nonces});
    std.debug.print("  avg n (data_len)   = {d:.0}\n", .{@as(f64, @floatFromInt(sum_n)) / fn_nonces});
    std.debug.print("  MISMATCHES         = {d}  {s}\n", .{ mismatches, if (mismatches == 0) "(EXACT)" else "(!!! FAIL)" });
    std.debug.print("  avg runs/hash      = {d:.0}  (runs per n={d:.0} positions)\n", .{ @as(f64, @floatFromInt(tot_runs)) / fn_nonces, @as(f64, @floatFromInt(sum_n)) / fn_nonces });
    std.debug.print("  positions: single-run copy = {d:.1}%   multi-run re-sort = {d:.1}%\n", .{
        100.0 * @as(f64, @floatFromInt(tot_single)) / @as(f64, @floatFromInt(sum_n)),
        100.0 * @as(f64, @floatFromInt(tot_multi)) / @as(f64, @floatFromInt(sum_n)),
    });
    std.debug.print("  phase us/hash: emit={d:.1}  run-sort={d:.1}  materialize={d:.1}\n", .{
        @as(f64, @floatFromInt(sa_pure.ns_emit)) / 1000.0 / fn_nonces,
        @as(f64, @floatFromInt(sa_pure.ns_sort)) / 1000.0 / fn_nonces,
        @as(f64, @floatFromInt(sa_pure.ns_mat)) / 1000.0 / fn_nonces,
    });

    // ---- Robust timing: INTERLEAVED per-rep so libsais and pure see the same
    // CPU frequency/thermal state. The frequency-invariant metric is the per-rep
    // ratio lib_ns/pure_ns (a "speedup"); report its max (best window) and median.
    // Absolute us/hash is reported too but is noisy on frequency-scaling laptops.
    const R: usize = 21;
    const Pass = struct {
        fn lib(ww: *astrobwt.Worker, in: []const u8, ln: []const u32, nn: usize, sl: []i32, tm: *std.time.Timer) u64 {
            tm.reset();
            var i: usize = 0;
            while (i < nn) : (i += 1) {
                const n: usize = ln[i];
                sa.suffixArrayCtx(ww.sa_ctx, in[i * astrobwt.SCRATCH ..][0..n], sl[0..n]) catch {};
            }
            return tm.read();
        }
        fn pure(scr: *sa_pure.Scratch, in: []const u8, ln: []const u32, fa: []const u8, nn: usize, sp: []i32, tm: *std.time.Timer) u64 {
            tm.reset();
            var i: usize = 0;
            while (i < nn) : (i += 1) {
                const n: usize = ln[i];
                sa_pure.buildSA(scr, in[i * astrobwt.SCRATCH ..][0..n].ptr, @intCast(n), fa[i * FLAG_CAP ..].ptr, sp[0..n].ptr);
            }
            return tm.read();
        }
    };

    // warmup
    _ = Pass.lib(w, inputs, lens, num_nonces, sa_lib, &timer);
    _ = Pass.pure(sc, inputs, lens, flags_all, num_nonces, sa_pu, &timer);

    var ratios: [R]f64 = undefined;
    var lib_min_ns: u64 = std.math.maxInt(u64);
    var pu_min_ns: u64 = std.math.maxInt(u64);
    var rep: usize = 0;
    while (rep < R) : (rep += 1) {
        const lt = Pass.lib(w, inputs, lens, num_nonces, sa_lib, &timer);
        const pt = Pass.pure(sc, inputs, lens, flags_all, num_nonces, sa_pu, &timer);
        ratios[rep] = @as(f64, @floatFromInt(lt)) / @as(f64, @floatFromInt(pt)); // >1 => pure faster
        if (lt < lib_min_ns) lib_min_ns = lt;
        if (pt < pu_min_ns) pu_min_ns = pt;
    }
    std.sort.pdq(f64, &ratios, {}, struct {
        fn lt(_: void, x: f64, y: f64) bool {
            return x < y;
        }
    }.lt);
    const best = ratios[R - 1];
    const median = ratios[R / 2];
    const lib_us = @as(f64, @floatFromInt(lib_min_ns)) / 1000.0 / fn_nonces;
    const pu_us = @as(f64, @floatFromInt(pu_min_ns)) / 1000.0 / fn_nonces;

    std.debug.print("\n  --- interleaved timing ({d} reps, {d} nonces each) ---\n", .{ R, num_nonces });
    std.debug.print("  libsais       us/hash (min) = {d:.1}\n", .{lib_us});
    std.debug.print("  buildSA(pure) us/hash (min) = {d:.1}\n", .{pu_us});
    std.debug.print("  speedup(lib/pure) per-rep: median={d:.2}x  best={d:.2}x   ({s})\n", .{
        median, best, if (median >= 1.0) "pure FASTER than libsais" else "pure slower than libsais",
    });

    if (mismatches != 0) std.process.exit(1);
}
