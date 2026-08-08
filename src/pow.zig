//! pow.zig -- the complete AstroBWTv3 hash: dluna_hash(input) -> 32-byte output.
//!
//! SHA256 -> Salsa20 expand -> RC4 -> FNV1a -> wolfCompute -> suffix array -> SHA256.
const std = @import("std");
const sha256 = @import("primitives/sha256.zig");
const salsa20 = @import("primitives/salsa20.zig");
const fnv1a = @import("primitives/fnv1a.zig");
const astrobwt = @import("astrobwt.zig");
const sa_fast = @import("sa_fast.zig");
const sa_v114_pure = @import("sa_v114_pure.zig");
const sha_mb = @import("sha256_mb.zig");
const pages = @import("pages.zig");

/// One descriptor-SA scratch per mining THREAD, shared by both lanes of `hash2`.
///
/// `hash2` runs `computeSA(in0, w0)` then `computeSA(in1, w1)` strictly
/// sequentially, and `Scratch` carries nothing across a `buildSA` call: the
/// Builder is constructed fresh with arena_len/runs_len/count at 0, `runs` is
/// strict write-before-read, and `runs_tmp` is fully partitioned by the
/// prefix-summed histogram before any pass reads it. (`arena` IS read past its
/// written end by the unconditional wide copy in materialize, but that garbage
/// only lands forward into a later bucket's territory and is overwritten in
/// order, or past `n` where it is never hashed -- unchanged by sharing.)
/// Reusing one Scratch across different inputs is already the shipped
/// behaviour; `difftest` does it 2000 times.
///
/// Deliberately `threadlocal` rather than an alias between the two Workers'
/// `sa_pure` fields: that would create a "both Workers must be same-thread"
/// invariant enforced nowhere across five Worker construction sites, and
/// violating it would be a silent data race producing wrong hashes. Threadlocal
/// makes cross-thread sharing impossible by construction.
///
/// WHY: halves the per-thread hot working set (~1.84 MiB -> ~943 KB). Measured
/// break point is between 12 and 16 threads, where all 8 E-cores come into play
/// -- an E-cluster shares 4 MB of L2 across 4 cores, so 1.84 MiB/thread thrashes
/// and 943 KB fits. Never freed: mining threads live for the process.
threadlocal var tls_sa_pure: ?*sa_v114_pure.Scratch = null;

// The profiler root opts in at compile time. Normal miner/bench roots do not
// declare this flag, so every timer and counter below is dead-code eliminated.
const profile_enabled = if (@hasDecl(@import("root"), "astrobwt_profile_enabled"))
    @import("root").astrobwt_profile_enabled
else
    false;

pub const ProfileCounters = struct {
    prepare_ns: u64 = 0,
    op_loop_ns: u64 = 0,
    sa_ns: u64 = 0,
    final_hash2_ns: u64 = 0,
};

pub var profile_counters: ProfileCounters = .{};

pub fn resetProfile() void {
    if (profile_enabled) profile_counters = .{};
}

pub const Worker = astrobwt.Worker;

/// Stage-5 SA backend selector -- all PURE ZIG (no C/C++ toolchain).
/// .v114_pure = clean-room descriptor SA (~2.4x libsais, the default);
/// .bucket = 2-byte counting + SIMD comparator; .radix = 8-byte-prefix radix.
/// All are byte-identical (the SA is unique); they differ only in speed.
/// The libsais (.lib) and C++ descriptor (.v114) backends were removed once
/// .v114_pure was validated -- the differential oracle now lives in the
/// standalone dev harnesses (src/sa_v114_check.zig), not the shipped miner.
const SaBackend = enum { bucket, radix, v114_pure };
const SA_BACKEND: SaBackend = .v114_pure;

/// Run the pipeline through stage 5: fills `w.sa[0..w.data_len]` with the suffix
/// array. The final SHA-256 over those bytes is done separately by `hash` (single)
/// or batched via `sha256_mb` (multi-buffer) -- splitting it out lets several
/// independent hashes share a latency-hiding multi-buffer SHA.
pub fn computeSA(input: []const u8, w: *Worker) !void {
    var profile_timer: std.time.Timer = if (profile_enabled)
        (std.time.Timer.start() catch unreachable)
    else
        undefined;
    var scratch: [384]u8 = [_]u8{0} ** 384;

    // 1. SHA256(input) -> scratch[320..352]
    sha256.hash(input, scratch[320..][0..32]);

    // 2. Salsa20/20 keystream(key=scratch[320..352], iv=0) -> scratch[0..256]
    salsa20.expand(scratch[320..][0..32], scratch[0..][0..256]);

    // 3. RC4(key=scratch[0..256]) over scratch[0..256], in place
    w.key.setKey(scratch[0..256]);
    w.key.process(scratch[0..256], scratch[0..256]);

    // 4. FNV1a-64 seed
    w.lhash = fnv1a.hash256(scratch[0..256]);
    w.prev_lhash = w.lhash;
    w.tries = 0;
    @memcpy(w.sData[0..256], scratch[0..256]);
    if (profile_enabled) profile_counters.prepare_ns += profile_timer.lap();

    // 5. wolfCompute -> sData[0..data_len]
    astrobwt.wolfCompute(w);
    @memset(w.sData[w.data_len..][0..16], 0);
    if (profile_enabled) profile_counters.op_loop_ns += profile_timer.lap();

    // 6. suffix array (stage 5) -- byte-identical to libsais (validated bit-for-bit
    // vs the C++ oracle over the fuzz corpus). Backend chosen for cache behavior
    // under 10-thread load; the SA is mathematically unique so the hash is identical.
    switch (SA_BACKEND) {
        .v114_pure => {
            // Pure-Zig clean-room descriptor SA (~2.4x libsais, no C/C++). Falls
            // back to the pure sa_fast bucket sort if the build declines (only on
            // degenerate n==0, which never occurs in mining).
            if (tls_sa_pure == null) {
                // Prefer a large page. The touched part of Scratch spans ~145 4 KB
                // pages against Gracemont's 48-entry L1 DTLB, so on the E-cores --
                // where the 12->16 thread cliff lives -- the walk is re-done on
                // every hash. `enableLockMemoryPrivilege()` runs in main before any
                // mining thread spawns, so the privilege is already in effect here.
                // Falls back to 4 KB pages when the privilege is absent or physical
                // memory is too fragmented (GetLastError 1314 / 1450): the miner
                // must still run on a machine that grants neither.
                if (pages.allocHugeBacking(@sizeOf(sa_v114_pure.Scratch))) |backing| {
                    tls_sa_pure = @ptrCast(@alignCast(backing.bytes.ptr));
                } else {
                    tls_sa_pure = std.heap.page_allocator.create(sa_v114_pure.Scratch) catch return error.OutOfMemory;
                }
            }
            if (!sa_v114_pure.build(tls_sa_pure.?, w.sData[0..].ptr, w.data_len, &w.template_markers, w.n_templates, w.sa[0..].ptr)) {
                if (w.sa_scratch == null) w.sa_scratch = std.heap.page_allocator.create(sa_fast.Scratch) catch return error.OutOfMemory;
                sa_fast.bucketSortSA(w.sa_scratch.?, w.sData[0..w.data_len].ptr, w.sa[0..w.data_len].ptr, w.data_len);
            }
        },
        .bucket => {
            if (w.sa_scratch == null) w.sa_scratch = std.heap.page_allocator.create(sa_fast.Scratch) catch return error.OutOfMemory;
            sa_fast.bucketSortSA(w.sa_scratch.?, w.sData[0..w.data_len].ptr, w.sa[0..w.data_len].ptr, w.data_len);
        },
        .radix => {
            if (w.sa_radix == null) w.sa_radix = std.heap.page_allocator.create(sa_fast.Radix8) catch return error.OutOfMemory;
            sa_fast.radixSortSA8(w.sa_radix.?, w.sData[0..w.data_len].ptr, w.sa[0..w.data_len].ptr, w.data_len);
        },
    }
    if (profile_enabled) profile_counters.sa_ns += profile_timer.lap();
}

/// SA bytes (the message hashed in stage 7) for a worker after computeSA.
pub inline fn saBytes(w: *Worker) []const u8 {
    return std.mem.sliceAsBytes(w.sa[0..w.data_len]);
}

/// Compute the AstroBWTv3 hash of `input` into `out`, using scratch `w`.
pub fn hash(input: []const u8, out: *[32]u8, w: *Worker) !void {
    try computeSA(input, w);
    // 7. SHA256 over the SA bytes -- pure-SSE SHA-NI (sha256_mb), ~0.86x std's time
    //    single-stream, byte-exact. The batched 2-nonce path (hash2) is faster still.
    sha_mb.hash1(saBytes(w), out);
}

/// Batched 2-nonce hash: builds both suffix arrays, then hashes them with a
/// multi-buffer SHA-256 (latency-hiding) -- the SHA stage is ~24% of the hash and
/// single-stream SHA-NI is latency-bound, so 2-way buys most of a 2x there.
/// Both suffix arrays are built, then hashed through the multi-buffer SHA.
pub fn hash2(in0: []const u8, in1: []const u8, out0: *[32]u8, out1: *[32]u8, w0: *Worker, w1: *Worker) !void {
    try computeSA(in0, w0);
    try computeSA(in1, w1);
    var profile_timer: std.time.Timer = if (profile_enabled)
        (std.time.Timer.start() catch unreachable)
    else
        undefined;
    // Batched 2-way multi-buffer SHA-NI: interleaves the two latency-bound rnds2
    // chains so the OoO engine overlaps them (~1.3x throughput on Raptor Cove).
    sha_mb.hash2(saBytes(w0), saBytes(w1), out0, out1);
    if (profile_enabled) profile_counters.final_hash2_ns += profile_timer.read();
}

test "KAT: pow(\"a\")" {
    const w = try std.testing.allocator.create(Worker);
    defer std.testing.allocator.destroy(w);
    w.* = .{};
    defer w.deinitSA();
    var out: [32]u8 = undefined;
    try hash("a", &out, w);
    var hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{s}", .{std.fmt.fmtSliceHexLower(&out)}) catch unreachable;
    try std.testing.expectEqualStrings(
        "54e2324ddacc3f0383501a9e5760f85d63e9bc6705e9124ca7aef89016ab81ea",
        &hex,
    );
}

// Regression: nonces whose final wolfCompute data byte is 0x00. A trailing-zero
// strip on data_len (formerly in astrobwt.zig / oracle.cpp) shortens the suffix
// array and diverges the hash from the DERO daemon on ~1% of nonces -- but the KAT
// and the C++ oracle both ended in nonzero bytes / shared the strip, so nothing
// caught it. These three 48-byte blobs hit the zero-final-byte case; the expected
// hashes are the canonical daemon values (github.com/deroproject/derohe
// astrobwtv3.AstroBWTv3, cross-checked over 20k inputs), NOT the local oracle.
test "KAT: zero-final-byte blobs match the DERO daemon" {
    const Vec = struct { in: []const u8, out: []const u8 };
    const vectors = [_]Vec{
        .{ .in = "c7376358448588908062349033c98868893c093683ba9a3f7dca1b9e19c946d3da8620f10e74289cd197164c145ff7e5", .out = "434c8f90a504f2d59fe3e935ba57a7bca0e5471913d5eff13b3f9797dc187d51" },
        .{ .in = "6b3c191e1448516deac2ea4126f9a5cad6f2f7150f9847bd7b745ba99fddd8373e096c79c600d2cc087701ee8123f2d7", .out = "fa70f91840fa93383e1fad3612e210566427355438f2e6a8b68fc1f7f0a91658" },
        .{ .in = "789e9f68144e6b62546c8058d53cfd2e9bd0ca2ccd758313d7d70d056cd6b9a63fd9a2148c16dbf6e9ea6515d62051c3", .out = "b4f6fae9dbfafd28a43361eaf2f907e4c885c416b4f0535978f17eea26028da9" },
    };
    const w = try std.testing.allocator.create(Worker);
    defer std.testing.allocator.destroy(w);
    w.* = .{};
    defer w.deinitSA();
    for (vectors) |v| {
        var blob: [48]u8 = undefined;
        _ = try std.fmt.hexToBytes(&blob, v.in);
        var out: [32]u8 = undefined;
        try hash(&blob, &out, w);
        var hex: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&hex, "{s}", .{std.fmt.fmtSliceHexLower(&out)}) catch unreachable;
        try std.testing.expectEqualStrings(v.out, &hex);
    }
}
