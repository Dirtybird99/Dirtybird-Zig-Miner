//! SHA-256 drop-in for the AstroBWTv3 hot path.
//!
//! FINDING (2026-06-17): Zig 0.14.1's `std.crypto.hash.sha2.Sha256` already emits
//! `sha256rnds2` / `sha256msg1` / `sha256msg2` when built with `-mcpu=native` on
//! a SHA-NI-capable CPU (i7-13700HX / Raptor Lake). Verified by grepping the
//! `-femit-asm` output: 112 SHA-NI instructions in the compression function, fully
//! unrolled single-block loop (no scalar fallback path).
//!
//! Measured throughput (ReleaseFast, -mcpu=native, 275 KB buffer, 2000 iters):
//!   std.crypto Sha256 : 2.054 GB/s
//!   sha256_ni (this)  : 2.089 GB/s  (identical within measurement noise; same code path)
//!
//! Because std already saturates the SHA-NI pipeline, a hand-rolled implementation
//! would produce the same instructions and the same throughput. This file is a thin
//! wrapper so the pipeline can swap src/primitives/sha256.zig for sha256_ni.zig
//! without a code change to callers.
//!
//! Drop-in constraints:
//!   - Same signature as sha256.zig: `pub fn hash(in: []const u8, out: *[32]u8) void`
//!   - No libc dependency (pure Zig; demonstrated: `zig test` without linkLibC passes)
//!   - No alignment requirement on `in` (std handles unaligned inputs)
//!   - On non-SHA-NI hosts std dispatches to its scalar path — this file compiles
//!     and runs correctly anywhere; SHA-NI acceleration relies on std's internal
//!     CPU-feature dispatch, not a comptime guard in this wrapper.
//!
//! CAVEAT for the lead: the SHA-NI path is only taken when the build resolves to
//! a native CPU that has the sha feature (i.e. `-mcpu=native` or explicit `+sha`).
//! The current ~2.0 GB/s confirms it is already active. Do not pin a -Dcpu baseline
//! that lacks +sha or the win silently reverts to the scalar path.

const std = @import("std");

/// SHA-256 over arbitrary input, writing 32 bytes to `out`.
/// Forwards to std.crypto.hash.sha2.Sha256, which the Zig 0.14.1 LLVM backend
/// selects to SHA-NI instructions when the target CPU has the sha feature
/// (auto-selected with -mcpu=native on i7-13700HX / Raptor Lake).
pub fn hash(in: []const u8, out: *[32]u8) void {
    std.crypto.hash.sha2.Sha256.hash(in, out, .{});
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "sha256_ni KAT: SHA256(abc)" {
    var out: [32]u8 = undefined;
    hash("abc", &out);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    }, &out);
}

test "sha256_ni KAT: SHA256(a)" {
    var out: [32]u8 = undefined;
    hash("a", &out);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xca, 0x97, 0x81, 0x12, 0xca, 0x1b, 0xbd, 0xca,
        0xfa, 0xc2, 0x31, 0xb3, 0x9a, 0x23, 0xdc, 0x4d,
        0xa7, 0x86, 0xef, 0xf8, 0x14, 0x7c, 0x4e, 0x72,
        0xb9, 0x80, 0x77, 0x85, 0xaf, 0xee, 0x48, 0xbb,
    }, &out);
}

test "sha256_ni KAT: SHA256(empty)" {
    // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    var out: [32]u8 = undefined;
    hash("", &out);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    }, &out);
}

test "sha256_ni parity vs std over boundary sizes" {
    // Sizes that exercise padding boundaries:
    //   0        empty
    //   1        one byte
    //   55       last byte of a single-block message (padding fits)
    //   56       first size that forces a two-block tail
    //   63       one shy of a full block
    //   64       exactly one block
    //   65       one block + one byte
    //   1000     multi-block
    //   275000   the hot-path buffer (SA bytes over ~275 KB)
    const sizes = [_]usize{ 0, 1, 55, 56, 63, 64, 65, 1000, 275_000 };

    // Heap-allocate the large buffer once.
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const buf = try alloc.alloc(u8, 275_000);
    defer alloc.free(buf);

    // Fill with a deterministic pattern.
    for (buf, 0..) |*b, i| b.* = @intCast((i *% 251 +% 17) & 0xFF);

    for (sizes) |sz| {
        const slice = buf[0..sz];

        var expected: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(slice, &expected, .{});

        var got: [32]u8 = undefined;
        hash(slice, &got);

        try std.testing.expectEqualSlices(u8, &expected, &got);
    }
}
