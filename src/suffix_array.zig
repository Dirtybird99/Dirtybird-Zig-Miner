//! suffix_array.zig -- AstroBWTv3 stage 5: suffix array construction.
//!
//! The hash hashes the suffix array of `sData[0..data_len]`. A suffix array is
//! UNIQUE for a given string, so any correct construction reproduces the exact
//! hash. v1 links libsais (the canonical, fast C implementation the upstream
//! SPSA/Tritonn paths verify against). A pure-Zig SA-IS can drop in behind this
//! same one-line interface later with zero downstream change.

const std = @import("std");

// int32_t libsais(const uint8_t *T, int32_t *SA, int32_t n, int32_t fs, int32_t *freq);
extern fn libsais(T: [*]const u8, SA: [*]i32, n: i32, fs: i32, freq: ?[*]i32) i32;
extern fn libsais_create_ctx() ?*anyopaque;
extern fn libsais_free_ctx(ctx: ?*anyopaque) void;
extern fn libsais_ctx(ctx: ?*anyopaque, T: [*]const u8, SA: [*]i32, n: i32, fs: i32, freq: ?[*]i32) i32;

/// Create a reusable context (per mining thread) to avoid re-allocating libsais's
/// internal buffers on every hash. Returns null on allocation failure.
pub fn createCtx() ?*anyopaque {
    return libsais_create_ctx();
}
pub fn freeCtx(ctx: ?*anyopaque) void {
    libsais_free_ctx(ctx);
}

/// Build the suffix array of `data` into `sa` (sa.len must be >= data.len).
pub fn suffixArray(data: []const u8, sa: []i32) !void {
    std.debug.assert(sa.len >= data.len);
    if (data.len == 0) return;
    const rc = libsais(data.ptr, sa.ptr, @intCast(data.len), 0, null);
    if (rc != 0) return error.SuffixArrayFailed;
}

/// Same, reusing `ctx` from createCtx() for buffer reuse. Byte-identical output.
pub fn suffixArrayCtx(ctx: ?*anyopaque, data: []const u8, sa: []i32) !void {
    std.debug.assert(sa.len >= data.len);
    if (data.len == 0) return;
    const rc = libsais_ctx(ctx, data.ptr, sa.ptr, @intCast(data.len), 0, null);
    if (rc != 0) return error.SuffixArrayFailed;
}

test "suffix array of banana is correct and unique" {
    // suffixes of "banana": a(5) ana(3) anana(1) banana(0) na(4) nana(2)
    const data = "banana";
    var sa: [6]i32 = undefined;
    try suffixArray(data, &sa);
    const expected = [_]i32{ 5, 3, 1, 0, 4, 2 };
    try std.testing.expectEqualSlices(i32, &expected, &sa);
}
