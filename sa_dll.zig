//! sa_dll.zig -- expose the v1.14 descriptor suffix array (+ libsais fallback) as a
//! Zig-built Windows DLL, so the Rust miner can link the SA exactly as the Zig miner
//! builds it: clang-19 + PGO + `-flto`, whole-program-LTO'd by Zig's own bundled lld.
//!
//! The C definitions (v114_wrapper.cpp / libsais.c) are pulled in via addSaDeps() in
//! build.zig and compiled to LTO bitcode; this shim re-exports them under `dero_`-
//! prefixed names (the original names stay internal to the DLL, so there is no symbol
//! collision and lld is free to inline the C body into the thin wrapper). The Rust side
//! maps these back via `#[link_name]` under the `sa_dll` cfg. One coarse call per hash,
//! so the wrapper indirection is unmeasurable.

extern fn v114_sa_build_fused(
    data: [*c]const u8,
    logical_len: u32,
    data_len_with_tail: u32,
    flags: [*c]const u8,
    flag_len: u32,
    out: [*c]u8,
    out_cap: usize,
    out_len: [*c]usize,
) c_int;

extern fn libsais(t: [*c]const u8, sa: [*c]i32, n: i32, fs: i32, freq: [*c]i32) c_int;

export fn dero_v114_sa_build_fused(
    data: [*c]const u8,
    logical_len: u32,
    data_len_with_tail: u32,
    flags: [*c]const u8,
    flag_len: u32,
    out: [*c]u8,
    out_cap: usize,
    out_len: [*c]usize,
) c_int {
    return v114_sa_build_fused(data, logical_len, data_len_with_tail, flags, flag_len, out, out_cap, out_len);
}

export fn dero_libsais(t: [*c]const u8, sa: [*c]i32, n: i32, fs: i32, freq: [*c]i32) c_int {
    return libsais(t, sa, n, fs, freq);
}
