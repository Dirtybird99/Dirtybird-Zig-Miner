//! sa_v114.zig -- the v1.14 descriptor suffix-array (stage 5), ~2x faster than
//! libsais on the Wolf-permuted data and byte-identical to it.
//!
//! It exploits the repeat structure of wolfCompute's output: wolfCompute builds
//! sData by copying the previous 256-byte chunk and editing a small window, and
//! records per-template "group markers" (posData) as it goes. `buildStage5Flags`
//! turns those markers into group-boundary flags; the descriptor SA (compiled C++
//! from the dirtybird reference, `vendor/v114/`) uses the flags to avoid redundant
//! suffix work on the repeated regions. EXACT -- validated bit-for-bit vs the C++
//! oracle over the differential-fuzz corpus.

const std = @import("std");
const astrobwt = @import("astrobwt.zig");

extern fn v114_sa_build_fused(
    data: [*]const u8,
    logical_len: u32,
    data_len_with_tail: u32,
    flags: [*]const u8,
    flag_len: u32,
    out: [*]u8,
    out_cap: usize,
    out_len: *usize,
) c_int;

/// Port of build_v114_stage5_flags: write group-boundary flags, return the count
/// (0 on failure). flags must hold at least (logical_len>>8)+1 bytes.
pub fn buildStage5Flags(markers: []const u16, n_templates: u32, logical_len: u32, flags: []u8) u32 {
    if (logical_len == 0) return 0;
    const flags_len: u32 = (logical_len >> 8) + 1;
    if (flags.len < flags_len) return 0;
    @memset(flags[0..flags_len], 0);
    flags[0] = 1;
    const limit = @min(n_templates, 277);
    var i: u32 = 0;
    while (i < limit) : (i += 1) {
        const pos_data: u32 = markers[i];
        const start_group = pos_data >> 7;
        const group_count = pos_data & 0x7f;
        const boundary = start_group + group_count;
        if (group_count != 0 and boundary > 0 and boundary < flags_len) {
            flags[boundary] = 1;
        }
    }
    return flags_len;
}

/// Build the SA of w.sData[0..data_len] into w.sa (libsais byte layout) using the
/// v1.14 descriptor path. Returns true on success; false => caller uses libsais.
pub fn descriptorSA(w: *astrobwt.Worker) bool {
    if (w.data_len == 0) return false;
    var flags: [320]u8 = undefined;
    const flag_len = buildStage5Flags(&w.template_markers, w.n_templates, w.data_len, &flags);
    if (flag_len == 0) return false;
    const sa_bytes_cap: usize = @as(usize, w.data_len) * 4;
    var out_len: usize = 0;
    const rc = v114_sa_build_fused(
        w.sData[0..].ptr,
        w.data_len,
        w.data_len + 3,
        &flags,
        flag_len,
        @as([*]u8, @ptrCast(&w.sa)),
        sa_bytes_cap,
        &out_len,
    );
    return rc == 1 and out_len == sa_bytes_cap;
}
