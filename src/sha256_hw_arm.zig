//! ARMv8 crypto-extension SHA-256, isolated in its own compilation unit.
//!
//! There is deliberately nothing architecture-specific below. std's Sha256
//! already carries a NEON `sha256h`/`sha256h2`/`sha256su0`/`sha256su1`
//! implementation, comptime-gated on the `.sha2` CPU feature; all this file
//! does is get compiled for a target that HAS that feature, which turns the
//! ordinary call underneath into the hardware path.
//!
//! Why a separate file at all: Zig has no per-function target features (no
//! `#[target_feature]` / `__attribute__((target))`), and CPU features are a
//! property of the whole compilation unit. The shipped `aarch64-linux-musl`
//! target resolves to the `generic` model, which has `.neon` but not `.sha2` --
//! so the miner has been running software SHA-256 on every ARM device. Giving
//! just this object `+sha2` (see `addArmSha` in build.zig) keeps the rest of the
//! binary at baseline, so one artifact still runs on ARMv8 cores that lack the
//! crypto extension.
//!
//! CONTRACT: call only when the CPU is known to have the extension. sha256_mb
//! guards every call with a runtime HWCAP probe; reaching this on a core
//! without the extension is SIGILL.

const std = @import("std");

/// Hash `in_ptr[0..in_len]` into `out`. C ABI so the baseline unit can declare
/// it `extern` without the two modules sharing a Zig type.
export fn dbzSha256ArmV8(in_ptr: [*]const u8, in_len: usize, out: *[32]u8) void {
    std.crypto.hash.sha2.Sha256.hash(in_ptr[0..in_len], out, .{});
}
