//! Aggregate test root. Pulls in every module's tests.
const std = @import("std");

test {
    _ = @import("primitives/sha256.zig");
    _ = @import("primitives/salsa20.zig");
    _ = @import("primitives/rc4.zig");
    _ = @import("primitives/fnv1a.zig");
    _ = @import("primitives/xxhash64.zig");
    _ = @import("primitives/siphash.zig");
    _ = @import("suffix_array.zig");
    _ = @import("sa_fast.zig");
    _ = @import("testvec.zig");
    _ = @import("stage_parity.zig");
    _ = @import("astrobwt.zig");
    _ = @import("pow.zig");
    _ = @import("pow_parity.zig");
    _ = @import("difficulty.zig");
    _ = @import("state.zig");
    _ = @import("miner.zig");
    _ = @import("net.zig");
    _ = @import("pages.zig");
    _ = @import("cpu_features.zig");
    _ = @import("console.zig");
    _ = @import("main.zig");
}
