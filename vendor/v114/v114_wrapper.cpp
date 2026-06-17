// v114_wrapper.cpp -- expose the v1.14 descriptor suffix-array build to Zig.
//
// The descriptor SA exploits the repeat structure recorded by wolfCompute (the
// per-template group markers -> `flags`) to build the EXACT suffix array ~2x
// faster than libsais on the (period-256 self-similar) Wolf-permuted data. It is
// byte-identical to libsais (the dirtybird source verifies this via memcmp).
#include "dluna_v114.h"
#include <cstdint>
#include <cstddef>

// Returns 1 on success (out filled with logical_len*4 SA bytes), 0 on failure
// (caller falls back to libsais). `out_len` receives the bytes written.
extern "C" int v114_sa_build_fused(const uint8_t* data,
                                   uint32_t logical_len,
                                   uint32_t data_len_with_tail,
                                   const uint8_t* flags,
                                   uint32_t flag_len,
                                   uint8_t* out,
                                   size_t out_cap,
                                   size_t* out_len) {
    return deroluna::stages::v114::stage_v114_sa_build_compact_fused_raw(
               data, logical_len, data_len_with_tail,
               flags, flag_len, out, out_cap, out_len)
               ? 1
               : 0;
}
