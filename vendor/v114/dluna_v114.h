// dluna_v114.h - Stage declarations for v1.14-specific clone work.

#pragma once

#include <cstddef>
#include <cstdint>

namespace deroluna::stages::v114 {

enum class Stage5SaBuildMode {
    Libsais,
    DescriptorArena,
};

bool stage_v114_encode(const uint8_t* in, size_t in_len,
                       uint8_t* out, size_t out_cap, size_t* out_len);

// Raw Stage 4 encode helper for live/bench plumbing. logical_len must fit the
// v1.14 17-bit descriptor arena-index field (<= 0x20000 bytes).
bool stage_v114_encode_with_arena_raw(const uint8_t* data,
                                      uint32_t logical_len,
                                      uint32_t data_len,
                                      const uint8_t* flags,
                                      uint32_t flag_len,
                                      uint8_t* desc_out,
                                      size_t desc_cap,
                                      size_t* desc_len,
                                      uint8_t* int_arena_out,
                                      size_t int_arena_cap,
                                      size_t* int_arena_len);

// Live-only compact variant. Direct singleton records are encoded as trusted
// literals so the helper only materializes arena spans for multi-position runs.
bool stage_v114_encode_compact_raw(const uint8_t* data,
                                   uint32_t logical_len,
                                   uint32_t data_len,
                                   const uint8_t* flags,
                                   uint32_t flag_len,
                                   uint8_t* desc_out,
                                   size_t desc_cap,
                                   size_t* desc_len,
                                   uint8_t* int_arena_out,
                                   size_t int_arena_cap,
                                   size_t* int_arena_len);

bool stage_v114_sa_build_compact_fused_raw(const uint8_t* data,
                                           uint32_t logical_len,
                                           uint32_t data_len,
                                           const uint8_t* flags,
                                           uint32_t flag_len,
                                           uint8_t* out,
                                           size_t out_cap,
                                           size_t* out_len);

bool stage_v114_hash_compact_fused_raw(const uint8_t* data,
                                       uint32_t logical_len,
                                       uint32_t data_len,
                                       const uint8_t* flags,
                                       uint32_t flag_len,
                                       uint8_t out_hash[32]);

bool stage_v114_sa_build(const uint8_t* in, size_t in_len,
                         uint8_t* out, size_t out_cap, size_t* out_len);

bool stage_v114_sa_build_with_mode(const uint8_t* in, size_t in_len,
                                   uint8_t* out, size_t out_cap, size_t* out_len,
                                   Stage5SaBuildMode mode);

// Raw Stage 5 descriptor helper over the same descriptor/int-arena contract.
bool stage_v114_sa_build_descriptor_raw(const uint8_t* data,
                                        uint32_t logical_len,
                                        uint32_t data_len,
                                        const uint8_t* int_arena,
                                        uint32_t int_len,
                                        const uint8_t* desc,
                                        uint32_t desc_len,
                                        uint8_t* out,
                                        size_t out_cap,
                                        size_t* out_len);

// Trusted variant for descriptors generated in-process by the raw Stage 4
// helper. Keeps bounds checks but skips replay-input consistency validation.
bool stage_v114_sa_build_descriptor_trusted_raw(const uint8_t* data,
                                                uint32_t logical_len,
                                                uint32_t data_len,
                                                const uint8_t* int_arena,
                                                uint32_t int_len,
                                                const uint8_t* desc,
                                                uint32_t desc_len,
                                                uint8_t* out,
                                                size_t out_cap,
                                                size_t* out_len);

}  // namespace deroluna::stages::v114
