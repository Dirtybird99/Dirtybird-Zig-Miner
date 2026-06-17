// v114_stubs.cpp - v1.14-specific replay stages.

#include "dluna_v114.h"

#include "libsais.h"

#include <openssl/sha.h>

#include <algorithm>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <limits>
#include <vector>

namespace deroluna::stages::v114 {

namespace {

#pragma pack(push, 1)
struct Stage4InputHeader {
    char magic[8];
    uint32_t version;
    uint32_t logical_len;
    uint32_t data_len;
    uint32_t flag_len;
    uint32_t reserved;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Stage5InputHeader {
    char magic[8];
    uint32_t version;
    uint32_t logical_len;
    uint32_t data_len;
    uint32_t int_len;
    uint32_t desc_len;
};
#pragma pack(pop)

static_assert(sizeof(Stage4InputHeader) == 28, "Stage4InputHeader layout");
static_assert(sizeof(Stage5InputHeader) == 28, "Stage5InputHeader layout");

constexpr char kStage4Magic[8] = {'D', 'L', 'S', '4', 'I', 'N', 0, 0};
constexpr char kStage5Magic[8] = {'D', 'L', 'S', '5', 'I', 'N', 0, 0};
constexpr uint32_t kStage4Version = 1;
constexpr uint32_t kStage5Version = 1;
constexpr uint32_t kDescriptorArenaIndexCount = 0x20000u;
constexpr uint32_t kStage4MaxGroupCount = kDescriptorArenaIndexCount >> 8;
constexpr uint32_t kStage4ShortRunMax = 25;

bool env_flag_enabled(const char* name) {
    const char* value = std::getenv(name);
    return value && value[0] == '1' && value[1] == '\0';
}

uint64_t stage5_prof_rdtsc() {
#if defined(__x86_64__) || defined(_M_X64)
    return __builtin_ia32_rdtsc();
#else
    return 0;
#endif
}

struct FusedStage5Profile {
    uint64_t calls = 0;
    uint64_t emit = 0;
    uint64_t sort = 0;
    uint64_t single = 0;
    uint64_t literal_group = 0;
    uint64_t two_run = 0;
    uint64_t prepare = 0;
    uint64_t merge = 0;
    uint64_t output = 0;
    uint64_t total = 0;
    uint64_t runs = 0;
    uint64_t arena = 0;
    uint64_t equal_groups = 0;
    uint64_t fallback_groups = 0;
    uint64_t single_runs = 0;
    uint64_t single_literal_runs = 0;
    uint64_t single_arena_runs = 0;
    uint64_t single_positions = 0;
    uint64_t single_arena_positions = 0;
    uint64_t single_adjacent_arena_runs = 0;
    uint64_t single_adjacent_arena_positions = 0;
    uint64_t emit_appends = 0;
    uint64_t emit_literal_appends = 0;
    uint64_t emit_arena_appends = 0;
    uint64_t emit_positions = 0;
    uint64_t emit_arena_positions = 0;
    uint64_t emit_run_capacity = 0;
    uint64_t emit_arena_capacity = 0;
};

bool fused_stage5_profile_enabled() {
    static const bool enabled = env_flag_enabled("DLUNA_PROFILE_STAGE5_FUSED");
    return enabled;
}

FusedStage5Profile& fused_stage5_profile() {
    static thread_local FusedStage5Profile profile;
    return profile;
}

void fused_stage5_profile_maybe_flush(FusedStage5Profile* profile) {
    if (!profile || profile->calls < 1024u) return;
    const uint64_t calls = profile->calls;
    std::fprintf(stderr,
                 "[FUSED_PROF calls=%llu emit=%llu sort=%llu single=%llu literal_group=%llu two_run=%llu prepare=%llu merge=%llu output=%llu total=%llu runs=%llu arena=%llu equal_groups=%llu fallback_groups=%llu single_runs=%llu single_literal_runs=%llu single_arena_runs=%llu single_positions=%llu single_arena_positions=%llu single_adjacent_arena_runs=%llu single_adjacent_arena_positions=%llu emit_appends=%llu emit_literal_appends=%llu emit_arena_appends=%llu emit_positions=%llu emit_arena_positions=%llu emit_run_capacity=%llu emit_arena_capacity=%llu]\n",
                 (unsigned long long)calls,
                 (unsigned long long)(profile->emit / calls),
                 (unsigned long long)(profile->sort / calls),
                 (unsigned long long)(profile->single / calls),
                 (unsigned long long)(profile->literal_group / calls),
                 (unsigned long long)(profile->two_run / calls),
                 (unsigned long long)(profile->prepare / calls),
                 (unsigned long long)(profile->merge / calls),
                 (unsigned long long)(profile->output / calls),
                 (unsigned long long)(profile->total / calls),
                 (unsigned long long)(profile->runs / calls),
                 (unsigned long long)(profile->arena / calls),
                 (unsigned long long)(profile->equal_groups / calls),
                 (unsigned long long)(profile->fallback_groups / calls),
                 (unsigned long long)(profile->single_runs / calls),
                 (unsigned long long)(profile->single_literal_runs / calls),
                 (unsigned long long)(profile->single_arena_runs / calls),
                 (unsigned long long)(profile->single_positions / calls),
                 (unsigned long long)(profile->single_arena_positions / calls),
                 (unsigned long long)(profile->single_adjacent_arena_runs / calls),
                 (unsigned long long)(profile->single_adjacent_arena_positions / calls),
                 (unsigned long long)(profile->emit_appends / calls),
                 (unsigned long long)(profile->emit_literal_appends / calls),
                 (unsigned long long)(profile->emit_arena_appends / calls),
                 (unsigned long long)(profile->emit_positions / calls),
                 (unsigned long long)(profile->emit_arena_positions / calls),
                 (unsigned long long)(profile->emit_run_capacity / calls),
                 (unsigned long long)(profile->emit_arena_capacity / calls));
    *profile = FusedStage5Profile{};
}

struct Stage4InputView {
    uint32_t logical_len = 0;
    uint32_t data_len = 0;
    uint32_t flag_len = 0;
    const uint8_t* flags = nullptr;
    const uint8_t* data = nullptr;
};

struct Stage5InputView {
    uint32_t logical_len = 0;
    uint32_t data_len = 0;
    uint32_t int_len = 0;
    uint32_t desc_len = 0;
    const uint8_t* data = nullptr;
    const uint8_t* int_arena = nullptr;
    const uint8_t* desc = nullptr;
};

bool parse_stage4_input(const uint8_t* in, size_t in_len, Stage4InputView* view) {
    if (!in || !view || in_len < sizeof(Stage4InputHeader)) return false;

    Stage4InputHeader h{};
    std::memcpy(&h, in, sizeof(h));
    if (std::memcmp(h.magic, kStage4Magic, sizeof(h.magic)) != 0) return false;
    if (h.version != kStage4Version) return false;
    if (h.logical_len == 0 || h.logical_len > kDescriptorArenaIndexCount ||
        h.data_len < h.logical_len) return false;

    const uint64_t need = static_cast<uint64_t>(sizeof(Stage4InputHeader)) +
                          h.flag_len + h.data_len;
    if (need != in_len) return false;

    const uint32_t group_limit = h.logical_len >> 8;
    if (h.flag_len <= group_limit) return false;

    view->logical_len = h.logical_len;
    view->data_len = h.data_len;
    view->flag_len = h.flag_len;
    view->flags = in + sizeof(Stage4InputHeader);
    view->data = view->flags + h.flag_len;
    return true;
}

bool parse_stage5_input(const uint8_t* in, size_t in_len, Stage5InputView* view) {
    if (!in || !view || in_len < sizeof(Stage5InputHeader)) return false;

    Stage5InputHeader h{};
    std::memcpy(&h, in, sizeof(h));
    if (std::memcmp(h.magic, kStage5Magic, sizeof(h.magic)) != 0) return false;
    if (h.version != kStage5Version) return false;
    if (h.logical_len == 0 || h.data_len < h.logical_len) return false;

    const uint64_t need = static_cast<uint64_t>(sizeof(Stage5InputHeader)) +
                          h.data_len + h.int_len + h.desc_len;
    if (need != in_len) return false;

    view->logical_len = h.logical_len;
    view->data_len = h.data_len;
    view->int_len = h.int_len;
    view->desc_len = h.desc_len;
    view->data = in + sizeof(Stage5InputHeader);
    view->int_arena = view->data + h.data_len;
    view->desc = view->int_arena + h.int_len;
    return true;
}

uint32_t load24_padded(const Stage4InputView& view, uint32_t pos) {
    uint32_t v = 0;
    if (pos < view.data_len) {
        v |= static_cast<uint32_t>(view.data[pos]);
    }
    if (pos + 1 < view.data_len) {
        v |= static_cast<uint32_t>(view.data[pos + 1]) << 8;
    }
    if (pos + 2 < view.data_len) {
        v |= static_cast<uint32_t>(view.data[pos + 2]) << 16;
    }
    return v;
}

uint32_t load24_unchecked(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16);
}

bool has_load24_padding(const Stage4InputView& view) {
    return view.data_len >= view.logical_len + 2u;
}

uint32_t load24_fast(const Stage4InputView& view, uint32_t pos, bool padded) {
    return padded ? load24_unchecked(view.data + pos)
                  : load24_padded(view, pos);
}

uint32_t load24_padded(const Stage5InputView& view, uint32_t pos) {
    uint32_t v = 0;
    if (pos < view.data_len) {
        v |= static_cast<uint32_t>(view.data[pos]);
    }
    if (pos + 1 < view.data_len) {
        v |= static_cast<uint32_t>(view.data[pos + 1]) << 8;
    }
    if (pos + 2 < view.data_len) {
        v |= static_cast<uint32_t>(view.data[pos + 2]) << 16;
    }
    return v;
}

uint32_t read_u32_le(const uint8_t* in) {
    return static_cast<uint32_t>(in[0]) |
           (static_cast<uint32_t>(in[1]) << 8) |
           (static_cast<uint32_t>(in[2]) << 16) |
           (static_cast<uint32_t>(in[3]) << 24);
}

void write_u32_le(uint8_t* out, uint32_t v) {
    out[0] = static_cast<uint8_t>(v);
    out[1] = static_cast<uint8_t>(v >> 8);
    out[2] = static_cast<uint8_t>(v >> 16);
    out[3] = static_cast<uint8_t>(v >> 24);
}

int compare_key3(uint32_t a, uint32_t b) {
    for (uint32_t i = 0; i < 3; ++i) {
        const uint32_t av = (a >> (i * 8u)) & 0xffu;
        const uint32_t bv = (b >> (i * 8u)) & 0xffu;
        if (av != bv) return av < bv ? -1 : 1;
    }
    return 0;
}

uint32_t stage5_radix_order_key(uint32_t key) {
    return ((key & 0x0000ffu) << 16) |
           (key & 0x00ff00u) |
           ((key & 0xff0000u) >> 16);
}

bool init_identity_arena(uint8_t* int_arena, size_t int_arena_cap,
                         uint32_t logical_len, size_t* int_arena_len) {
    const uint64_t needed = static_cast<uint64_t>(logical_len) * 4u;
    if (needed > std::numeric_limits<size_t>::max() || int_arena_cap < needed) {
        return false;
    }
    for (uint32_t pos = 0; pos < logical_len; ++pos) {
        write_u32_le(int_arena + static_cast<size_t>(pos) * 4u, pos);
    }
    *int_arena_len = static_cast<size_t>(needed);
    return true;
}

bool write_arena_pos(uint8_t* int_arena, size_t int_arena_cap,
                     uint32_t index, uint32_t pos) {
    const uint64_t off = static_cast<uint64_t>(index) * 4u;
    if (off > int_arena_cap || int_arena_cap - static_cast<size_t>(off) < 4u) {
        return false;
    }
    write_u32_le(int_arena + static_cast<size_t>(off), pos);
    return true;
}

std::vector<uint32_t>& stage4_order_scratch() {
    static thread_local std::vector<uint32_t>* order = nullptr;
    if (!order) order = new std::vector<uint32_t>;
    return *order;
}

void emit_direct_records(const Stage4InputView& view, uint32_t start, uint32_t count,
                         uint8_t* out, size_t* record_count) {
    for (uint32_t rel = 0; rel < count; ++rel) {
        const uint32_t pos = start + rel;
        const size_t off = (*record_count) * 8;
        write_u32_le(out + off, load24_padded(view, pos));
        write_u32_le(out + off + 4, 0x00020000u + pos);
        ++(*record_count);
    }
}

bool write_record(uint8_t* out, size_t out_cap, size_t* record_count,
                  uint32_t key, uint32_t packed);

bool emit_compact_literal_records(const Stage4InputView& view, uint32_t start,
                                  uint32_t count, uint8_t* out, size_t out_cap,
                                  size_t* record_count,
                                  bool count1_singletons,
                                  uint8_t* int_arena,
                                  size_t int_arena_cap,
                                  uint32_t* arena_entries) {
    const bool padded = has_load24_padding(view);
    for (uint32_t rel = 0; rel < count; ++rel) {
        const uint32_t pos = start + rel;
        uint32_t packed = pos;
        if (count1_singletons) {
            if (!int_arena || !arena_entries ||
                *arena_entries >= kDescriptorArenaIndexCount) {
                return false;
            }
            const uint32_t arena_index = *arena_entries;
            if (!write_arena_pos(int_arena, int_arena_cap, arena_index, pos)) {
                return false;
            }
            *arena_entries = arena_index + 1u;
            packed = 0x00020000u + arena_index;
        }
        if (!write_record(out, out_cap, record_count,
                          load24_fast(view, pos, padded), packed)) {
            return false;
        }
    }
    return true;
}

int compare_suffixes(const Stage4InputView& view, uint32_t a, uint32_t b) {
    if (a == b) return 0;
    while (a < view.logical_len && b < view.logical_len) {
        const uint8_t av = view.data[a];
        const uint8_t bv = view.data[b];
        if (av != bv) return av < bv ? -1 : 1;
        ++a;
        ++b;
    }
    if (a == view.logical_len && b == view.logical_len) return 0;
    return a == view.logical_len ? -1 : 1;
}

bool write_record(uint8_t* out, size_t out_cap, size_t* record_count,
                  uint32_t key, uint32_t packed) {
    const size_t off = (*record_count) * 8u;
    if (off > out_cap || out_cap - off < 8u) return false;
    write_u32_le(out + off, key);
    write_u32_le(out + off + 4u, packed);
    ++(*record_count);
    return true;
}

bool emit_full_group_run(const Stage4InputView& view, uint32_t start_group,
                         uint32_t end_group, uint8_t* out, size_t out_cap,
                         size_t* record_count, uint8_t* int_arena = nullptr,
                         size_t int_arena_cap = 0) {
    const uint32_t group_count = end_group - start_group;
    if (group_count == 0) return true;

    const uint32_t base = start_group << 8;
    if (group_count == 1) {
        const size_t before = *record_count;
        emit_direct_records(view, base, 256, out, record_count);
        return ((*record_count - before) == 256) && ((*record_count) * 8u <= out_cap);
    }

    std::vector<uint32_t>& order = stage4_order_scratch();
    order.resize(group_count);
    for (uint32_t chunk = 0; chunk < group_count; ++chunk) {
        order[chunk] = base + (chunk << 8) + 255u;
    }
    std::sort(order.begin(), order.end(),
              [&](uint32_t a, uint32_t b) {
                  return compare_suffixes(view, a, b) < 0;
              });

    for (int rel = 255; rel >= 0; --rel) {
        const uint32_t arena_base =
            base + static_cast<uint32_t>(255 - rel) * group_count;
        if (int_arena) {
            for (uint32_t i = 0; i < group_count; ++i) {
                if (!write_arena_pos(int_arena, int_arena_cap,
                                     arena_base + i, order[i])) {
                    return false;
                }
            }
        }

        uint32_t group_start = 0;
        while (group_start < group_count) {
            const uint32_t key = load24_padded(view, order[group_start]);
            uint32_t group_end = group_start + 1;
            while (group_end < group_count &&
                   load24_padded(view, order[group_end]) == key) {
                ++group_end;
            }

            const uint32_t arena_index = arena_base + group_start;
            const uint32_t packed = ((group_end - group_start) << 17) + arena_index;
            if (!write_record(out, out_cap, record_count, key, packed)) return false;
            group_start = group_end;
        }

        if (rel > 0) {
            for (uint32_t i = 0; i < group_count; ++i) {
                --order[i];
            }
            for (uint32_t i = 1; i < group_count; ++i) {
                const uint32_t pos = order[i];
                const uint8_t key = view.data[pos];
                uint32_t j = i;
                while (j > 0 && view.data[order[j - 1u]] > key) {
                    order[j] = order[j - 1u];
                    --j;
                }
                order[j] = pos;
            }
        }
    }

    return true;
}

bool append_compact_arena_positions(uint8_t* int_arena, size_t int_arena_cap,
                                    const std::vector<uint32_t>& order,
                                    uint32_t first, uint32_t count,
                                    uint32_t* arena_entries) {
    if (!int_arena || !arena_entries) return false;
    if (*arena_entries > kDescriptorArenaIndexCount ||
        count > kDescriptorArenaIndexCount - *arena_entries) {
        return false;
    }

    for (uint32_t i = 0; i < count; ++i) {
        if (!write_arena_pos(int_arena, int_arena_cap,
                             *arena_entries + i, order[first + i])) {
            return false;
        }
    }
    *arena_entries += count;
    return true;
}

bool append_compact_arena_positions_fixed(uint8_t* int_arena, size_t int_arena_cap,
                                          const uint32_t* order,
                                          uint32_t first, uint32_t count,
                                          uint32_t* arena_entries) {
    if (!int_arena || !arena_entries || !order) return false;
    if (*arena_entries > kDescriptorArenaIndexCount ||
        count > kDescriptorArenaIndexCount - *arena_entries) {
        return false;
    }

    for (uint32_t i = 0; i < count; ++i) {
        if (!write_arena_pos(int_arena, int_arena_cap,
                             *arena_entries + i, order[first + i])) {
            return false;
        }
    }
    *arena_entries += count;
    return true;
}

bool write_compact_order_group(uint8_t* out, size_t out_cap,
                               size_t* record_count, uint32_t key,
                               const uint32_t* order, uint32_t first,
                               uint32_t count, uint8_t* int_arena,
                               size_t int_arena_cap, uint32_t* arena_entries,
                               bool count1_singletons) {
    uint32_t packed = order[first];
    if (count > 1 || count1_singletons) {
        const uint32_t arena_index = *arena_entries;
        if (!append_compact_arena_positions_fixed(
                int_arena, int_arena_cap, order, first, count, arena_entries)) {
            return false;
        }
        packed = (count << 17) + arena_index;
    }
    return write_record(out, out_cap, record_count, key, packed);
}

void sort_stage4_suffix_order_small(const Stage4InputView& view,
                                    uint32_t* order, uint32_t count) {
    for (uint32_t i = 1; i < count; ++i) {
        const uint32_t pos = order[i];
        uint32_t j = i;
        while (j > 0 && compare_suffixes(view, pos, order[j - 1u]) < 0) {
            order[j] = order[j - 1u];
            --j;
        }
        order[j] = pos;
    }
}

bool emit_full_group_run_compact_two(const Stage4InputView& view,
                                     uint32_t start_group, uint8_t* out,
                                     size_t out_cap, size_t* record_count,
                                     uint8_t* int_arena,
                                     size_t int_arena_cap,
                                     uint32_t* arena_entries,
                                     bool count1_singletons) {
    const bool padded = has_load24_padding(view);
    const uint32_t base = start_group << 8;
    uint32_t order[2] = {base + 255u, base + 511u};
    if (compare_suffixes(view, order[1], order[0]) < 0) {
        std::swap(order[0], order[1]);
    }

    for (int rel = 255; rel >= 0; --rel) {
        const uint32_t key0 = load24_fast(view, order[0], padded);
        const uint32_t key1 = load24_fast(view, order[1], padded);
        if (key0 == key1) {
            if (!write_compact_order_group(out, out_cap, record_count,
                                           key0, order, 0, 2, int_arena,
                                           int_arena_cap, arena_entries,
                                           count1_singletons)) {
                return false;
            }
        } else {
            if (!write_compact_order_group(out, out_cap, record_count,
                                           key0, order, 0, 1, int_arena,
                                           int_arena_cap, arena_entries,
                                           count1_singletons)) {
                return false;
            }
            if (!write_compact_order_group(out, out_cap, record_count,
                                           key1, order, 1, 1, int_arena,
                                           int_arena_cap, arena_entries,
                                           count1_singletons)) {
                return false;
            }
        }

        if (rel > 0) {
            --order[0];
            --order[1];
            if (view.data[order[0]] > view.data[order[1]]) {
                std::swap(order[0], order[1]);
            }
        }
    }

    return true;
}

template <uint32_t GroupCount>
bool emit_full_group_run_compact_fixed(const Stage4InputView& view,
                                       uint32_t start_group, uint8_t* out,
                                       size_t out_cap, size_t* record_count,
                                       uint8_t* int_arena,
                                       size_t int_arena_cap,
                                       uint32_t* arena_entries,
                                       bool count1_singletons) {
    static_assert(GroupCount >= 3 && GroupCount <= 4,
                  "fixed compact handler is only for tiny short runs");
    const bool padded = has_load24_padding(view);
    const uint32_t base = start_group << 8;
    uint32_t order[GroupCount];
    uint32_t keys[GroupCount];
    for (uint32_t chunk = 0; chunk < GroupCount; ++chunk) {
        order[chunk] = base + (chunk << 8) + 255u;
    }
    sort_stage4_suffix_order_small(view, order, GroupCount);

    for (int rel = 255; rel >= 0; --rel) {
        for (uint32_t i = 0; i < GroupCount; ++i) {
            keys[i] = load24_fast(view, order[i], padded);
        }

        uint32_t group_start = 0;
        while (group_start < GroupCount) {
            const uint32_t key = keys[group_start];
            uint32_t group_end = group_start + 1;
            while (group_end < GroupCount && keys[group_end] == key) {
                ++group_end;
            }
            const uint32_t count = group_end - group_start;
            if (!write_compact_order_group(out, out_cap, record_count,
                                           key, order, group_start, count,
                                           int_arena, int_arena_cap,
                                           arena_entries,
                                           count1_singletons)) {
                return false;
            }
            group_start = group_end;
        }

        if (rel > 0) {
            for (uint32_t i = 0; i < GroupCount; ++i) {
                --order[i];
            }
            for (uint32_t i = 1; i < GroupCount; ++i) {
                const uint32_t pos = order[i];
                const uint8_t key = view.data[pos];
                uint32_t j = i;
                while (j > 0 && view.data[order[j - 1u]] > key) {
                    order[j] = order[j - 1u];
                    --j;
                }
                order[j] = pos;
            }
        }
    }

    return true;
}

bool emit_full_group_run_compact_short(const Stage4InputView& view,
                                       uint32_t start_group,
                                       uint32_t end_group, uint8_t* out,
                                       size_t out_cap, size_t* record_count,
                                        uint8_t* int_arena,
                                        size_t int_arena_cap,
                                        uint32_t* arena_entries,
                                        bool count1_singletons) {
    const uint32_t group_count = end_group - start_group;
    if (group_count == 0 || group_count > kStage4ShortRunMax) return false;
    if (group_count == 2) {
        return emit_full_group_run_compact_two(
            view, start_group, out, out_cap, record_count, int_arena,
            int_arena_cap, arena_entries, count1_singletons);
    }
    if (group_count == 3) {
        return emit_full_group_run_compact_fixed<3>(
            view, start_group, out, out_cap, record_count, int_arena,
            int_arena_cap, arena_entries, count1_singletons);
    }
    if (group_count == 4) {
        return emit_full_group_run_compact_fixed<4>(
            view, start_group, out, out_cap, record_count, int_arena,
            int_arena_cap, arena_entries, count1_singletons);
    }
    const bool padded = has_load24_padding(view);
    const uint32_t base = start_group << 8;
    uint32_t order[kStage4ShortRunMax];
    uint32_t keys[kStage4ShortRunMax];
    for (uint32_t chunk = 0; chunk < group_count; ++chunk) {
        order[chunk] = base + (chunk << 8) + 255u;
    }
    sort_stage4_suffix_order_small(view, order, group_count);

    for (int rel = 255; rel >= 0; --rel) {
        for (uint32_t i = 0; i < group_count; ++i) {
            keys[i] = load24_fast(view, order[i], padded);
        }

        uint32_t group_start = 0;
        while (group_start < group_count) {
            const uint32_t key = keys[group_start];
            uint32_t group_end = group_start + 1;
            while (group_end < group_count && keys[group_end] == key) {
                ++group_end;
            }

            const uint32_t count = group_end - group_start;
            if (!write_compact_order_group(out, out_cap, record_count,
                                           key, order, group_start, count,
                                           int_arena, int_arena_cap,
                                           arena_entries,
                                           count1_singletons)) {
                return false;
            }
            group_start = group_end;
        }

        if (rel > 0) {
            for (uint32_t i = 0; i < group_count; ++i) {
                --order[i];
            }
            for (uint32_t i = 1; i < group_count; ++i) {
                const uint32_t pos = order[i];
                const uint8_t key = view.data[pos];
                uint32_t j = i;
                while (j > 0 && view.data[order[j - 1u]] > key) {
                    order[j] = order[j - 1u];
                    --j;
                }
                order[j] = pos;
            }
        }
    }

    return true;
}

bool emit_full_group_run_compact(const Stage4InputView& view, uint32_t start_group,
                                 uint32_t end_group, uint8_t* out,
                                 size_t out_cap, size_t* record_count,
                                 uint8_t* int_arena, size_t int_arena_cap,
                                 uint32_t* arena_entries,
                                 bool count1_singletons) {
    const uint32_t group_count = end_group - start_group;
    if (group_count == 0) return true;

    const uint32_t base = start_group << 8;
    if (group_count == 1) {
        return emit_compact_literal_records(view, base, 256,
                                            out, out_cap, record_count,
                                            count1_singletons, int_arena,
                                            int_arena_cap, arena_entries);
    }
    if (group_count <= kStage4ShortRunMax) {
        return emit_full_group_run_compact_short(
            view, start_group, end_group, out, out_cap, record_count,
            int_arena, int_arena_cap, arena_entries, count1_singletons);
    }
    if (group_count > kStage4MaxGroupCount) return false;
    const bool padded = has_load24_padding(view);

    std::vector<uint32_t>& order = stage4_order_scratch();
    order.resize(group_count);
    for (uint32_t chunk = 0; chunk < group_count; ++chunk) {
        order[chunk] = base + (chunk << 8) + 255u;
    }
    std::sort(order.begin(), order.end(),
              [&](uint32_t a, uint32_t b) {
                  return compare_suffixes(view, a, b) < 0;
              });

    uint32_t keys[kStage4MaxGroupCount];
    for (int rel = 255; rel >= 0; --rel) {
        for (uint32_t i = 0; i < group_count; ++i) {
            keys[i] = load24_fast(view, order[i], padded);
        }

        uint32_t group_start = 0;
        while (group_start < group_count) {
            const uint32_t key = keys[group_start];
            uint32_t group_end = group_start + 1;
            while (group_end < group_count && keys[group_end] == key) {
                ++group_end;
            }

            const uint32_t count = group_end - group_start;
            uint32_t packed = order[group_start];
            if (count > 1 || count1_singletons) {
                const uint32_t arena_index = *arena_entries;
                if (!append_compact_arena_positions(int_arena, int_arena_cap,
                                                    order, group_start, count,
                                                    arena_entries)) {
                    return false;
                }
                packed = (count << 17) + arena_index;
            }
            if (!write_record(out, out_cap, record_count, key, packed)) return false;
            group_start = group_end;
        }

        if (rel > 0) {
            for (uint32_t i = 0; i < group_count; ++i) {
                --order[i];
            }
            for (uint32_t i = 1; i < group_count; ++i) {
                const uint32_t pos = order[i];
                const uint8_t key = view.data[pos];
                uint32_t j = i;
                while (j > 0 && view.data[order[j - 1u]] > key) {
                    order[j] = order[j - 1u];
                    --j;
                }
                order[j] = pos;
            }
        }
    }

    return true;
}

int compare_suffixes(const Stage5InputView& view, uint32_t a, uint32_t b) {
    if (a == b) return 0;

    const size_t a_len = view.logical_len - a;
    const size_t b_len = view.logical_len - b;
    const size_t common = std::min(a_len, b_len);
    const int cmp = std::memcmp(view.data + a, view.data + b, common);
    if (cmp != 0) return cmp < 0 ? -1 : 1;
    if (a_len == b_len) return 0;
    return a_len < b_len ? -1 : 1;
}

uint64_t load_be64(const uint8_t* p) {
    return (static_cast<uint64_t>(p[0]) << 56) |
           (static_cast<uint64_t>(p[1]) << 48) |
           (static_cast<uint64_t>(p[2]) << 40) |
           (static_cast<uint64_t>(p[3]) << 32) |
           (static_cast<uint64_t>(p[4]) << 24) |
           (static_cast<uint64_t>(p[5]) << 16) |
           (static_cast<uint64_t>(p[6]) << 8) |
           static_cast<uint64_t>(p[7]);
}

int compare_suffixes_after_key(const Stage5InputView& view, uint32_t a, uint32_t b) {
    if (a == b) return 0;

    const size_t a_len = view.logical_len - a;
    const size_t b_len = view.logical_len - b;
    const size_t common_with_key = std::min(a_len, b_len);
    if (common_with_key <= 3u) {
        if (a_len == b_len) return 0;
        return a_len < b_len ? -1 : 1;
    }

    const size_t common = common_with_key - 3u;
    const uint8_t* ap = view.data + a + 3u;
    const uint8_t* bp = view.data + b + 3u;
    if (common >= 8u) {
        const uint64_t av = load_be64(ap);
        const uint64_t bv = load_be64(bp);
        if (av != bv) return av < bv ? -1 : 1;
    }
    const int cmp = common > 8u
        ? std::memcmp(ap + 8u, bp + 8u, common - 8u)
        : std::memcmp(ap, bp, common);
    if (cmp != 0) return cmp < 0 ? -1 : 1;
    if (a_len == b_len) return 0;
    return a_len < b_len ? -1 : 1;
}

bool suffix_is_zero_tail(const Stage5InputView& view, uint32_t pos) {
    for (uint32_t i = pos; i < view.logical_len; ++i) {
        if (view.data[i] != 0) return false;
    }
    return true;
}

struct Stage5Run {
    uint32_t key = 0;
    uint32_t packed = 0;
};
static_assert(sizeof(Stage5Run) == 8, "Stage5Run mirrors v1.14 descriptor records");

Stage5Run make_stage5_run(uint32_t key, uint32_t begin, uint32_t count,
                          bool scratch) {
    return Stage5Run{key, scratch ? begin : ((count << 17) + begin)};
}

uint32_t stage5_run_encoded_count(const Stage5Run& run) {
    return run.packed >> 17;
}

bool stage5_run_is_literal(const Stage5Run& run) {
    return stage5_run_encoded_count(run) == 0;
}

uint32_t stage5_run_begin(const Stage5Run& run) {
    return run.packed & 0x1ffffu;
}

uint32_t stage5_run_count(const Stage5Run& run) {
    const uint32_t count = stage5_run_encoded_count(run);
    return count == 0 ? 1u : count;
}

void fused_stage5_profile_note_emit_shape(
    FusedStage5Profile* profile,
    const std::vector<Stage5Run>& runs,
    const std::vector<uint32_t>& arena_positions) {
    if (!profile) return;
    profile->emit_appends += runs.size();
    profile->emit_arena_positions += arena_positions.size();
    profile->emit_run_capacity += runs.capacity();
    profile->emit_arena_capacity += arena_positions.capacity();
    for (const Stage5Run& run : runs) {
        const uint32_t count = stage5_run_count(run);
        profile->emit_positions += count;
        if (stage5_run_is_literal(run)) {
            ++profile->emit_literal_appends;
        } else {
            ++profile->emit_arena_appends;
        }
    }
}

struct Stage5HeapNode {
    uint32_t run = 0;
    uint32_t rel = 0;
};

struct Stage5Scratch {
    std::vector<uint32_t> group_positions;
    std::vector<uint32_t> merge_positions;
    std::vector<uint32_t> run_lengths;
    std::vector<uint32_t> next_run_lengths;
    std::vector<Stage5Run> runs;
    std::vector<Stage5Run> radix_tmp;
    std::vector<Stage5HeapNode> heap;
    std::vector<uint32_t> seen_generation;
    uint32_t generation = 0;
};

struct FusedStage5Scratch {
    std::vector<uint32_t> order;
    std::vector<uint32_t> arena_positions;
    std::vector<uint32_t> group_positions;
    std::vector<uint32_t> merge_positions;
    std::vector<uint32_t> run_lengths;
    std::vector<uint32_t> next_run_lengths;
    std::vector<Stage5Run> runs;
    std::vector<Stage5Run> radix_tmp;
};

struct Stage5DescriptorGuard {
    bool* active = nullptr;

    explicit Stage5DescriptorGuard(bool* flag) : active(flag) {
        *active = true;
    }

    ~Stage5DescriptorGuard() {
        *active = false;
    }
};

void radix_sort_runs_by_key(std::vector<Stage5Run>* runs,
                            std::vector<Stage5Run>* tmp) {
    tmp->resize(runs->size());
    for (uint32_t pass = 0; pass < 2; ++pass) {
        size_t counts[4096] = {};
        const uint32_t shift = pass * 12u;
        for (const Stage5Run& run : *runs) {
            ++counts[(stage5_radix_order_key(run.key) >> shift) & 0xfffu];
        }

        size_t sum = 0;
        for (size_t& count : counts) {
            const size_t n = count;
            count = sum;
            sum += n;
        }

        for (const Stage5Run& run : *runs) {
            const uint32_t bucket =
                (stage5_radix_order_key(run.key) >> shift) & 0xfffu;
            (*tmp)[counts[bucket]++] = run;
        }
        runs->swap(*tmp);
    }
}

void radix_sort_runs_by_stored_key(std::vector<Stage5Run>* runs,
                                   std::vector<Stage5Run>* tmp) {
    const size_t n = runs->size();
    if (n <= 1) return;
    tmp->resize(n);

    uint32_t counts0[256] = {};
    uint32_t counts1[256] = {};
    uint32_t counts2[256] = {};

    for (const Stage5Run& run : *runs) {
        ++counts0[run.key & 0xffu];
        ++counts1[(run.key >> 8) & 0xffu];
        ++counts2[(run.key >> 16) & 0xffu];
    }

    // Pass 0
    uint32_t sum0 = 0;
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = counts0[i];
        counts0[i] = sum0;
        sum0 += c;
    }
    for (const Stage5Run& run : *runs) {
        (*tmp)[counts0[run.key & 0xffu]++] = run;
    }

    // Pass 1
    uint32_t sum1 = 0;
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = counts1[i];
        counts1[i] = sum1;
        sum1 += c;
    }
    for (const Stage5Run& run : *tmp) {
        (*runs)[counts1[(run.key >> 8) & 0xffu]++] = run;
    }

    // Pass 2
    uint32_t sum2 = 0;
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = counts2[i];
        counts2[i] = sum2;
        sum2 += c;
    }
    for (const Stage5Run& run : *runs) {
        (*tmp)[counts2[(run.key >> 16) & 0xffu]++] = run;
    }
    runs->swap(*tmp);
}

uint32_t stage5_run_pos(const Stage5InputView& view,
                        const Stage5Run& run, uint32_t rel) {
    const uint32_t begin = stage5_run_begin(run);
    if (stage5_run_is_literal(run)) {
        return begin;
    }
    return read_u32_le(view.int_arena + static_cast<size_t>(begin + rel) * 4u);
}

bool suffix_less_after_key(const Stage5InputView& view, uint32_t a, uint32_t b) {
    const int cmp = compare_suffixes_after_key(view, a, b);
    if (cmp != 0) return cmp < 0;
    return a < b;
}

void merge_sorted_suffix_positions_after_key(const Stage5InputView& view,
                                             const std::vector<uint32_t>& src,
                                             size_t left_begin,
                                             size_t left_end,
                                             size_t right_end,
                                             std::vector<uint32_t>* dst,
                                             size_t dst_begin) {
    size_t left = left_begin;
    size_t right = left_end;
    size_t out = dst_begin;
    while (left < left_end && right < right_end) {
        const uint32_t lpos = src[left];
        const uint32_t rpos = src[right];
        if (suffix_less_after_key(view, lpos, rpos)) {
            (*dst)[out++] = lpos;
            ++left;
        } else {
            (*dst)[out++] = rpos;
            ++right;
        }
    }
    while (left < left_end) {
        (*dst)[out++] = src[left++];
    }
    while (right < right_end) {
        (*dst)[out++] = src[right++];
    }
}

void merge_equal_key_runs_after_key(const Stage5InputView& view,
                                    std::vector<uint32_t>* positions,
                                    std::vector<uint32_t>* merge_positions,
                                    std::vector<uint32_t>* run_lengths,
                                    std::vector<uint32_t>* next_run_lengths) {
    if (run_lengths->size() <= 1u) return;

    merge_positions->resize(positions->size());
    std::vector<uint32_t>* src = positions;
    std::vector<uint32_t>* dst = merge_positions;
    while (run_lengths->size() > 1u) {
        next_run_lengths->clear();
        size_t in_base = 0;
        size_t out_base = 0;
        for (size_t i = 0; i < run_lengths->size(); i += 2u) {
            const uint32_t left_len = (*run_lengths)[i];
            if (i + 1u == run_lengths->size()) {
                std::memcpy(dst->data() + out_base, src->data() + in_base,
                            static_cast<size_t>(left_len) * sizeof(uint32_t));
                next_run_lengths->push_back(left_len);
                in_base += left_len;
                out_base += left_len;
                continue;
            }

            const uint32_t right_len = (*run_lengths)[i + 1u];
            merge_sorted_suffix_positions_after_key(
                view, *src, in_base, in_base + left_len,
                in_base + left_len + right_len, dst, out_base);
            next_run_lengths->push_back(left_len + right_len);
            in_base += static_cast<size_t>(left_len) + right_len;
            out_base += static_cast<size_t>(left_len) + right_len;
        }
        run_lengths->swap(*next_run_lengths);
        std::swap(src, dst);
    }

    if (src != positions) {
        positions->swap(*src);
    }
}

bool try_write_literal_equal_key_group_after_key(const Stage5InputView& view,
                                                 const std::vector<Stage5Run>& runs,
                                                 size_t group_start,
                                                 size_t group_end,
                                                 uint8_t* out,
                                                 size_t* out_pos) {
    constexpr size_t kMaxStackLiteralGroup = 32;
    const size_t count = group_end - group_start;
    if (count == 0 || count > kMaxStackLiteralGroup) return false;

    uint32_t positions[kMaxStackLiteralGroup];
    for (size_t i = 0; i < count; ++i) {
        const Stage5Run& run = runs[group_start + i];
        if (!stage5_run_is_literal(run)) return false;
        positions[i] = stage5_run_begin(run);
    }

    for (size_t i = 1; i < count; ++i) {
        const uint32_t pos = positions[i];
        size_t j = i;
        while (j > 0 && suffix_less_after_key(view, pos, positions[j - 1u])) {
            positions[j] = positions[j - 1u];
            --j;
        }
        positions[j] = pos;
    }

    size_t write_pos = *out_pos;
    for (size_t i = 0; i < count; ++i) {
        write_u32_le(out + write_pos * 4u, positions[i]);
        ++write_pos;
    }
    *out_pos = write_pos;
    return true;
}

bool try_write_two_equal_key_runs_after_key(const Stage5InputView& view,
                                            const std::vector<Stage5Run>& runs,
                                            size_t group_start,
                                            size_t group_end,
                                            uint8_t* out,
                                            size_t* out_pos) {
    if (group_end != group_start + 2u) return false;

    const Stage5Run& left = runs[group_start];
    const Stage5Run& right = runs[group_start + 1u];
    const uint32_t left_count = stage5_run_count(left);
    const uint32_t right_count = stage5_run_count(right);
    uint32_t left_rel = 0;
    uint32_t right_rel = 0;
    size_t write_pos = *out_pos;

    while (left_rel < left_count && right_rel < right_count) {
        const uint32_t lpos = stage5_run_pos(view, left, left_rel);
        const uint32_t rpos = stage5_run_pos(view, right, right_rel);
        if (suffix_less_after_key(view, lpos, rpos)) {
            write_u32_le(out + write_pos * 4u, lpos);
            ++left_rel;
        } else {
            write_u32_le(out + write_pos * 4u, rpos);
            ++right_rel;
        }
        ++write_pos;
    }
    while (left_rel < left_count) {
        write_u32_le(out + write_pos * 4u,
                     stage5_run_pos(view, left, left_rel));
        ++left_rel;
        ++write_pos;
    }
    while (right_rel < right_count) {
        write_u32_le(out + write_pos * 4u,
                     stage5_run_pos(view, right, right_rel));
        ++right_rel;
        ++write_pos;
    }

    *out_pos = write_pos;
    return true;
}

uint32_t fused_run_pos(const std::vector<uint32_t>& arena_positions,
                       const Stage5Run& run, uint32_t rel) {
    const uint32_t begin = stage5_run_begin(run);
    if (stage5_run_is_literal(run)) {
        return begin;
    }
    return arena_positions[static_cast<size_t>(begin) + rel];
}

bool append_fused_order_group(std::vector<Stage5Run>* runs,
                              std::vector<uint32_t>* arena_positions,
                              uint32_t key, const uint32_t* order,
                              uint32_t first, uint32_t count,
                              bool count1_singletons) {
    if (!runs || !arena_positions || !order || count == 0) return false;
    const uint32_t ordered_key = stage5_radix_order_key(key);

    if (count == 1 && !count1_singletons) {
        runs->push_back(make_stage5_run(ordered_key, order[first], 1, true));
        return true;
    }

    const size_t begin = arena_positions->size();
    if (begin > kDescriptorArenaIndexCount ||
        count > kDescriptorArenaIndexCount - begin) {
        return false;
    }
    arena_positions->resize(begin + count);
    std::memcpy(arena_positions->data() + begin, order + first,
                static_cast<size_t>(count) * sizeof(uint32_t));
    runs->push_back(make_stage5_run(ordered_key, static_cast<uint32_t>(begin),
                                    count, false));
    return true;
}

bool emit_fused_literal_records(const Stage4InputView& view, uint32_t start,
                                uint32_t count, FusedStage5Scratch* scratch,
                                bool count1_singletons) {
    if (!scratch) return false;
    const bool padded = has_load24_padding(view);
    for (uint32_t rel = 0; rel < count; ++rel) {
        const uint32_t pos = start + rel;
        uint32_t one = pos;
        if (!append_fused_order_group(&scratch->runs, &scratch->arena_positions,
                                      load24_fast(view, pos, padded), &one, 0, 1,
                                      count1_singletons)) {
            return false;
        }
    }
    return true;
}

bool emit_full_group_run_compact_fused_two(const Stage4InputView& view,
                                           uint32_t start_group,
                                           FusedStage5Scratch* scratch,
                                           bool count1_singletons) {
    if (!scratch) return false;
    const bool padded = has_load24_padding(view);
    const uint32_t base = start_group << 8;
    uint32_t order[2] = {base + 255u, base + 511u};
    if (compare_suffixes(view, order[1], order[0]) < 0) {
        std::swap(order[0], order[1]);
    }

    for (int rel = 255; rel >= 0; --rel) {
        const uint32_t key0 = load24_fast(view, order[0], padded);
        const uint32_t key1 = load24_fast(view, order[1], padded);
        if (key0 == key1) {
            if (!append_fused_order_group(&scratch->runs,
                                          &scratch->arena_positions, key0,
                                          order, 0, 2, count1_singletons)) {
                return false;
            }
        } else {
            if (!append_fused_order_group(&scratch->runs,
                                          &scratch->arena_positions, key0,
                                          order, 0, 1, count1_singletons) ||
                !append_fused_order_group(&scratch->runs,
                                          &scratch->arena_positions, key1,
                                          order, 1, 1, count1_singletons)) {
                return false;
            }
        }

        if (rel > 0) {
            --order[0];
            --order[1];
            if (view.data[order[0]] > view.data[order[1]]) {
                std::swap(order[0], order[1]);
            }
        }
    }

    return true;
}

template <uint32_t GroupCount>
bool emit_full_group_run_compact_fused_fixed(const Stage4InputView& view,
                                             uint32_t start_group,
                                             FusedStage5Scratch* scratch,
                                             bool count1_singletons) {
    static_assert(GroupCount >= 3 && GroupCount <= 4,
                  "fixed compact handler is only for tiny short runs");
    if (!scratch) return false;
    const bool padded = has_load24_padding(view);
    const uint32_t base = start_group << 8;
    uint32_t order[GroupCount];
    uint32_t keys[GroupCount];
    for (uint32_t chunk = 0; chunk < GroupCount; ++chunk) {
        order[chunk] = base + (chunk << 8) + 255u;
    }
    sort_stage4_suffix_order_small(view, order, GroupCount);

    for (int rel = 255; rel >= 0; --rel) {
        for (uint32_t i = 0; i < GroupCount; ++i) {
            keys[i] = load24_fast(view, order[i], padded);
        }

        uint32_t group_start = 0;
        while (group_start < GroupCount) {
            const uint32_t key = keys[group_start];
            uint32_t group_end = group_start + 1;
            while (group_end < GroupCount && keys[group_end] == key) {
                ++group_end;
            }
            if (!append_fused_order_group(&scratch->runs,
                                          &scratch->arena_positions, key,
                                          order, group_start,
                                          group_end - group_start,
                                          count1_singletons)) {
                return false;
            }
            group_start = group_end;
        }

        if (rel > 0) {
            for (uint32_t i = 0; i < GroupCount; ++i) {
                --order[i];
            }
            for (uint32_t i = 1; i < GroupCount; ++i) {
                const uint32_t pos = order[i];
                const uint8_t key = view.data[pos];
                uint32_t j = i;
                while (j > 0 && view.data[order[j - 1u]] > key) {
                    order[j] = order[j - 1u];
                    --j;
                }
                order[j] = pos;
            }
        }
    }

    return true;
}

bool emit_full_group_run_compact_fused_short(const Stage4InputView& view,
                                             uint32_t start_group,
                                             uint32_t end_group,
                                             FusedStage5Scratch* scratch,
                                             bool count1_singletons) {
    if (!scratch) return false;
    const uint32_t group_count = end_group - start_group;
    if (group_count == 0 || group_count > kStage4ShortRunMax) return false;
    if (group_count == 2) {
        return emit_full_group_run_compact_fused_two(
            view, start_group, scratch, count1_singletons);
    }
    if (group_count == 3) {
        return emit_full_group_run_compact_fused_fixed<3>(
            view, start_group, scratch, count1_singletons);
    }
    if (group_count == 4) {
        return emit_full_group_run_compact_fused_fixed<4>(
            view, start_group, scratch, count1_singletons);
    }

    const bool padded = has_load24_padding(view);
    const uint32_t base = start_group << 8;
    uint32_t order[kStage4ShortRunMax];
    uint32_t keys[kStage4ShortRunMax];
    for (uint32_t chunk = 0; chunk < group_count; ++chunk) {
        order[chunk] = base + (chunk << 8) + 255u;
    }
    sort_stage4_suffix_order_small(view, order, group_count);

    for (int rel = 255; rel >= 0; --rel) {
        for (uint32_t i = 0; i < group_count; ++i) {
            keys[i] = load24_fast(view, order[i], padded);
        }

        uint32_t group_start = 0;
        while (group_start < group_count) {
            const uint32_t key = keys[group_start];
            uint32_t group_end = group_start + 1;
            while (group_end < group_count && keys[group_end] == key) {
                ++group_end;
            }
            if (!append_fused_order_group(&scratch->runs,
                                          &scratch->arena_positions, key,
                                          order, group_start,
                                          group_end - group_start,
                                          count1_singletons)) {
                return false;
            }
            group_start = group_end;
        }

        if (rel > 0) {
            for (uint32_t i = 0; i < group_count; ++i) {
                --order[i];
            }
            for (uint32_t i = 1; i < group_count; ++i) {
                const uint32_t pos = order[i];
                const uint8_t key = view.data[pos];
                uint32_t j = i;
                while (j > 0 && view.data[order[j - 1u]] > key) {
                    order[j] = order[j - 1u];
                    --j;
                }
                order[j] = pos;
            }
        }
    }

    return true;
}

bool emit_full_group_run_compact_fused(const Stage4InputView& view,
                                       uint32_t start_group,
                                       uint32_t end_group,
                                       FusedStage5Scratch* scratch,
                                       bool count1_singletons) {
    if (!scratch) return false;
    const uint32_t group_count = end_group - start_group;
    if (group_count == 0) return true;
    if (group_count > kStage4MaxGroupCount) return false;

    const uint32_t base = start_group << 8;
    if (group_count == 1) {
        return emit_fused_literal_records(view, base, 256, scratch,
                                          count1_singletons);
    }
    if (group_count <= kStage4ShortRunMax) {
        return emit_full_group_run_compact_fused_short(
            view, start_group, end_group, scratch, count1_singletons);
    }

    const bool padded = has_load24_padding(view);
    std::vector<uint32_t>& order = scratch->order;
    order.resize(group_count);
    for (uint32_t chunk = 0; chunk < group_count; ++chunk) {
        order[chunk] = base + (chunk << 8) + 255u;
    }
    std::sort(order.begin(), order.end(),
              [&](uint32_t a, uint32_t b) {
                  return compare_suffixes(view, a, b) < 0;
              });

    uint32_t keys[kStage4MaxGroupCount];
    for (int rel = 255; rel >= 0; --rel) {
        for (uint32_t i = 0; i < group_count; ++i) {
            keys[i] = load24_fast(view, order[i], padded);
        }

        uint32_t group_start = 0;
        while (group_start < group_count) {
            const uint32_t key = keys[group_start];
            uint32_t group_end = group_start + 1;
            while (group_end < group_count && keys[group_end] == key) {
                ++group_end;
            }

            if (!append_fused_order_group(&scratch->runs,
                                          &scratch->arena_positions,
                                          key, order.data(), group_start,
                                          group_end - group_start,
                                          count1_singletons)) {
                return false;
            }
            group_start = group_end;
        }

        if (rel > 0) {
            for (uint32_t i = 0; i < group_count; ++i) {
                --order[i];
            }
            for (uint32_t i = 1; i < group_count; ++i) {
                const uint32_t pos = order[i];
                const uint8_t key = view.data[pos];
                uint32_t j = i;
                while (j > 0 && view.data[order[j - 1u]] > key) {
                    order[j] = order[j - 1u];
                    --j;
                }
                order[j] = pos;
            }
        }
    }

    return true;
}

bool fused_try_write_literal_equal_key_group_after_key(
    const Stage5InputView& view, const std::vector<Stage5Run>& runs,
    size_t group_start, size_t group_end, uint8_t* out, size_t* out_pos) {
    constexpr size_t kMaxStackLiteralGroup = 32;
    const size_t count = group_end - group_start;
    if (count == 0 || count > kMaxStackLiteralGroup) return false;

    uint32_t positions[kMaxStackLiteralGroup];
    for (size_t i = 0; i < count; ++i) {
        const Stage5Run& run = runs[group_start + i];
        if (!stage5_run_is_literal(run)) return false;
        positions[i] = stage5_run_begin(run);
    }

    for (size_t i = 1; i < count; ++i) {
        const uint32_t pos = positions[i];
        size_t j = i;
        while (j > 0 && suffix_less_after_key(view, pos, positions[j - 1u])) {
            positions[j] = positions[j - 1u];
            --j;
        }
        positions[j] = pos;
    }

    size_t write_pos = *out_pos;
    for (size_t i = 0; i < count; ++i) {
        write_u32_le(out + write_pos * 4u, positions[i]);
        ++write_pos;
    }
    *out_pos = write_pos;
    return true;
}

bool fused_try_write_two_equal_key_runs_after_key(
    const Stage5InputView& view, const std::vector<uint32_t>& arena_positions,
    const std::vector<Stage5Run>& runs, size_t group_start, size_t group_end,
    uint8_t* out, size_t* out_pos) {
    if (group_end != group_start + 2u) return false;

    const Stage5Run& left = runs[group_start];
    const Stage5Run& right = runs[group_start + 1u];
    const uint32_t left_count = stage5_run_count(left);
    const uint32_t right_count = stage5_run_count(right);
    uint32_t left_rel = 0;
    uint32_t right_rel = 0;
    size_t write_pos = *out_pos;

    while (left_rel < left_count && right_rel < right_count) {
        const uint32_t lpos = fused_run_pos(arena_positions, left, left_rel);
        const uint32_t rpos = fused_run_pos(arena_positions, right, right_rel);
        if (suffix_less_after_key(view, lpos, rpos)) {
            write_u32_le(out + write_pos * 4u, lpos);
            ++left_rel;
        } else {
            write_u32_le(out + write_pos * 4u, rpos);
            ++right_rel;
        }
        ++write_pos;
    }
    while (left_rel < left_count) {
        write_u32_le(out + write_pos * 4u,
                     fused_run_pos(arena_positions, left, left_rel));
        ++left_rel;
        ++write_pos;
    }
    while (right_rel < right_count) {
        write_u32_le(out + write_pos * 4u,
                     fused_run_pos(arena_positions, right, right_rel));
        ++right_rel;
        ++write_pos;
    }

    *out_pos = write_pos;
    return true;
}

struct FusedHashSink {
    static constexpr uint32_t kBufferWords = 2048u;

    SHA256_CTX ctx{};
    uint8_t buffer[kBufferWords * sizeof(uint32_t)] = {};
    uint32_t buffered = 0;
    size_t positions = 0;
};

void fused_hash_sink_init(FusedHashSink* sink) {
    SHA256_Init(&sink->ctx);
    sink->buffered = 0;
    sink->positions = 0;
}

void fused_hash_sink_flush(FusedHashSink* sink) {
    if (sink->buffered == 0) return;
    SHA256_Update(&sink->ctx, sink->buffer,
                  static_cast<size_t>(sink->buffered) * 4u);
    sink->buffered = 0;
}

void fused_hash_sink_write_pos(FusedHashSink* sink, uint32_t pos) {
    write_u32_le(sink->buffer + static_cast<size_t>(sink->buffered) * 4u, pos);
    ++sink->buffered;
    ++sink->positions;
    if (sink->buffered == FusedHashSink::kBufferWords) {
        SHA256_Update(&sink->ctx, sink->buffer, sizeof(sink->buffer));
        sink->buffered = 0;
    }
}

void fused_hash_sink_write_positions(FusedHashSink* sink,
                                     const uint32_t* positions,
                                     uint32_t count) {
    if (!positions || count == 0) return;
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    for (uint32_t i = 0; i < count; ++i) {
        fused_hash_sink_write_pos(sink, positions[i]);
    }
#else
    while (count != 0) {
        if (sink->buffered == 0 && count >= FusedHashSink::kBufferWords) {
            const uint32_t full =
                count & ~(FusedHashSink::kBufferWords - 1u);
            SHA256_Update(&sink->ctx, positions,
                          static_cast<size_t>(full) * sizeof(uint32_t));
            sink->positions += full;
            positions += full;
            count -= full;
            continue;
        }

        const uint32_t space = FusedHashSink::kBufferWords - sink->buffered;
        const uint32_t chunk = std::min(count, space);
        std::memcpy(sink->buffer + static_cast<size_t>(sink->buffered) * 4u,
                    positions, static_cast<size_t>(chunk) * sizeof(uint32_t));
        sink->buffered += chunk;
        sink->positions += chunk;
        positions += chunk;
        count -= chunk;
        if (sink->buffered == FusedHashSink::kBufferWords) {
            SHA256_Update(&sink->ctx, sink->buffer, sizeof(sink->buffer));
            sink->buffered = 0;
        }
    }
#endif
}

void fused_hash_sink_final(FusedHashSink* sink, uint8_t out_hash[32]) {
    fused_hash_sink_flush(sink);
    SHA256_Final(out_hash, &sink->ctx);
}

bool fused_try_hash_literal_equal_key_group_after_key(
    const Stage5InputView& view, const std::vector<Stage5Run>& runs,
    size_t group_start, size_t group_end, FusedHashSink* sink) {
    constexpr size_t kMaxStackLiteralGroup = 32;
    const size_t count = group_end - group_start;
    if (!sink || count == 0 || count > kMaxStackLiteralGroup) return false;

    uint32_t positions[kMaxStackLiteralGroup];
    for (size_t i = 0; i < count; ++i) {
        const Stage5Run& run = runs[group_start + i];
        if (!stage5_run_is_literal(run)) return false;
        positions[i] = stage5_run_begin(run);
    }

    for (size_t i = 1; i < count; ++i) {
        const uint32_t pos = positions[i];
        size_t j = i;
        while (j > 0 && suffix_less_after_key(view, pos, positions[j - 1u])) {
            positions[j] = positions[j - 1u];
            --j;
        }
        positions[j] = pos;
    }

    for (size_t i = 0; i < count; ++i) {
        fused_hash_sink_write_pos(sink, positions[i]);
    }
    return true;
}

bool fused_try_hash_two_equal_key_runs_after_key(
    const Stage5InputView& view, const std::vector<uint32_t>& arena_positions,
    const std::vector<Stage5Run>& runs, size_t group_start, size_t group_end,
    FusedHashSink* sink) {
    if (!sink || group_end != group_start + 2u) return false;

    const Stage5Run& left = runs[group_start];
    const Stage5Run& right = runs[group_start + 1u];
    const uint32_t left_count = stage5_run_count(left);
    const uint32_t right_count = stage5_run_count(right);
    uint32_t left_rel = 0;
    uint32_t right_rel = 0;

    while (left_rel < left_count && right_rel < right_count) {
        const uint32_t lpos = fused_run_pos(arena_positions, left, left_rel);
        const uint32_t rpos = fused_run_pos(arena_positions, right, right_rel);
        if (suffix_less_after_key(view, lpos, rpos)) {
            fused_hash_sink_write_pos(sink, lpos);
            ++left_rel;
        } else {
            fused_hash_sink_write_pos(sink, rpos);
            ++right_rel;
        }
    }
    while (left_rel < left_count) {
        fused_hash_sink_write_pos(
            sink, fused_run_pos(arena_positions, left, left_rel));
        ++left_rel;
    }
    while (right_rel < right_count) {
        fused_hash_sink_write_pos(
            sink, fused_run_pos(arena_positions, right, right_rel));
        ++right_rel;
    }

    return true;
}

bool write_fused_runs_to_sa(const Stage5InputView& view,
                            FusedStage5Scratch* scratch,
                            uint8_t* out, size_t out_cap, size_t* out_len) {
    if (out_len) *out_len = 0;
    if (!scratch || !out || !out_len) return false;

    const uint64_t needed = static_cast<uint64_t>(view.logical_len) * 4u;
    if (needed > std::numeric_limits<size_t>::max() || out_cap < needed) {
        return false;
    }

    std::vector<Stage5Run>& runs = scratch->runs;
    std::vector<Stage5Run>& radix_tmp = scratch->radix_tmp;
    std::vector<uint32_t>& arena_positions = scratch->arena_positions;
    std::vector<uint32_t>& group_positions = scratch->group_positions;
    std::vector<uint32_t>& merge_positions = scratch->merge_positions;
    std::vector<uint32_t>& run_lengths = scratch->run_lengths;
    std::vector<uint32_t>& next_run_lengths = scratch->next_run_lengths;

    FusedStage5Profile* profile =
        fused_stage5_profile_enabled() ? &fused_stage5_profile() : nullptr;
    const uint64_t sort0 = profile ? stage5_prof_rdtsc() : 0;
    radix_sort_runs_by_stored_key(&runs, &radix_tmp);
    if (profile) profile->sort += stage5_prof_rdtsc() - sort0;

    size_t group_start = 0;
    size_t out_pos = 0;
    bool previous_single_arena = false;
    uint32_t previous_single_arena_end = 0;
    while (group_start < runs.size()) {
        size_t group_end = group_start + 1;
        while (group_end < runs.size() &&
               runs[group_start].key == runs[group_end].key) {
            ++group_end;
        }

        if (group_end == group_start + 1) {
            const uint64_t single0 = profile ? stage5_prof_rdtsc() : 0;
            const Stage5Run& run = runs[group_start];
            const uint32_t run_count = stage5_run_count(run);
            if (profile) {
                ++profile->single_runs;
                profile->single_positions += run_count;
            }
            if (!stage5_run_is_literal(run)) {
                const uint32_t run_begin = stage5_run_begin(run);
                if (profile) {
                    ++profile->single_arena_runs;
                    profile->single_arena_positions += run_count;
                    if (previous_single_arena &&
                        previous_single_arena_end == run_begin) {
                        ++profile->single_adjacent_arena_runs;
                        profile->single_adjacent_arena_positions += run_count;
                    }
                    previous_single_arena = true;
                    previous_single_arena_end = run_begin + run_count;
                }
                std::memcpy(out + out_pos * 4u,
                            arena_positions.data() + run_begin,
                            static_cast<size_t>(run_count) * sizeof(uint32_t));
                out_pos += run_count;
            } else {
                if (profile) {
                    ++profile->single_literal_runs;
                    previous_single_arena = false;
                }
                write_u32_le(out + out_pos * 4u, stage5_run_begin(run));
                ++out_pos;
            }
            if (profile) profile->single += stage5_prof_rdtsc() - single0;
        } else {
            previous_single_arena = false;
            if (profile) {
                ++profile->equal_groups;
            }
            const uint64_t literal0 = profile ? stage5_prof_rdtsc() : 0;
            bool handled = fused_try_write_literal_equal_key_group_after_key(
                view, runs, group_start, group_end, out, &out_pos);
            if (profile) profile->literal_group += stage5_prof_rdtsc() - literal0;
            if (!handled) {
                const uint64_t two0 = profile ? stage5_prof_rdtsc() : 0;
                handled = fused_try_write_two_equal_key_runs_after_key(
                    view, arena_positions, runs, group_start, group_end,
                    out, &out_pos);
                if (profile) profile->two_run += stage5_prof_rdtsc() - two0;
            }
            if (handled) {
                group_start = group_end;
                continue;
            }
            if (profile) {
                ++profile->fallback_groups;
            }
            const uint64_t prepare0 = profile ? stage5_prof_rdtsc() : 0;
            group_positions.clear();
            run_lengths.clear();
            size_t group_positions_count = 0;
            for (size_t i = group_start; i < group_end; ++i) {
                const uint32_t count = stage5_run_count(runs[i]);
                group_positions_count += count;
                run_lengths.push_back(count);
            }
            group_positions.reserve(group_positions_count);
            for (size_t i = group_start; i < group_end; ++i) {
                const Stage5Run& run = runs[i];
                const uint32_t run_count = stage5_run_count(run);
                for (uint32_t rel = 0; rel < run_count; ++rel) {
                    group_positions.push_back(
                        fused_run_pos(arena_positions, run, rel));
                }
            }
            if (profile) profile->prepare += stage5_prof_rdtsc() - prepare0;
            const uint64_t merge0 = profile ? stage5_prof_rdtsc() : 0;
            merge_equal_key_runs_after_key(view, &group_positions,
                                           &merge_positions, &run_lengths,
                                           &next_run_lengths);
            if (profile) profile->merge += stage5_prof_rdtsc() - merge0;
            const uint64_t output0 = profile ? stage5_prof_rdtsc() : 0;
            for (uint32_t pos : group_positions) {
                write_u32_le(out + out_pos * 4u, pos);
                ++out_pos;
            }
            if (profile) profile->output += stage5_prof_rdtsc() - output0;
        }
        group_start = group_end;
    }

    if (out_pos != view.logical_len) {
        *out_len = 0;
        return false;
    }

    *out_len = static_cast<size_t>(needed);
    return true;
}

bool write_fused_runs_to_hash(const Stage5InputView& view,
                              FusedStage5Scratch* scratch,
                              uint8_t out_hash[32]) {
    if (!scratch || !out_hash) return false;

    std::vector<Stage5Run>& runs = scratch->runs;
    std::vector<Stage5Run>& radix_tmp = scratch->radix_tmp;
    std::vector<uint32_t>& arena_positions = scratch->arena_positions;
    std::vector<uint32_t>& group_positions = scratch->group_positions;
    std::vector<uint32_t>& merge_positions = scratch->merge_positions;
    std::vector<uint32_t>& run_lengths = scratch->run_lengths;
    std::vector<uint32_t>& next_run_lengths = scratch->next_run_lengths;

    radix_sort_runs_by_stored_key(&runs, &radix_tmp);

    FusedHashSink sink;
    fused_hash_sink_init(&sink);

    size_t group_start = 0;
    while (group_start < runs.size()) {
        size_t group_end = group_start + 1;
        while (group_end < runs.size() &&
               runs[group_start].key == runs[group_end].key) {
            ++group_end;
        }

        if (group_end == group_start + 1) {
            const Stage5Run& run = runs[group_start];
            const uint32_t run_count = stage5_run_count(run);
            if (!stage5_run_is_literal(run)) {
                const uint32_t run_begin = stage5_run_begin(run);
                fused_hash_sink_write_positions(
                    &sink, arena_positions.data() + run_begin, run_count);
            } else {
                fused_hash_sink_write_pos(&sink, stage5_run_begin(run));
            }
        } else if (!fused_try_hash_literal_equal_key_group_after_key(
                       view, runs, group_start, group_end, &sink) &&
                   !fused_try_hash_two_equal_key_runs_after_key(
                       view, arena_positions, runs, group_start, group_end,
                       &sink)) {
            group_positions.clear();
            run_lengths.clear();
            size_t group_positions_count = 0;
            for (size_t i = group_start; i < group_end; ++i) {
                const uint32_t count = stage5_run_count(runs[i]);
                group_positions_count += count;
                run_lengths.push_back(count);
            }
            group_positions.reserve(group_positions_count);
            for (size_t i = group_start; i < group_end; ++i) {
                const Stage5Run& run = runs[i];
                const uint32_t run_count = stage5_run_count(run);
                for (uint32_t rel = 0; rel < run_count; ++rel) {
                    group_positions.push_back(
                        fused_run_pos(arena_positions, run, rel));
                }
            }
            merge_equal_key_runs_after_key(view, &group_positions,
                                           &merge_positions, &run_lengths,
                                           &next_run_lengths);
            fused_hash_sink_write_positions(
                &sink, group_positions.data(),
                static_cast<uint32_t>(group_positions.size()));
        }
        group_start = group_end;
    }

    if (sink.positions != view.logical_len) {
        return false;
    }
    fused_hash_sink_final(&sink, out_hash);
    return true;
}

bool stage_v114_sa_build_libsais(const Stage5InputView& view,
                                 uint8_t* out, size_t out_cap, size_t* out_len) {
    const uint64_t needed = static_cast<uint64_t>(view.logical_len) * 4u;
    if (needed > std::numeric_limits<size_t>::max() || out_cap < needed) {
        return false;
    }
    if (view.logical_len > static_cast<uint32_t>(std::numeric_limits<int32_t>::max())) {
        return false;
    }

    std::vector<int32_t> sa(view.logical_len);
    const int32_t rc = libsais(view.data, sa.data(),
                               static_cast<int32_t>(view.logical_len), 0, nullptr);
    if (rc != 0) return false;

    for (uint32_t i = 0; i < view.logical_len; ++i) {
        write_u32_le(out + static_cast<size_t>(i) * 4u,
                     static_cast<uint32_t>(sa[i]));
    }

    *out_len = static_cast<size_t>(needed);
    return true;
}

bool stage_v114_sa_build_descriptor(const Stage5InputView& view,
                                    uint8_t* out, size_t out_cap, size_t* out_len) {
    const uint64_t needed = static_cast<uint64_t>(view.logical_len) * 4u;
    if (needed > std::numeric_limits<size_t>::max() || out_cap < needed) {
        return false;
    }
    if ((view.int_len % 4u) != 0 || (view.desc_len % 8u) != 0) {
        return false;
    }

    const uint32_t arena_count = view.int_len / 4u;
    static thread_local bool active = false;
    if (active) {
        return false;
    }
    Stage5DescriptorGuard guard(&active);

    // Leak the per-thread scratch intentionally: MinGW emutls has documented
    // destructor hazards in this tree, and descriptor mode is bench-only.
    static thread_local Stage5Scratch* scratch = nullptr;
    if (!scratch) {
        scratch = new Stage5Scratch;
    }

    std::vector<Stage5Run>& runs = scratch->runs;
    std::vector<Stage5Run>& radix_tmp = scratch->radix_tmp;
    std::vector<Stage5HeapNode>& heap = scratch->heap;
    std::vector<uint32_t>& seen_generation = scratch->seen_generation;
    if (++scratch->generation == 0) {
        std::fill(seen_generation.begin(), seen_generation.end(), 0);
        scratch->generation = 1;
    }
    const uint32_t generation = scratch->generation;
    if (seen_generation.size() < view.logical_len) {
        seen_generation.resize(view.logical_len, 0);
    }

    // Captured DLS5IN descriptor runs are already internally suffix-sorted.
    // Descriptor mode validates bounds, duplicates, and key/position matches,
    // then preserves that run order and merges only across equal-key runs.
    runs.clear();
    runs.reserve(view.desc_len / 8u);
    size_t total_positions = 0;

    for (uint32_t desc_off = 0; desc_off < view.desc_len; desc_off += 8u) {
        const uint32_t key = read_u32_le(view.desc + desc_off);
        const uint32_t packed = read_u32_le(view.desc + desc_off + 4u);
        const uint32_t count = packed >> 17;
        const uint32_t arena_index = packed & 0x1ffffu;

        if (count == 0 || arena_index > arena_count ||
            count > arena_count - arena_index) {
            return false;
        }
        if (total_positions > view.logical_len ||
            static_cast<size_t>(count) > view.logical_len - total_positions) {
            return false;
        }

        uint32_t prev_pos = 0;
        bool have_prev = false;
        for (uint32_t rel = 0; rel < count; ++rel) {
            const uint32_t pos =
                read_u32_le(view.int_arena + static_cast<size_t>(arena_index + rel) * 4u);
            if (pos >= view.logical_len) {
                return false;
            }
            if (seen_generation[pos] == generation) {
                return false;
            }
            if (load24_padded(view, pos) != key) {
                return false;
            }
            if (have_prev && compare_suffixes(view, prev_pos, pos) > 0) {
                return false;
            }
            seen_generation[pos] = generation;
            prev_pos = pos;
            have_prev = true;
        }
        runs.push_back(make_stage5_run(key, arena_index, count, false));
        total_positions += count;
    }

    if (total_positions > view.logical_len) {
        return false;
    }
    if (total_positions < view.logical_len) {
        for (uint32_t pos = 0; pos < view.logical_len; ++pos) {
            if (seen_generation[pos] == generation) continue;
            if (!suffix_is_zero_tail(view, pos)) {
                return false;
            }
            seen_generation[pos] = generation;
            runs.push_back(make_stage5_run(load24_padded(view, pos), pos, 1, true));
            ++total_positions;
        }
    }
    if (total_positions != view.logical_len) {
        return false;
    }

    radix_sort_runs_by_key(&runs, &radix_tmp);

    size_t group_start = 0;
    size_t out_pos = 0;
    while (group_start < runs.size()) {
        size_t group_end = group_start + 1;
        while (group_end < runs.size() &&
               runs[group_start].key == runs[group_end].key) {
            ++group_end;
        }

        if (group_end == group_start + 1) {
            const Stage5Run& run = runs[group_start];
            const uint32_t run_count = stage5_run_count(run);
            const uint32_t run_begin = stage5_run_begin(run);
            if (!stage5_run_is_literal(run)) {
                const size_t bytes = static_cast<size_t>(run_count) * 4u;
                std::memcpy(out + out_pos * 4u,
                            view.int_arena + static_cast<size_t>(run_begin) * 4u,
                            bytes);
                out_pos += run_count;
            } else {
                write_u32_le(out + out_pos * 4u, run_begin);
                ++out_pos;
            }
        } else {
            heap.clear();
            heap.reserve(group_end - group_start);
            for (size_t i = group_start; i < group_end; ++i) {
                heap.push_back(Stage5HeapNode{static_cast<uint32_t>(i), 0});
            }

            auto heap_less = [&](const Stage5HeapNode& a, const Stage5HeapNode& b) {
                const Stage5Run& ar = runs[a.run];
                const Stage5Run& br = runs[b.run];
                const uint32_t apos = stage5_run_pos(view, ar, a.rel);
                const uint32_t bpos = stage5_run_pos(view, br, b.rel);
                const int cmp = compare_suffixes_after_key(view, apos, bpos);
                if (cmp != 0) return cmp > 0;
                return apos > bpos;
            };

            std::make_heap(heap.begin(), heap.end(), heap_less);
            while (!heap.empty()) {
                std::pop_heap(heap.begin(), heap.end(), heap_less);
                Stage5HeapNode node = heap.back();
                heap.pop_back();

                const Stage5Run& run = runs[node.run];
                write_u32_le(out + out_pos * 4u,
                             stage5_run_pos(view, run, node.rel));
                ++out_pos;

                ++node.rel;
                if (node.rel < stage5_run_count(run)) {
                    heap.push_back(node);
                    std::push_heap(heap.begin(), heap.end(), heap_less);
                }
            }
        }
        group_start = group_end;
    }

    if (out_pos != view.logical_len) {
        *out_len = 0;
        return false;
    }

    *out_len = static_cast<size_t>(needed);
    return true;
}

bool stage_v114_sa_build_descriptor_trusted(const Stage5InputView& view,
                                            uint8_t* out, size_t out_cap,
                                            size_t* out_len) {
    const uint64_t needed = static_cast<uint64_t>(view.logical_len) * 4u;
    if (needed > std::numeric_limits<size_t>::max() || out_cap < needed) {
        return false;
    }
    if ((view.int_len % 4u) != 0 || (view.desc_len % 8u) != 0) {
        return false;
    }

    const uint32_t arena_count = view.int_len / 4u;
    static thread_local bool active = false;
    if (active) {
        return false;
    }
    Stage5DescriptorGuard guard(&active);

    static thread_local Stage5Scratch* scratch = nullptr;
    if (!scratch) {
        scratch = new Stage5Scratch;
    }

    std::vector<uint32_t>& group_positions = scratch->group_positions;
    std::vector<uint32_t>& merge_positions = scratch->merge_positions;
    std::vector<uint32_t>& run_lengths = scratch->run_lengths;
    std::vector<uint32_t>& next_run_lengths = scratch->next_run_lengths;
    std::vector<Stage5Run>& runs = scratch->runs;
    std::vector<Stage5Run>& radix_tmp = scratch->radix_tmp;
    group_positions.clear();
    merge_positions.clear();
    run_lengths.clear();
    next_run_lengths.clear();
    runs.clear();
    runs.reserve(view.desc_len / 8u);

    size_t total_positions = 0;
    for (uint32_t desc_off = 0; desc_off < view.desc_len; desc_off += 8u) {
        const uint32_t key = read_u32_le(view.desc + desc_off);
        const uint32_t packed = read_u32_le(view.desc + desc_off + 4u);
        const uint32_t count = packed >> 17;
        const uint32_t arena_index = packed & 0x1ffffu;

        if (count == 0) {
            if (arena_index >= view.logical_len) {
                return false;
            }
            if (total_positions >= view.logical_len) {
                return false;
            }
            runs.push_back(make_stage5_run(key, arena_index, 1, true));
            ++total_positions;
            continue;
        }

        if (count == 0 || arena_index > arena_count ||
            count > arena_count - arena_index) {
            return false;
        }
        if (total_positions > view.logical_len ||
            static_cast<size_t>(count) > view.logical_len - total_positions) {
            return false;
        }

        runs.push_back(make_stage5_run(key, arena_index, count, false));
        total_positions += count;
    }
    if (total_positions != view.logical_len) {
        return false;
    }

    radix_sort_runs_by_key(&runs, &radix_tmp);

    size_t group_start = 0;
    size_t out_pos = 0;
    while (group_start < runs.size()) {
        size_t group_end = group_start + 1;
        while (group_end < runs.size() &&
               runs[group_start].key == runs[group_end].key) {
            ++group_end;
        }

        if (group_end == group_start + 1) {
            const Stage5Run& run = runs[group_start];
            const uint32_t run_count = stage5_run_count(run);
            const uint32_t run_begin = stage5_run_begin(run);
            if (!stage5_run_is_literal(run)) {
                const size_t bytes = static_cast<size_t>(run_count) * 4u;
                std::memcpy(out + out_pos * 4u,
                            view.int_arena + static_cast<size_t>(run_begin) * 4u,
                            bytes);
                out_pos += run_count;
            } else {
                write_u32_le(out + out_pos * 4u, run_begin);
                ++out_pos;
            }
        } else if (!try_write_literal_equal_key_group_after_key(
                       view, runs, group_start, group_end, out, &out_pos) &&
                   !try_write_two_equal_key_runs_after_key(
                       view, runs, group_start, group_end, out, &out_pos)) {
            group_positions.clear();
            run_lengths.clear();
            size_t group_positions_count = 0;
            for (size_t i = group_start; i < group_end; ++i) {
                const uint32_t count = stage5_run_count(runs[i]);
                group_positions_count += count;
                run_lengths.push_back(count);
            }
            group_positions.reserve(group_positions_count);
            for (size_t i = group_start; i < group_end; ++i) {
                const Stage5Run& run = runs[i];
                const uint32_t run_count = stage5_run_count(run);
                for (uint32_t rel = 0; rel < run_count; ++rel) {
                    group_positions.push_back(
                        stage5_run_pos(view, run, rel));
                }
            }
            merge_equal_key_runs_after_key(view, &group_positions, &merge_positions,
                                           &run_lengths, &next_run_lengths);
            for (uint32_t pos : group_positions) {
                write_u32_le(out + out_pos * 4u, pos);
                ++out_pos;
            }
        }
        group_start = group_end;
    }

    if (out_pos != view.logical_len) {
        *out_len = 0;
        return false;
    }

    *out_len = static_cast<size_t>(needed);
    return true;
}

}  // namespace

bool stage_v114_encode(const uint8_t* in, size_t in_len,
                       uint8_t* out, size_t out_cap, size_t* out_len) {
    if (out_len) *out_len = 0;
    if (!in || !out || !out_len) return false;

    Stage4InputView view;
    if (!parse_stage4_input(in, in_len, &view)) return false;

    const uint64_t max_out = static_cast<uint64_t>(view.logical_len) * 8u;
    if (max_out > std::numeric_limits<size_t>::max() || out_cap < max_out) {
        return false;
    }

    const uint32_t full_groups = view.logical_len >> 8;
    uint32_t run_start = 0;
    size_t records = 0;

    for (uint32_t group = 1; group <= full_groups; ++group) {
        if (view.flags[group] != 0 || group == full_groups) {
            if (!emit_full_group_run(view, run_start, group, out, out_cap, &records)) {
                *out_len = 0;
                return false;
            }
            run_start = group;
        }
    }

    emit_direct_records(view, full_groups << 8, view.logical_len & 0xffu,
                        out, &records);

    *out_len = records * 8u;
    return true;
}

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
                                      size_t* int_arena_len) {
    if (desc_len) *desc_len = 0;
    if (int_arena_len) *int_arena_len = 0;
    if (!data || !flags || !desc_out || !desc_len ||
        !int_arena_out || !int_arena_len) {
        return false;
    }
    if (logical_len == 0 || logical_len > kDescriptorArenaIndexCount ||
        data_len < logical_len) {
        return false;
    }
    const uint32_t group_limit = logical_len >> 8;
    if (flag_len <= group_limit) {
        return false;
    }

    const uint64_t max_desc = static_cast<uint64_t>(logical_len) * 8u;
    if (max_desc > std::numeric_limits<size_t>::max() || desc_cap < max_desc) {
        return false;
    }
    if (!init_identity_arena(int_arena_out, int_arena_cap,
                             logical_len, int_arena_len)) {
        return false;
    }

    Stage4InputView view{};
    view.logical_len = logical_len;
    view.data_len = data_len;
    view.flag_len = flag_len;
    view.flags = flags;
    view.data = data;

    const uint32_t full_groups = logical_len >> 8;
    uint32_t run_start = 0;
    size_t records = 0;

    for (uint32_t group = 1; group <= full_groups; ++group) {
        if (view.flags[group] != 0 || group == full_groups) {
            if (!emit_full_group_run(view, run_start, group,
                                     desc_out, desc_cap, &records,
                                     int_arena_out, int_arena_cap)) {
                *desc_len = 0;
                *int_arena_len = 0;
                return false;
            }
            run_start = group;
        }
    }

    emit_direct_records(view, full_groups << 8, logical_len & 0xffu,
                        desc_out, &records);

    *desc_len = records * 8u;
    return true;
}

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
                                   size_t* int_arena_len) {
    if (desc_len) *desc_len = 0;
    if (int_arena_len) *int_arena_len = 0;
    if (!data || !flags || !desc_out || !desc_len ||
        !int_arena_out || !int_arena_len) {
        return false;
    }
    if (logical_len == 0 || logical_len > kDescriptorArenaIndexCount ||
        data_len < logical_len) {
        return false;
    }
    const uint32_t group_limit = logical_len >> 8;
    if (flag_len <= group_limit) {
        return false;
    }

    const uint64_t max_desc = static_cast<uint64_t>(logical_len) * 8u;
    if (max_desc > std::numeric_limits<size_t>::max() || desc_cap < max_desc) {
        return false;
    }

    Stage4InputView view{};
    view.logical_len = logical_len;
    view.data_len = data_len;
    view.flag_len = flag_len;
    view.flags = flags;
    view.data = data;

    const uint32_t full_groups = logical_len >> 8;
    uint32_t run_start = 0;
    size_t records = 0;
    uint32_t arena_entries = 0;
    static const bool count1_singletons =
        env_flag_enabled("DLUNA_STAGE5_COUNT1_SINGLETONS");

    for (uint32_t group = 1; group <= full_groups; ++group) {
        if (view.flags[group] != 0 || group == full_groups) {
            if (!emit_full_group_run_compact(view, run_start, group,
                                              desc_out, desc_cap, &records,
                                              int_arena_out, int_arena_cap,
                                              &arena_entries,
                                              count1_singletons)) {
                *desc_len = 0;
                *int_arena_len = 0;
                return false;
            }
            run_start = group;
        }
    }

    if (!emit_compact_literal_records(view, full_groups << 8,
                                       logical_len & 0xffu,
                                       desc_out, desc_cap, &records,
                                       count1_singletons, int_arena_out,
                                       int_arena_cap, &arena_entries)) {
        return false;
    }

    *desc_len = records * 8u;
    *int_arena_len = static_cast<size_t>(arena_entries) * 4u;
    return true;
}

bool stage_v114_sa_build_compact_fused_raw(const uint8_t* data,
                                           uint32_t logical_len,
                                           uint32_t data_len,
                                           const uint8_t* flags,
                                           uint32_t flag_len,
                                           uint8_t* out,
                                           size_t out_cap,
                                           size_t* out_len) {
    if (out_len) *out_len = 0;
    if (!data || !flags || !out || !out_len) {
        return false;
    }
    if (logical_len == 0 || logical_len > kDescriptorArenaIndexCount ||
        data_len < logical_len) {
        return false;
    }
    const uint32_t group_limit = logical_len >> 8;
    if (flag_len <= group_limit) {
        return false;
    }

    Stage4InputView stage4{};
    stage4.logical_len = logical_len;
    stage4.data_len = data_len;
    stage4.flag_len = flag_len;
    stage4.flags = flags;
    stage4.data = data;

    Stage5InputView stage5{};
    stage5.logical_len = logical_len;
    stage5.data_len = data_len;
    stage5.data = data;

    static thread_local FusedStage5Scratch* scratch = nullptr;
    if (!scratch) {
        scratch = new FusedStage5Scratch;
    }

    scratch->arena_positions.clear();
    scratch->group_positions.clear();
    scratch->merge_positions.clear();
    scratch->run_lengths.clear();
    scratch->next_run_lengths.clear();
    scratch->runs.clear();
    scratch->arena_positions.reserve(logical_len);
    scratch->runs.reserve(logical_len);

    const uint32_t full_groups = logical_len >> 8;
    uint32_t run_start = 0;
    static const bool count1_singletons =
        env_flag_enabled("DLUNA_STAGE5_COUNT1_SINGLETONS");

    FusedStage5Profile* profile =
        fused_stage5_profile_enabled() ? &fused_stage5_profile() : nullptr;
    const uint64_t total0 = profile ? stage5_prof_rdtsc() : 0;
    const uint64_t emit0 = profile ? stage5_prof_rdtsc() : 0;
    for (uint32_t group = 1; group <= full_groups; ++group) {
        if (stage4.flags[group] != 0 || group == full_groups) {
            if (!emit_full_group_run_compact_fused(stage4, run_start, group,
                                                   scratch,
                                                   count1_singletons)) {
                *out_len = 0;
                return false;
            }
            run_start = group;
        }
    }

    if (!emit_fused_literal_records(stage4, full_groups << 8,
                                    logical_len & 0xffu, scratch,
                                    count1_singletons)) {
        *out_len = 0;
        return false;
    }
    if (profile) profile->emit += stage5_prof_rdtsc() - emit0;
    fused_stage5_profile_note_emit_shape(
        profile, scratch->runs, scratch->arena_positions);

    const bool ok = write_fused_runs_to_sa(stage5, scratch, out, out_cap, out_len);
    if (profile) {
        profile->total += stage5_prof_rdtsc() - total0;
        profile->runs += scratch->runs.size();
        profile->arena += scratch->arena_positions.size();
        ++profile->calls;
        fused_stage5_profile_maybe_flush(profile);
    }
    return ok;
}

bool stage_v114_hash_compact_fused_raw(const uint8_t* data,
                                       uint32_t logical_len,
                                       uint32_t data_len,
                                       const uint8_t* flags,
                                       uint32_t flag_len,
                                       uint8_t out_hash[32]) {
    if (!data || !flags || !out_hash) {
        return false;
    }
    if (logical_len == 0 || logical_len > kDescriptorArenaIndexCount ||
        data_len < logical_len) {
        return false;
    }
    const uint32_t group_limit = logical_len >> 8;
    if (flag_len <= group_limit) {
        return false;
    }

    Stage4InputView stage4{};
    stage4.logical_len = logical_len;
    stage4.data_len = data_len;
    stage4.flag_len = flag_len;
    stage4.flags = flags;
    stage4.data = data;

    Stage5InputView stage5{};
    stage5.logical_len = logical_len;
    stage5.data_len = data_len;
    stage5.data = data;

    static thread_local FusedStage5Scratch* scratch = nullptr;
    if (!scratch) {
        scratch = new FusedStage5Scratch;
    }

    scratch->arena_positions.clear();
    scratch->group_positions.clear();
    scratch->merge_positions.clear();
    scratch->run_lengths.clear();
    scratch->next_run_lengths.clear();
    scratch->runs.clear();
    scratch->arena_positions.reserve(logical_len);
    scratch->runs.reserve(logical_len);

    const uint32_t full_groups = logical_len >> 8;
    uint32_t run_start = 0;
    static const bool count1_singletons =
        env_flag_enabled("DLUNA_STAGE5_COUNT1_SINGLETONS");

    for (uint32_t group = 1; group <= full_groups; ++group) {
        if (stage4.flags[group] != 0 || group == full_groups) {
            if (!emit_full_group_run_compact_fused(stage4, run_start, group,
                                                   scratch,
                                                   count1_singletons)) {
                return false;
            }
            run_start = group;
        }
    }

    if (!emit_fused_literal_records(stage4, full_groups << 8,
                                    logical_len & 0xffu, scratch,
                                    count1_singletons)) {
        return false;
    }

    return write_fused_runs_to_hash(stage5, scratch, out_hash);
}

bool stage_v114_sa_build(const uint8_t* in, size_t in_len,
                         uint8_t* out, size_t out_cap, size_t* out_len) {
    return stage_v114_sa_build_with_mode(in, in_len, out, out_cap, out_len,
                                         Stage5SaBuildMode::Libsais);
}

bool stage_v114_sa_build_with_mode(const uint8_t* in, size_t in_len,
                                   uint8_t* out, size_t out_cap, size_t* out_len,
                                   Stage5SaBuildMode mode) {
    if (out_len) *out_len = 0;
    if (!in || !out || !out_len) return false;

    Stage5InputView view;
    if (!parse_stage5_input(in, in_len, &view)) return false;

    switch (mode) {
    case Stage5SaBuildMode::Libsais:
        return stage_v114_sa_build_libsais(view, out, out_cap, out_len);
    case Stage5SaBuildMode::DescriptorArena:
        return stage_v114_sa_build_descriptor(view, out, out_cap, out_len);
    }

    return false;
}

bool stage_v114_sa_build_descriptor_raw(const uint8_t* data,
                                        uint32_t logical_len,
                                        uint32_t data_len,
                                        const uint8_t* int_arena,
                                        uint32_t int_len,
                                        const uint8_t* desc,
                                        uint32_t desc_len,
                                        uint8_t* out,
                                        size_t out_cap,
                                        size_t* out_len) {
    if (out_len) *out_len = 0;
    if (!data || !out || !out_len) {
        return false;
    }
    if (logical_len == 0 || data_len < logical_len) {
        return false;
    }
    if ((int_len != 0 && !int_arena) || (desc_len != 0 && !desc)) {
        return false;
    }

    Stage5InputView view{};
    view.logical_len = logical_len;
    view.data_len = data_len;
    view.int_len = int_len;
    view.desc_len = desc_len;
    view.data = data;
    view.int_arena = int_arena;
    view.desc = desc;
    return stage_v114_sa_build_descriptor(view, out, out_cap, out_len);
}

bool stage_v114_sa_build_descriptor_trusted_raw(const uint8_t* data,
                                                uint32_t logical_len,
                                                uint32_t data_len,
                                                const uint8_t* int_arena,
                                                uint32_t int_len,
                                                const uint8_t* desc,
                                                uint32_t desc_len,
                                                uint8_t* out,
                                                size_t out_cap,
                                                size_t* out_len) {
    if (out_len) *out_len = 0;
    if (!data || !out || !out_len) {
        return false;
    }
    if (logical_len == 0 || data_len < logical_len) {
        return false;
    }
    if ((int_len != 0 && !int_arena) || (desc_len != 0 && !desc)) {
        return false;
    }

    Stage5InputView view{};
    view.logical_len = logical_len;
    view.data_len = data_len;
    view.int_len = int_len;
    view.desc_len = desc_len;
    view.data = data;
    view.int_arena = int_arena;
    view.desc = desc;
    return stage_v114_sa_build_descriptor_trusted(view, out, out_cap, out_len);
}

}  // namespace deroluna::stages::v114
