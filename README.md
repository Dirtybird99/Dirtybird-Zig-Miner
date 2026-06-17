# Dirtybird Zig Miner

A clean-room [Zig](https://ziglang.org) port of the AstroBWTv3 DERO CPU miner, by the Dirtybird author ([GitHub: Dirtybird99](https://github.com/Dirtybird99)). It is a from-scratch reimplementation of DERO's AstroBWTv3 proof-of-work — `SHA256 -> Salsa20 -> RC4 -> FNV1a -> wolfCompute -> suffix array -> SHA256` — that is **byte-exact with the reference** miner, wrapped in a smaller, memory-safe codebase: the entire pipeline orchestration, mining loop, and TLS-WebSocket getwork client are pure Zig, with the suffix-array stage shared with the reference (see [Layout](#layout)).

## Key result

At **10 threads**, on the same machine and the same pool, heat-soaked, this miner out-hashes the reference `dirtybird` v1.0.20 C miner by **~10%** (with the optimized/PGO build — see [Build](#build)).

The advantage is structural and per-hash, not a scheduling trick. This port runs the **identical suffix-array construction and identical wolfCompute** as the reference, so every stage except the last does the same work in the same time. The win comes entirely from the **final SHA-256**: the SA byte buffer (~270 KB) is hashed through a **batched 2-way multi-buffer SHA-NI** path. A single SHA-NI stream is latency-bound — each `sha256rnds2` depends on the previous one — so interleaving the instruction streams of two independent nonces lets the out-of-order engine overlap the dependent chains and reclaim idle SHA-port cycles. The result is a strictly faster, **byte-identical** final hash.

The multi-buffer round body is written as **pure legacy-SSE inline assembly** (the canonical Intel `sha256_process_x86` sequence: `movdqu/pshufd/pshufb/palignr/pblendw/paddd/sha256{rnds2,msg1,msg2}` only). This is deliberate: letting the compiler lower the round through VEX/256-bit ops dirties the YMM upper half every block and makes each legacy-SSE `sha256rnds2` pay a ~70-cycle AVX→SSE transition penalty. Keeping the hot loop strictly in the SSE domain avoids that entirely.

**Honest bounds.** The two-way SHA speedup is throughput-bound by the single shared SHA execution port. On **Raptor Cove** the ceiling is **~1.3×** for the final-hash stage (not 2×); AMD Zen's wider SHA units reach the textbook ~1.5–1.7×, but this is a single SHA port. Because the final SHA is only part of the per-hash cost, that ~1.3× SHA edge nets out to the ~10% end-to-end figure above. Numbers were taken heat-soaked, at 10 threads, on the same physical machine and pool as the reference, using the PGO build; treat them as machine-specific, not a universal claim.

**Correctness** is validated three ways and is a hard precondition for the speed claim — a faster wrong hash is a rejected share:

- **KAT:** `pow("a") == 54e2324ddacc3f0383501a9e5760f85d63e9bc6705e9124ca7aef89016ab81ea` (checked at every startup; the miner refuses to run if it fails — run it standalone with `--selftest`).
- **Per-stage parity** against a faithful C++ reference oracle (SHA, Salsa20, RC4, FNV1a, wolfCompute output + length, SA bytes, final hash) on fixed inputs.
- **Differential fuzz** vs the oracle: 32,000+ random inputs, 0 mismatches.

The batched final SHA is independently checked to be byte-identical to `std.crypto`'s SHA-256 for each message, so the multi-buffer path changes timing only, never output.

## Algorithm (AstroBWTv3)

```
hash(input) = SHA256( SuffixArray( wolfCompute( FNV1a( RC4( Salsa20( SHA256(input) ) ) ) ) ) )
```

1. `SHA256(input)` → 32-byte key
2. `Salsa20/20(key, iv=0)` → 256-byte keystream
3. `RC4` over the keystream in place; RC4 state persists into wolfCompute
4. `FNV1a-64` seeds the rolling hash; the 256-byte block seeds `sData`
5. **wolfCompute** — a 278-iteration byte-permutation loop (CodeLUT opcodes, with XXHash64 / FNV1a / HighwayHash-SipHash re-mixing gated on the data) producing a variable-length buffer
6. **suffix array** of that buffer
7. `SHA256` over the SA position bytes → final 32-byte hash

A suffix array is unique for a given string, so step 6 is byte-identical across every conformant implementation; step 7's input is therefore the same bytes the daemon hashes.

## Build

Requirements:

- **Zig 0.14.1** (pinned).
- An **x86-64 CPU with SHA-NI and AVX2** (e.g. Intel Raptor Lake / Alder Lake, or AMD Zen). The accelerated final hash requires `+sha`; the build targets `+avx2`. On a host without these features the SHA path compiles and runs but falls back to `std.crypto`.

Build the miner:

```sh
zig build -Doptimize=ReleaseFast -Dcpu=native
```

The binary lands at `zig-out/bin/zig-miner` (`zig-miner.exe` on Windows).

**Optional PGO (recommended for the headline performance).** The C/C++ suffix-array translation units — most of the per-hash cost — support a two-pass profile-guided build, which is what the ~10% result above was measured with:

```sh
# 1. instrumented build (needs your Clang profile runtime)
zig build -Doptimize=ReleaseFast -Dcpu=native -Dpgo=gen -Dprofile_rt=/path/to/libclang_rt.profile-x86_64.a
# 2. run it briefly to emit profiles into _pgo/, then merge:
llvm-profdata merge -output=_pgo/merged.profdata _pgo/*.profraw
# 3. rebuild folding the profile back in
zig build -Doptimize=ReleaseFast -Dcpu=native -Dpgo=use
```

## Quick start

The included **`script.sh`** is an interactive launcher: it builds the miner if needed, prompts you for your daemon/pool address and DERO wallet, then starts mining.

```sh
./script.sh
```

```
Daemon/pool address (host:port): pool.example:10100
DERO wallet address: dero1q...your_wallet...
Threads [10]: 10
```

On Windows, run it from Git Bash (`bash script.sh`). It is a thin wrapper around the flags documented below.

## Usage

```sh
zig-miner -d pool.example:10100 -w dero1q...your_wallet... -t 10
```

> The host and wallet above are placeholders. Supply your own DERO pool/daemon and a valid checksummed DERO wallet address.

| Flag | Meaning |
|------|---------|
| `-d host:port` | Daemon/pool address. The miner connects over TLS-WebSocket to `wss://host/ws/{wallet}` (DERO getwork). |
| `-w <dero-wallet>` | Your DERO wallet address. **Required to mine.** Must be a valid checksummed address — pools reject malformed addresses at the upgrade. |
| `-t <threads>` | Number of mining threads. Defaults to the logical CPU count. |
| `-V` | Verbose output. |
| `--selftest` | Run the `pow("a")` known-answer test and exit (`0` = PASS, `1` = FAIL). Mines nothing. |
| `-h`, `--help` | Print usage and exit. |
| `-v`, `--version` | Print version and exit. |

On startup the miner runs the KAT automatically and refuses to mine if it fails. The reporter line shows running time, height, blocks/miniblocks, submitted shares, difficulty, and current/average KH/s. `Ctrl-C` shuts down cleanly.

## Layout

```
src/
  main.zig          CLI, startup KAT, thread orchestration, reporter
  pow.zig           full AstroBWTv3 hash pipeline + per-nonce Worker scratch
  astrobwt.zig      wolfCompute (the 278-iteration branch core)
  codelut.zig       CodeLUT[256] opcode table
  suffix_array.zig  suffix-array stage (libsais wrapper / fallback)
  sa_v114.zig       descriptor suffix-array path (default backend)
  sha256_mb.zig     multi-buffer SHA-NI (1-way and batched 2-way), legacy-SSE asm
  miner.zig         mining thread: batched nonce search, target check, share staging
  net.zig           TLS-WebSocket getwork client (connect / job / submit / backoff)
  state.zig         shared MinerState (job + submit mailbox + counters)
  primitives/       sha256, salsa20, rc4, fnv1a, xxhash64, siphash
vendor/
  libsais/          canonical exact suffix array (Apache-2.0; the fallback path)
  v114/             the v1.14 descriptor suffix array (extern "C" wrapper; default)
```

Both suffix-array backends are compiled as C/C++ and linked through Zig's C interop. The **v1.14 descriptor** SA is the default (the same construction the reference miner uses); **libsais** is a drop-in fallback when the descriptor build declines a given input. Because a suffix array is unique for its input, both produce byte-identical results — the choice affects only speed.

## Credits & license

This project is licensed **MIT** (see [`LICENSE`](LICENSE)). It bundles third-party code under its own terms — see [`THIRD-PARTY-LICENSES`](THIRD-PARTY-LICENSES):

- **libsais** — © 2021–2025 Ilya Grebnov, licensed under **Apache-2.0**.
- The **descriptor suffix array** (`vendor/v114/`) is derived from [`dirtybird-miner`](https://github.com/Dirtybird99/dirtybird-miner) (MIT).
- The **SHA-NI** round sequence (`src/sha256_mb.zig`) is adapted from Intel's reference `sha256_process_x86` and the Zig standard library's `std.crypto`.

This is a clean-room reimplementation; the AstroBWTv3 algorithm and DERO protocol belong to their respective authors.
