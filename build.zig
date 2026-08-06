const std = @import("std");
const builtin = @import("builtin");

// Suffix-array dependencies, compiled as C/C++ and linked through Zig's C interop:
//   * libsais  -- canonical exact suffix array (the fallback path)
//   * the v1.14 "descriptor" suffix array -- exact, structure-aware, the default
//     backend; compiled from the dirtybird reference source and exposed via a
//     small extern "C" wrapper.
// The suffix array is most of the per-hash cost, so these are built with the
// reference's release flags (-DNDEBUG drops the libsais/v114 asserts from the hot
// path). -Dpgo=gen|use enables an optional two-pass profile-guided build.
fn addSaDeps(c: *std.Build.Step.Compile, b: *std.Build, pgo: []const u8, profile_rt: ?[]const u8) void {
    var cf = std.ArrayList([]const u8).init(b.allocator);
    var cppf = std.ArrayList([]const u8).init(b.allocator);
    cf.appendSlice(&.{ "-O3", "-DNDEBUG", "-fomit-frame-pointer", "-finline-functions", "-fno-sanitize=all" }) catch @panic("oom");
    cppf.appendSlice(&.{ "-O3", "-DNDEBUG", "-fomit-frame-pointer", "-finline-functions", "-fno-vectorize", "-fno-slp-vectorize", "-fno-sanitize=all", "-std=c++17" }) catch @panic("oom");

    if (std.mem.eql(u8, pgo, "gen")) {
        // Instrumented build: writes profiles to _pgo/ when the binary runs.
        cf.append("-fprofile-generate=_pgo") catch @panic("oom");
        cppf.append("-fprofile-generate=_pgo") catch @panic("oom");
        // Instrumentation needs your Clang profile runtime (libclang_rt.profile-*).
        // Provide it with -Dprofile_rt=<path>, e.g. the one shipped by your LLVM/MinGW.
        if (profile_rt) |p| {
            c.addObjectFile(.{ .cwd_relative = p });
        } else {
            std.debug.print(
                "build: -Dpgo=gen requires -Dprofile_rt=<path to libclang_rt.profile-x86_64.a>\n",
                .{},
            );
            @panic("missing -Dprofile_rt for -Dpgo=gen");
        }
    } else if (std.mem.eql(u8, pgo, "use")) {
        // Fold a previously-merged profile (llvm-profdata merge _pgo/*.profraw) back in.
        cf.appendSlice(&.{ "-fprofile-use=_pgo/merged.profdata", "-flto" }) catch @panic("oom");
        cppf.appendSlice(&.{ "-fprofile-use=_pgo/merged.profdata", "-flto" }) catch @panic("oom");
    }

    c.addCSourceFile(.{ .file = b.path("vendor/libsais/libsais.c"), .flags = cf.items });
    c.addCSourceFile(.{ .file = b.path("vendor/v114/sha_stub.c"), .flags = cf.items });
    c.addCSourceFile(.{ .file = b.path("vendor/v114/v114_stubs.cpp"), .flags = cppf.items });
    c.addCSourceFile(.{ .file = b.path("vendor/v114/v114_wrapper.cpp"), .flags = cppf.items });
    c.addIncludePath(b.path("vendor/libsais"));
    c.addIncludePath(b.path("vendor/v114"));
    c.linkLibC();
    c.linkLibCpp();
}

// ARMv8 crypto-extension SHA-256, compiled as its own object.
//
// std's Sha256 has a NEON sha256h/sha256su implementation gated at comptime on
// the `.sha2` CPU feature, but `aarch64-linux-musl` resolves to the `generic`
// model, which lacks it -- so every ARM build ran software SHA-256. Zig has no
// per-function target features, so the only way to emit those instructions from
// a baseline binary is a separate compilation unit that carries the feature.
// The call is guarded at runtime by a HWCAP probe (sha256_mb.armSha2Available),
// so the single arm64 artifact still runs on cores without the extension.
//
// Skipped when the main target already has `.sha2` (an explicit -Dcpu, or
// aarch64-macos, which baselines to apple_m1): std is already accelerated there
// and sha256_mb won't reference the extern.
fn addArmSha(
    b: *std.Build,
    art: *std.Build.Step.Compile,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    want_pie: bool,
) void {
    if (target.result.cpu.arch != .aarch64) return;
    if (std.Target.aarch64.featureSetHas(target.result.cpu.features, .sha2)) return;

    const hw_target = b.resolveTargetQuery(.{
        .cpu_arch = .aarch64,
        .os_tag = target.result.os.tag,
        .abi = target.result.abi,
        // `.sha2` alone, not `.crypto` -- the latter also drags in `.aes`.
        .cpu_features_add = std.Target.aarch64.featureSet(&.{.sha2}),
    });
    const obj = b.addObject(.{
        .name = "sha256_hw_arm",
        .root_source_file = b.path("src/sha256_hw_arm.zig"),
        .target = hw_target,
        .optimize = optimize,
    });
    // The miner is PIE on aarch64-linux; a non-PIC object would not relocate.
    if (want_pie) obj.root_module.pic = true;
    art.addObject(obj);
}

pub fn build(b: *std.Build) void {
    // Default to the best-performance configuration so a bare `zig build` (no flags)
    // produces the fastest binary for the BUILD HOST: ReleaseFast, the host's native
    // CPU on x86_64 (so AVX-512 hosts automatically get the gated 64-byte AVX-512
    // suffix-array kernels in src/sa_v114_pure.zig -- measured +5.9% on Zen5 vs the
    // x86_64_v3+sha baseline), and PGO when a local profile exists. A native binary
    // only runs on the build host (or a compatible CPU), so portable/release builds
    // pin a baseline explicitly: -Dcpu=x86_64_v3+sha (AVX2+SHA-NI), -Dtarget=...,
    // exactly as scripts/release.sh and CI do. All overridable via -Doptimize /
    // -Dtarget / -Dcpu / -Dpgo.
    const optimize = b.option(std.builtin.OptimizeMode, "optimize", "Optimization mode (default: ReleaseFast)") orelse .ReleaseFast;
    const version = b.option([]const u8, "version", "Version embedded in zig-miner (release builds set this from the tag)") orelse "dev";
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", version);

    var default_query: std.Target.Query = .{};
    if (builtin.target.cpu.arch == .x86_64) default_query = .{
        .cpu_arch = .x86_64,
        .cpu_model = .{ .native = {} },
    };
    const target = b.standardTargetOptions(.{ .default_target = default_query });

    // Position-independent executables. Android's loader (and Termux's system_linker_exec
    // path on Android 10+) only accepts ET_DYN; a non-PIE ET_EXEC binary is rejected with
    // "unexpected e_type: 2". So default PIE on for aarch64-linux (the arm64-linux-musl
    // Termux/ARM artifact, and a future aarch64-linux-android build). x86_64/Windows/macOS
    // keep Zig's defaults -- no PIE perf cost on the desktop hot path. Override with -Dpie.
    const pie_opt = b.option(bool, "pie", "Position-independent executable (auto: on for aarch64-linux, e.g. Android/Termux)");
    const want_pie = pie_opt orelse (target.result.os.tag == .linux and target.result.cpu.arch == .aarch64);

    const profile_rt = b.option([]const u8, "profile_rt", "Path to libclang_rt.profile-x86_64.a (required for -Dpgo=gen)");
    const pgo_opt = b.option([]const u8, "pgo", "PGO for the C/C++ suffix array: gen | use | off (default: use when _pgo/merged.profdata exists on x86_64)") orelse "use";

    // Resolve PGO: "use" applies only on x86_64 with the profile present; otherwise fall
    // back to plain ReleaseFast (byte-identical hash, just not profile-optimized) so a
    // bare build never fails on a fresh clone, a non-x86 target, or in CI.
    var pgo = pgo_opt;
    if (std.mem.eql(u8, pgo_opt, "use")) {
        const have_profile = blk: {
            b.build_root.handle.access("_pgo/merged.profdata", .{}) catch break :blk false;
            break :blk true;
        };
        if (!(have_profile and target.result.cpu.arch == .x86_64)) pgo = "off";
    }
    std.debug.print("build: optimize={s} cpu={s} pgo={s}\n", .{ @tagName(optimize), target.result.cpu.model.name, pgo });

    const exe = b.addExecutable(.{
        .name = "zig-miner",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (want_pie) exe.pie = true;
    addArmSha(b, exe, target, optimize, want_pie);
    exe.root_module.addOptions("build_options", build_options);
    // The miner is fully pure Zig -- no addSaDeps, no libc/libcpp, no C toolchain.
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Build and run the miner");
    run_step.dependOn(&run_cmd.step);

    // ---- synthetic hashrate benchmark (no network; used by the Benchmarks CI).
    // Usage: zig build bench -- <threads> <seconds> <aff 0/1> <affmode>
    const bench = b.addExecutable(.{
        .name = "bench",
        .root_source_file = b.path("src/bench.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (want_pie) bench.pie = true;
    addArmSha(b, bench, target, optimize, want_pie);
    b.installArtifact(bench);
    const bench_run = b.addRunArtifact(bench);
    if (b.args) |args| bench_run.addArgs(args);
    const bench_step = b.step("bench", "Run the synthetic hashrate benchmark");
    bench_step.dependOn(&bench_run.step);

    // ---- batched (2-nonce, multi-buffer SHA) hashrate benchmark — the production
    // path (miner.zig uses pow.hash2). Built from current source with the same
    // flags/PGO as the miner so its KH/s is the trustworthy baseline.
    // Usage: zig build bench2 -- <threads> <seconds> <aff 0/1> <affmode>
    const bench2 = b.addExecutable(.{
        .name = "bench2",
        .root_source_file = b.path("src/bench2.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (want_pie) bench2.pie = true;
    addArmSha(b, bench2, target, optimize, want_pie);
    b.installArtifact(bench2);
    const bench2_run = b.addRunArtifact(bench2);
    if (b.args) |args| bench2_run.addArgs(args);
    const bench2_step = b.step("bench2", "Run the batched multi-buffer hashrate benchmark");
    bench2_step.dependOn(&bench2_run.step);

    // ---- p95 tail-latency harness (the optimize-loop's metric; frozen ground
    // truth while a loop is running). Stdout contract: exactly one line
    // `p95_ns=<N>`. Usage: zig build p95 -- [pin] [repeats] [pairs] [hp]
    const p95 = b.addExecutable(.{
        .name = "p95bench",
        .root_source_file = b.path("src/p95bench.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (want_pie) p95.pie = true;
    addArmSha(b, p95, target, optimize, want_pie);
    b.installArtifact(p95);
    const p95_run = b.addRunArtifact(p95);
    if (b.args) |args| p95_run.addArgs(args);
    const p95_step = b.step("p95", "Run the p95 per-hash tail-latency harness");
    p95_step.dependOn(&p95_run.step);

    // ---- compile-time-instrumented stage profiler for the exact pure-Zig
    // production hash2 path. Usage: zig build prof -- [pairs] [repeats] [pin]
    const prof = b.addExecutable(.{
        .name = "prof",
        .root_source_file = b.path("src/prof.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (want_pie) prof.pie = true;
    addArmSha(b, prof, target, optimize, want_pie);
    b.installArtifact(prof);
    const prof_run = b.addRunArtifact(prof);
    if (b.args) |args| prof_run.addArgs(args);
    const prof_step = b.step("prof", "Run the pure-Zig production hash2 stage profiler");
    prof_step.dependOn(&prof_run.step);

    // ---- differential harness (`zig build difftest -- gen|check ...`): emit
    // deterministic inputs, or hash each and compare against `<in> <out>` pairs from a
    // reference (the C oracle, or a daemon harness). Wired so the fix for the
    // trailing-zero-strip hash bug can be checked against the real DERO daemon.
    const difftest = b.addExecutable(.{
        .name = "difftest",
        .root_source_file = b.path("src/difftest.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (want_pie) difftest.pie = true;
    addArmSha(b, difftest, target, optimize, want_pie);
    b.installArtifact(difftest);
    const difftest_run = b.addRunArtifact(difftest);
    if (b.args) |args| difftest_run.addArgs(args);
    const difftest_step = b.step("difftest", "Differential fuzz vs a reference (oracle or daemon)");
    difftest_step.dependOn(&difftest_run.step);

    // ---- unit + parity tests (KAT pow("a"), per-stage + full-pipeline parity).
    const tests = b.addTest(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (want_pie) tests.pie = true;
    addArmSha(b, tests, target, optimize, want_pie);
    tests.root_module.addOptions("build_options", build_options);
    addSaDeps(tests, b, pgo, profile_rt);
    const tests_run = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit + parity tests");
    test_step.dependOn(&tests_run.step);

    // ---- SA-as-DLL experiment (`zig build sa-dll`): build the descriptor SA as a
    // Zig-LTO'd shared library so the Rust miner can link the SA exactly as this miner
    // builds it (clang-19 + PGO + -flto, whole-program-LTO'd by Zig's own lld). addSaDeps
    // gives it the identical C/C++ compilation; sa_dll.zig re-exports the entry points.
    // This step is additive — the DLL is the one artifact a bare `zig build` skips.
    const sa_dll = b.addSharedLibrary(.{
        .name = "dero_sa",
        .root_source_file = b.path("sa_dll.zig"),
        .target = target,
        .optimize = optimize,
    });
    addSaDeps(sa_dll, b, pgo, profile_rt);
    const sa_dll_install = b.addInstallArtifact(sa_dll, .{});
    const sa_dll_step = b.step("sa-dll", "Build the descriptor SA as a Zig-LTO'd DLL (dero_sa.dll)");
    sa_dll_step.dependOn(&sa_dll_install.step);
}
