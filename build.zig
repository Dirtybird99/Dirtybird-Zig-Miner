const std = @import("std");

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

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const pgo = b.option([]const u8, "pgo", "PGO for the C/C++ suffix array: gen | use (default: off)") orelse "off";
    const profile_rt = b.option([]const u8, "profile_rt", "Path to libclang_rt.profile-x86_64.a (required for -Dpgo=gen)");

    const exe = b.addExecutable(.{
        .name = "zig-miner",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    addSaDeps(exe, b, pgo, profile_rt);
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
    addSaDeps(bench, b, pgo, profile_rt);
    b.installArtifact(bench);
    const bench_run = b.addRunArtifact(bench);
    if (b.args) |args| bench_run.addArgs(args);
    const bench_step = b.step("bench", "Run the synthetic hashrate benchmark");
    bench_step.dependOn(&bench_run.step);
}
