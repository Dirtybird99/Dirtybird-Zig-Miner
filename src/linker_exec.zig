//! linker_exec.zig -- argv normalization for Android's system_linker_exec.
//!
//! WHY THIS EXISTS: on Android 10+ Termux cannot execve() a binary in the app
//! data directory (W^X); it launches it through the system dynamic linker:
//!
//!     execve("/system/bin/linker64", [argv0, "/abs/path/zig-miner", args...])
//!
//! Bionic's linker never rewrites the kernel argument block on the stack --
//! bionic-linked programs compensate inside their own libc (the linker exports
//! `initial_linker_arg_count` through __libc_shared_globals). This binary is
//! static and reads argc/argv straight off the stack, so on-device it sees its
//! own absolute path at argv[1] and, before this module existed, fed it to the
//! flag parser: every Termux launch -- including a bare `./zig-miner` -- died
//! on the usage screen (issue #18).
//!
//! The auxv is equally unrewritten (AT_PHDR/AT_EXECFN describe the linker) and
//! /proc/self/exe points at linker64, so nothing derived from either can serve
//! as self-truth here. What CAN be trusted: termux-exec exports
//! TERMUX_EXEC__PROC_SELF_EXE with the real executable path, and the injected
//! argv[1] must be this very binary's file. `decide` shifts argv by exactly one
//! element only when that evidence lines up; everywhere else (Windows, macOS,
//! x86 Linux, direct kernel loads) it is a no-op, because a non-flag argv[1]
//! was already a guaranteed usage()+exit(1) -- the miner has no positional
//! arguments -- so a shift can never eat a meaningful argument.

const std = @import("std");
const builtin = @import("builtin");

/// Set by termux-exec for processes it routes through the system linker.
pub const real_exe_env = "TERMUX_EXEC__PROC_SELF_EXE";

/// Launch-state evidence. Pure inputs to `decide` so the decision is
/// unit-testable without an Android device.
pub const Evidence = struct {
    /// Value of TERMUX_EXEC__PROC_SELF_EXE (the real binary path), if set.
    env_real_exe: ?[]const u8 = null,
    /// /proc/self/exe (or AT_EXECFN) basename is "linker64" or "linker".
    self_exe_is_linker: bool = false,
    /// args[1] and env_real_exe name the same file (dev+ino). null = not determinable.
    arg1_same_file_as_env: ?bool = null,
    /// args[1] exists and is a regular file. null = not determinable.
    arg1_is_regular_file: ?bool = null,
};

pub const Verdict = struct {
    shift: bool,
    /// Static description of why; surfaced by --argdiag.
    reason: []const u8,
};

/// Pure shift decision over (argc, argv[1], evidence). argv[1] is passed as an
/// optional slice rather than the argv array so tests can use string literals.
pub fn decide(args_len: usize, arg1: ?[]const u8, ev: Evidence) Verdict {
    if (args_len < 2) return .{ .shift = false, .reason = "argc < 2" };
    const a1 = arg1 orelse return .{ .shift = false, .reason = "args[1] missing" };
    if (a1.len == 0) return .{ .shift = false, .reason = "args[1] empty" };
    if (a1[0] == '-') return .{ .shift = false, .reason = "args[1] is a flag" };
    if (ev.env_real_exe == null and !ev.self_exe_is_linker)
        return .{ .shift = false, .reason = "no linker-exec evidence" };

    if (ev.env_real_exe) |env_path| {
        if (ev.arg1_same_file_as_env) |same| {
            if (same) return .{ .shift = true, .reason = real_exe_env ++ " set; args[1] is this binary (dev/ino)" };
            return .{ .shift = false, .reason = "args[1] is not this binary" };
        }
        // stat unavailable: fall back to exact path equality, then to the
        // weaker linker-basename + regular-file combination.
        if (std.mem.eql(u8, a1, env_path))
            return .{ .shift = true, .reason = real_exe_env ++ " set; args[1] equals it" };
        if (ev.self_exe_is_linker and ev.arg1_is_regular_file == true)
            return .{ .shift = true, .reason = "launched via linker; args[1] is an existing file" };
        return .{ .shift = false, .reason = "args[1] could not be identified as this binary" };
    }

    // Linker-basename evidence alone: require args[1] to at least be a real file.
    if (ev.arg1_is_regular_file == true)
        return .{ .shift = true, .reason = "launched via linker; args[1] is an existing file" };
    return .{ .shift = false, .reason = "launched via linker but args[1] is not a regular file" };
}

pub fn basenameIsLinker(path: []const u8) bool {
    const b = std.fs.path.basename(path);
    return std.mem.eql(u8, b, "linker64") or std.mem.eql(u8, b, "linker");
}

pub const Normalized = struct {
    /// View into the original argsAlloc slice (raw[1..] when shifted). Never
    /// pass this to argsFree -- free the original slice.
    args: [][:0]u8,
    shifted: bool,
    reason: []const u8,
};

/// Gather evidence (Linux only; inert elsewhere) and apply `decide`.
pub fn normalizeArgs(raw: [][:0]u8) Normalized {
    const arg1: ?[]const u8 = if (raw.len >= 2) raw[1] else null;
    const v = decide(raw.len, arg1, gatherEvidence(arg1));
    return .{
        .args = if (v.shift) raw[1..] else raw,
        .shifted = v.shift,
        .reason = v.reason,
    };
}

/// Directory of the REAL executable (allocated), seeing through
/// system_linker_exec: env marker first, then /proc/self/exe unless it names
/// the linker, then dirname of the (normalized) argv[0] if absolute.
pub fn realExeDirAlloc(alloc: std.mem.Allocator, argv0: ?[]const u8) ?[]u8 {
    if (builtin.os.tag == .linux) {
        if (std.posix.getenv(real_exe_env)) |p| {
            if (p.len > 0 and std.fs.path.isAbsolute(p)) {
                if (std.fs.path.dirname(p)) |d| return alloc.dupe(u8, d) catch null;
            }
        }
    }
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    if (std.fs.selfExePath(&buf)) |p| {
        if (!(builtin.os.tag == .linux and basenameIsLinker(p))) {
            if (std.fs.path.dirname(p)) |d| return alloc.dupe(u8, d) catch null;
        }
    } else |_| {}
    if (argv0) |a0| {
        if (std.fs.path.isAbsolute(a0)) {
            if (std.fs.path.dirname(a0)) |d| return alloc.dupe(u8, d) catch null;
        }
    }
    return null;
}

fn gatherEvidence(arg1: ?[]const u8) Evidence {
    // if/else on the comptime-known tag so the non-taken branch is never
    // analyzed (getenv/fstatat/getauxval don't exist on all targets).
    if (builtin.os.tag == .linux) {
        var ev: Evidence = .{};

        if (std.posix.getenv(real_exe_env)) |p| {
            if (p.len > 0) ev.env_real_exe = p;
        }

        var buf: [std.fs.max_path_bytes]u8 = undefined;
        if (std.fs.selfExePath(&buf)) |p| {
            ev.self_exe_is_linker = basenameIsLinker(p);
        } else |_| {
            const execfn = std.os.linux.getauxval(std.elf.AT_EXECFN);
            if (execfn != 0) {
                const p = std.mem.span(@as([*:0]const u8, @ptrFromInt(execfn)));
                ev.self_exe_is_linker = basenameIsLinker(p);
            }
        }

        const a1 = arg1 orelse return ev;
        if (a1.len == 0 or a1[0] == '-') return ev;

        const st1: ?std.posix.Stat = std.posix.fstatat(std.posix.AT.FDCWD, a1, 0) catch null;
        if (st1) |s| ev.arg1_is_regular_file = std.posix.S.ISREG(s.mode);
        if (ev.env_real_exe) |env_path| {
            if (st1) |s1| {
                if (std.posix.fstatat(std.posix.AT.FDCWD, env_path, 0) catch null) |s2| {
                    ev.arg1_same_file_as_env = (s1.dev == s2.dev and s1.ino == s2.ino);
                }
            }
        }
        return ev;
    } else {
        return .{};
    }
}

// ---- --argdiag ----

/// Provided by the linker on ELF targets. Under linker-exec the auxv describes
/// the LINKER's image (AT_PHDR included), so this symbol is the only
/// auxv-independent way to find our own ELF header. Referenced exclusively
/// from Linux comptime branches; lazy analysis keeps other targets clean.
extern const __ehdr_start: std.elf.Ehdr;

fn ownPhdrs() []const std.elf.Phdr {
    const ehdr = &__ehdr_start;
    const addr = @intFromPtr(ehdr) + @as(usize, @intCast(ehdr.e_phoff));
    return @as([*]const std.elf.Phdr, @ptrFromInt(addr))[0..ehdr.e_phnum];
}

fn reportTls(label: []const u8, phdrs: []const std.elf.Phdr) void {
    if (phdrs.len == 0) {
        std.debug.print("{s}: <unavailable>\n", .{label});
        return;
    }
    for (phdrs) |*ph| {
        if (ph.p_type == std.elf.PT_TLS) {
            std.debug.print("{s}: align 0x{x}  filesz 0x{x}  memsz 0x{x}\n", .{ label, ph.p_align, ph.p_filesz, ph.p_memsz });
            return;
        }
    }
    std.debug.print("{s}: none\n", .{label});
}

/// --argdiag: print the raw launch state (argv, auxv, self-exe resolution,
/// shift verdict) and return the process exit code (always 0). Takes the RAW
/// argv -- the pre-normalization view is the evidence being reported.
pub fn argDiag(version: []const u8, raw_args: []const [:0]u8) u8 {
    const p = std.debug.print;
    p("argdiag : zig-miner v{s} ({s}-{s})\n", .{ version, @tagName(builtin.cpu.arch), @tagName(builtin.os.tag) });
    p("argc    : {d}\n", .{raw_args.len});
    for (raw_args, 0..) |a, idx| p("argv[{d}] : {s}\n", .{ idx, a });

    if (builtin.os.tag == .linux) {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        if (std.fs.selfExePath(&buf)) |sp| {
            p("/proc/self/exe : {s}\n", .{sp});
        } else |e| {
            p("/proc/self/exe : <error: {s}>\n", .{@errorName(e)});
        }
        const execfn = std.os.linux.getauxval(std.elf.AT_EXECFN);
        if (execfn != 0) {
            p("AT_EXECFN      : {s}\n", .{std.mem.span(@as([*:0]const u8, @ptrFromInt(execfn)))});
        } else {
            p("AT_EXECFN      : <unset>\n", .{});
        }
        if (std.posix.getenv(real_exe_env)) |v| {
            p(real_exe_env ++ " : {s}\n", .{v});
        } else {
            p(real_exe_env ++ " : <unset>\n", .{});
        }

        const at_base = std.os.linux.getauxval(std.elf.AT_BASE);
        const at_phdr = std.os.linux.getauxval(std.elf.AT_PHDR);
        const at_phnum = std.os.linux.getauxval(std.elf.AT_PHNUM);
        const own = ownPhdrs();
        p("AT_BASE        : 0x{x}\n", .{at_base});
        p("AT_PHDR (auxv) : 0x{x}  AT_PHNUM: {d}\n", .{ at_phdr, at_phnum });
        p("own phdrs      : 0x{x}  phnum: {d}  (__ehdr_start)\n", .{ @intFromPtr(own.ptr), own.len });
        if (at_phdr == @intFromPtr(own.ptr)) {
            p("auxv identity  : MATCH -- auxv describes this binary\n", .{});
        } else {
            p("auxv identity  : MISMATCH -- auxv describes another image (the loader)\n", .{});
        }
        const auxv_phdrs: []const std.elf.Phdr = if (at_phdr != 0 and at_phnum != 0)
            @as([*]const std.elf.Phdr, @ptrFromInt(at_phdr))[0..at_phnum]
        else
            &.{};
        reportTls("PT_TLS (auxv)  ", auxv_phdrs);
        reportTls("PT_TLS (own)   ", own);
    } else {
        p("(linux launch diagnostics not applicable on {s})\n", .{@tagName(builtin.os.tag)});
    }

    const arg1: ?[]const u8 = if (raw_args.len >= 2) raw_args[1] else null;
    const v = decide(raw_args.len, arg1, gatherEvidence(arg1));
    p("verdict : {s} -- {s}\n", .{ if (v.shift) "SHIFT" else "NO SHIFT", v.reason });
    if (v.shift) {
        p("normalized argv :", .{});
        for (raw_args[1..]) |a| p(" {s}", .{a});
        p("\n", .{});
    }
    return 0;
}

// ---- tests ----

const t = std.testing;
const own_path = "/data/data/com.termux/files/home/zig-miner";

test "decide: no evidence never shifts" {
    try t.expect(!decide(3, own_path, .{}).shift);
    try t.expect(!decide(3, own_path, .{ .arg1_is_regular_file = true }).shift);
}

test "decide: env marker with dev/ino match shifts" {
    const ev: Evidence = .{ .env_real_exe = own_path, .arg1_same_file_as_env = true };
    try t.expect(decide(2, own_path, ev).shift);
}

test "decide: env marker with dev/ino mismatch does not shift" {
    const ev: Evidence = .{ .env_real_exe = own_path, .arg1_same_file_as_env = false, .arg1_is_regular_file = true };
    try t.expect(!decide(2, "/some/other/file", ev).shift);
}

test "decide: env marker, stat unavailable, exact string match shifts" {
    const ev: Evidence = .{ .env_real_exe = own_path };
    try t.expect(decide(2, own_path, ev).shift);
    try t.expect(!decide(2, "/some/other/file", ev).shift);
}

test "decide: env marker, stat unavailable, linker basename + regular file shifts" {
    const ev: Evidence = .{ .env_real_exe = own_path, .self_exe_is_linker = true, .arg1_is_regular_file = true };
    try t.expect(decide(2, "./zig-miner", ev).shift);
}

test "decide: linker basename alone requires a regular file" {
    try t.expect(decide(2, own_path, .{ .self_exe_is_linker = true, .arg1_is_regular_file = true }).shift);
    try t.expect(!decide(2, own_path, .{ .self_exe_is_linker = true, .arg1_is_regular_file = false }).shift);
    try t.expect(!decide(2, own_path, .{ .self_exe_is_linker = true }).shift);
}

test "decide: flags and degenerate argv never shift" {
    const ev: Evidence = .{ .env_real_exe = own_path, .self_exe_is_linker = true, .arg1_same_file_as_env = true, .arg1_is_regular_file = true };
    try t.expect(!decide(1, null, ev).shift); // plain launch, argc==1
    try t.expect(!decide(0, null, ev).shift); // empty argv
    try t.expect(!decide(2, "-d", ev).shift);
    try t.expect(!decide(2, "--selftest", ev).shift);
    try t.expect(!decide(2, "-", ev).shift);
    try t.expect(!decide(2, "", ev).shift);
}

test "decide: dev/ino verdict wins over weaker evidence" {
    // Even with the linker basename and an existing file, an explicit
    // "not the same file" answer must veto the shift.
    const ev: Evidence = .{
        .env_real_exe = own_path,
        .self_exe_is_linker = true,
        .arg1_same_file_as_env = false,
        .arg1_is_regular_file = true,
    };
    try t.expect(!decide(2, "/some/other/file", ev).shift);
}

test "basenameIsLinker" {
    try t.expect(basenameIsLinker("linker64"));
    try t.expect(basenameIsLinker("linker"));
    try t.expect(basenameIsLinker("/system/bin/linker64"));
    try t.expect(basenameIsLinker("/system/bin/linker"));
    try t.expect(!basenameIsLinker("zig-miner"));
    try t.expect(!basenameIsLinker("linker64x"));
    try t.expect(!basenameIsLinker("xlinker"));
    try t.expect(!basenameIsLinker(""));
    try t.expect(basenameIsLinker("some/linker64"));
}

test "normalizeArgs: view semantics on a no-shift launch" {
    // On every CI host this is a no-evidence launch (env unset, self exe is the
    // test binary), so normalizeArgs must return the identical slice.
    var a0 = "zig-miner".*;
    var a1 = "-V".*;
    var argv = [_][:0]u8{ &a0, &a1 };
    const n = normalizeArgs(&argv);
    try t.expect(!n.shifted);
    try t.expectEqual(@as(usize, 2), n.args.len);
    try t.expectEqual(@as([*][:0]u8, &argv), n.args.ptr);
}
