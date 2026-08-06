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
//! static and reads argc/argv straight off the stack, so under that launch it
//! sees its own absolute path at argv[1]; handed to the flag parser, every
//! such launch -- including a bare `./zig-miner` -- dies on the usage screen.
//!
//! The auxv is equally unrewritten (AT_PHDR/AT_EXECFN describe the linker) and
//! /proc/self/exe points at linker64, so nothing derived from either can serve
//! as self-truth here. What CAN be trusted, in order: the auxv describing a
//! DIFFERENT image than the one running (impossible under a kernel load, so a
//! mismatch proves a loader in front of us); termux-exec's
//! TERMUX_EXEC__PROC_SELF_EXE marker naming the real executable; and argv[1]
//! itself once verified (dev/ino) to be this very binary's file. `decide`
//! shifts argv by exactly one element only when that evidence lines up;
//! everywhere else (Windows, macOS, x86 Linux, direct kernel loads) it is a
//! no-op, because a non-flag argv[1] is already a guaranteed usage()+exit(1)
//! -- the miner has no positional arguments -- so a shift can never eat a
//! meaningful argument.
//!
//! One evidence pass feeds everything: the shift decision, the real-executable
//! directory used for config.json resolution, and the --argdiag report. Those
//! three answering "who am I" differently is itself a bug class.

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
    /// auxv AT_PHDR does not describe this binary's own image (via
    /// __ehdr_start). Impossible under a kernel load; proves a loader ran us.
    auxv_mismatch: bool = false,
    /// args[1] and env_real_exe name the same file (dev+ino). null = not determinable.
    arg1_same_file_as_env: ?bool = null,
    /// args[1] exists and is a regular file (false when not determinable).
    arg1_is_regular_file: bool = false,

    fn loaderContext(ev: Evidence) bool {
        return ev.self_exe_is_linker or ev.auxv_mismatch;
    }
};

pub const Verdict = struct {
    shift: bool,
    /// Static description of why; surfaced by --argdiag and on parse failures.
    reason: []const u8,
};

const reason_existing_file = "launched via system linker; args[1] is an existing file";

/// Pure shift decision over (argv[1], evidence). argv[1] is an optional slice
/// (null when argc < 2) rather than the argv array so tests can use literals.
pub fn decide(arg1: ?[]const u8, ev: Evidence) Verdict {
    const a1 = arg1 orelse return .{ .shift = false, .reason = "no argument after argv[0]" };
    if (a1.len == 0) return .{ .shift = false, .reason = "args[1] empty" };
    if (a1[0] == '-') return .{ .shift = false, .reason = "args[1] is a flag" };
    if (ev.env_real_exe == null and !ev.loaderContext())
        return .{ .shift = false, .reason = "no linker-exec evidence" };

    if (ev.env_real_exe) |env_path| {
        if (ev.arg1_same_file_as_env) |same| {
            if (same) return .{ .shift = true, .reason = real_exe_env ++ " set; args[1] is this binary (dev/ino)" };
            return .{ .shift = false, .reason = "args[1] is not this binary" };
        }
        // stat unavailable: fall back to exact path equality, then to the
        // weaker loader-context + regular-file combination.
        if (std.mem.eql(u8, a1, env_path))
            return .{ .shift = true, .reason = real_exe_env ++ " set; args[1] equals it" };
        if (ev.loaderContext() and ev.arg1_is_regular_file)
            return .{ .shift = true, .reason = reason_existing_file };
        return .{ .shift = false, .reason = "args[1] could not be identified as this binary" };
    }

    // Loader context alone: require args[1] to at least be a real file.
    if (ev.arg1_is_regular_file)
        return .{ .shift = true, .reason = reason_existing_file };
    return .{ .shift = false, .reason = "launched via system linker but args[1] is not a regular file" };
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
    /// The evidence the verdict rests on; also drives real-exe-dir resolution.
    ev: Evidence,
};

/// Gather evidence (Linux only; inert elsewhere) and apply `decide`.
pub fn normalizeArgs(raw: [][:0]u8) Normalized {
    const arg1: ?[]const u8 = if (raw.len >= 2) raw[1] else null;
    const ev = gatherEvidence(arg1);
    const v = decide(arg1, ev);
    return .{
        .args = if (v.shift) raw[1..] else raw,
        .shifted = v.shift,
        .reason = v.reason,
        .ev = ev,
    };
}

/// Directory of the REAL executable (allocated), from the same evidence that
/// drove the shift decision. Trust order: a shifted argv[0] (that path was
/// just verified to be this binary), then /proc/self/exe when it doesn't name
/// the system linker, then the env marker -- but only in loader context, so a
/// stale inherited variable can never override a working /proc/self/exe.
pub fn realExeDirAlloc(alloc: std.mem.Allocator, norm: *const Normalized) ?[]u8 {
    if (norm.shifted and norm.args.len > 0) {
        const a0 = norm.args[0];
        if (std.fs.path.isAbsolute(a0)) {
            if (std.fs.path.dirname(a0)) |d| return alloc.dupe(u8, d) catch null;
        }
    }
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    if (selfExeReal(&buf)) |p| {
        if (!(builtin.os.tag == .linux and basenameIsLinker(p))) {
            if (std.fs.path.dirname(p)) |d| return alloc.dupe(u8, d) catch null;
        }
    }
    if (builtin.os.tag == .linux) {
        if (norm.ev.loaderContext()) {
            if (norm.ev.env_real_exe) |p| {
                if (std.fs.path.isAbsolute(p)) {
                    if (std.fs.path.dirname(p)) |d| return alloc.dupe(u8, d) catch null;
                }
            }
        }
    }
    return null;
}

/// This process's executable path: /proc/self/exe (selfExePath), with an
/// AT_EXECFN fallback on Linux for /proc-restricted environments. All
/// self-identity callers go through here so they cannot diverge.
fn selfExeReal(buf: *[std.fs.max_path_bytes]u8) ?[]const u8 {
    if (std.fs.selfExePath(buf)) |p| return p else |_| {}
    if (builtin.os.tag == .linux) {
        const execfn = std.os.linux.getauxval(std.elf.AT_EXECFN);
        if (execfn != 0) return std.mem.span(@as([*:0]const u8, @ptrFromInt(execfn)));
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
        if (selfExeReal(&buf)) |p| ev.self_exe_is_linker = basenameIsLinker(p);
        ev.auxv_mismatch = auxvMismatch();

        const a1 = arg1 orelse return ev;
        if (a1.len == 0 or a1[0] == '-') return ev; // decide() rejects these before reading stats

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

// ---- own-image identity (Linux/ELF) ----

/// Provided by the linker on ELF targets. The auxv cannot be self-truth here
/// (under a loader it describes the loader's image), so this symbol is the
/// only reliable way to find our own ELF header. Reference it exclusively
/// from Linux comptime branches; lazy analysis keeps other targets linking.
extern const __ehdr_start: std.elf.Ehdr;

fn ownPhdrs() []const std.elf.Phdr {
    const ehdr = &__ehdr_start;
    const addr = @intFromPtr(ehdr) + @as(usize, @intCast(ehdr.e_phoff));
    return @as([*]const std.elf.Phdr, @ptrFromInt(addr))[0..ehdr.e_phnum];
}

/// True when auxv AT_PHDR describes some other image than the one running --
/// impossible under a direct kernel load, definitive proof of a loader.
fn auxvMismatch() bool {
    const at_phdr = std.os.linux.getauxval(std.elf.AT_PHDR);
    if (at_phdr == 0) return false;
    return at_phdr != @intFromPtr(ownPhdrs().ptr);
}

// ---- --argdiag ----

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
/// argv and runs the same normalizeArgs pipeline the miner uses, so the
/// printed verdict can never drift from the decision being diagnosed.
pub fn argDiag(version: []const u8, raw_args: [][:0]u8) u8 {
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
        if (auxvMismatch()) {
            p("auxv identity  : MISMATCH -- auxv describes another image (the loader)\n", .{});
        } else {
            p("auxv identity  : MATCH -- auxv describes this binary\n", .{});
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

    const n = normalizeArgs(raw_args);
    p("verdict : {s} -- {s}\n", .{ if (n.shifted) "SHIFT" else "NO SHIFT", n.reason });
    if (n.shifted) {
        p("normalized argv :", .{});
        for (n.args) |a| p(" {s}", .{a});
        p("\n", .{});
    }
    return 0;
}

// ---- tests ----

const t = std.testing;
const own_path = "/data/data/com.termux/files/home/zig-miner";

test "decide: no evidence never shifts" {
    try t.expect(!decide(own_path, .{}).shift);
    try t.expect(!decide(own_path, .{ .arg1_is_regular_file = true }).shift);
}

test "decide: env marker with dev/ino match shifts" {
    const ev: Evidence = .{ .env_real_exe = own_path, .arg1_same_file_as_env = true };
    try t.expect(decide(own_path, ev).shift);
}

test "decide: dev/ino veto wins over every weaker signal" {
    const ev: Evidence = .{
        .env_real_exe = own_path,
        .self_exe_is_linker = true,
        .auxv_mismatch = true,
        .arg1_same_file_as_env = false,
        .arg1_is_regular_file = true,
    };
    try t.expect(!decide("/some/other/file", ev).shift);
}

test "decide: env marker, stat unavailable, exact string match shifts" {
    const ev: Evidence = .{ .env_real_exe = own_path };
    try t.expect(decide(own_path, ev).shift);
    try t.expect(!decide("/some/other/file", ev).shift);
}

test "decide: env marker, stat unavailable, loader context + regular file shifts" {
    const ev: Evidence = .{ .env_real_exe = own_path, .self_exe_is_linker = true, .arg1_is_regular_file = true };
    try t.expect(decide("./zig-miner", ev).shift);
}

test "decide: linker basename alone requires a regular file" {
    try t.expect(decide(own_path, .{ .self_exe_is_linker = true, .arg1_is_regular_file = true }).shift);
    try t.expect(!decide(own_path, .{ .self_exe_is_linker = true }).shift);
}

test "decide: auxv mismatch is loader context in its own right" {
    try t.expect(decide(own_path, .{ .auxv_mismatch = true, .arg1_is_regular_file = true }).shift);
    try t.expect(!decide(own_path, .{ .auxv_mismatch = true }).shift);
}

test "decide: flags and degenerate argv never shift" {
    const ev: Evidence = .{
        .env_real_exe = own_path,
        .self_exe_is_linker = true,
        .auxv_mismatch = true,
        .arg1_same_file_as_env = true,
        .arg1_is_regular_file = true,
    };
    try t.expect(!decide(null, ev).shift); // argc < 2
    try t.expect(!decide("-d", ev).shift);
    try t.expect(!decide("--selftest", ev).shift);
    try t.expect(!decide("-", ev).shift);
    try t.expect(!decide("", ev).shift);
}

test "basenameIsLinker" {
    try t.expect(basenameIsLinker("linker64"));
    try t.expect(basenameIsLinker("linker"));
    try t.expect(basenameIsLinker("/system/bin/linker64"));
    try t.expect(basenameIsLinker("/apex/com.android.runtime/bin/linker64"));
    try t.expect(!basenameIsLinker("zig-miner"));
    try t.expect(!basenameIsLinker("linker64x"));
    try t.expect(!basenameIsLinker("xlinker"));
    try t.expect(!basenameIsLinker(""));
    try t.expect(basenameIsLinker("some/linker64"));
}

test "normalizeArgs: view semantics on a no-shift launch" {
    // args[1] is flag-shaped, so decide refuses before consulting evidence;
    // deterministic on every host and target.
    var a0 = "zig-miner".*;
    var a1 = "-V".*;
    var argv = [_][:0]u8{ &a0, &a1 };
    const n = normalizeArgs(&argv);
    try t.expect(!n.shifted);
    try t.expectEqual(@as(usize, 2), n.args.len);
    try t.expectEqual(@as([*][:0]u8, &argv), n.args.ptr);
}
