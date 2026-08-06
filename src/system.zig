//! system.zig -- Windows performance primitives for the AstroBWTv3 DERO miner.
//!
//! Provides:
//!   - Large-page (2 MB) allocation via SeLockMemoryPrivilege + VirtualAlloc
//!   - Thread-to-logical-CPU pinning via SetThreadAffinityMask
//!   - Thread priority elevation + power-throttling disable
//!   - Recommended affinity ordering for n mining threads
//!
//! All Win32 calls are made directly via `extern "kernel32"` / `extern "advapi32"`.
//! No third-party dependencies; pure Zig 0.14.1.
//!
//! Link flags (for standalone test exe):
//!   .tools\zig\zig.exe build-exe _system\test_system.zig -OReleaseFast -lc -ladvapi32 -lkernel32
//! When built via build.zig, kernel32 and advapi32 are pulled in automatically.

const std = @import("std");
const builtin = @import("builtin");
const windows = std.os.windows;

// ── Win32 base types ─────────────────────────────────────────────────────────
const BOOL = windows.BOOL;
const HANDLE = windows.HANDLE;
const DWORD = windows.DWORD;
const ULONG = windows.ULONG;
const SIZE_T = windows.SIZE_T;
const ULONG_PTR = windows.ULONG_PTR;
const LPVOID = windows.LPVOID;
const TRUE: BOOL = 1;
const FALSE: BOOL = 0;

// ── VirtualAlloc / VirtualFree flags ─────────────────────────────────────────
const MEM_COMMIT: DWORD = 0x00001000;
const MEM_RESERVE: DWORD = 0x00002000;
const MEM_RELEASE: DWORD = 0x00008000;
const MEM_LARGE_PAGES: DWORD = 0x20000000;
const PAGE_READWRITE: DWORD = 0x04;

// ── Thread priority constants ─────────────────────────────────────────────────
const THREAD_PRIORITY_HIGHEST: c_int = 2;
// const THREAD_PRIORITY_ABOVE_NORMAL: c_int = 1; // kept for reference

// ── SetThreadInformation / ThreadPowerThrottling ──────────────────────────────
// THREAD_INFORMATION_CLASS value 3 = ThreadPowerThrottling (processthreadsapi.h)
const ThreadPowerThrottling: c_int = 3;
const THREAD_POWER_THROTTLING_CURRENT_VERSION: ULONG = 1;
const THREAD_POWER_THROTTLING_EXECUTION_SPEED: ULONG = 0x1;

const THREAD_POWER_THROTTLING_STATE = extern struct {
    Version: ULONG,
    ControlMask: ULONG,
    StateMask: ULONG,
};

// ── Token / privilege constants ───────────────────────────────────────────────
const TOKEN_QUERY: DWORD = 0x0008;
const TOKEN_ADJUST_PRIVILEGES: DWORD = 0x0020;
const SE_PRIVILEGE_ENABLED: DWORD = 0x00000002;

// ERROR codes
const ERROR_SUCCESS: DWORD = 0;
const ERROR_NOT_ALL_ASSIGNED: DWORD = 1300;

const LUID = extern struct {
    LowPart: DWORD,
    HighPart: i32,
};

const LUID_AND_ATTRIBUTES = extern struct {
    Luid: LUID,
    Attributes: DWORD,
};

const TOKEN_PRIVILEGES = extern struct {
    PrivilegeCount: DWORD,
    Privileges: [1]LUID_AND_ATTRIBUTES,
};

// ── kernel32 declarations not in std ────────────────────────────────────────
extern "kernel32" fn GetCurrentThread() callconv(.winapi) HANDLE;
extern "kernel32" fn GetCurrentProcess() callconv(.winapi) HANDLE;
extern "kernel32" fn SetPriorityClass(hProcess: HANDLE, dwPriorityClass: DWORD) callconv(.winapi) BOOL;
const HIGH_PRIORITY_CLASS: DWORD = 0x00000080;
extern "kernel32" fn VirtualAlloc(
    lpAddress: ?LPVOID,
    dwSize: SIZE_T,
    flAllocationType: DWORD,
    flProtect: DWORD,
) callconv(.winapi) ?LPVOID;
extern "kernel32" fn VirtualFree(
    lpAddress: ?LPVOID,
    dwSize: SIZE_T,
    dwFreeType: DWORD,
) callconv(.winapi) BOOL;
extern "kernel32" fn GetLargePageMinimum() callconv(.winapi) SIZE_T;
extern "kernel32" fn SetThreadAffinityMask(
    hThread: HANDLE,
    dwThreadAffinityMask: ULONG_PTR,
) callconv(.winapi) ULONG_PTR;
extern "kernel32" fn SetThreadPriority(
    hThread: HANDLE,
    nPriority: c_int,
) callconv(.winapi) BOOL;
extern "kernel32" fn SetThreadInformation(
    hThread: HANDLE,
    ThreadInformationClass: c_int,
    ThreadInformation: *anyopaque,
    ThreadInformationSize: DWORD,
) callconv(.winapi) BOOL;
extern "kernel32" fn GetLastError() callconv(.winapi) DWORD;

// ── advapi32 declarations ─────────────────────────────────────────────────────
extern "advapi32" fn OpenProcessToken(
    ProcessHandle: HANDLE,
    DesiredAccess: DWORD,
    TokenHandle: *HANDLE,
) callconv(.winapi) BOOL;
extern "advapi32" fn LookupPrivilegeValueA(
    lpSystemName: ?[*:0]const u8,
    lpName: [*:0]const u8,
    lpLuid: *LUID,
) callconv(.winapi) BOOL;
extern "advapi32" fn AdjustTokenPrivileges(
    TokenHandle: HANDLE,
    DisableAllPrivileges: BOOL,
    NewState: *TOKEN_PRIVILEGES,
    BufferLength: DWORD,
    PreviousState: ?*TOKEN_PRIVILEGES,
    ReturnLength: ?*DWORD,
) callconv(.winapi) BOOL;
extern "advapi32" fn CloseHandle(hObject: HANDLE) callconv(.winapi) BOOL;

// ── 1. enableLockMemoryPrivilege ──────────────────────────────────────────────
/// Enable SeLockMemoryPrivilege for the current process.
///
/// Returns true only if the privilege was actually granted (GetLastError == 0
/// after AdjustTokenPrivileges — NOT just the BOOL return, which is always TRUE
/// even when ERROR_NOT_ALL_ASSIGNED).
///
/// IMPORTANT: Requires the calling user to hold the "Lock pages in memory"
/// right.  To grant it on this machine:
///   1. Run `secpol.msc` as Administrator.
///   2. Local Policies > User Rights Assignment > Lock pages in memory.
///   3. Add Users/Groups button → add your account (or the miner service user).
///   4. Log off and back on (or reboot) — the right takes effect at next logon.
/// Without it, AdjustTokenPrivileges succeeds-but-lies; GetLastError returns
/// ERROR_NOT_ALL_ASSIGNED (1300), so this function returns false.
pub fn enableLockMemoryPrivilege() bool {
    var token: HANDLE = undefined;
    if (OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &token,
    ) == FALSE) return false;
    defer _ = CloseHandle(token);

    var luid: LUID = undefined;
    if (LookupPrivilegeValueA(null, "SeLockMemoryPrivilege", &luid) == FALSE) {
        return false;
    }

    var tp = TOKEN_PRIVILEGES{
        .PrivilegeCount = 1,
        .Privileges = [1]LUID_AND_ATTRIBUTES{.{
            .Luid = luid,
            .Attributes = SE_PRIVILEGE_ENABLED,
        }},
    };

    _ = AdjustTokenPrivileges(token, FALSE, &tp, @sizeOf(TOKEN_PRIVILEGES), null, null);
    // AdjustTokenPrivileges returns TRUE even when it cannot fully apply the
    // change (ERROR_NOT_ALL_ASSIGNED = 1300). We must check GetLastError.
    return GetLastError() == ERROR_SUCCESS;
}

// ── 2. allocLargePages / freeLargePages ──────────────────────────────────────
/// Allocate `size` bytes as large pages (typically 2 MB pages on x86-64).
///
/// - Rounds `size` up to the next multiple of GetLargePageMinimum().
/// - Requires that enableLockMemoryPrivilege() has previously returned true.
/// - Returns null on failure; caller should fall back to normal alloc.
///   On failure GetLastError() == 1314 means privilege not held;
///   == 1450 means insufficient contiguous physical memory (try after reboot).
pub fn allocLargePages(size: usize) ?[]align(4096) u8 {
    const page_min = GetLargePageMinimum();
    if (page_min == 0) return null; // large pages not supported on this CPU/OS

    const rounded = roundUp(size, page_min);
    const ptr = VirtualAlloc(
        null,
        rounded,
        MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES,
        PAGE_READWRITE,
    ) orelse return null;

    const bytes: [*]align(4096) u8 = @alignCast(@ptrCast(ptr));
    return bytes[0..rounded];
}

/// Free a buffer previously returned by allocLargePages.
/// Pass the exact slice you received; the length field is ignored by VirtualFree
/// (MEM_RELEASE requires dwSize == 0), but we accept the full slice for symmetry.
pub fn freeLargePages(buf: []align(4096) u8) void {
    _ = VirtualFree(@ptrCast(buf.ptr), 0, MEM_RELEASE);
}

// ── 3. pinThreadToLogical / setProcessHighPriority ─────────────────────────────
/// Raise the whole process scheduling priority. Windows: HIGH priority class
/// (matches the C miner's `-p max`; base priority 13, so HIGHEST threads reach 15
/// instead of 10 under NORMAL class). Linux: best-effort nice -10 on the calling
/// process (requires CAP_SYS_NICE below the session's rlimit; failure is ignored).
pub fn setProcessHighPriority() void {
    if (builtin.os.tag == .windows) {
        _ = SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    } else if (builtin.os.tag == .linux) {
        setLinuxPriority(-10);
    }
}

/// Pin the calling thread to a single logical processor `cpu` (0-based).
/// Windows: SetThreadAffinityMask; Linux: sched_setaffinity(0).
/// Out-of-range or disallowed CPUs silently no-op (both OSes reject the bits).
pub fn pinThreadToLogical(cpu: u7) void {
    if (builtin.os.tag == .windows) {
        const mask: ULONG_PTR = @as(ULONG_PTR, 1) << cpu;
        _ = SetThreadAffinityMask(GetCurrentThread(), mask);
    } else if (builtin.os.tag == .linux) {
        var set: std.os.linux.cpu_set_t = @splat(0);
        const word = @as(usize, cpu) / @bitSizeOf(usize);
        const bit: u6 = @intCast(cpu % @bitSizeOf(usize));
        set[word] |= @as(usize, 1) << bit;
        std.os.linux.sched_setaffinity(0, &set) catch {};
    }
}

// ── 3b. Linux priority (best-effort nice via raw syscall) ─────────────────────
fn setLinuxPriority(nice: i32) void {
    // setpriority(which=PRIO_PROCESS, who=0, prio=nice). Negative values below the
    // RLIMIT_NICE floor need CAP_SYS_NICE; if denied, keep the inherited value.
    _ = std.os.linux.syscall3(.setpriority, 0, 0, @bitCast(@as(isize, nice)));
}

// ── 4. setThreadHighPriority ──────────────────────────────────────────────────
/// Elevate the calling thread's scheduling priority and disable power throttling.
///
/// Windows:
/// - SetThreadPriority(THREAD_PRIORITY_HIGHEST) — moves the thread into the
///   highest real-time-adjacent Windows priority bucket.
/// - SetThreadInformation(ThreadPowerThrottling, StateMask=0) — tells the
///   scheduler to disable execution-speed throttling for this thread.
///   StateMask=0 with ControlMask=EXECUTION_SPEED means "do not throttle."
///   This call may fail on older Windows 10 builds; failure is silently ignored.
///
/// Linux: best-effort nice -10 for the calling thread (same privilege caveat).
pub fn setThreadHighPriority() void {
    if (builtin.os.tag == .windows) {
        _ = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

        var pts = THREAD_POWER_THROTTLING_STATE{
            .Version = THREAD_POWER_THROTTLING_CURRENT_VERSION,
            .ControlMask = THREAD_POWER_THROTTLING_EXECUTION_SPEED,
            .StateMask = 0, // 0 = do NOT throttle
        };
        _ = SetThreadInformation(
            GetCurrentThread(),
            ThreadPowerThrottling,
            @ptrCast(&pts),
            @sizeOf(THREAD_POWER_THROTTLING_STATE),
        );
    } else if (builtin.os.tag == .linux) {
        setLinuxPriority(-10);
    }
}

// ── 4b. enableVirtualTerminal ─────────────────────────────────────────────────
const STD_OUTPUT_HANDLE: DWORD = 0xFFFFFFF5; // (DWORD)-11
const STD_ERROR_HANDLE: DWORD = 0xFFFFFFF4; // (DWORD)-12
const ENABLE_VIRTUAL_TERMINAL_PROCESSING: DWORD = 0x0004;
extern "kernel32" fn GetStdHandle(nStdHandle: DWORD) callconv(.winapi) HANDLE;
extern "kernel32" fn GetConsoleMode(hConsoleHandle: HANDLE, lpMode: *DWORD) callconv(.winapi) BOOL;
extern "kernel32" fn SetConsoleMode(hConsoleHandle: HANDLE, dwMode: DWORD) callconv(.winapi) BOOL;

/// Enable ANSI escape processing on stdout+stderr. Returns true only when stderr,
/// where the status line is written, accepted virtual-terminal processing.
pub fn enableVirtualTerminal() bool {
    var stderr_ok = false;
    for ([_]DWORD{ STD_OUTPUT_HANDLE, STD_ERROR_HANDLE }) |which| {
        const h = GetStdHandle(which);
        var mode: DWORD = 0;
        if (GetConsoleMode(h, &mode) == FALSE) continue;
        const ok = SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != FALSE;
        if (which == STD_ERROR_HANDLE) stderr_ok = ok;
    }
    return stderr_ok;
}

// ── 5. recommendedAffinityForThreads ─────────────────────────────────────────
/// Maximum logical CPUs the affinity map can address. 128 matches Linux's
/// CPU_SETSIZE and keeps the map small; callers index it with @min(tid, MAX-1).
pub const MAX_AFFINITY: usize = 128;

/// Return an ordered list of logical CPU IDs for n mining threads.
///
/// Ordering rationale (AstroBWTv3 is memory/cache-heavy: suffix-array build,
/// RC4 in-place, 278-iter branch loop with CodeLUT):
///
///   1. One thread per distinct physical core first: each occupies its own
///      physical core → no L1/L2 sharing = full cache per thread.
///   2. Remaining SMT siblings last: they share L1/L2 with the core's first
///      thread; worst cache locality for this workload.
///
/// Windows: derived from a fixed layout (i7-13700HX: P-core even logicals
/// 0..14, then E-cores 16..23, then P-core HT siblings 1..15) because the
/// current build has no portable topology API.
///
/// Linux: discovered from sysfs (/sys/devices/system/cpu/cpuN/topology/
/// thread_siblings_list), filtered to the process's allowed set
/// (sched_getaffinity), so it adapts to AMD Zen4/Zen5, Intel hybrid, and
/// cgroup-restricted environments. Falls back to an SMT-pair assumption
/// (evens first) if sysfs is unreadable.
///
/// Returns up to MAX_AFFINITY entries; entries beyond n are 0-filled.
pub fn recommendedAffinityForThreads(n: usize) [MAX_AFFINITY]u7 {
    var result = [_]u7{0} ** MAX_AFFINITY;
    const count = @min(n, MAX_AFFINITY);

    if (comptime builtin.os.tag == .windows) {
        // Fixed i7-13700HX layout: 8 distinct P-core physicals, 8 E-cores, 8 HT siblings.
        const order = [_]u7{
            0,  2,  4,  6,  8,  10, 12, 14, // 8 distinct P-core physicals
            16, 17, 18, 19, 20, 21, 22, 23, // 8 E-cores (no HT)
            1,  3,  5,  7,  9,  11, 13, 15, // 8 P-core HT siblings
        };
        for (0..@min(count, order.len)) |i| result[i] = order[i];
    } else if (comptime builtin.os.tag == .linux) {
        linuxAffinityOrder(&result, count);
    } else {
        for (0..count) |i| result[i] = @intCast(i);
    }
    return result;
}

/// Linux: fill `result` with `count` logical CPUs ordered one-per-physical-core
/// first, SMT siblings last. Respects the process's allowed affinity mask.
fn linuxAffinityOrder(result: *[MAX_AFFINITY]u7, count: usize) void {
    var allowed: std.os.linux.cpu_set_t = @splat(0);
    _ = std.os.linux.sched_getaffinity(0, @sizeOf(std.os.linux.cpu_set_t), &allowed);

    const allowedCpu = struct {
        fn f(set: std.os.linux.cpu_set_t, cpu: usize) bool {
            if (cpu >= std.os.linux.CPU_SETSIZE) return false;
            const w = cpu / @bitSizeOf(usize);
            const bit: u6 = @intCast(cpu % @bitSizeOf(usize));
            return (set[w] & (@as(usize, 1) << bit)) != 0;
        }
    }.f;

    // Group representative per cpu (lowest sibling in its core), from sysfs.
    var rep = [_]u8{0xff} ** MAX_AFFINITY; // 0xff = unknown
    var have_sysfs = false;
    for (0..MAX_AFFINITY) |cpu| {
        var pbuf: [80]u8 = undefined;
        const path = std.fmt.bufPrint(&pbuf, "/sys/devices/system/cpu/cpu{d}/topology/thread_siblings_list", .{cpu}) catch continue;
        const f = std.fs.openFileAbsolute(path, .{}) catch continue;
        defer f.close();
        var buf: [64]u8 = undefined;
        const rd = f.readAll(&buf) catch continue;
        var lo: u8 = 0xff;
        var it = std.mem.splitScalar(u8, std.mem.trim(u8, buf[0..rd], " \n"), ',');
        while (it.next()) |tok| {
            if (tok.len == 0) continue;
            if (std.mem.indexOfScalar(u8, tok, '-')) |dash| {
                const a = std.fmt.parseInt(u8, tok[0..dash], 10) catch continue;
                const b = std.fmt.parseInt(u8, tok[dash + 1 ..], 10) catch continue;
                const m = @min(a, b);
                if (lo == 0xff or m < lo) lo = m;
            } else {
                const a = std.fmt.parseInt(u8, tok, 10) catch continue;
                if (lo == 0xff or a < lo) lo = a;
            }
        }
        if (lo != 0xff) {
            rep[cpu] = lo;
            have_sysfs = true;
        }
    }

    // Ordered output: pass 1 = each allowed representative (ascending, which is
    // also ascending-by-core since reps are core minima); pass 2 = other siblings.
    var out: [MAX_AFFINITY]u7 = undefined;
    var olen: usize = 0;

    if (have_sysfs) {
        // A cpu whose siblings file failed to read keeps rep 0xff; treat it as a
        // representative so it lands in the physical-core wave, not after all
        // real siblings.
        for (0..MAX_AFFINITY) |cpu| {
            if (!allowedCpu(allowed, cpu)) continue;
            if (rep[cpu] == cpu or rep[cpu] == 0xff) {
                out[olen] = @intCast(cpu);
                olen += 1;
            }
        }
        for (0..MAX_AFFINITY) |cpu| {
            if (!allowedCpu(allowed, cpu)) continue;
            if (rep[cpu] != cpu and rep[cpu] != 0xff) {
                out[olen] = @intCast(cpu);
                olen += 1;
            }
        }
    } else {
        // Fallback: assume SMT pairs (2i, 2i+1): evens first, then odds.
        for (0..MAX_AFFINITY) |cpu| {
            if (!allowedCpu(allowed, cpu)) continue;
            if (cpu % 2 == 0) {
                out[olen] = @intCast(cpu);
                olen += 1;
            }
        }
        for (0..MAX_AFFINITY) |cpu| {
            if (!allowedCpu(allowed, cpu)) continue;
            if (cpu % 2 == 1) {
                out[olen] = @intCast(cpu);
                olen += 1;
            }
        }
    }

    const take = @min(count, olen);
    for (0..take) |i| result[i] = out[i];
    if (olen == 0) {
        // sched_getaffinity failed (allowed came back all zeros) or every cpu was
        // filtered out. Never return an all-zero map: that would pin every thread
        // to cpu 0. Fall back to plain ascending cpus; pins to any cpu that is
        // genuinely disallowed fail silently, leaving that thread unpinned.
        for (0..@min(count, MAX_AFFINITY)) |i| result[i] = @intCast(i);
    }
}

// ── internal helpers ──────────────────────────────────────────────────────────
fn roundUp(value: usize, multiple: usize) usize {
    return (value + multiple - 1) / multiple * multiple;
}

// ── basic self-tests (run with `zig build test`) ───────────────────────────────
test "roundUp" {
    try std.testing.expectEqual(@as(usize, 4096), roundUp(1, 4096));
    try std.testing.expectEqual(@as(usize, 4096), roundUp(4096, 4096));
    try std.testing.expectEqual(@as(usize, 8192), roundUp(4097, 4096));
    try std.testing.expectEqual(@as(usize, 2 * 1024 * 1024), roundUp(1, 2 * 1024 * 1024));
}

test "recommendedAffinityForThreads ordering" {
    const map = recommendedAffinityForThreads(10);
    if (builtin.os.tag == .windows) {
        // Fixed i7-13700HX layout: 8 distinct P-core physicals, then 2 E-cores.
        try std.testing.expectEqual(@as(u7, 0), map[0]);
        try std.testing.expectEqual(@as(u7, 2), map[1]);
        try std.testing.expectEqual(@as(u7, 14), map[7]);
        try std.testing.expectEqual(@as(u7, 16), map[8]);
        try std.testing.expectEqual(@as(u7, 17), map[9]);
    } else if (builtin.os.tag == .linux) {
        // Topology-aware: the map must never contain a cpu twice (machine-
        // independent property). Ascending order can't be asserted here because
        // on machines with fewer physical cores than requested threads the
        // SMT siblings legitimately follow physicals (e.g. 0,2,4,6,1,3,... on a
        // 4-core box), which is not strictly ascending.
        try std.testing.expectEqual(@as(u7, 0), map[0]);
        var seen = [_]bool{false} ** MAX_AFFINITY;
        for (0..10) |i| {
            try std.testing.expect(!seen[map[i]]);
            seen[map[i]] = true;
        }
    }
    // Beyond n should be zero on every OS
    try std.testing.expectEqual(@as(u7, 0), map[10]);
}
