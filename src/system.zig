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

// ── 3. pinThreadToLogical ─────────────────────────────────────────────────────
/// Pin the calling thread to a single logical processor `cpu` (0-based).
///
/// On i7-13700HX:
///   Logical  0..15  = P-core HT siblings, paired as (0,1),(2,3),(4,5)...,(14,15)
///   Logical 16..23  = E-cores (no HT)
///
/// SetThreadAffinityMask ignores calls that set bits outside the process affinity
/// mask, so out-of-range `cpu` values will silently no-op.
/// Raise the whole process to HIGH priority class (matches the C miner's `-p max`;
/// base priority 13, so HIGHEST threads reach 15 instead of 10 under NORMAL class).
pub fn setProcessHighPriority() void {
    _ = SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
}

pub fn pinThreadToLogical(cpu: u6) void {
    const mask: ULONG_PTR = @as(ULONG_PTR, 1) << cpu;
    _ = SetThreadAffinityMask(GetCurrentThread(), mask);
}

// ── 4. setThreadHighPriority ──────────────────────────────────────────────────
/// Elevate the calling thread's scheduling priority and disable power throttling.
///
/// - SetThreadPriority(THREAD_PRIORITY_HIGHEST) — moves the thread into the
///   highest real-time-adjacent Windows priority bucket.
/// - SetThreadInformation(ThreadPowerThrottling, StateMask=0) — tells the
///   scheduler to disable execution-speed throttling for this thread.
///   StateMask=0 with ControlMask=EXECUTION_SPEED means "do not throttle."
///   This call may fail on older Windows 10 builds; failure is silently ignored.
pub fn setThreadHighPriority() void {
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
}

// ── 4b. enableVirtualTerminal ─────────────────────────────────────────────────
const STD_OUTPUT_HANDLE: DWORD = 0xFFFFFFF5; // (DWORD)-11
const STD_ERROR_HANDLE: DWORD = 0xFFFFFFF4; // (DWORD)-12
const ENABLE_VIRTUAL_TERMINAL_PROCESSING: DWORD = 0x0004;
extern "kernel32" fn GetStdHandle(nStdHandle: DWORD) callconv(.winapi) HANDLE;
extern "kernel32" fn GetConsoleMode(hConsoleHandle: HANDLE, lpMode: *DWORD) callconv(.winapi) BOOL;
extern "kernel32" fn SetConsoleMode(hConsoleHandle: HANDLE, dwMode: DWORD) callconv(.winapi) BOOL;

/// Enable ANSI escape (virtual terminal) processing on stdout+stderr so the colored
/// status line renders on Windows 10+/Windows Terminal. Failure-silent (a redirected
/// or legacy console simply keeps its mode; the reporter's TTY check skips color there).
pub fn enableVirtualTerminal() void {
    for ([_]DWORD{ STD_OUTPUT_HANDLE, STD_ERROR_HANDLE }) |which| {
        const h = GetStdHandle(which);
        var mode: DWORD = 0;
        if (GetConsoleMode(h, &mode) == FALSE) continue;
        _ = SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
}

// ── 5. recommendedAffinityForThreads ─────────────────────────────────────────
/// Return an ordered list of logical CPU IDs for n mining threads.
///
/// Ordering rationale (AstroBWTv3 is memory/cache-heavy: suffix-array build,
/// RC4 in-place, 278-iter branch loop with CodeLUT):
///
///   1. P-core distinct physicals first (even logicals 0,2,4,6,8,10,12,14):
///      each occupies its own physical core → no L1/L2 sharing = full cache per thread.
///   2. E-cores (16..23): have their own L2 but smaller; still beat HT siblings.
///   3. P-core HT siblings (odd logicals 1,3,5,7,9,11,13,15): share L1/L2 with
///      the already-scheduled partner; worst cache locality for this workload.
///
/// For 10 threads on i7-13700HX our recommendation is:
///   logical [0,2,4,6,8,10,12,14,16,17] — 8 distinct P-cores + 2 E-cores.
/// This gives 10 independent cache domains (8 P-core L2s + shared E-cluster L2).
/// Prefer this over 8P+2HT-siblings because sibling pairs share 2MB L2 and will
/// thrash each other on the 278-iter CodeLUT loop (~5KB hot data per thread).
///
/// The lead should A/B test this against all-E-core-excluded and all-HT configs.
///
/// Returns up to 24 entries; entries beyond n are 0-filled.
pub fn recommendedAffinityForThreads(n: usize) [24]u6 {
    // Ordered preference: distinct P-core physicals, then E-cores, then HT siblings.
    const order = [24]u6{
        // 8 distinct P-core physical cores (even logicals = first HT sibling)
        0,  2,  4,  6,  8,  10, 12, 14,
        // 8 E-cores (no HT)
        16, 17, 18, 19, 20, 21, 22, 23,
        // 8 P-core HT siblings (share L1/L2 with their even partner above)
        1,  3,  5,  7,  9,  11, 13, 15,
    };

    var result = [_]u6{0} ** 24;
    const count = @min(n, 24);
    for (0..count) |i| {
        result[i] = order[i];
    }
    return result;
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
    // First 8 should be distinct P-core physicals
    try std.testing.expectEqual(@as(u6, 0), map[0]);
    try std.testing.expectEqual(@as(u6, 2), map[1]);
    try std.testing.expectEqual(@as(u6, 14), map[7]);
    // 9th+10th should be first two E-cores
    try std.testing.expectEqual(@as(u6, 16), map[8]);
    try std.testing.expectEqual(@as(u6, 17), map[9]);
    // Beyond n should be zero
    try std.testing.expectEqual(@as(u6, 0), map[10]);
}
