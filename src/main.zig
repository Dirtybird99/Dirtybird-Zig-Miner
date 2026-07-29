//! main.zig -- DIRTYBIRD/Zig miner entry point. AstroBWTv3 DERO CPU miner.
const std = @import("std");
const builtin = @import("builtin");
const pow = @import("pow.zig");
const miner = @import("miner.zig");
const state = @import("state.zig");
const net = @import("net.zig");
const system = @import("system.zig");
const config = @import("config.zig");
const console = @import("console.zig");
const pages = @import("pages.zig");
const cpu_features = @import("cpu_features.zig");
const sha_mb = @import("sha256_mb.zig");
const build_options = @import("build_options");

const VERSION = build_options.version;

// aarch64-linux (Android/Termux) TLS-segment alignment anchor. Pure-Zig
// replacement for src/bionic_tls_align.c: a 64-byte-aligned threadlocal forces
// the process TLS segment to >=64B alignment, which Android's Bionic loader
// requires (an under-aligned TLS segment can crash at process start). Only
// meaningful on aarch64-linux; kept alive by a reference in main() so it isn't
// stripped (matches the C anchor's `used`/`retain`).
const bionic_tls_anchor_needed = builtin.target.cpu.arch == .aarch64 and builtin.target.os.tag == .linux;
threadlocal var bionic_tls_align_anchor: u8 align(64) = 0;

var G: state.MinerState = .{};

// ---- net integration: glue MinerState to net.Hooks ----
const Ctx = struct {
    s: *state.MinerState,
    share_jobid: [state.MAX_JOBID]u8 = undefined,
    share_blob: [state.BLOB_LEN * 2]u8 = undefined,
};

fn onJob(ctx_ptr: *anyopaque, job: *const net.Job) void {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr));
    _ = ctx.s.setJob(&job.blob, job.jobid(), job.height, job.difficulty);
    // This connection has now issued work, so staged shares can be sent. Until
    // this point the miner is still hashing the previous session's job.
    ctx.s.markSessionHasJob();
    // Latch: only overwrite a counter when the job actually carried it, so a pool that
    // omits these fields doesn't flicker the display to 0 (matches the C ref).
    if (job.miniblocks) |m| ctx.s.accepted.store(m, .monotonic);
    if (job.blocks) |b| ctx.s.blocks.store(b, .monotonic);
    if (job.rejected) |r| ctx.s.rejected.store(r, .monotonic);
}

fn pollShare(ctx_ptr: *anyopaque) ?net.Share {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr));
    const staged = ctx.s.takeStagedShare(&ctx.share_jobid, &ctx.share_blob) orelse return null;
    _ = ctx.s.submitted.fetchAdd(1, .monotonic);
    return net.Share{
        .jobid = ctx.share_jobid[0..staged.jobid_len],
        .mbl_blob_hex = &ctx.share_blob,
    };
}

fn setConnected(ctx_ptr: *anyopaque, connected: bool) void {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr));
    ctx.s.connected.store(connected, .monotonic);
    // A session boundary in either direction invalidates everything staged:
    // job_epoch is monotonic across reconnects, so a share held from the old
    // connection still matches the current epoch and would be sent on the new
    // one against a job that session never issued.
    ctx.s.resetSubmitSession();
}

/// net.zig's log sink: route its INFO/WARN/ERROR lines (Connecting/Connected/...) through
/// the timestamped console logger. ctx is unused -- the console writes to the shared stderr.
fn netLog(ctx_ptr: *anyopaque, level: []const u8, msg: []const u8) void {
    _ = ctx_ptr;
    console.logLineRaw(level, msg);
}

fn shouldQuit(ctx_ptr: *anyopaque) bool {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr));
    return ctx.s.quit.load(.monotonic);
}

// ---- Ctrl-C handling (Windows) ----
fn ctrlHandler(dwCtrlType: u32) callconv(.C) std.os.windows.BOOL {
    _ = dwCtrlType;
    G.quit.store(true, .monotonic);
    return std.os.windows.TRUE;
}

fn installSignalHandler() void {
    if (builtin.os.tag == .windows) {
        _ = std.os.windows.kernel32.SetConsoleCtrlHandler(ctrlHandler, std.os.windows.TRUE);
    } else {
        const handler = struct {
            fn h(_: c_int) callconv(.C) void {
                G.quit.store(true, .monotonic);
            }
        }.h;
        const act = std.posix.Sigaction{ .handler = .{ .handler = handler }, .mask = std.posix.empty_sigset, .flags = 0 };
        std.posix.sigaction(std.posix.SIG.INT, &act, null);
        std.posix.sigaction(std.posix.SIG.TERM, &act, null);
    }
}

fn usage() void {
    std.debug.print(
        \\Usage: zig-miner [-d [ws://|wss://]host:port] [-w wallet] [-t threads] [-c config.json] [-V] [--selftest]
        \\  -d  daemon/pool address [scheme://]host:port  (default community-pools.mysrv.cloud:10300)
        \\        DERO getwork (local derod AND pools) is TLS: bare and wss:// connect over TLS.
        \\        ws:// forces plaintext (only for getwork behind a TLS-terminating proxy).
        \\  -w  DERO wallet address            (default from config.json / built-in)
        \\  -t  mining threads                 (default: logical CPU count)
        \\  -c, --config-file <path>           config file (default: config.json)
        \\  -V  verbose
        \\  --selftest  run pow("a") KAT and exit (0=PASS,1=FAIL)
        \\  --bench     run an AstroBWTv3 hashrate benchmark (~5s) and exit
        \\  --setup     interactively write config.json (pool/wallet/threads), then exit
        \\  -h, --help / -v, --version
        \\
    , .{});
}

/// Run the pow("a") known-answer test, writing the lowercase hex digest into `hex_out`.
/// Returns true on the expected digest. Pure (no printing) so both the startup KAT (silent
/// on success, like the C miner) and the `--selftest` command can share it.
fn powKat(alloc: std.mem.Allocator, hex_out: *[64]u8) !bool {
    const w = try alloc.create(pow.Worker);
    defer alloc.destroy(w);
    w.* = .{};
    defer w.deinitSA();
    var out: [32]u8 = undefined;
    try pow.hash("a", &out, w);
    _ = std.fmt.bufPrint(hex_out, "{s}", .{std.fmt.fmtSliceHexLower(&out)}) catch unreachable;
    const expected = "54e2324ddacc3f0383501a9e5760f85d63e9bc6705e9124ca7aef89016ab81ea";
    return std.mem.eql(u8, hex_out, expected);
}

fn selftest(alloc: std.mem.Allocator) !u8 {
    var hex: [64]u8 = undefined;
    const pass = try powKat(alloc, &hex);
    std.debug.print("selftest pow(a): {s} {s}\n", .{ hex, if (pass) "PASS" else "FAIL" });

    // The KAT above only covers hash1. The mining loop calls hash2, and a
    // correct digest cannot by itself prove the accelerated backend ran -- so
    // name the backend and differential-check the real path against std.
    std.debug.print("selftest sha backend: {s}\n", .{sha_mb.backendName()});
    const buf = try alloc.alloc(u8, sha_mb.parity_buf_len);
    defer alloc.free(buf);
    const parity = sha_mb.parityCheck(buf);
    std.debug.print("selftest sha hash2 parity: {s}\n", .{if (parity) "PASS" else "FAIL"});

    return if (pass and parity) 0 else 1;
}

/// `--bench`: AstroBWTv3 hashrate benchmark (Go dero-miner `--testnet`/bench path runs
/// the PoW in a tight loop, no networking). Single thread, ~5s, reports H/s. Each
/// iteration varies the nonce in the work blob so the BWT input differs every hash.
fn bench(alloc: std.mem.Allocator) !u8 {
    const w = try alloc.create(pow.Worker);
    defer alloc.destroy(w);
    w.* = .{};
    defer w.deinitSA();

    var input: [48]u8 = .{0} ** 48; // BLOB_SIZE work blob
    var out: [32]u8 = undefined;
    std.debug.print("benchmarking AstroBWTv3 (1 thread, ~5s)...\n", .{});
    var timer = try std.time.Timer.start();
    const duration_ns: u64 = 5 * std.time.ns_per_s;
    var count: u64 = 0;
    while (timer.read() < duration_ns) : (count += 1) {
        std.mem.writeInt(u64, input[0..8], count, .little); // unique nonce per hash
        try pow.hash(&input, &out, w);
    }
    const elapsed_s = @as(f64, @floatFromInt(timer.read())) / @as(f64, std.time.ns_per_s);
    const hps = if (elapsed_s > 0) @as(f64, @floatFromInt(count)) / elapsed_s else 0;
    std.debug.print("AstroBWTv3: {d} hashes in {d:.2}s = {d:.1} H/s\n", .{ count, elapsed_s, hps });
    return 0;
}

var g_verbose = false;
var g_status_tty = false;

// ANSI SGR colors matching the C miner (dirtybird-miner src/main.cpp).
const A_RESET = "\x1b[0m";
const A_CLREOL = "\x1b[K";
const A_BYELLOW = "\x1b[93m";
const A_BGREEN = "\x1b[92m";
const A_BWHITE = "\x1b[97m";
const A_GREEN = "\x1b[32m";
const A_BLUE = "\x1b[34m";
const A_CYAN = "\x1b[36m";
const A_MAGENTA = "\x1b[35m";
const A_WHITE = "\x1b[37m";
const A_BRED = "\x1b[91m";

/// Humanize difficulty to K/M/G via integer division (matches the C reporter).
fn fmtDiff(buf: []u8, d: u64) []const u8 {
    if (d >= 1_000_000_000) return std.fmt.bufPrint(buf, "{d}G", .{d / 1_000_000_000}) catch "?";
    if (d >= 1_000_000) return std.fmt.bufPrint(buf, "{d}M", .{d / 1_000_000}) catch "?";
    if (d >= 1_000) return std.fmt.bufPrint(buf, "{d}K", .{d / 1_000}) catch "?";
    return std.fmt.bufPrint(buf, "{d}", .{d}) catch "?";
}

const ReportStats = struct {
    rate: f64,
    avg: f64,
    height: i64,
    accepted: i64,
    blocks: i64,
    rejected: i64,
    diff: []const u8,
    hh: u64,
    mm: u64,
    ss: u64,
};

const rate_window_slots = 10;

const HashrateSnapshot = struct {
    elapsed_ns: u64,
    hashes: i64,
};

const RateWindow = struct {
    points: [rate_window_slots]HashrateSnapshot,
    next: usize = 0,
    start: HashrateSnapshot,
    last: HashrateSnapshot,

    fn init(elapsed_ns: u64, hashes: i64) RateWindow {
        const snapshot = HashrateSnapshot{ .elapsed_ns = elapsed_ns, .hashes = hashes };
        return .{
            .points = .{snapshot} ** rate_window_slots,
            .start = snapshot,
            .last = snapshot,
        };
    }

    fn rateBetween(newer: HashrateSnapshot, older: HashrateSnapshot) f64 {
        if (newer.elapsed_ns <= older.elapsed_ns or newer.hashes < older.hashes) return 0;
        const elapsed_s = @as(f64, @floatFromInt(newer.elapsed_ns - older.elapsed_ns)) /
            @as(f64, std.time.ns_per_s);
        return @as(f64, @floatFromInt(newer.hashes - older.hashes)) / elapsed_s / 1000.0;
    }

    fn sample(self: *RateWindow, elapsed_ns: u64, hashes: i64) f64 {
        const current = HashrateSnapshot{ .elapsed_ns = elapsed_ns, .hashes = hashes };
        if (current.elapsed_ns <= self.last.elapsed_ns or current.hashes < self.last.hashes) return 0;
        const old = self.points[self.next];
        self.points[self.next] = current;
        self.next = (self.next + 1) % self.points.len;
        self.last = current;
        return rateBetween(current, old);
    }

    fn average(self: *const RateWindow, elapsed_ns: u64, hashes: i64) f64 {
        return rateBetween(.{ .elapsed_ns = elapsed_ns, .hashes = hashes }, self.start);
    }
};

/// The family's five rungs, widest first. Shared byte-for-byte with the C++,
/// Rust and Go miners: same field sets, same labels, same separators, same
/// colour-to-field mapping. Do not reshape one of these without changing all
/// four -- the conformance fixture below is the same table in every repo.
const StatusLayout = enum { full, medium, narrow, compact, minimal };

const status_ladder = [_]StatusLayout{ .full, .medium, .narrow, .compact, .minimal };

/// `DIRTYBIRD_COLS` overrides the width probe, for setups where the ioctl
/// reports 0 (some CI pty wrappers, a few Android terminals). Checked first so
/// it works even where the probe would have succeeded.
fn envColumns() ?usize {
    var buf: [64]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const raw = std.process.getEnvVarOwned(fba.allocator(), "DIRTYBIRD_COLS") catch return null;
    const v = std.fmt.parseInt(usize, std.mem.trim(u8, raw, " \t\r\n"), 10) catch return null;
    return if (v > 0 and v < 10000) v else null;
}

fn terminalColumns() usize {
    if (envColumns()) |v| return v;
    if (builtin.os.tag == .windows) {
        var info: std.os.windows.CONSOLE_SCREEN_BUFFER_INFO = undefined;
        if (std.os.windows.kernel32.GetConsoleScreenBufferInfo(std.io.getStdErr().handle, &info) != std.os.windows.FALSE) {
            const buffer_cols: i32 = @intCast(info.dwSize.X);
            const window_cols: i32 = @as(i32, @intCast(info.srWindow.Right)) -
                @as(i32, @intCast(info.srWindow.Left)) + 1;
            const cols = @min(buffer_cols, window_cols);
            if (cols > 0) return @intCast(cols);
        }
    } else {
        var size: std.posix.winsize = .{ .row = 0, .col = 0, .xpixel = 0, .ypixel = 0 };
        const result = std.posix.system.ioctl(
            std.io.getStdErr().handle,
            std.posix.T.IOCGWINSZ,
            @intFromPtr(&size),
        );
        if (std.posix.errno(result) == .SUCCESS and size.col > 0) return size.col;
    }
    // 80, not 40: "console of unknown size" is a real case (Git Bash/mintty
    // report a terminal but fail the size query on a pty handle), and assuming
    // a classic 80 keeps the line on one row there. Assuming narrow instead
    // just discards fields nobody asked to lose. The siblings agree on 80.
    return 80;
}

fn visibleWidth(line: []const u8) usize {
    var width: usize = 0;
    var i: usize = 0;
    while (i < line.len) {
        if (line[i] == '\x1b' and i + 1 < line.len and line[i + 1] == '[') {
            i += 2;
            while (i < line.len and !(line[i] >= 0x40 and line[i] <= 0x7e)) : (i += 1) {}
            if (i < line.len) i += 1;
        } else {
            if (line[i] >= 0x20) width += 1;
            i += 1;
        }
    }
    return width;
}

/// Render one rung. Every SGR sits immediately before the run it colours, and a
/// separator is emitted in Text with the escape preceding it -- so the tag runs
/// straight into the rate with no Text escape between them, and the final field
/// is followed *directly* by Reset. That last detail is load-bearing: this used
/// to emit a trailing A_BWHITE before the reset, giving FULL 17 SGR sequences
/// where the C++ and Rust miners emit 16. It is invisible on screen (a colour
/// set immediately before a reset is a no-op), so only a byte test catches it.
/// Go inherited the same extra escape from this function.
///
/// The reject colour is the only value-dependent escape, and MINIMAL is the one
/// rung that carries no reject field -- so its bytes are reject-independent.
fn renderStatusLayout(buf: []u8, stats: ReportStats, layout: StatusLayout) ![]const u8 {
    const rejcol = if (stats.rejected > 0) A_BRED else A_WHITE;
    var stream = std.io.fixedBufferStream(buf);
    const writer = stream.writer();

    try writer.writeByte('\r');
    switch (layout) {
        .full => {
            try writer.print("{s}[DIRTYBIRD] ", .{A_BYELLOW});
            try writer.print("{s}{d:.2} KH/s{s} ({s}{d:.2} KH/s avg{s})", .{
                A_BGREEN, stats.rate, A_BWHITE, A_GREEN, stats.avg, A_BWHITE,
            });
            try writer.print(" | {s}Height:{d}{s}", .{ A_BLUE, stats.height, A_BWHITE });
            try writer.print(" | {s}Miniblocks:{d}{s}", .{ A_CYAN, stats.accepted, A_BWHITE });
            try writer.print(" | {s}Blocks:{d}{s}", .{ A_GREEN, stats.blocks, A_BWHITE });
            try writer.print(" | {s}REJ:{d}{s}", .{ rejcol, stats.rejected, A_BWHITE });
            try writer.print(" | {s}Diff:{s}{s}", .{ A_MAGENTA, stats.diff, A_BWHITE });
            try writer.print(" | {s}{d:0>2}:{d:0>2}:{d:0>2}", .{ A_WHITE, stats.hh, stats.mm, stats.ss });
        },
        .medium => {
            try writer.print("{s}[DIRTYBIRD] ", .{A_BYELLOW});
            try writer.print("{s}{d:.2} KH/s{s} ({s}{d:.2} avg{s})", .{
                A_BGREEN, stats.rate, A_BWHITE, A_GREEN, stats.avg, A_BWHITE,
            });
            try writer.print(" | {s}H:{d}{s}", .{ A_BLUE, stats.height, A_BWHITE });
            try writer.print(" | {s}MB:{d}{s}", .{ A_CYAN, stats.accepted, A_BWHITE });
            try writer.print(" | {s}B:{d}{s}", .{ A_GREEN, stats.blocks, A_BWHITE });
            try writer.print(" | {s}R:{d}{s}", .{ rejcol, stats.rejected, A_BWHITE });
            try writer.print(" | {s}D:{s}{s}", .{ A_MAGENTA, stats.diff, A_BWHITE });
            try writer.print(" | {s}{d:0>2}:{d:0>2}:{d:0>2}", .{ A_WHITE, stats.hh, stats.mm, stats.ss });
        },
        .narrow => {
            try writer.print("{s}[DIRTYBIRD] ", .{A_BYELLOW});
            try writer.print("{s}{d:.2} KH/s{s}", .{ A_BGREEN, stats.rate, A_BWHITE });
            try writer.print(" | {s}H:{d}{s}", .{ A_BLUE, stats.height, A_BWHITE });
            try writer.print(" | {s}MB:{d}{s}", .{ A_CYAN, stats.accepted, A_BWHITE });
            try writer.print(" | {s}B:{d}{s}", .{ A_GREEN, stats.blocks, A_BWHITE });
            try writer.print(" | {s}R:{d}{s}", .{ rejcol, stats.rejected, A_BWHITE });
            try writer.print(" | {s}D:{s}{s}", .{ A_MAGENTA, stats.diff, A_BWHITE });
            try writer.print(" | {s}{d:0>2}:{d:0>2}:{d:0>2}", .{ A_WHITE, stats.hh, stats.mm, stats.ss });
        },
        .compact => {
            try writer.print("{s}[DB] ", .{A_BYELLOW});
            try writer.print("{s}{d:.2} KH/s{s}", .{ A_BGREEN, stats.rate, A_BWHITE });
            try writer.print(" | {s}H:{d}{s}", .{ A_BLUE, stats.height, A_BWHITE });
            try writer.print(" {s}MB:{d}{s}", .{ A_CYAN, stats.accepted, A_BWHITE });
            try writer.print(" {s}B:{d}{s}", .{ A_GREEN, stats.blocks, A_BWHITE });
            try writer.print(" {s}R:{d}{s}", .{ rejcol, stats.rejected, A_BWHITE });
            try writer.print(" | {s}{d:0>2}:{d:0>2}:{d:0>2}", .{ A_WHITE, stats.hh, stats.mm, stats.ss });
        },
        .minimal => {
            try writer.print("{s}[DB] ", .{A_BYELLOW});
            try writer.print("{s}{d:.2} KH/s{s}", .{ A_BGREEN, stats.rate, A_BWHITE });
            try writer.print(" {s}MB:{d}{s}", .{ A_CYAN, stats.accepted, A_BWHITE });
            try writer.print(" {s}B:{d}", .{ A_GREEN, stats.blocks });
        },
    }
    // Reset before erase: erase-to-EOL fills with the *active* SGR background,
    // so erasing first would paint a coloured bar the day a background is added.
    try writer.print("{s}{s}", .{ A_RESET, A_CLREOL });
    return stream.getWritten();
}

/// Copy `line` into `out`, keeping every complete CSI sequence and every control
/// byte (neither costs a column) and dropping printable bytes once `budget`
/// visible columns have been emitted. Byte-truncating a coloured line can cut an
/// escape in half, which wedges the terminal's colour state and prints the
/// escape's tail as literal text -- so the trailing reset and erase always
/// survive. This is the C miner's `ansi_clamp`.
fn ansiClamp(out: []u8, line: []const u8, budget: usize) []const u8 {
    var w: usize = 0;
    var vis: usize = 0;
    var i: usize = 0;
    while (i < line.len) {
        if (line[i] == '\x1b' and i + 1 < line.len and line[i + 1] == '[') {
            var j = i + 2;
            while (j < line.len and !(line[j] >= 0x40 and line[j] <= 0x7e)) : (j += 1) {}
            if (j < line.len) j += 1;
            const seq = line[i..j];
            if (w + seq.len > out.len) return out[0..w];
            @memcpy(out[w..][0..seq.len], seq);
            w += seq.len;
            i = j;
        } else {
            const b = line[i];
            const keep = b < 0x20 or vis < budget;
            if (keep) {
                if (w + 1 > out.len) return out[0..w];
                out[w] = b;
                w += 1;
                if (b >= 0x20) vis += 1;
            }
            i += 1;
        }
    }
    return out[0..w];
}

fn formatStatusLine(buf: []u8, stats: ReportStats, tty: bool, columns: usize) []const u8 {
    return formatStatusLineChecked(buf, stats, tty, columns) catch if (tty) "\r" ++ A_CLREOL else "\n";
}

fn formatStatusLineChecked(buf: []u8, stats: ReportStats, tty: bool, columns: usize) ![]const u8 {
    if (!tty) {
        var stream = std.io.fixedBufferStream(buf);
        const writer = stream.writer();
        try writer.print(
            "[DIRTYBIRD] {d:.2} KH/s ({d:.2} KH/s avg) | Height:{d} | Miniblocks:{d} | Blocks:{d} | REJ:{d} | Diff:{s} | {d:0>2}:{d:0>2}:{d:0>2}",
            .{ stats.rate, stats.avg, stats.height, stats.accepted, stats.blocks, stats.rejected, stats.diff, stats.hh, stats.mm, stats.ss },
        );
        try writer.writeByte('\n');
        return stream.getWritten();
    }

    // `columns == 0` means "width unknown", which is UNBOUNDED -- select FULL.
    // It used to mean budget 0, i.e. clip everything away. Note this is a pure
    // width question: whether we have a terminal at all is the `tty` argument,
    // and conflating the two is what makes a shared fixture unportable.
    const budget = if (columns > 0) columns - 1 else std.math.maxInt(usize);
    for (status_ladder) |layout| {
        const line = try renderStatusLayout(buf, stats, layout);
        if (visibleWidth(line) <= budget) return line;
    }

    // Narrower than the smallest rung: re-render MINIMAL *with* colour and clamp
    // it escape-aware, so the trailing reset and erase survive.
    var minimal_buf: [512]u8 = undefined;
    const minimal = try renderStatusLayout(&minimal_buf, stats, .minimal);
    return ansiClamp(buf, minimal, budget);
}

/// Whether the live status row has anything true to report this tick.
///
/// A displayed 0.00 KH/s is not a rare fault -- it is what every launch prints.
/// getwork sends no job at connect time (the first arrives on a dispatch tick
/// ~500ms later), so dial + TLS + upgrade + first job is ~1-3s of genuine zero
/// and the reporter's first tick lands inside it. Reconnect backoff (1s
/// doubling to a 30s cap) is the same story, repeatedly, on a flaky link.
///
/// No DERO miner in the ecosystem displays a live zero. tnn-miner -- the
/// ancestor this miner's worker gate already cites -- suppresses its row two
/// ways: `if (!isConnected) return 1;` (reporter.cpp:31) plus a first-hashrate
/// gate commented "Mining hasn't started yet - don't print status, just
/// accumulate stats". 8lecramm's C miner reaches the same result structurally,
/// calling print_status only from inside the worker thread. netrunner's GUI
/// shows a grey "---" placeholder and a separate "Offline" label.
///
/// Suppressing rather than printing a reason is safe here because the
/// transitions are already logged, and console.logLine emits `\r\x1b[K` before
/// its text -- so a log line erases whatever row is on screen instead of
/// leaving a stale one behind.
fn statusRowHasSomethingToSay(connected: bool, job_epoch: u64) bool {
    return connected and job_epoch > 0;
}

fn reporter() void {
    var timer = std.time.Timer.start() catch |err| {
        console.logLine("ERROR", "status timer initialization failed: {s}", .{@errorName(err)});
        G.quit.store(true, .monotonic);
        return;
    };
    const start_hashes = G.total_hashes.load(.monotonic);
    const start_ns = timer.read();
    var rates = RateWindow.init(start_ns, start_hashes);
    while (!G.quit.load(.monotonic)) {
        std.time.sleep(std.time.ns_per_s);
        const now_ns = timer.read();
        const elapsed_ns = now_ns - start_ns;
        const total = G.total_hashes.load(.monotonic);
        const rate = rates.sample(now_ns, total);
        const avg = rates.average(now_ns, total);
        const sec: u64 = elapsed_ns / std.time.ns_per_s;
        const hh = sec / 3600;
        const mm = (sec % 3600) / 60;
        const ss = sec % 60;

        const height = G.height.load(.monotonic);
        const accepted = G.accepted.load(.monotonic);
        const blocks = G.blocks.load(.monotonic);
        const rejected = G.rejected.load(.monotonic);
        const submitted = G.submitted.load(.monotonic);
        const stale_drops = G.stale_drops.load(.monotonic);
        const submit_drops = G.submit_drops.load(.monotonic);
        var dbuf: [24]u8 = undefined;
        const diff = fmtDiff(&dbuf, G.difficulty.load(.monotonic));

        // The sampling above runs on EVERY tick, printed or not: skipping it
        // would let the sliding window go stale, so the rate would read wrong
        // for ~10s after mining resumes. tnn's reporter says the same thing --
        // "don't print status, just accumulate stats".
        //
        // The redirected record is deliberately NOT suppressed. It is
        // machine-parsed (HiveOS consumes it), where a run of 0.00 records
        // during an outage is the correct report and a gap is not.
        const worth_printing = statusRowHasSomethingToSay(
            G.connected.load(.monotonic),
            G.job_epoch.load(.acquire),
        );
        if (!g_status_tty or worth_printing) {
            // Five rungs of worst-case u64 fields plus 16 SGR sequences; 1024
            // was sized for three rungs and would degrade to a bare "\r\x1b[K"
            // on overflow rather than narrowing.
            var line_buf: [2048]u8 = undefined;
            const line = formatStatusLine(&line_buf, .{
                .rate = rate,
                .avg = avg,
                .height = height,
                .accepted = accepted,
                .blocks = blocks,
                .rejected = rejected,
                .diff = diff,
                .hh = hh,
                .mm = mm,
                .ss = ss,
            }, g_status_tty, if (g_status_tty) terminalColumns() else 0);
            std.debug.print("{s}", .{line});
        }

        // The funnel is a separate record, never part of the status line. When
        // it lived inside the line it was counted as columns, so -v could push
        // FULL past its width and silently select a narrower rung than the
        // terminal could actually hold -- and it landed after the reset, so the
        // line no longer ended with one. C++ and Rust both keep it outside.
        //
        // All five counters come from the one snapshot taken above. They used to
        // be split -- acc/rej from locals, the other three loaded fresh at the
        // call -- so the record could pair a `submitted` from after a tick with
        // an `acc`/`rej` from before it, and the funnel would not balance. That
        // arithmetic balancing is the only reason this record exists.
        if (g_verbose) {
            console.logLine("INFO", "funnel submitted:{d} acc:{d} rej:{d} stale:{d} sendfail:{d}", .{
                submitted, accepted, rejected, stale_drops, submit_drops,
            });
        }
    }
}

test "RateWindow uses reporter baseline, real elapsed time, and ten samples" {
    const second = std.time.ns_per_s;

    var nonzero = RateWindow.init(0, 5_000);
    try std.testing.expectApproxEqAbs(@as(f64, 1.0), nonzero.sample(second, 6_000), 0.000_001);
    try std.testing.expectApproxEqAbs(@as(f64, 1.0), nonzero.average(second, 6_000), 0.000_001);

    var irregular = RateWindow.init(0, 0);
    try std.testing.expectApproxEqAbs(@as(f64, 1.0), irregular.sample(second + second / 4, 1_250), 0.000_001);
    try std.testing.expectEqual(@as(f64, 0), irregular.sample(second, 1_500));
    try std.testing.expectEqual(@as(f64, 0), irregular.sample(2 * second, 1_000));

    var steady = RateWindow.init(0, 0);
    var tick: u64 = 1;
    while (tick <= 11) : (tick += 1) {
        try std.testing.expectApproxEqAbs(
            @as(f64, 1.0),
            steady.sample(tick * second, @intCast(tick * 1_000)),
            0.000_001,
        );
    }
}

test "RateWindow decays to zero after ten idle samples" {
    const second = std.time.ns_per_s;
    var rates = RateWindow.init(0, 0);
    var tick: u64 = 1;
    while (tick <= 5) : (tick += 1) _ = rates.sample(tick * second, @intCast(tick * 1_000));
    while (tick < 15) : (tick += 1) _ = rates.sample(tick * second, 5_000);
    try std.testing.expectApproxEqAbs(@as(f64, 0.0), rates.sample(15 * second, 5_000), 0.000_001);
    try std.testing.expectApproxEqAbs(1.0 / 3.0, rates.average(15 * second, 5_000), 0.000_001);
}

test "formatStatusLine rewrites one colored TTY row" {
    var buf: [512]u8 = undefined;
    const line = formatStatusLine(&buf, .{
        .rate = 23.76,
        .avg = 20.71,
        .height = 7212998,
        .accepted = 1998,
        .blocks = 262,
        .rejected = 4,
        .diff = "20K",
        .hh = 0,
        .mm = 0,
        .ss = 5,
    }, true, 200);

    try std.testing.expect(std.mem.startsWith(u8, line, "\r" ++ A_BYELLOW ++ "[DIRTYBIRD] "));
    try std.testing.expect(std.mem.indexOf(u8, line, "Height:7212998") != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, line, '\n') == null);
    try std.testing.expect(std.mem.endsWith(u8, line, A_RESET ++ A_CLREOL));
}

// ===========================================================================
// Status-line conformance fixture.
//
// THE SAME TABLE LIVES IN ALL FOUR MINERS (C++ tools/replay/test_statusline.cpp,
// Rust, Go, here). The four must render byte-identical visible payloads at every
// width. If you change a rung here without changing the other three, this table
// is what should stop you.
//
// Values are the C++ suite's "screenshot" case. The widths below are DATA, not
// constants: they are what this fixture happens to measure. Never turn them into
// hardcoded selection thresholds -- doing exactly that is what reintroduced
// line-wrap in the C and Rust ports. Selection renders and measures.
// ===========================================================================

const fixture = ReportStats{
    .rate = 0.00,
    .avg = 4.96,
    .height = 7368356,
    .accepted = 962,
    .blocks = 93,
    .rejected = 25,
    .diff = "795K",
    .hh = 0,
    .mm = 1,
    .ss = 11,
};

const fx_full = "[DIRTYBIRD] 0.00 KH/s (4.96 KH/s avg) | Height:7368356 | Miniblocks:962 | Blocks:93 | REJ:25 | Diff:795K | 00:01:11";
const fx_medium = "[DIRTYBIRD] 0.00 KH/s (4.96 avg) | H:7368356 | MB:962 | B:93 | R:25 | D:795K | 00:01:11";
const fx_narrow = "[DIRTYBIRD] 0.00 KH/s | H:7368356 | MB:962 | B:93 | R:25 | D:795K | 00:01:11";
const fx_compact = "[DB] 0.00 KH/s | H:7368356 MB:962 B:93 R:25 | 00:01:11";
const fx_minimal = "[DB] 0.00 KH/s MB:962 B:93";

/// Drop every CSI sequence and control byte, leaving the visible payload.
fn stripAnsi(out: []u8, line: []const u8) []const u8 {
    var w: usize = 0;
    var i: usize = 0;
    while (i < line.len) {
        if (line[i] == '\x1b' and i + 1 < line.len and line[i + 1] == '[') {
            i += 2;
            while (i < line.len and !(line[i] >= 0x40 and line[i] <= 0x7e)) : (i += 1) {}
            if (i < line.len) i += 1;
        } else {
            if (line[i] >= 0x20) {
                out[w] = line[i];
                w += 1;
            }
            i += 1;
        }
    }
    return out[0..w];
}

fn countSgr(line: []const u8) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i + 1 < line.len) : (i += 1) {
        if (line[i] == '\x1b' and line[i + 1] == '[') n += 1;
    }
    return n;
}

test "each rung renders the family's canonical payload at its own width" {
    // palette_sgr is the family's documented per-tier count: 16/16/14/12/6.
    const cases = [_]struct { layout: StatusLayout, want: []const u8, cols: usize, palette_sgr: usize }{
        .{ .layout = .full, .want = fx_full, .cols = 115, .palette_sgr = 16 },
        .{ .layout = .medium, .want = fx_medium, .cols = 87, .palette_sgr = 16 },
        .{ .layout = .narrow, .want = fx_narrow, .cols = 76, .palette_sgr = 14 },
        .{ .layout = .compact, .want = fx_compact, .cols = 54, .palette_sgr = 12 },
        .{ .layout = .minimal, .want = fx_minimal, .cols = 26, .palette_sgr = 6 },
    };
    for (cases) |c| {
        var buf: [1024]u8 = undefined;
        const line = try renderStatusLayout(&buf, fixture, c.layout);
        var plain: [1024]u8 = undefined;
        try std.testing.expectEqualStrings(c.want, stripAnsi(&plain, line));
        try std.testing.expectEqual(c.cols, visibleWidth(line));
        // +2 for the trailing reset and erase, which every tier carries. A FULL
        // of 19 here means the legacy trailing A_BWHITE has come back.
        try std.testing.expectEqual(c.palette_sgr + 2, countSgr(line));
    }
}

test "FULL ends with the time colour straight into reset -- no extra escape" {
    // The single highest-risk byte in the family spec. An A_BWHITE here is a
    // visual no-op (a colour set immediately before a reset), so nothing but a
    // byte assertion will ever catch its return. C++ and Rust emit 16 SGR at
    // FULL; this file used to emit 17, and Go inherited that from here.
    var buf: [1024]u8 = undefined;
    const line = try renderStatusLayout(&buf, fixture, .full);
    try std.testing.expect(std.mem.endsWith(
        u8,
        line,
        A_WHITE ++ "00:01:11" ++ A_RESET ++ A_CLREOL,
    ));
    try std.testing.expect(std.mem.indexOf(u8, line, A_BWHITE ++ A_RESET) == null);
}

test "canonical FULL coloured bytes" {
    var buf: [1024]u8 = undefined;
    const line = try renderStatusLayout(&buf, fixture, .full);
    try std.testing.expectEqualStrings(
        "\r" ++ A_BYELLOW ++ "[DIRTYBIRD] " ++ A_BGREEN ++ "0.00 KH/s" ++ A_BWHITE ++ " (" ++
            A_GREEN ++ "4.96 KH/s avg" ++ A_BWHITE ++ ") | " ++ A_BLUE ++ "Height:7368356" ++ A_BWHITE ++ " | " ++
            A_CYAN ++ "Miniblocks:962" ++ A_BWHITE ++ " | " ++ A_GREEN ++ "Blocks:93" ++ A_BWHITE ++ " | " ++
            A_BRED ++ "REJ:25" ++ A_BWHITE ++ " | " ++ A_MAGENTA ++ "Diff:795K" ++ A_BWHITE ++ " | " ++
            A_WHITE ++ "00:01:11" ++ A_RESET ++ A_CLREOL,
        line,
    );
}

test "MEDIUM coloured bytes with a non-zero reject count" {
    // The rejects-are-red escape is pinned almost nowhere in the family: every
    // other coloured golden uses R:0, where RejHi and Time are the same bytes.
    var buf: [1024]u8 = undefined;
    const line = try renderStatusLayout(&buf, fixture, .medium);
    try std.testing.expectEqualStrings(
        "\r" ++ A_BYELLOW ++ "[DIRTYBIRD] " ++ A_BGREEN ++ "0.00 KH/s" ++ A_BWHITE ++ " (" ++
            A_GREEN ++ "4.96 avg" ++ A_BWHITE ++ ") | " ++ A_BLUE ++ "H:7368356" ++ A_BWHITE ++ " | " ++
            A_CYAN ++ "MB:962" ++ A_BWHITE ++ " | " ++ A_GREEN ++ "B:93" ++ A_BWHITE ++ " | " ++
            A_BRED ++ "R:25" ++ A_BWHITE ++ " | " ++ A_MAGENTA ++ "D:795K" ++ A_BWHITE ++ " | " ++
            A_WHITE ++ "00:01:11" ++ A_RESET ++ A_CLREOL,
        line,
    );

    // ...and the reject colour is the ONLY value-dependent escape.
    var zero = fixture;
    zero.rejected = 0;
    var zbuf: [1024]u8 = undefined;
    const zline = try renderStatusLayout(&zbuf, zero, .medium);
    try std.testing.expect(std.mem.indexOf(u8, zline, A_BRED) == null);
    try std.testing.expect(std.mem.indexOf(u8, zline, A_WHITE ++ "R:0") != null);
}

test "the width ladder selects the expected rung at every boundary" {
    const Row = struct { cols: usize, want: []const u8 };
    const table = [_]Row{
        .{ .cols = 0, .want = fx_full }, // unknown width => unbounded
        .{ .cols = 200, .want = fx_full },
        .{ .cols = 116, .want = fx_full }, // boundary
        .{ .cols = 115, .want = fx_medium }, // boundary - 1
        .{ .cols = 88, .want = fx_medium }, // boundary
        .{ .cols = 87, .want = fx_narrow }, // boundary - 1
        .{ .cols = 80, .want = fx_narrow }, // classic console
        .{ .cols = 77, .want = fx_narrow }, // boundary
        .{ .cols = 76, .want = fx_compact }, // boundary - 1
        .{ .cols = 56, .want = fx_compact }, // the reported Termux width
        .{ .cols = 55, .want = fx_compact }, // boundary
        .{ .cols = 54, .want = fx_minimal }, // boundary - 1
        .{ .cols = 27, .want = fx_minimal }, // boundary
    };
    for (table) |row| {
        var buf: [2048]u8 = undefined;
        const line = formatStatusLine(&buf, fixture, true, row.cols);
        var plain: [2048]u8 = undefined;
        try std.testing.expectEqualStrings(row.want, stripAnsi(&plain, line));

        // Structural invariants, every row.
        try std.testing.expect(line[0] == '\r');
        try std.testing.expect(std.mem.indexOfScalar(u8, line[1..], '\r') == null);
        try std.testing.expect(std.mem.indexOfScalar(u8, line, '\n') == null);
        try std.testing.expect(std.mem.endsWith(u8, line, A_RESET ++ A_CLREOL));
        if (row.cols > 0) try std.testing.expect(visibleWidth(line) <= row.cols - 1);
    }
}

test "below the smallest rung the line is clamped, never mangled" {
    const table = [_]struct { cols: usize, want: []const u8 }{
        .{ .cols = 26, .want = "[DB] 0.00 KH/s MB:962 B:9" },
        .{ .cols = 20, .want = "[DB] 0.00 KH/s MB:9" },
        // budget 10 -- the same budget as Go's own clamp golden, which is
        // "[DB] 5.04 " for its fixture (status_test.go, `tiny`). Trailing space
        // included: the clamp counts columns, it does not trim. This row is the
        // only cross-miner check on the clamp payloads; every other rung was
        // verified field-for-field against Go's renderer.
        .{ .cols = 11, .want = "[DB] 0.00 " },
        .{ .cols = 10, .want = "[DB] 0.00" },
        .{ .cols = 1, .want = "" },
    };
    for (table) |row| {
        var buf: [2048]u8 = undefined;
        const line = formatStatusLine(&buf, fixture, true, row.cols);
        var plain: [2048]u8 = undefined;
        try std.testing.expectEqualStrings(row.want, stripAnsi(&plain, line));
        try std.testing.expect(visibleWidth(line) <= row.cols - 1);
        // Colour state must still be reset and the row cleared, or a heavily
        // clamped line leaves the previous tick's tail on screen under a
        // half-written escape.
        try std.testing.expect(std.mem.endsWith(u8, line, A_RESET ++ A_CLREOL));
        try std.testing.expect(line[0] == '\r');
    }
}

test "colour never changes which rung is selected" {
    // A byte-length comparison instead of a column count would pin every
    // terminal to the narrowest rung. Verify the plain payload is width-driven
    // only: the visible text at width N must equal the visible text of the rung
    // the ladder picks, regardless of how many escape bytes it carries.
    var cols: usize = 20;
    while (cols <= 130) : (cols += 1) {
        var buf: [2048]u8 = undefined;
        const line = formatStatusLine(&buf, fixture, true, cols);
        try std.testing.expect(visibleWidth(line) <= cols - 1);
        var plain: [2048]u8 = undefined;
        const p = stripAnsi(&plain, line);
        const known = std.mem.eql(u8, p, fx_full) or std.mem.eql(u8, p, fx_medium) or
            std.mem.eql(u8, p, fx_narrow) or std.mem.eql(u8, p, fx_compact) or
            std.mem.eql(u8, p, fx_minimal) or
            (p.len < fx_minimal.len and std.mem.startsWith(u8, fx_minimal, p));
        try std.testing.expect(known);
    }
}

test "difficulty humanisation truncates and never rounds" {
    // Shared vector table. This is untested in all four miners: every status
    // fixture passes `diff` pre-formatted, and the C++ reference does not
    // humanise at all (its DlunaStatus.diff is a const char *). So the reference
    // suite provides zero coverage here and two ports can agree on every status
    // width while disagreeing in production. 1999 -> "1K": a %.1f or rounding
    // port emits "2K".
    const cases = [_]struct { in: u64, want: []const u8 }{
        .{ .in = 0, .want = "0" },
        .{ .in = 999, .want = "999" },
        .{ .in = 1_000, .want = "1K" },
        .{ .in = 1_999, .want = "1K" },
        .{ .in = 795_000, .want = "795K" },
        .{ .in = 999_999, .want = "999K" },
        .{ .in = 1_000_000, .want = "1M" },
        .{ .in = 999_999_999, .want = "999M" },
        .{ .in = 1_000_000_000, .want = "1G" },
        .{ .in = std.math.maxInt(u64), .want = "18446744073G" },
    };
    for (cases) |c| {
        var buf: [24]u8 = undefined;
        try std.testing.expectEqualStrings(c.want, fmtDiff(&buf, c.in));
    }
}

test "the status row stays silent until there is something true to report" {
    // Every launch: not connected, no job. This is the tick that used to print
    // "[DIRTYBIRD] 0.00 KH/s (0.00 KH/s avg) | Height:0 | ..." on every run.
    try std.testing.expect(!statusRowHasSomethingToSay(false, 0));

    // Connected, but getwork has not pushed a job yet -- workers are still
    // parked on the startup gate, so the rate is genuinely zero.
    try std.testing.expect(!statusRowHasSomethingToSay(true, 0));

    // Mining.
    try std.testing.expect(statusRowHasSomethingToSay(true, 1));

    // Dropped mid-run. A job was seen earlier, so job_epoch stays high, but
    // workers are parked on the disconnect gate for the whole backoff (1s
    // doubling to 30s). Having once had a job must not keep the row alive.
    try std.testing.expect(!statusRowHasSomethingToSay(false, 5));
}

test "a 100-hour uptime widens every rung carrying it" {
    // %02d does not clamp: hh=100 renders "100:00:00", 9 columns not 8. No
    // fixture in any of the four miners crosses this, so every published tier
    // width silently shifts on a rig that runs four days.
    var long = fixture;
    long.hh = 100;
    var buf: [2048]u8 = undefined;
    const line = try renderStatusLayout(&buf, long, .full);
    try std.testing.expectEqual(@as(usize, 116), visibleWidth(line));
    var plain: [2048]u8 = undefined;
    try std.testing.expect(std.mem.endsWith(u8, stripAnsi(&plain, line), "| 100:01:11"));
}

test "formatStatusLine emits one plain newline record when redirected" {
    var buf: [512]u8 = undefined;
    const line = formatStatusLine(&buf, .{
        .rate = 23.76,
        .avg = 20.71,
        .height = 7212998,
        .accepted = 1998,
        .blocks = 262,
        .rejected = 4,
        .diff = "312M",
        .hh = 1,
        .mm = 2,
        .ss = 3,
    }, false, 0);

    try std.testing.expectEqualStrings(
        "[DIRTYBIRD] 23.76 KH/s (20.71 KH/s avg) | Height:7212998 | Miniblocks:1998 | Blocks:262 | REJ:4 | Diff:312M | 01:02:03\n",
        line,
    );
    try std.testing.expect(std.mem.indexOfScalar(u8, line, '\r') == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, line, '\x1b') == null);
}

/// Parse "[wss://|ws://]host:port" into G.host/G.port and pick the transport (G.tls).
/// DERO getwork -- a local `derod` daemon (`Getwork_server` listens with `AddrsTLS` + a
/// self-signed cert) AND public pools -- is TLS (`wss://`), which is why every miner uses
/// verify-none. So a bare address defaults to TLS; `wss://` is explicit TLS; `ws://` forces
/// plaintext (only useful if getwork is fronted by a TLS-terminating proxy). Port optional
/// (keeps the current port on parse failure). Shared by -d and the config.json daemon-address.
fn setDaemon(hp_in: []const u8) void {
    var hp = hp_in;
    var explicit_tls: ?bool = null;
    if (std.mem.startsWith(u8, hp, "wss://")) {
        explicit_tls = true;
        hp = hp["wss://".len..];
    } else if (std.mem.startsWith(u8, hp, "ws://")) {
        explicit_tls = false;
        hp = hp["ws://".len..];
    }
    // Tolerate a trailing path (e.g. wss://host:port/ws/...) -- the wallet supplies the path.
    if (std.mem.indexOfScalar(u8, hp, '/')) |slash| hp = hp[0..slash];
    if (std.mem.lastIndexOfScalar(u8, hp, ':')) |c| {
        G.host = hp[0..c];
        G.port = std.fmt.parseInt(u16, hp[c + 1 ..], 10) catch G.port;
    } else G.host = hp;
    G.tls = explicit_tls orelse true; // DERO getwork is TLS; bare addresses connect over wss://
}

/// Absolute path to config.json next to the running executable, or null if unresolved.
fn exeConfigPath(alloc: std.mem.Allocator) ?[]u8 {
    const dir = std.fs.selfExeDirPathAlloc(alloc) catch return null;
    defer alloc.free(dir);
    return std.fs.path.join(alloc, &.{ dir, "config.json" }) catch null;
}

/// Read one trimmed line from stdin; null on empty/EOF (caller keeps the current value).
fn promptLine(buf: []u8) ?[]const u8 {
    const line = std.io.getStdIn().reader().readUntilDelimiterOrEof(buf, '\n') catch return null;
    const l = line orelse return null;
    const t = std.mem.trim(u8, l, " \t\r\n");
    return if (t.len == 0) null else t;
}

const setup_endpoints = [_][]const u8{
    "community-pools.mysrv.cloud:10300",
    "dero.rabidmining.com:10300",
    "dero-node.net:10100",
    "node.derofoundation.org:10100",
};

fn validEndpoint(endpoint: []const u8) bool {
    var host_port = endpoint;
    if (std.mem.startsWith(u8, host_port, "wss://")) {
        host_port = host_port["wss://".len..];
    } else if (std.mem.startsWith(u8, host_port, "ws://")) {
        host_port = host_port["ws://".len..];
    } else if (std.mem.indexOf(u8, host_port, "://") != null) {
        return false;
    }

    const colon = std.mem.lastIndexOfScalar(u8, host_port, ':') orelse return false;
    const host = host_port[0..colon];
    const port_text = host_port[colon + 1 ..];
    if (host.len == 0 or host.len > 253 or port_text.len == 0 or std.mem.indexOfScalar(u8, host, ':') != null) return false;

    var label_len: usize = 0;
    var last_was_hyphen = false;
    for (host) |c| {
        if (c == '.') {
            if (label_len == 0 or last_was_hyphen) return false;
            label_len = 0;
            last_was_hyphen = false;
            continue;
        }
        if (!std.ascii.isAlphanumeric(c) and c != '-') return false;
        if (label_len == 0 and c == '-') return false;
        label_len += 1;
        if (label_len > 63) return false;
        last_was_hyphen = c == '-';
    }
    if (label_len == 0 or last_was_hyphen) return false;

    const port = std.fmt.parseInt(u32, port_text, 10) catch return false;
    return port >= 1 and port <= 65535;
}

fn promptEndpoint(current: []const u8, choice_buf: []u8, custom_buf: []u8) []const u8 {
    while (true) {
        std.debug.print(
            \\
            \\  Daemon/pool:
            \\    1. Community Pools (recommended for phones) - community-pools.mysrv.cloud:10300
            \\    2. Rabid Mining - dero.rabidmining.com:10300
            \\    3. dero-node.net solo - dero-node.net:10100
            \\    4. DERO Foundation solo/full-block - node.derofoundation.org:10100
            \\    5. Custom
            \\  Pools provide steadier phone-friendly payouts; solo rewards arrive less often.
            \\  Selection [Enter keeps {s}]:
        , .{current});
        const choice = promptLine(choice_buf) orelse return current;
        const selected = std.fmt.parseInt(u8, choice, 10) catch {
            std.debug.print("  Invalid selection; choose 1-5.\n", .{});
            continue;
        };
        if (selected >= 1 and selected <= setup_endpoints.len) return setup_endpoints[selected - 1];
        if (selected != 5) {
            std.debug.print("  Invalid selection; choose 1-5.\n", .{});
            continue;
        }
        while (true) {
            std.debug.print("  Custom [ws://|wss://]host:port [Enter keeps {s}]: ", .{current});
            const custom = promptLine(custom_buf) orelse return current;
            if (validEndpoint(custom)) return custom;
            std.debug.print("  Invalid endpoint; use [ws://|wss://]host:port with port 1-65535.\n", .{});
        }
    }
}

test "validEndpoint accepts presets and rejects unsafe custom values" {
    for (setup_endpoints) |endpoint| try std.testing.expect(validEndpoint(endpoint));
    try std.testing.expect(validEndpoint("ws://localhost:10100"));
    try std.testing.expect(validEndpoint("wss://pool.example:65535"));

    for ([_][]const u8{
        "",
        "pool.example",
        "pool.example:0",
        "pool.example:65536",
        "pool.example:not-a-port",
        "http://pool.example:10100",
        "wss://pool.example:10100/ws",
        "pool.example:10100?x=1",
        "pool example:10100",
        "pool\"example:10100",
        "pool\\example:10100",
        ".pool.example:10100",
        "pool..example:10100",
        "-pool.example:10100",
        "pool-.example:10100",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example:10100",
    }) |endpoint| try std.testing.expect(!validEndpoint(endpoint));
}

/// Load config `path` (absolute or cwd-relative) and apply daemon/wallet/threads as
/// defaults; CLI flags parsed afterwards override these. Returns true if the file was
/// read+parsed. The raw daemon and threads values are retained for --setup defaults.
/// A missing/invalid file is non-fatal (returns false).
fn loadConfig(
    alloc: std.mem.Allocator,
    path: []const u8,
    nthreads: *usize,
    cfg_daemon: *?[]const u8,
    cfg_threads: *i64,
) bool {
    const file = (if (std.fs.path.isAbsolute(path))
        std.fs.openFileAbsolute(path, .{})
    else
        std.fs.cwd().openFile(path, .{})) catch return false;
    defer file.close();
    const bytes = file.readToEndAlloc(alloc, 64 * 1024) catch return false;
    defer alloc.free(bytes);
    const c = config.parseConfig(alloc, bytes) catch |e| {
        std.debug.print("warning: could not parse {s}: {s}\n", .{ path, @errorName(e) });
        return false;
    };
    if (c.daemon_address) |hp| {
        cfg_daemon.* = hp;
        setDaemon(hp);
    }
    if (c.wallet) |w| G.wallet = w;
    if (c.threads) |t| {
        cfg_threads.* = t;
        if (t > 0) nthreads.* = @intCast(t);
    }
    // Silent on success to match the C miner's display (it prints nothing before the
    // banner). The no-config / parse-error diagnostics above remain for misconfiguration.
    return true;
}

pub fn main() !u8 {
    // Keep the aarch64-linux TLS-alignment anchor from being stripped.
    if (bionic_tls_anchor_needed) asm volatile (""
        :
        : [p] "r" (&bionic_tls_align_anchor),
        : "memory"
    );

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    var do_selftest = false;
    var do_bench = false;
    var do_setup = false;
    var nthreads: usize = 0;
    var cfg_daemon: ?[]const u8 = null;
    var cfg_threads: i64 = -1; // raw config threads value (for --setup's "current" display)

    // -c/--config-file override, scanned up-front (also consumed in the loop below).
    var explicit_cfg: ?[]const u8 = null;
    {
        var j: usize = 1;
        while (j < args.len) : (j += 1) {
            if ((std.mem.eql(u8, args[j], "-c") or std.mem.eql(u8, args[j], "--config-file")) and j + 1 < args.len) {
                explicit_cfg = args[j + 1];
            }
        }
    }

    // Load config.json: explicit -c, else next to the executable, else the working dir.
    // CLI flags below override it; a missing file is reported (no silent fallback).
    {
        var loaded = false;
        if (explicit_cfg) |p| {
            loaded = loadConfig(alloc, p, &nthreads, &cfg_daemon, &cfg_threads);
        } else {
            if (exeConfigPath(alloc)) |ep| {
                defer alloc.free(ep);
                loaded = loadConfig(alloc, ep, &nthreads, &cfg_daemon, &cfg_threads);
            }
            if (!loaded) loaded = loadConfig(alloc, "config.json", &nthreads, &cfg_daemon, &cfg_threads);
        }
        if (!loaded) std.debug.print("config : no config.json found (next to the exe or in the working dir) -- using built-in defaults\n", .{});
    }

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-d") and i + 1 < args.len) {
            i += 1;
            cfg_daemon = args[i];
            setDaemon(args[i]);
        } else if ((std.mem.eql(u8, a, "-c") or std.mem.eql(u8, a, "--config-file")) and i + 1 < args.len) {
            i += 1; // already applied in the config-loading block above
        } else if (std.mem.eql(u8, a, "-w") and i + 1 < args.len) {
            i += 1;
            G.wallet = args[i];
        } else if (std.mem.eql(u8, a, "-t") and i + 1 < args.len) {
            i += 1;
            nthreads = std.fmt.parseInt(usize, args[i], 10) catch 0;
        } else if (std.mem.eql(u8, a, "-V") or std.mem.eql(u8, a, "--verbose")) {
            g_verbose = true;
        } else if (std.mem.eql(u8, a, "--selftest")) {
            do_selftest = true;
        } else if (std.mem.eql(u8, a, "--bench")) {
            do_bench = true;
        } else if (std.mem.eql(u8, a, "--setup")) {
            do_setup = true;
        } else if (std.mem.eql(u8, a, "-p") or std.mem.eql(u8, a, "--priority")) {
            i += 1; // accepted for CLI compatibility; not yet used
        } else if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) {
            usage();
            return 0;
        } else if (std.mem.eql(u8, a, "-v") or std.mem.eql(u8, a, "--version")) {
            std.debug.print("zig-miner v{s}\n", .{VERSION});
            return 0;
        } else {
            usage();
            return 1;
        }
    }

    // Interactive editor: writes config.json next to the exe (the same file the binary
    // reads), so start.bat and a hand-edited config.json are the one persistent knob.
    if (do_setup) {
        var dbuf: [128]u8 = undefined;
        const cur_daemon = cfg_daemon orelse (std.fmt.bufPrint(&dbuf, "{s}{s}:{d}", .{
            if (G.tls) "" else "ws://", G.host, G.port,
        }) catch setup_endpoints[0]);
        var in_choice: [32]u8 = undefined;
        var in_d: [256]u8 = undefined;
        var in_w: [256]u8 = undefined;
        var in_t: [64]u8 = undefined;
        std.debug.print("Setup -- press Enter to keep the current value.\n", .{});
        const daemon = promptEndpoint(cur_daemon, &in_choice, &in_d);
        std.debug.print("  DERO wallet [{s}]: ", .{G.wallet});
        const wallet = promptLine(&in_w) orelse G.wallet;
        std.debug.print("  Threads (-1 = auto) [{d}]: ", .{cfg_threads});
        const threads: i64 = if (promptLine(&in_t)) |s| (std.fmt.parseInt(i64, s, 10) catch cfg_threads) else cfg_threads;

        var wpath_owned: ?[]u8 = null;
        defer if (wpath_owned) |p| alloc.free(p);
        const wpath: []const u8 = if (explicit_cfg) |p| p else blk: {
            wpath_owned = exeConfigPath(alloc);
            break :blk (wpath_owned orelse "config.json");
        };
        const f = (if (std.fs.path.isAbsolute(wpath))
            std.fs.createFileAbsolute(wpath, .{})
        else
            std.fs.cwd().createFile(wpath, .{})) catch |e| {
            std.debug.print("error: could not write {s}: {s}\n", .{ wpath, @errorName(e) });
            return 1;
        };
        defer f.close();
        config.writeConfig(f.writer(), daemon, wallet, threads) catch |e| {
            std.debug.print("error: writing config: {s}\n", .{@errorName(e)});
            return 1;
        };
        std.debug.print("saved {s}\n", .{wpath});
        return 0;
    }

    if (do_selftest) return selftest(alloc);
    if (do_bench) return bench(alloc);

    if (G.wallet.len == 0) {
        std.debug.print("error: -w <wallet> is required\n", .{});
        usage();
        return 1;
    }

    if (nthreads == 0) nthreads = std.Thread.getCpuCount() catch 4;
    G.nthreads = nthreads;

    if (builtin.os.tag == .windows) {
        g_status_tty = std.io.getStdErr().isTty() and system.enableVirtualTerminal();
    } else {
        g_status_tty = std.io.getStdErr().isTty();
    }
    console.setTty(g_status_tty);

    // Startup banner -- timestamped INFO lines matching the Dirtybird C miner.
    console.logLine("INFO", "Dirtybird Miner", .{});
    console.logLine("INFO", "Server:  {s}://{s}:{d}", .{ if (G.tls) "wss" else "ws", G.host, G.port });
    console.logLine("INFO", "Wallet:  {s}", .{G.wallet});
    console.logLine("INFO", "Threads: {d}", .{nthreads});
    cpu_features.log(cpu_features.detect());
    std.debug.print("\n", .{}); // blank line before Connecting (C: trailing printf("\n"))

    // Startup KAT (matches the C miner's pow("a") check; silent on success, like the C).
    {
        var hex: [64]u8 = undefined;
        if (!try powKat(alloc, &hex)) {
            console.logLine("ERROR", "pow(\"a\") self-test failed; refusing to mine.", .{});
            return 1;
        }
    }

    installSignalHandler();

    // Max-performance profile (matches the C miner's `-p max`): HIGH priority
    // class + SeLockMemoryPrivilege; per-thread P-core pinning is done in mineThread.
    if (builtin.os.tag == .windows) {
        _ = system.enableLockMemoryPrivilege();
        system.setProcessHighPriority();
    }

    // Mining-thread workers: TWO per thread (one per lane of the batched, 2-way
    // multi-buffer SHA in mineThread/pow.hash2). Each thread's lane pair (indices
    // 2*idx and 2*idx+1) is packed into one huge-page backing when the OS grants it
    // (Windows large pages; Linux THP request), falling back to heap allocation.
    const workers = try alloc.alloc(*pow.Worker, nthreads * 2);
    defer alloc.free(workers);
    // Per-pair large-page backing: backings[idx] is the 2-worker block for lane
    // pair idx, or null if that pair came from the heap. Declared (and its free
    // defer registered) BEFORE the worker-cleanup defer so LIFO keeps both
    // `backings` and `workers` valid while cleanup runs.
    const backings = try alloc.alloc(?pages.PageBacking, nthreads);
    defer alloc.free(backings);
    for (backings) |*b| b.* = null;
    // Cleanup over the successfully-created prefix: exactly `created` workers and
    // their backings are released on any exit -- a partial-construction OOM error
    // or normal shutdown -- with no leak and no double-free. Two-phase: deinitSA
    // every created worker FIRST, then free the backings. Both workers of a packed
    // pair live inside the same large-page block, and deinitSA reads fields inside
    // that block, so the block must not be freed until both have been deinit'd.
    var created: usize = 0;
    defer {
        for (workers[0..created]) |wp| wp.deinitSA();
        for (backings) |b| {
            if (b) |backing| pages.freeHugeBacking(backing);
        }
        // Heap-allocated workers (no large-page backing for their pair) are freed
        // individually. A pair is heap-backed iff backings[pair] is null.
        for (workers[0..created], 0..) |wp, wi| {
            if (backings[wi / 2] == null) alloc.destroy(wp);
        }
    }
    {
        var idx: usize = 0;
        while (idx < nthreads) : (idx += 1) {
            const lane0 = 2 * idx;
            const lane1 = lane0 + 1;
            // Try one huge-page backing for the lane pair. On success both workers
            // live in it and `created` jumps by 2 with no fallible op in between,
            // so a huge-page pair is always complete (never half-built).
            if (pages.allocHugeBacking(2 * @sizeOf(pow.Worker))) |backing| {
                backings[idx] = backing;
                const buf = backing.bytes;
                const w0: *pow.Worker = @ptrCast(@alignCast(buf.ptr));
                const w1: *pow.Worker = @ptrCast(@alignCast(buf.ptr + @sizeOf(pow.Worker)));
                w0.* = .{};
                w1.* = .{};
                workers[lane0] = w0;
                created += 1;
                workers[lane1] = w1;
                created += 1;
                continue;
            }
            // Heap fallback: each worker is created independently so a `try` OOM
            // mid-pair leaves `created` exact (odd if w0 succeeded but w1 failed),
            // and cleanup frees only what was built.
            workers[lane0] = try alloc.create(pow.Worker);
            workers[lane0].* = .{};
            created += 1;
            workers[lane1] = try alloc.create(pow.Worker);
            workers[lane1].* = .{};
            created += 1;
        }
    }

    // Report actual huge-page-backed pairs. Linux THP is advisory: successful
    // madvise means requested, not guaranteed resident huge pages.
    if (builtin.os.tag == .windows or builtin.os.tag == .linux) {
        var backed_pairs: usize = 0;
        var mapped_mb: usize = 0;
        for (backings) |b| {
            if (b) |backing| {
                backed_pairs += 1;
                mapped_mb += backing.mappedLen() / (1024 * 1024);
            }
        }
        if (builtin.os.tag == .windows) {
            console.logLine("INFO", "Large pages: {d}/{d} worker pairs ({d} MB locked)", .{ backed_pairs, nthreads, mapped_mb });
        } else {
            console.logLine("INFO", "Huge pages: {d}/{d} worker pairs (THP requested, {d} MB mapped)", .{ backed_pairs, nthreads, mapped_mb });
        }
    }

    var ctx = Ctx{ .s = &G };
    const hooks = net.Hooks{
        .ctx = &ctx,
        .on_job = onJob,
        .poll_share = pollShare,
        .set_connected = setConnected,
        .log = netLog,
        .should_quit = shouldQuit,
    };
    const cfg = net.Config{ .host = G.host, .port = G.port, .wallet = G.wallet, .tls = G.tls };

    const net_thread = try std.Thread.spawn(.{}, net.run, .{ alloc, cfg, hooks });
    const rpt_thread = try std.Thread.spawn(.{}, reporter, .{});

    const miners = try alloc.alloc(std.Thread, nthreads);
    defer alloc.free(miners);
    for (miners, 0..) |*t, idx| t.* = try std.Thread.spawn(.{}, miner.mineThread, .{ &G, idx, workers[2 * idx], workers[2 * idx + 1] });

    for (miners) |t| t.join();
    net_thread.join();
    rpt_thread.join();

    std.debug.print("\nShutdown. {d} hashes, {d} miniblocks ({d} blocks), {d} rejected.\n", .{
        G.total_hashes.load(.monotonic), G.accepted.load(.monotonic), G.blocks.load(.monotonic), G.rejected.load(.monotonic),
    });
    return 0;
}
