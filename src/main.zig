//! main.zig -- DIRTYBIRD/Zig miner entry point. AstroBWTv3 DERO CPU miner.
const std = @import("std");
const builtin = @import("builtin");
const pow = @import("pow.zig");
const miner = @import("miner.zig");
const state = @import("state.zig");
const net = @import("net.zig");
const system = @import("system.zig");
const config = @import("config.zig");

const VERSION = "0.1.3";

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
    ctx.s.accepted.store(job.miniblocks, .monotonic);
    ctx.s.blocks.store(job.blocks, .monotonic);
    ctx.s.rejected.store(job.rejected, .monotonic);
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
    if (!connected) ctx.s.net_rtt_us.store(-1, .monotonic); // clear net: while disconnected
}

fn setNetRtt(ctx_ptr: *anyopaque, rtt_us: i64) void {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr));
    ctx.s.net_rtt_us.store(rtt_us, .monotonic);
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
        \\Usage: zig-miner [-d host:port] [-w wallet] [-t threads] [-c config.json] [-V] [--selftest]
        \\  -d  daemon/pool address host:port  (default community-pools.mysrv.cloud:10300)
        \\  -w  DERO wallet address            (default from config.json / built-in)
        \\  -t  mining threads                 (default: logical CPU count)
        \\  -c, --config-file <path>           config file (default: config.json)
        \\  -V  verbose
        \\  --selftest  run pow("a") KAT and exit (0=PASS,1=FAIL)
        \\  --setup     interactively write config.json (pool/wallet/threads), then exit
        \\  -h, --help / -v, --version
        \\
    , .{});
}

fn selftest(alloc: std.mem.Allocator) !u8 {
    const w = try alloc.create(pow.Worker);
    defer alloc.destroy(w);
    w.* = .{};
    defer w.deinitSA();
    var out: [32]u8 = undefined;
    try pow.hash("a", &out, w);
    var hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{s}", .{std.fmt.fmtSliceHexLower(&out)}) catch unreachable;
    const expected = "54e2324ddacc3f0383501a9e5760f85d63e9bc6705e9124ca7aef89016ab81ea";
    const pass = std.mem.eql(u8, &hex, expected);
    std.debug.print("selftest pow(a): {s} {s}\n", .{ hex, if (pass) "PASS" else "FAIL" });
    return if (pass) 0 else 1;
}

var g_verbose = false;

// ANSI SGR colors matching the C miner (dirtybird-miner src/main.cpp). VT is enabled on
// Windows; the reporter emits these only when stderr is a TTY (plain text when piped).
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

/// Format net RTT (microseconds; -1 = unavailable) as the C does: --, <1ms, or Nms.
fn fmtNet(buf: []u8, us: i64) []const u8 {
    if (us < 0) return "--";
    if (us < 1000) return "<1ms";
    return std.fmt.bufPrint(buf, "{d}ms", .{@divTrunc(us, 1000)}) catch "?";
}

fn reporter() void {
    var prev: i64 = 0;
    const t0 = std.time.milliTimestamp();
    var prev_t = t0;
    const tty = std.io.getStdErr().isTty();
    while (!G.quit.load(.monotonic)) {
        std.time.sleep(std.time.ns_per_s);
        const now = std.time.milliTimestamp();
        const dt = @as(f64, @floatFromInt(now - prev_t)) / 1000.0;
        const elapsed = @as(f64, @floatFromInt(now - t0)) / 1000.0;
        prev_t = now;
        const total = G.total_hashes.load(.monotonic);
        const delta = total - prev;
        prev = total;
        const rate = if (dt > 0) @as(f64, @floatFromInt(delta)) / (dt * 1000.0) else 0;
        const avg = if (elapsed > 0) @as(f64, @floatFromInt(total)) / (elapsed * 1000.0) else 0;
        const sec: u64 = @intFromFloat(elapsed);
        const hh = sec / 3600;
        const mm = (sec % 3600) / 60;
        const ss = sec % 60;

        const height = G.height.load(.monotonic);
        const accepted = G.accepted.load(.monotonic);
        const blocks = G.blocks.load(.monotonic);
        const rejected = G.rejected.load(.monotonic);
        var dbuf: [24]u8 = undefined;
        const diff = fmtDiff(&dbuf, G.difficulty.load(.monotonic));
        var nbuf: [16]u8 = undefined;
        const netstr = fmtNet(&nbuf, G.net_rtt_us.load(.monotonic));

        if (tty) {
            const rejcol = if (rejected > 0) A_BRED else A_WHITE;
            std.debug.print("\r{s}[DIRTYBIRD] {s}{d:.2} KH/s{s} ({s}{d:.2} KH/s avg{s}) | {s}Height:{d}{s} | {s}Miniblocks:{d}{s} | {s}Blocks:{d}{s} | {s}REJ:{d}{s} | {s}Diff:{s}{s} | {s}net:{s}{s} | {s}{d:0>2}:{d:0>2}:{d:0>2}{s}{s}      ", .{
                A_BYELLOW, A_BGREEN, rate,     A_BWHITE, A_GREEN,  avg,       A_BWHITE,
                A_BLUE,    height,   A_BWHITE, A_CYAN,   accepted, A_BWHITE,  A_GREEN,
                blocks,    A_BWHITE, rejcol,   rejected, A_BWHITE, A_MAGENTA, diff,
                A_BWHITE,  A_CYAN,   netstr,   A_BWHITE, A_WHITE,  hh,        mm,
                ss,        A_RESET,  A_CLREOL,
            });
        } else {
            std.debug.print("[DIRTYBIRD] {d:.2} KH/s ({d:.2} KH/s avg) | Height:{d} | Miniblocks:{d} | Blocks:{d} | REJ:{d} | Diff:{s} | net:{s} | {d:0>2}:{d:0>2}:{d:0>2}\n", .{
                rate, avg, height, accepted, blocks, rejected, diff, netstr, hh, mm, ss,
            });
        }

        if (g_verbose) {
            std.debug.print("\n[funnel] submitted:{d} acc:{d} rej:{d} stale:{d} sendfail:{d}\n", .{
                G.submitted.load(.monotonic),   accepted,                        rejected,
                G.stale_drops.load(.monotonic), G.submit_drops.load(.monotonic),
            });
        }
    }
}

/// Split "host:port" into G.host/G.port (port optional; keeps the current port on parse
/// failure). Shared by the -d flag and the config.json daemon-address.
fn setDaemon(hp: []const u8) void {
    if (std.mem.lastIndexOfScalar(u8, hp, ':')) |c| {
        G.host = hp[0..c];
        G.port = std.fmt.parseInt(u16, hp[c + 1 ..], 10) catch G.port;
    } else G.host = hp;
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

/// Load config `path` (absolute or cwd-relative) and apply daemon/wallet/threads as
/// defaults; CLI flags parsed afterwards override these. Returns true if the file was
/// read+parsed. `cfg_threads` receives the raw threads value (for --setup's display).
/// A missing/invalid file is non-fatal (returns false).
fn loadConfig(alloc: std.mem.Allocator, path: []const u8, nthreads: *usize, cfg_threads: *i64) bool {
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
    if (c.daemon_address) |hp| setDaemon(hp);
    if (c.wallet) |w| G.wallet = w;
    if (c.threads) |t| {
        cfg_threads.* = t;
        if (t > 0) nthreads.* = @intCast(t);
    }
    std.debug.print("config : loaded {s}\n", .{path});
    return true;
}

pub fn main() !u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    var do_selftest = false;
    var do_setup = false;
    var nthreads: usize = 0;
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
            loaded = loadConfig(alloc, p, &nthreads, &cfg_threads);
        } else {
            if (exeConfigPath(alloc)) |ep| {
                defer alloc.free(ep);
                loaded = loadConfig(alloc, ep, &nthreads, &cfg_threads);
            }
            if (!loaded) loaded = loadConfig(alloc, "config.json", &nthreads, &cfg_threads);
        }
        if (!loaded) std.debug.print("config : no config.json found (next to the exe or in the working dir) -- using built-in defaults\n", .{});
    }

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-d") and i + 1 < args.len) {
            i += 1;
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
        const cur_daemon = std.fmt.bufPrint(&dbuf, "{s}:{d}", .{ G.host, G.port }) catch "community-pools.mysrv.cloud:10300";
        var in_d: [256]u8 = undefined;
        var in_w: [256]u8 = undefined;
        var in_t: [64]u8 = undefined;
        std.debug.print("Setup -- press Enter to keep the current value.\n", .{});
        std.debug.print("  Daemon/pool host:port [{s}]: ", .{cur_daemon});
        const daemon = promptLine(&in_d) orelse cur_daemon;
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

    if (G.wallet.len == 0) {
        std.debug.print("error: -w <wallet> is required\n", .{});
        usage();
        return 1;
    }

    if (nthreads == 0) nthreads = std.Thread.getCpuCount() catch 4;
    G.nthreads = nthreads;

    std.debug.print("zig-miner v{s}\n  server : {s}:{d}\n  wallet : {s}\n  threads: {d}\n\n", .{ VERSION, G.host, G.port, G.wallet, nthreads });

    // Startup KAT (matches the C miner's pow("a") check).
    {
        const code = try selftest(alloc);
        if (code != 0) {
            std.debug.print("FATAL: pow(\"a\") self-test failed; refusing to mine.\n", .{});
            return 1;
        }
    }

    installSignalHandler();

    // Max-performance profile (matches the C miner's `-p max`): HIGH priority
    // class + SeLockMemoryPrivilege; per-thread P-core pinning is done in mineThread.
    if (builtin.os.tag == .windows) {
        _ = system.enableLockMemoryPrivilege();
        system.setProcessHighPriority();
        system.enableVirtualTerminal(); // ANSI colors for the status line
    }

    // Mining-thread workers: TWO per thread (one per lane of the batched, 2-way
    // multi-buffer SHA in mineThread/pow.hash2).
    const workers = try alloc.alloc(*pow.Worker, nthreads * 2);
    defer alloc.free(workers);
    // One defer over the successfully-created prefix frees exactly `created`
    // workers on any exit -- a partial-construction OOM error or normal shutdown --
    // with no leak and no double-free.
    var created: usize = 0;
    defer for (workers[0..created]) |wp| {
        wp.deinitSA();
        alloc.destroy(wp);
    };
    for (workers) |*wp| {
        wp.* = try alloc.create(pow.Worker);
        wp.*.* = .{};
        created += 1;
    }

    var ctx = Ctx{ .s = &G };
    const hooks = net.Hooks{
        .ctx = &ctx,
        .on_job = onJob,
        .poll_share = pollShare,
        .set_connected = setConnected,
        .set_net_rtt = setNetRtt,
        .should_quit = shouldQuit,
    };
    const cfg = net.Config{ .host = G.host, .port = G.port, .wallet = G.wallet };

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
