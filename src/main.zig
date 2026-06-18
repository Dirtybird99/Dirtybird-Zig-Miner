//! main.zig -- DIRTYBIRD/Zig miner entry point. AstroBWTv3 DERO CPU miner.
const std = @import("std");
const builtin = @import("builtin");
const pow = @import("pow.zig");
const miner = @import("miner.zig");
const state = @import("state.zig");
const net = @import("net.zig");
const system = @import("system.zig");
const config = @import("config.zig");

const VERSION = "0.1.1";

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

fn reporter() void {
    var prev: i64 = 0;
    const t0 = std.time.milliTimestamp();
    var prev_t = t0;
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
        std.debug.print("\r{d:0>3}:{d:0>2}:{d:0>2} H:{d} IB:{d} MB:{d} MBR:{d} SH:{d} Diff:{d} @ {d:.2} KH/s ({d:.2} avg)   ", .{
            sec / 3600,                  (sec % 3600) / 60,            sec % 60,
            G.height.load(.monotonic),   G.blocks.load(.monotonic),    G.accepted.load(.monotonic),
            G.rejected.load(.monotonic), G.submitted.load(.monotonic), G.difficulty.load(.monotonic),
            rate,                        avg,
        });
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

/// Load config.json (DeroLuna-compatible keys) if present and apply its daemon/wallet/
/// threads as defaults. CLI flags (parsed afterwards) override these; a missing or
/// invalid file is non-fatal (we fall through to the compiled-in defaults).
fn loadConfig(alloc: std.mem.Allocator, path: []const u8, nthreads: *usize) void {
    const file = std.fs.cwd().openFile(path, .{}) catch return;
    defer file.close();
    const bytes = file.readToEndAlloc(alloc, 64 * 1024) catch return;
    defer alloc.free(bytes);
    const c = config.parseConfig(alloc, bytes) catch |e| {
        std.debug.print("warning: could not parse {s}: {s}\n", .{ path, @errorName(e) });
        return;
    };
    if (c.daemon_address) |hp| setDaemon(hp);
    if (c.wallet) |w| G.wallet = w;
    if (c.threads) |t| {
        if (t > 0) nthreads.* = @intCast(t);
    }
    std.debug.print("config : loaded {s}\n", .{path});
}

pub fn main() !u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    var do_selftest = false;
    var nthreads: usize = 0;

    // Load config.json (or -c/--config-file <path>) first; CLI flags below override it.
    {
        var cfg_path: []const u8 = "config.json";
        var j: usize = 1;
        while (j < args.len) : (j += 1) {
            if ((std.mem.eql(u8, args[j], "-c") or std.mem.eql(u8, args[j], "--config-file")) and j + 1 < args.len) {
                cfg_path = args[j + 1];
            }
        }
        loadConfig(alloc, cfg_path, &nthreads);
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
