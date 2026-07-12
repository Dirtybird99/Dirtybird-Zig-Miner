//! difftest.zig -- differential fuzz: Zig pow vs the C oracle.
//!
//!   difftest gen <n> <seed>        emit n deterministic hex inputs (one per line)
//!   difftest check <in> <oracle>   hash each input with Zig, compare to oracle pairs
//!
//! Driver (bash):
//!   difftest gen 5000 1 > in.txt
//!   oracle pairs < in.txt > or.txt
//!   difftest check in.txt or.txt
const std = @import("std");
const pow = @import("pow.zig");

fn hexEncode(bytes: []const u8, out: []u8) []u8 {
    const hexd = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[i * 2] = hexd[b >> 4];
        out[i * 2 + 1] = hexd[b & 0xf];
    }
    return out[0 .. bytes.len * 2];
}

fn hexNibble(c: u8) u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => 0,
    };
}

fn hexDecode(s: []const u8, out: []u8) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i + 1 < s.len + 1 and i + 1 <= s.len and n < out.len) : (i += 2) {
        out[n] = (hexNibble(s[i]) << 4) | hexNibble(s[i + 1]);
        n += 1;
    }
    return n;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    if (args.len >= 4 and std.mem.eql(u8, args[1], "gen")) {
        const n = try std.fmt.parseInt(u64, args[2], 10);
        const seed = try std.fmt.parseInt(u64, args[3], 10);
        var prng = std.Random.DefaultPrng.init(seed);
        const rand = prng.random();

        var stdout_buf = std.io.bufferedWriter(std.io.getStdOut().writer());
        const w = stdout_buf.writer();
        var inbuf: [128]u8 = undefined;
        var hexbuf: [256]u8 = undefined;
        var i: u64 = 0;
        while (i < n) : (i += 1) {
            // Mostly 48-byte mining blobs; periodically exercise varied lengths.
            const len: usize = if (i % 7 == 0) (1 + rand.uintLessThan(usize, 64)) else 48;
            rand.bytes(inbuf[0..len]);
            const hex = hexEncode(inbuf[0..len], &hexbuf);
            try w.print("{s}\n", .{hex});
        }
        try stdout_buf.flush();
        return;
    }

    if (args.len >= 4 and std.mem.eql(u8, args[1], "check")) {
        const in_txt = try std.fs.cwd().readFileAlloc(alloc, args[2], 1 << 30);
        defer alloc.free(in_txt);
        const or_txt = try std.fs.cwd().readFileAlloc(alloc, args[3], 1 << 30);
        defer alloc.free(or_txt);

        const worker = try alloc.create(pow.Worker);
        worker.* = .{};
        defer alloc.destroy(worker);
        defer worker.deinitSA();
        // Second worker so we can also exercise the PRODUCTION batched path
        // (pow.hash2, used by miner.zig) and assert it matches the single path.
        const worker1 = try alloc.create(pow.Worker);
        worker1.* = .{};
        defer alloc.destroy(worker1);
        defer worker1.deinitSA();

        var in_lines = std.mem.tokenizeScalar(u8, in_txt, '\n');
        var or_lines = std.mem.tokenizeScalar(u8, or_txt, '\n');

        var inbuf: [128]u8 = undefined;
        var checked: u64 = 0;
        var mismatches: u64 = 0;
        var h2_mismatches: u64 = 0;

        while (in_lines.next()) |raw_in| {
            const in_hex = std.mem.trim(u8, raw_in, " \r");
            if (in_hex.len == 0) continue;
            const or_line = or_lines.next() orelse {
                std.debug.print("ERROR: oracle ran out of lines at #{d}\n", .{checked});
                std.process.exit(2);
            };
            // oracle line: "<in_hex> <out_hex>"
            var toks = std.mem.tokenizeScalar(u8, or_line, ' ');
            const or_in = std.mem.trim(u8, toks.next() orelse continue, " \r");
            const or_out = std.mem.trim(u8, toks.next() orelse continue, " \r");
            if (!std.mem.eql(u8, or_in, in_hex)) {
                std.debug.print("ERROR: input mismatch at #{d}: zig={s} oracle={s}\n", .{ checked, in_hex, or_in });
                std.process.exit(2);
            }

            const in_len = hexDecode(in_hex, &inbuf);
            var out: [32]u8 = undefined;
            try pow.hash(inbuf[0..in_len], &out, worker);
            var zig_hex: [64]u8 = undefined;
            const zh = hexEncode(&out, &zig_hex);

            if (!std.mem.eql(u8, zh, or_out)) {
                mismatches += 1;
                if (mismatches <= 5) {
                    std.debug.print("MISMATCH #{d} input={s}\n  zig   ={s}\n  oracle={s}\n", .{ checked, in_hex, zh, or_out });
                }
            }

            // Production-path cross-check: hash2(in, in) must equal the single hash
            // in both lanes (same computeSA; only the multi-buffer SHA differs).
            var o0: [32]u8 = undefined;
            var o1: [32]u8 = undefined;
            try pow.hash2(inbuf[0..in_len], inbuf[0..in_len], &o0, &o1, worker, worker1);
            if (!std.mem.eql(u8, &o0, &out) or !std.mem.eql(u8, &o1, &out)) {
                h2_mismatches += 1;
                if (h2_mismatches <= 3) std.debug.print("HASH2 MISMATCH #{d} input={s}\n", .{ checked, in_hex });
            }
            checked += 1;
        }

        std.debug.print("difftest: checked={d} mismatches={d} hash2_mismatches={d} -> {s}\n", .{ checked, mismatches, h2_mismatches, if (mismatches == 0 and h2_mismatches == 0) "PASS" else "FAIL" });
        if (h2_mismatches != 0) std.process.exit(1);
        if (mismatches != 0) std.process.exit(1);
        return;
    }

    std.debug.print("usage: difftest gen <n> <seed> | difftest check <in> <oracle>\n", .{});
    std.process.exit(2);
}
