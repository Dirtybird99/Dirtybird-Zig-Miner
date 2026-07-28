//! Minimal DNS-over-UDP A-record resolver, used only when the system resolver
//! cannot answer.
//!
//! WHY THIS EXISTS: Android has no `/etc/resolv.conf`. Zig's std resolver reads
//! that file and, when it is missing, falls back to querying 127.0.0.1:53
//! (lib/std/net.zig: FileNotFound => linuxLookupNameFromNumericUnspec(...,
//! "127.0.0.1", 53)). Nothing is listening there on a phone, so every pool
//! hostname fails to resolve and the miner cannot connect at all under Termux.
//! Android resolves through netd rather than a file, which a static musl binary
//! has no way to reach -- so the portable fix is to ask a public resolver
//! ourselves. The Go sibling hit the identical failure and solved it the same
//! way.
//!
//! Scope is deliberately tiny: one question, A records only (the miner is
//! IPv4-only at the connect site anyway), no caching, no EDNS, no TCP retry.
//! This is a fallback for a resolver that is already broken, not a resolver.

const std = @import("std");
const builtin = @import("builtin");

/// Public resolvers, tried in order. Cloudflare then Google.
pub const servers = [_][4]u8{
    .{ 1, 1, 1, 1 },
    .{ 8, 8, 8, 8 },
};

const query_timeout_ms: i64 = 3000;

pub const Error = error{
    NameTooLong,
    NoAnswer,
    BadResponse,
};

/// Encode `host` as a DNS query for an A record into `buf`, returning the used
/// slice. `id` is echoed by the server and checked on the way back.
pub fn buildQuery(buf: []u8, host: []const u8, id: u16) ![]u8 {
    if (host.len + 18 > buf.len) return Error.NameTooLong;
    var w: usize = 0;

    std.mem.writeInt(u16, buf[0..2], id, .big);
    std.mem.writeInt(u16, buf[2..4], 0x0100, .big); // standard query, recursion desired
    std.mem.writeInt(u16, buf[4..6], 1, .big); // QDCOUNT
    std.mem.writeInt(u16, buf[6..8], 0, .big); // ANCOUNT
    std.mem.writeInt(u16, buf[8..10], 0, .big); // NSCOUNT
    std.mem.writeInt(u16, buf[10..12], 0, .big); // ARCOUNT
    w = 12;

    // QNAME: each dot-separated label as <len><bytes>, terminated by a zero byte.
    var it = std.mem.splitScalar(u8, host, '.');
    while (it.next()) |label| {
        if (label.len == 0) continue; // tolerate a trailing dot
        if (label.len > 63) return Error.NameTooLong;
        if (w + 1 + label.len >= buf.len) return Error.NameTooLong;
        buf[w] = @intCast(label.len);
        @memcpy(buf[w + 1 ..][0..label.len], label);
        w += 1 + label.len;
    }
    if (w + 5 > buf.len) return Error.NameTooLong;
    buf[w] = 0;
    w += 1;
    std.mem.writeInt(u16, buf[w..][0..2], 1, .big); // QTYPE = A
    std.mem.writeInt(u16, buf[w + 2 ..][0..2], 1, .big); // QCLASS = IN
    w += 4;
    return buf[0..w];
}

/// Skip a (possibly compressed) name starting at `i`, returning the offset just
/// past it. A pointer ends the name, so this never follows one -- we only need
/// the length, never the text.
fn skipName(msg: []const u8, i_in: usize) !usize {
    var i = i_in;
    while (true) {
        if (i >= msg.len) return Error.BadResponse;
        const len = msg[i];
        if (len == 0) return i + 1;
        if (len & 0xC0 == 0xC0) { // compression pointer: 2 bytes, ends the name
            if (i + 2 > msg.len) return Error.BadResponse;
            return i + 2;
        }
        if (len > 63) return Error.BadResponse;
        i += 1 + len;
    }
}

/// Pull the first A record out of a response, checking that it answers `id`.
pub fn parseFirstA(msg: []const u8, id: u16) !?[4]u8 {
    if (msg.len < 12) return Error.BadResponse;
    if (std.mem.readInt(u16, msg[0..2], .big) != id) return Error.BadResponse;
    const flags = std.mem.readInt(u16, msg[2..4], .big);
    if (flags & 0x8000 == 0) return Error.BadResponse; // not a response
    if (flags & 0x000F != 0) return null; // RCODE != 0: NXDOMAIN etc.
    const qdcount = std.mem.readInt(u16, msg[4..6], .big);
    const ancount = std.mem.readInt(u16, msg[6..8], .big);

    var i: usize = 12;
    var q: u16 = 0;
    while (q < qdcount) : (q += 1) {
        i = try skipName(msg, i);
        if (i + 4 > msg.len) return Error.BadResponse;
        i += 4; // QTYPE + QCLASS
    }

    var a: u16 = 0;
    while (a < ancount) : (a += 1) {
        i = try skipName(msg, i);
        if (i + 10 > msg.len) return Error.BadResponse;
        const rtype = std.mem.readInt(u16, msg[i..][0..2], .big);
        const rdlen = std.mem.readInt(u16, msg[i + 8 ..][0..2], .big);
        i += 10;
        if (i + rdlen > msg.len) return Error.BadResponse;
        if (rtype == 1 and rdlen == 4) {
            return [4]u8{ msg[i], msg[i + 1], msg[i + 2], msg[i + 3] };
        }
        i += rdlen; // CNAME or anything else: skip
    }
    return null;
}

/// Ask one server for `host`'s A record. Returns null when the server answers
/// but has no address for the name.
fn queryServer(server: [4]u8, host: []const u8, id: u16) !?[4]u8 {
    var qbuf: [512]u8 = undefined;
    const query = try buildQuery(&qbuf, host, id);

    const fd = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    defer std.posix.close(fd);

    const tv = std.posix.timeval{
        .sec = @intCast(@divTrunc(query_timeout_ms, 1000)),
        .usec = @intCast(@mod(query_timeout_ms, 1000) * 1000),
    };
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv));

    const dest = std.net.Address.initIp4(server, 53);
    _ = try std.posix.sendto(fd, query, 0, &dest.any, dest.getOsSockLen());

    var rbuf: [512]u8 = undefined;
    const n = try std.posix.recv(fd, &rbuf, 0);
    return try parseFirstA(rbuf[0..n], id);
}

/// Resolve `host` to an IPv4 address via the public resolvers.
///
/// Call this only after the system resolver has failed: it exists for platforms
/// where that path is structurally broken, not as a replacement for it.
pub fn resolveIPv4(host: []const u8, port: u16) !std.net.Address {
    // Windows always has a working resolver, and this UDP path is POSIX-shaped.
    if (builtin.os.tag == .windows) return Error.NoAnswer;

    // Vary the query id per attempt; a fixed id makes off-path spoofing
    // trivially easy and costs nothing to avoid.
    var seed: u64 = @bitCast(std.time.milliTimestamp());
    for (servers) |srv| {
        seed = seed *% 6364136223846793005 +% 1442695040888963407;
        const id: u16 = @truncate(seed >> 33);
        const got = queryServer(srv, host, id) catch continue;
        if (got) |ip| return std.net.Address.initIp4(ip, port);
    }
    return Error.NoAnswer;
}

// ---------------------------------------------------------------------------
// Tests -- offline: the wire format is exercised without touching the network.
// ---------------------------------------------------------------------------

test "buildQuery encodes labels and the A/IN question" {
    var buf: [512]u8 = undefined;
    const q = try buildQuery(&buf, "pool.example.com", 0xBEEF);
    try std.testing.expectEqual(@as(u16, 0xBEEF), std.mem.readInt(u16, q[0..2], .big));
    try std.testing.expectEqual(@as(u16, 0x0100), std.mem.readInt(u16, q[2..4], .big));
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, q[4..6], .big));
    // 4 "pool" 7 "example" 3 "com" 0
    try std.testing.expectEqualSlices(u8, "\x04pool\x07example\x03com\x00", q[12 .. q.len - 4]);
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, q[q.len - 4 ..][0..2], .big));
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, q[q.len - 2 ..][0..2], .big));
}

test "buildQuery rejects an over-long label" {
    var buf: [512]u8 = undefined;
    const long = "a" ** 64;
    try std.testing.expectError(Error.NameTooLong, buildQuery(&buf, long, 1));
}

test "parseFirstA reads an A record behind a compression pointer" {
    // Header: id=0x1234, response+RD+RA, QD=1, AN=1
    // Question: 4"test"3"com"0 A IN
    // Answer:   name=ptr(0x0C), A, IN, ttl=60, rdlen=4, 93.184.216.34
    const msg = [_]u8{
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x04, 't',  'e',  's',  't',  0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01,
        0x00, 0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C,
        0x00, 0x04, 93,   184,  216,  34,
    };
    const got = try parseFirstA(&msg, 0x1234);
    try std.testing.expectEqual([4]u8{ 93, 184, 216, 34 }, got.?);
}

test "parseFirstA rejects a mismatched transaction id" {
    const msg = [_]u8{
        0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    try std.testing.expectError(Error.BadResponse, parseFirstA(&msg, 0x9999));
}

test "parseFirstA returns null for NXDOMAIN" {
    const msg = [_]u8{
        0x12, 0x34, 0x81, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    try std.testing.expectEqual(@as(?[4]u8, null), try parseFirstA(&msg, 0x1234));
}

test "parseFirstA skips a CNAME to reach the A record" {
    const msg = [_]u8{
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x01, 'a',  0x00, 0x00, 0x01, 0x00, 0x01,
        // answer 1: CNAME, rdlen 2 (a pointer), skipped
        0xC0, 0x0C, 0x00, 0x05, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x02, 0xC0, 0x0C,
        // answer 2: the A record
        0xC0, 0x0C, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 10,   0,    0,
        7,
    };
    const got = try parseFirstA(&msg, 0x1234);
    try std.testing.expectEqual([4]u8{ 10, 0, 0, 7 }, got.?);
}

test "parseFirstA rejects a truncated record" {
    const msg = [_]u8{
        0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x0C, 0x00, 0x01,
    };
    try std.testing.expectError(Error.BadResponse, parseFirstA(&msg, 0x1234));
}
