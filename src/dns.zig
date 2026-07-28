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
//!
//! SECURITY. Any hostile AP can *force* this path by blackholing the DHCP
//! resolver, so it is treated as attacker-reachable rather than as a rare
//! corner. Against an OFF-PATH attacker it carries the four standard RFC 5452
//! anti-spoofing controls: the socket is connect()ed so the kernel enforces the
//! source address, the transaction id is CSPRNG, the echoed question must match
//! byte for byte, and answers pointing at bogons are refused. v0.3.0 shipped
//! with none of the first three -- a 27-byte forged packet resolved any
//! hostname to the attacker's address (see the regression tests below).
//!
//! It does NOT defend against an ON-PATH attacker, and cannot: net.zig dials
//! with `.host = .no_verification`, inherited because DERO getwork daemons
//! present random self-signed certs. Anyone who can read and rewrite the
//! traffic wins there without touching DNS. Closing that needs SPKI pinning for
//! public pools or DoT/DoH here -- a design decision, not a patch, and it is
//! shared with the Go sibling.

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
    if (host.len == 0) return Error.NameTooLong;
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
    // RFC 1035 2.3.4: the encoded name, root label included, caps at 255 bytes.
    // The buffer check above only bounds it at ~494, so a mistyped -d argument
    // (never length-checked: main.zig's setDaemon skips validEndpoint) would
    // otherwise become an oversized query and a 6s stall reported as NoAnswer.
    if (w + 1 - 12 > 255) return Error.NameTooLong;
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

/// Addresses no pool can legitimately live at. A filtering resolver reached via
/// transparent :53 redirection answers 0.0.0.0 for blocked names, and on Linux
/// connect() to 0.0.0.0 targets loopback -- so without this the miner silently
/// dials whatever local service holds port 10100. Private ranges are NOT here:
/// a derod on the LAN is a supported setup.
fn isBogon(a: [4]u8) bool {
    return a[0] == 0 // 0.0.0.0/8   "this network"
    or a[0] == 127 // 127.0.0.0/8 loopback
    or (a[0] == 169 and a[1] == 254) // link-local
    or a[0] >= 224; // multicast + reserved, incl. 255.255.255.255
}

/// Pull the first A record out of a response.
///
/// `question` is the QNAME+QTYPE+QCLASS we sent, i.e. everything after the
/// 12-byte header of the query. Echoing it back is mandatory (RFC 1035 4.1.2),
/// so requiring an exact match is what ties this answer to *our* question --
/// RFC 5452 4.2. Without it a single forged 27-byte packet declaring QDCOUNT=0
/// and one answer RR resolves any hostname to the attacker's address, because
/// the question loop simply runs zero times.
pub fn parseFirstA(msg: []const u8, id: u16, question: []const u8) !?[4]u8 {
    if (msg.len < 12) return Error.BadResponse;
    if (std.mem.readInt(u16, msg[0..2], .big) != id) return Error.BadResponse;
    const flags = std.mem.readInt(u16, msg[2..4], .big);
    if (flags & 0x8000 == 0) return Error.BadResponse; // not a response
    if (flags & 0x0200 != 0) return Error.BadResponse; // TC: truncated, needs TCP
    if (flags & 0x000F != 0) return null; // RCODE != 0: NXDOMAIN etc.

    // We always send exactly one question, so anything else is not our reply.
    if (std.mem.readInt(u16, msg[4..6], .big) != 1) return Error.BadResponse;
    if (msg.len < 12 + question.len) return Error.BadResponse;
    if (!std.mem.eql(u8, msg[12 .. 12 + question.len], question)) return Error.BadResponse;

    const ancount = std.mem.readInt(u16, msg[6..8], .big);
    var i: usize = 12 + question.len;

    var a: u16 = 0;
    while (a < ancount) : (a += 1) {
        i = try skipName(msg, i);
        if (i + 10 > msg.len) return Error.BadResponse;
        const rtype = std.mem.readInt(u16, msg[i..][0..2], .big);
        const rclass = std.mem.readInt(u16, msg[i + 2 ..][0..2], .big);
        const rdlen = std.mem.readInt(u16, msg[i + 8 ..][0..2], .big);
        i += 10;
        if (i + rdlen > msg.len) return Error.BadResponse;
        if (rtype == 1 and rclass == 1 and rdlen == 4) {
            const ip = [4]u8{ msg[i], msg[i + 1], msg[i + 2], msg[i + 3] };
            if (isBogon(ip)) return Error.BadResponse;
            return ip;
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

    // connect() the UDP socket so the kernel drops datagrams from anyone but
    // this server. std.posix.recv is recvfrom(..., null, null), so it discards
    // the source address by construction -- without connect() nothing here ever
    // learns the reply did not come from Cloudflare, and any host on the same
    // Wi-Fi can answer from its own address with no IP forgery at all (which
    // would also sail straight through egress filtering). It additionally turns
    // ICMP port-unreachable into a prompt error instead of a 3s hang.
    const dest = std.net.Address.initIp4(server, 53);
    try std.posix.connect(fd, &dest.any, dest.getOsSockLen());
    _ = try std.posix.send(fd, query, 0);

    var rbuf: [512]u8 = undefined;
    const n = try std.posix.recv(fd, &rbuf, 0);
    return try parseFirstA(rbuf[0..n], id, query[12..]);
}

/// Resolve `host` to an IPv4 address via the public resolvers.
///
/// Call this only after the system resolver has failed: it exists for platforms
/// where that path is structurally broken, not as a replacement for it.
pub fn resolveIPv4(host: []const u8, port: u16) !std.net.Address {
    // Windows always has a working resolver, and this UDP path is POSIX-shaped.
    if (builtin.os.tag == .windows) return Error.NoAnswer;

    // A fresh CSPRNG id per query. This was an LCG seeded from milliTimestamp():
    // both constants ship in this source file, and because reconnect backoff
    // carried no jitter an attacker who drops the session knows the resolve
    // instant to within tens of milliseconds -- roughly 100 candidate seeds,
    // hence ~100 candidate ids rather than 65536. That is ~7 of the 16 bits the
    // id is supposed to contribute. std.crypto.random needs no seeding.
    for (servers) |srv| {
        const id = std.crypto.random.int(u16);
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

/// The question we would have sent for "test.com" / "a": QNAME+QTYPE+QCLASS,
/// i.e. buildQuery's output past the 12-byte header.
const q_test_com = "\x04test\x03com\x00\x00\x01\x00\x01";
const q_a = "\x01a\x00\x00\x01\x00\x01";

test "buildQuery rejects an empty host" {
    var buf: [512]u8 = undefined;
    try std.testing.expectError(Error.NameTooLong, buildQuery(&buf, "", 1));
}

test "buildQuery rejects a name over the 255-byte encoded limit" {
    var buf: [512]u8 = undefined;
    // Five 60-char labels: every label is legal, the buffer has room, but the
    // encoded name is 306 bytes. Only the RFC cap rejects this.
    const long = ("a" ** 60) ++ ("." ++ ("a" ** 60)) ** 4;
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
    const got = try parseFirstA(&msg, 0x1234, q_test_com);
    try std.testing.expectEqual([4]u8{ 93, 184, 216, 34 }, got.?);
}

test "parseFirstA rejects a mismatched transaction id" {
    const msg = [_]u8{
        0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    try std.testing.expectError(Error.BadResponse, parseFirstA(&msg, 0x9999, q_test_com));
}

test "parseFirstA returns null for NXDOMAIN" {
    const msg = [_]u8{
        0x12, 0x34, 0x81, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    try std.testing.expectEqual(@as(?[4]u8, null), try parseFirstA(&msg, 0x1234, q_test_com));
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
    const got = try parseFirstA(&msg, 0x1234, q_a);
    try std.testing.expectEqual([4]u8{ 10, 0, 0, 7 }, got.?);
}

test "parseFirstA rejects a truncated record" {
    const msg = [_]u8{
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x04, 't',  'e',  's',  't',  0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01,
        0x00, 0x01, 0xC0, 0x0C, 0x00, 0x01,
    };
    try std.testing.expectError(Error.BadResponse, parseFirstA(&msg, 0x1234, q_test_com));
}

// --- Regression tests for the spoofing audit. Each is red before its fix. ---

test "parseFirstA rejects the QDCOUNT=0 forgery" {
    // 27 bytes, and before question matching it resolved ANY hostname to
    // 192.168.1.66: with QDCOUNT=0 the question loop ran zero times, every
    // bound check passed, and the answer RR was read straight out.
    const msg = [_]u8{
        0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, // owner name = root
        0x00, 0x01, // TYPE A
        0x00, 0x01, // CLASS IN
        0x00, 0x00, 0x00, 0x3C, // TTL
        0x00, 0x04, // RDLEN
        192,  168,
        1,    66,
    };
    try std.testing.expectEqual(@as(usize, 27), msg.len);
    try std.testing.expectError(Error.BadResponse, parseFirstA(&msg, 0x1234, q_test_com));
}

test "parseFirstA rejects an answer to a different question" {
    // Correct id, well-formed, one question -- but it answers evil.com while we
    // asked for test.com. RFC 5452 4.2: the question must be echoed.
    const msg = [_]u8{
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x04, 'e',  'v',  'i',  'l',  0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01,
        0x00, 0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C,
        0x00, 0x04, 6,    6,    6,    6,
    };
    try std.testing.expectError(Error.BadResponse, parseFirstA(&msg, 0x1234, q_test_com));
}

test "parseFirstA rejects a truncated (TC) response instead of trusting it" {
    const msg = [_]u8{
        0x12, 0x34, 0x83, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x04, 't',  'e',  's',  't',  0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01,
        0x00, 0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C,
        0x00, 0x04, 93,   184,  216,  34,
    };
    try std.testing.expectError(Error.BadResponse, parseFirstA(&msg, 0x1234, q_test_com));
}

test "parseFirstA rejects a bogon answer" {
    // A filtering resolver answers 0.0.0.0 for a blocked name; connect() to it
    // targets loopback on Linux, silently dialling a local service.
    const msg = [_]u8{
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x04, 't',  'e',  's',  't',  0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01,
        0x00, 0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C,
        0x00, 0x04, 0,    0,    0,    0,
    };
    try std.testing.expectError(Error.BadResponse, parseFirstA(&msg, 0x1234, q_test_com));
    try std.testing.expect(isBogon(.{ 127, 0, 0, 1 }));
    try std.testing.expect(isBogon(.{ 169, 254, 1, 1 }));
    try std.testing.expect(isBogon(.{ 255, 255, 255, 255 }));
    // A LAN derod is a supported setup and must NOT be filtered.
    try std.testing.expect(!isBogon(.{ 192, 168, 1, 50 }));
    try std.testing.expect(!isBogon(.{ 10, 0, 0, 7 }));
}

test "parseFirstA ignores an A record in the wrong class" {
    const msg = [_]u8{
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x04, 't',  'e',  's',  't',  0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01,
        0x00, 0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x3C,
        0x00, 0x04, 93,   184,  216,  34,
    };
    try std.testing.expectEqual(@as(?[4]u8, null), try parseFirstA(&msg, 0x1234, q_test_com));
}

test "buildQuery output feeds parseFirstA's question check" {
    // The two halves must agree on where the question starts and ends, or every
    // real answer would be rejected. Round-trip them.
    var buf: [512]u8 = undefined;
    const query = try buildQuery(&buf, "test.com", 0x1234);
    try std.testing.expectEqualSlices(u8, q_test_com, query[12..]);
}
