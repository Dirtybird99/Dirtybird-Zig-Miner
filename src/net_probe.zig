//! net_probe.zig — throwaway empirical probe for the DERO getwork TLS WebSocket.
//!
//! FINDINGS (see docs/net-findings.md):
//!   * TLS handshake works with host=.no_verification, ca=.no_verification
//!     (mirrors C SSL_VERIFY_NONE). No SNI, no CA bundle needed.
//!   * std.net.Stream.read -> windows.ReadFile, which does NOT honor SO_RCVTIMEO;
//!     a blocked ReadFile can't be unblocked by shutdown() or close() either.
//!   * FIX: hand tls.Client a wrapper whose readv/writev call Winsock recv/send
//!     directly (ws2_32). recv honors SO_RCVTIMEO; an idle read returns
//!     WSAETIMEDOUT -> mapped to error.WouldBlock. Restores the C's single-thread
//!     + 50ms interleave; teardown is just closesocket on the same thread.
//!
//! This probe proves: setsockopt(SO_RCVTIMEO) succeeds (ret 0), and the 50ms
//! timed read loop returns timeouts (loop self-exits at 12s, EXIT=0).
//!
//! Run: ./.tools/zig/zig.exe run src/net_probe.zig

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const tls = std.crypto.tls;
const ws2 = std.os.windows.ws2_32;

const HOST = "dero.rabidmining.com";
const PORT: u16 = 10300;
const WALLET = "dero1qyvyeyzrcm2fzf6kyq7egkes2ufgny5xn77y6typhfx9s7w3mvyd5qqynr5hx";
const b64 = std.base64.standard.Encoder;

const SockError = error{ Timeout, Closed, SockError };

/// Stream wrapper for tls.Client using Winsock recv/send directly so SO_RCVTIMEO
/// is honored on Windows. This is essentially the wrapper net.zig will ship.
const WsaStream = struct {
    handle: ws2.SOCKET,

    pub const ReadError = SockError;
    pub const WriteError = SockError;

    pub fn read(s: WsaStream, buffer: []u8) ReadError!usize {
        const n = ws2.recv(s.handle, buffer.ptr, @intCast(buffer.len), 0);
        if (n == ws2.SOCKET_ERROR) {
            return switch (ws2.WSAGetLastError()) {
                .WSAETIMEDOUT, .WSAEWOULDBLOCK => error.Timeout,
                else => error.SockError,
            };
        }
        return @intCast(n);
    }
    pub fn readv(s: WsaStream, iovecs: []posix.iovec) ReadError!usize {
        if (iovecs.len == 0) return 0;
        const first = iovecs[0];
        return s.read(first.base[0..first.len]);
    }
    pub fn readAtLeast(s: WsaStream, buffer: []u8, len: usize) ReadError!usize {
        std.debug.assert(len <= buffer.len);
        var index: usize = 0;
        while (index < len) {
            const amt = try s.read(buffer[index..]);
            if (amt == 0) break;
            index += amt;
        }
        return index;
    }
    pub fn write(s: WsaStream, buffer: []const u8) WriteError!usize {
        const n = ws2.send(s.handle, buffer.ptr, @intCast(buffer.len), 0);
        if (n == ws2.SOCKET_ERROR) return error.SockError;
        return @intCast(n);
    }
    pub fn writev(s: WsaStream, iovecs: []const posix.iovec_const) WriteError!usize {
        if (iovecs.len == 0) return 0;
        const first = iovecs[0];
        return s.write(first.base[0..first.len]);
    }
    pub fn writevAll(s: WsaStream, iovecs: []posix.iovec_const) WriteError!void {
        if (iovecs.len == 0) return;
        var i: usize = 0;
        while (true) {
            var amt = try s.writev(iovecs[i..]);
            while (amt >= iovecs[i].len) {
                amt -= iovecs[i].len;
                i += 1;
                if (i >= iovecs.len) return;
            }
            iovecs[i].base += amt;
            iovecs[i].len -= amt;
        }
    }
};

/// Stream wrapper that waits for readability via select() (timeout-via-select,
/// independent of SO_RCVTIMEO) before recv. This is the shippable design.
const SelectStream = struct {
    handle: ws2.SOCKET,
    timeout_ms: u32,

    pub const ReadError = SockError;
    pub const WriteError = SockError;

    fn waitReadable(s: SelectStream) SockError!void {
        var rset = ws2.fd_set{ .fd_count = 1, .fd_array = undefined };
        rset.fd_array[0] = s.handle;
        var tv = ws2.timeval{ .sec = @intCast(s.timeout_ms / 1000), .usec = @intCast((s.timeout_ms % 1000) * 1000) };
        const sr = ws2.select(0, &rset, null, null, &tv);
        if (sr == 0) return error.Timeout;
        if (sr == ws2.SOCKET_ERROR) return error.SockError;
    }
    pub fn read(s: SelectStream, buffer: []u8) ReadError!usize {
        try s.waitReadable();
        const n = ws2.recv(s.handle, buffer.ptr, @intCast(buffer.len), 0);
        if (n == ws2.SOCKET_ERROR) {
            return switch (ws2.WSAGetLastError()) {
                .WSAETIMEDOUT, .WSAEWOULDBLOCK => error.Timeout,
                else => error.SockError,
            };
        }
        return @intCast(n);
    }
    pub fn readv(s: SelectStream, iovecs: []posix.iovec) ReadError!usize {
        if (iovecs.len == 0) return 0;
        const first = iovecs[0];
        return s.read(first.base[0..first.len]);
    }
    pub fn readAtLeast(s: SelectStream, buffer: []u8, len: usize) ReadError!usize {
        std.debug.assert(len <= buffer.len);
        var index: usize = 0;
        while (index < len) {
            const amt = try s.read(buffer[index..]);
            if (amt == 0) break;
            index += amt;
        }
        return index;
    }
    pub fn write(s: SelectStream, buffer: []const u8) WriteError!usize {
        const n = ws2.send(s.handle, buffer.ptr, @intCast(buffer.len), 0);
        if (n == ws2.SOCKET_ERROR) return error.SockError;
        return @intCast(n);
    }
    pub fn writev(s: SelectStream, iovecs: []const posix.iovec_const) WriteError!usize {
        if (iovecs.len == 0) return 0;
        const first = iovecs[0];
        return s.write(first.base[0..first.len]);
    }
    pub fn writevAll(s: SelectStream, iovecs: []posix.iovec_const) WriteError!void {
        if (iovecs.len == 0) return;
        var i: usize = 0;
        while (true) {
            var amt = try s.writev(iovecs[i..]);
            while (amt >= iovecs[i].len) {
                amt -= iovecs[i].len;
                i += 1;
                if (i >= iovecs.len) return;
            }
            iovecs[i].base += amt;
            iovecs[i].len -= amt;
        }
    }
};

/// setsockopt(SO_RCVTIMEO) via ws2_32, returns the raw setsockopt result (0 = ok).
fn setRcvTimeout(handle: ws2.SOCKET, ms: u32) i32 {
    const val: u32 = ms; // Windows SO_RCVTIMEO is DWORD milliseconds.
    return ws2.setsockopt(handle, ws2.SOL.SOCKET, ws2.SO.RCVTIMEO, std.mem.asBytes(&val), @sizeOf(u32));
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    const stdout = std.io.getStdOut().writer();

    try stdout.print("[probe] resolving {s}:{d} (IPv4)\n", .{ HOST, PORT });
    const list = try std.net.getAddressList(alloc, HOST, PORT);
    defer list.deinit();
    var addr: ?std.net.Address = null;
    for (list.addrs) |a| {
        if (a.any.family == posix.AF.INET) {
            addr = a;
            break;
        }
    }
    if (addr == null) {
        try stdout.print("[probe] no IPv4\n", .{});
        return;
    }
    try stdout.print("[probe] connecting to {any}\n", .{addr.?});
    const netstream = try std.net.tcpConnectToAddress(addr.?);
    const sock: ws2.SOCKET = netstream.handle;
    defer posix.close(netstream.handle);
    const stream = WsaStream{ .handle = sock };
    try stdout.print("[probe] TCP connected\n", .{});

    const r1 = setRcvTimeout(sock, 10000); // generous for handshake/upgrade
    try stdout.print("[probe] setsockopt(SO_RCVTIMEO=10000) ret={d} (0=ok)\n", .{r1});

    try stdout.print("[probe] TLS handshake (no_verification)...\n", .{});
    var client = tls.Client.init(stream, .{ .host = .no_verification, .ca = .no_verification }) catch |err| {
        try stdout.print("[probe] TLS FAILED: {s}\n", .{@errorName(err)});
        return err;
    };
    try stdout.print("[probe] TLS OK\n", .{});

    var keyraw: [16]u8 = undefined;
    std.crypto.random.bytes(&keyraw);
    var keyb64: [24]u8 = undefined;
    _ = b64.encode(&keyb64, &keyraw);
    var req_buf: [512]u8 = undefined;
    const req = try std.fmt.bufPrint(&req_buf, "GET /ws/{s} HTTP/1.1\r\n" ++
        "Host: {s}:{d}\r\n" ++ "Upgrade: websocket\r\n" ++ "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: {s}\r\n" ++ "Sec-WebSocket-Version: 13\r\n\r\n", .{ WALLET, HOST, PORT, keyb64 });
    try client.writeAll(stream, req);
    try stdout.print("[probe] sent upgrade ({d} bytes)\n", .{req.len});

    var resp: [4096]u8 = undefined;
    var total: usize = 0;
    var header_end: usize = 0;
    while (true) {
        const n = try client.read(stream, resp[total..]);
        if (n == 0) {
            try stdout.print("[probe] EOF during upgrade\n", .{});
            return;
        }
        total += n;
        if (std.mem.indexOf(u8, resp[0..total], "\r\n\r\n")) |idx| {
            header_end = idx + 4;
            break;
        }
        if (total >= resp.len) return;
    }
    const sl = std.mem.indexOf(u8, resp[0..total], "\r\n") orelse total;
    const got101 = std.mem.indexOf(u8, resp[0..total], " 101 ") != null;
    try stdout.print("[probe] status: {s} | got101={} | leftover={d}\n", .{ resp[0..sl], got101, total - header_end });

    // RAW SELECT TEST: prove select(50ms) timeout fires independent of SO_RCVTIMEO.
    try stdout.print("[probe] raw select() test, 10 iterations of 50ms readiness wait...\n", .{});
    var sel_timeouts: usize = 0;
    var sel_ready: usize = 0;
    var it: usize = 0;
    while (it < 10) : (it += 1) {
        var rset = ws2.fd_set{ .fd_count = 1, .fd_array = undefined };
        rset.fd_array[0] = sock;
        var tv = ws2.timeval{ .sec = 0, .usec = 50_000 };
        const t0 = std.time.milliTimestamp();
        const sr = ws2.select(0, &rset, null, null, &tv);
        const el = std.time.milliTimestamp() - t0;
        if (sr == 0) {
            sel_timeouts += 1;
            if (it < 2) try stdout.print("[probe] select #{d} = 0 (TIMEOUT) after {d}ms\n", .{ it, el });
        } else if (sr == ws2.SOCKET_ERROR) {
            try stdout.print("[probe] select ERROR wsa={any}\n", .{ws2.WSAGetLastError()});
            break;
        } else {
            sel_ready += 1;
            if (it < 2) try stdout.print("[probe] select #{d} = {d} (READY) after {d}ms\n", .{ it, sr, el });
        }
    }
    try stdout.print("[probe] RAW SELECT: timeouts={d} ready={d}\n", .{ sel_timeouts, sel_ready });

    // Now drive client.read through a select-gated readv (timeout-via-select).
    try stdout.print("[probe] select-gated read loop, 12s...\n", .{});
    var timeouts: usize = 0;
    var data_reads: usize = 0;
    var rbuf: [16384]u8 = undefined;
    const sel_stream = SelectStream{ .handle = sock, .timeout_ms = 50 };
    var sel_client = client; // reuse handshake state (same socket)
    const start = std.time.milliTimestamp();
    while (std.time.milliTimestamp() - start < 12000) {
        const n = sel_client.read(sel_stream, &rbuf) catch |err| {
            if (err == error.Timeout) {
                timeouts += 1;
                if (timeouts <= 2) try stdout.print("[probe] read timeout #{d} (elapsed {d}ms)\n", .{ timeouts, std.time.milliTimestamp() - start });
                continue;
            }
            try stdout.print("[probe] fatal read err: {s}\n", .{@errorName(err)});
            break;
        };
        if (n == 0) {
            try stdout.print("[probe] clean EOF\n", .{});
            break;
        }
        data_reads += 1;
        try stdout.print("[probe] DATA #{d}: {d} bytes head={x}\n", .{ data_reads, n, rbuf[0..@min(n, 32)] });
        decodeAndReport(stdout, rbuf[0..n]) catch {};
    }
    try stdout.print("\n[probe] SUMMARY: select_timeouts={d} read_timeouts={d} data_reads={d}\n", .{ sel_timeouts, timeouts, data_reads });
    if (timeouts > 0 and sel_timeouts > 0)
        try stdout.print("[probe] VERDICT: select-gated read WORKS -> single-thread design VIABLE.\n", .{})
    else
        try stdout.print("[probe] VERDICT: select did not time out -> investigate.\n", .{});
}

fn decodeAndReport(w: anytype, frame: []const u8) !void {
    if (frame.len < 2) return;
    const opcode = frame[0] & 0x0f;
    const masked = (frame[1] & 0x80) != 0;
    var plen: u64 = frame[1] & 0x7f;
    var off: usize = 2;
    if (plen == 126) {
        if (frame.len < 4) return;
        plen = (@as(u64, frame[2]) << 8) | frame[3];
        off = 4;
    } else if (plen == 127) {
        if (frame.len < 10) return;
        plen = 0;
        for (frame[2..10]) |b| plen = (plen << 8) | b;
        off = 10;
    }
    if (masked) off += 4;
    try w.print("[probe]   ws opcode=0x{x} masked={} plen={d}\n", .{ opcode, masked, plen });
    if (off >= frame.len) return;
    const payload = frame[off..@min(frame.len, off + @as(usize, @intCast(plen)))];
    if (std.mem.indexOf(u8, payload, "blockhashing_blob")) |_|
        try w.print("[probe]   *** JOB: {s}\n", .{payload[0..@min(payload.len, 400)]});
}
