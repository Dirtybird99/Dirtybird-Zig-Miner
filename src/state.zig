//! state.zig -- MinerState: all shared mutable state between the network thread and
//! the mining threads. One global instance. Mirrors the C MinerState.
const std = @import("std");

pub const BLOB_LEN = 48;
pub const MAX_JOBID = 128;
pub const SUBMIT_RING = 8; // submit mailbox depth: enough to never drop a found miniblock

const Atomic = std.atomic.Value;

/// One staged submission (a found miniblock awaiting send).
const SubmitEntry = struct {
    jobid: [MAX_JOBID]u8 = undefined,
    jobid_len: usize = 0,
    blob_hex: [BLOB_LEN * 2]u8 = undefined,
    epoch: u64 = 0,
};

pub const MinerState = struct {
    // ---- job (blob/jobid/height under job_mutex; difficulty/epoch atomic) ----
    job_mutex: std.Thread.Mutex = .{},
    blob: [BLOB_LEN]u8 = [_]u8{0} ** BLOB_LEN,
    jobid_buf: [MAX_JOBID]u8 = undefined,
    jobid_len: usize = 0,
    height: Atomic(i64) = Atomic(i64).init(0),
    difficulty: Atomic(u64) = Atomic(u64).init(0),
    job_epoch: Atomic(u64) = Atomic(u64).init(0),

    connected: Atomic(bool) = Atomic(bool).init(false),
    /// True only once the CURRENT connection has delivered a job. Gates the
    /// submit drain: job_epoch is monotonic across reconnects and so cannot
    /// distinguish sessions on its own.
    session_has_job: Atomic(bool) = Atomic(bool).init(false),
    quit: Atomic(bool) = Atomic(bool).init(false),

    // ---- submit mailbox: small FIFO ring so concurrent hits are never dropped ----
    // The reference C spin-waits to deposit a single in-flight share; an 8-entry ring
    // gives the same "never drop a found miniblock" without blocking the miner thread.
    submit_mutex: std.Thread.Mutex = .{},
    submit_ready: Atomic(bool) = Atomic(bool).init(false), // ring non-empty (lock-free hint)
    submit_ring: [SUBMIT_RING]SubmitEntry = undefined,
    submit_head: usize = 0, // index of next entry to pop
    submit_count: usize = 0, // entries currently queued

    // ---- counters ----
    total_hashes: Atomic(i64) = Atomic(i64).init(0),
    accepted: Atomic(i64) = Atomic(i64).init(0),
    rejected: Atomic(i64) = Atomic(i64).init(0),
    blocks: Atomic(i64) = Atomic(i64).init(0),
    submitted: Atomic(i64) = Atomic(i64).init(0),
    stale_drops: Atomic(i64) = Atomic(i64).init(0),
    submit_drops: Atomic(i64) = Atomic(i64).init(0), // found a share but the ring was full

    // ---- config (set once at startup, read-only after) ----
    // Compiled-in backstop defaults: a user who forgets -w/-d (and has no config.json)
    // still mines to the community pool. config.json and CLI flags override these.
    host: []const u8 = "community-pools.mysrv.cloud",
    port: u16 = 10300,
    // Transport for the getwork WebSocket: true => TLS (wss://, the default pool);
    // false => plaintext (ws://, a local derod daemon). Set from the -d/config scheme.
    tls: bool = true,
    wallet: []const u8 = "dero1qyvuemd6z0uzsx5ufc99f0jhyzvvpysmrd2t3526ht7a9dfh7jve2qqt0vu5y",
    nthreads: usize = 0,

    pub const JobSnapshot = struct { epoch: u64, difficulty: u64, blob: [BLOB_LEN]u8, jobid_len: usize };

    /// Called by the network layer when a job arrives. Returns true if work changed.
    pub fn setJob(self: *MinerState, blob: *const [BLOB_LEN]u8, jobid: []const u8, height: i64, difficulty: u64) bool {
        self.job_mutex.lock();
        defer self.job_mutex.unlock();

        const jid = jobid[0..@min(jobid.len, MAX_JOBID)];
        const changed = !std.mem.eql(u8, &self.blob, blob) or
            self.height.load(.monotonic) != height or
            self.difficulty.load(.monotonic) != difficulty or
            !std.mem.eql(u8, self.jobid_buf[0..self.jobid_len], jid);

        @memcpy(&self.blob, blob);
        @memcpy(self.jobid_buf[0..jid.len], jid);
        self.jobid_len = jid.len;
        self.height.store(height, .monotonic);
        self.difficulty.store(difficulty, .monotonic);
        if (changed) _ = self.job_epoch.fetchAdd(1, .monotonic);
        return changed;
    }

    /// Snapshot the current job into `out_jobid` (must be >= MAX_JOBID).
    pub fn snapshotJob(self: *MinerState, out_jobid: []u8) JobSnapshot {
        self.job_mutex.lock();
        defer self.job_mutex.unlock();
        var snap = JobSnapshot{
            .epoch = self.job_epoch.load(.monotonic),
            .difficulty = self.difficulty.load(.monotonic),
            .blob = self.blob,
            .jobid_len = self.jobid_len,
        };
        @memcpy(out_jobid[0..self.jobid_len], self.jobid_buf[0..self.jobid_len]);
        _ = &snap;
        return snap;
    }

    /// Miner found a candidate; push it onto the submit ring (stale-gated by epoch).
    /// Never overwrites a still-pending share -- a full ring counts a submit_drop
    /// (which should be ~never at solo difficulty).
    pub fn stageShare(self: *MinerState, jobid: []const u8, blob_hex: *const [BLOB_LEN * 2]u8, epoch: u64) void {
        if (self.job_epoch.load(.acquire) != epoch) {
            _ = self.stale_drops.fetchAdd(1, .monotonic);
            return;
        }
        self.submit_mutex.lock();
        defer self.submit_mutex.unlock();
        if (self.job_epoch.load(.acquire) != epoch) {
            _ = self.stale_drops.fetchAdd(1, .monotonic);
            return;
        }
        if (self.submit_count >= SUBMIT_RING) {
            _ = self.submit_drops.fetchAdd(1, .monotonic);
            return;
        }
        const tail = (self.submit_head + self.submit_count) % SUBMIT_RING;
        const e = &self.submit_ring[tail];
        const jid = jobid[0..@min(jobid.len, MAX_JOBID)];
        @memcpy(e.jobid[0..jid.len], jid);
        e.jobid_len = jid.len;
        @memcpy(&e.blob_hex, blob_hex);
        e.epoch = epoch;
        self.submit_count += 1;
        self.submit_ready.store(true, .release);
    }

    /// Drop everything staged and re-arm the session gate. Called when a
    /// connection is established.
    ///
    /// job_epoch is MONOTONIC across reconnects, so a share staged moments
    /// before a drop still MATCHES the current epoch -- takeStagedShare's
    /// per-item check cannot tell it apart from a fresh one, and it would be
    /// sent on the new connection against a job that session never issued.
    /// Measured against a test daemon before this existed: 4 such shares
    /// reached a fresh session. The sibling miners had the same defect (Go 17,
    /// C++ 66) and closed it the same way.
    ///
    /// Clearing alone is not sufficient -- see session_has_job.
    pub fn resetSubmitSession(self: *MinerState) void {
        self.session_has_job.store(false, .release);
        self.submit_mutex.lock();
        defer self.submit_mutex.unlock();
        if (self.submit_count > 0) {
            _ = self.stale_drops.fetchAdd(@intCast(self.submit_count), .monotonic);
            self.submit_count = 0;
            self.submit_head = 0;
        }
        self.submit_ready.store(false, .release);
    }

    /// Mark that the CURRENT connection has delivered a job. Until it has, the
    /// miner is still hashing the previous session's work: those shares match
    /// the monotonic epoch but belong to a job this connection never sent, so
    /// nothing may be submitted. Clearing the ring at connect does not cover
    /// this, because workers keep staging during the ~500ms before the new
    /// session's first push (in C++ that residue was 55 of the original 66).
    pub fn markSessionHasJob(self: *MinerState) void {
        self.session_has_job.store(true, .release);
    }

    pub const StagedShare = struct { jobid_len: usize, epoch: u64 };

    /// Network side: pop the next non-stale staged share into caller buffers. Skips and
    /// counts stale entries. Returns null when the ring holds no fresh share. Call in a
    /// loop to drain a backlog: `while (takeStagedShare(...)) |s| send(s)`.
    pub fn takeStagedShare(self: *MinerState, out_jobid: []u8, out_blob_hex: []u8) ?StagedShare {
        // Nothing may leave until this connection has issued a job; anything
        // staged before that belongs to the previous session (see
        // markSessionHasJob).
        if (!self.session_has_job.load(.acquire)) return null;
        if (!self.submit_ready.load(.acquire)) return null;
        self.submit_mutex.lock();
        defer self.submit_mutex.unlock();
        const cur_epoch = self.job_epoch.load(.acquire);
        while (self.submit_count > 0) {
            const e = &self.submit_ring[self.submit_head];
            self.submit_head = (self.submit_head + 1) % SUBMIT_RING;
            self.submit_count -= 1;
            if (self.submit_count == 0) self.submit_ready.store(false, .release);
            if (e.epoch != cur_epoch) {
                _ = self.stale_drops.fetchAdd(1, .monotonic);
                continue; // stale -> skip, try the next entry
            }
            @memcpy(out_jobid[0..e.jobid_len], e.jobid[0..e.jobid_len]);
            @memcpy(out_blob_hex[0 .. BLOB_LEN * 2], &e.blob_hex);
            return .{ .jobid_len = e.jobid_len, .epoch = e.epoch };
        }
        self.submit_ready.store(false, .release);
        return null;
    }
};

test "setJob detects change and bumps epoch; stage/take roundtrip" {
    var s = MinerState{};
    var blob = [_]u8{0} ** BLOB_LEN;
    blob[0] = 0xAB;
    try std.testing.expect(s.setJob(&blob, "job1", 100, 1000));
    try std.testing.expectEqual(@as(u64, 1), s.job_epoch.load(.monotonic));
    // same job -> no change
    try std.testing.expect(!s.setJob(&blob, "job1", 100, 1000));
    try std.testing.expectEqual(@as(u64, 1), s.job_epoch.load(.monotonic));

    // The drain only runs on a live session that has issued work; model that.
    s.markSessionHasJob();
    var hex = [_]u8{'a'} ** (BLOB_LEN * 2);
    s.stageShare("job1", &hex, 1);
    var jbuf: [MAX_JOBID]u8 = undefined;
    var hbuf: [BLOB_LEN * 2]u8 = undefined;
    const got = s.takeStagedShare(&jbuf, &hbuf).?;
    try std.testing.expectEqualStrings("job1", jbuf[0..got.jobid_len]);
    try std.testing.expectEqualSlices(u8, &hex, &hbuf);
    // mailbox now empty
    try std.testing.expect(s.takeStagedShare(&jbuf, &hbuf) == null);
}

test "submit ring: FIFO order, none lost, ring-full and stale handling" {
    var s = MinerState{};
    var blob = [_]u8{0} ** BLOB_LEN;
    blob[0] = 0xCD;
    try std.testing.expect(s.setJob(&blob, "j", 1, 1000)); // epoch 1
    // The network thread only drains on a live session that has issued work;
    // takeStagedShare refuses to emit anything before that (see
    // markSessionHasJob), so model a connected session here.
    s.markSessionHasJob();
    var jbuf: [MAX_JOBID]u8 = undefined;
    var hbuf: [BLOB_LEN * 2]u8 = undefined;

    // Stage 3 distinct shares at epoch 1; draining must return them in FIFO order.
    var i: u8 = 0;
    while (i < 3) : (i += 1) {
        var hex = [_]u8{0} ** (BLOB_LEN * 2);
        @memset(&hex, 'A' + i);
        s.stageShare("j", &hex, 1);
    }
    i = 0;
    while (i < 3) : (i += 1) {
        _ = s.takeStagedShare(&jbuf, &hbuf) orelse return error.MissingShare;
        for (hbuf) |b| try std.testing.expectEqual(@as(u8, 'A' + i), b);
    }
    try std.testing.expect(s.takeStagedShare(&jbuf, &hbuf) == null);

    // Ring-full: SUBMIT_RING entries fit; the next is dropped and counted.
    i = 0;
    while (i < SUBMIT_RING + 1) : (i += 1) {
        var hex = [_]u8{'a'} ** (BLOB_LEN * 2);
        s.stageShare("j", &hex, 1);
    }
    try std.testing.expectEqual(@as(i64, 1), s.submit_drops.load(.monotonic));
    i = 0;
    while (i < SUBMIT_RING) : (i += 1) try std.testing.expect(s.takeStagedShare(&jbuf, &hbuf) != null);
    try std.testing.expect(s.takeStagedShare(&jbuf, &hbuf) == null);

    // Stale: staged at epoch 1, then the job advances -> taken as stale (null), counted.
    var hexz = [_]u8{'z'} ** (BLOB_LEN * 2);
    s.stageShare("j", &hexz, 1);
    var blob2 = [_]u8{0} ** BLOB_LEN;
    blob2[0] = 0xEE;
    try std.testing.expect(s.setJob(&blob2, "j2", 2, 1000)); // epoch -> 2
    try std.testing.expect(s.takeStagedShare(&jbuf, &hbuf) == null);
    try std.testing.expect(s.stale_drops.load(.monotonic) >= 1);
}

test "a share staged on a dead session is never sent on the next one" {
    // job_epoch is MONOTONIC across reconnects, so the per-item epoch check in
    // takeStagedShare cannot tell a share from the previous connection apart
    // from a fresh one -- it matches. Measured against a test daemon before
    // this was fixed: 4 such shares reached a fresh session (Go saw 17, C++ 66).
    var s = MinerState{};
    var blob = [_]u8{0} ** BLOB_LEN;
    blob[0] = 0xCD;
    var jbuf: [MAX_JOBID]u8 = undefined;
    var hbuf: [BLOB_LEN * 2]u8 = undefined;

    // --- session 1: connected, job received, a share staged but not yet sent.
    try std.testing.expect(s.setJob(&blob, "old-job", 1, 1000));
    s.markSessionHasJob();
    var hex = [_]u8{'X'} ** (BLOB_LEN * 2);
    s.stageShare("old-job", &hex, s.job_epoch.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 1), s.submit_count);

    // --- the connection drops and a new one comes up.
    s.resetSubmitSession();
    try std.testing.expectEqual(@as(usize, 0), s.submit_count);
    try std.testing.expect(s.takeStagedShare(&jbuf, &hbuf) == null);
    // The loss is counted, not silent.
    try std.testing.expectEqual(@as(i64, 1), s.stale_drops.load(.monotonic));

    // --- CRUCIAL: workers keep hashing the OLD job until the new session
    // pushes one, and those shares still match the monotonic epoch. Clearing
    // the ring alone does not stop them -- in C++ this residue was 55 of the
    // original 66. Nothing may be sent until this session issues work.
    s.stageShare("old-job", &hex, s.job_epoch.load(.monotonic));
    try std.testing.expect(s.takeStagedShare(&jbuf, &hbuf) == null);

    // --- once the new session delivers a job, normal service resumes.
    try std.testing.expect(s.setJob(&blob, "new-job", 2, 1000));
    s.markSessionHasJob();
    s.stageShare("new-job", &hex, s.job_epoch.load(.monotonic));
    const got = s.takeStagedShare(&jbuf, &hbuf) orelse return error.FreshShareWasNotSent;
    try std.testing.expectEqualStrings("new-job", jbuf[0..got.jobid_len]);
}
