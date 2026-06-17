//! state.zig -- MinerState: all shared mutable state between the network thread and
//! the mining threads. One global instance. Mirrors the C MinerState.
const std = @import("std");

pub const BLOB_LEN = 48;
pub const MAX_JOBID = 128;

const Atomic = std.atomic.Value;

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
    quit: Atomic(bool) = Atomic(bool).init(false),

    // ---- single-slot submit mailbox ----
    submit_mutex: std.Thread.Mutex = .{},
    submit_ready: Atomic(bool) = Atomic(bool).init(false),
    submit_jobid: [MAX_JOBID]u8 = undefined,
    submit_jobid_len: usize = 0,
    submit_blob_hex: [BLOB_LEN * 2]u8 = undefined,
    submit_epoch: u64 = 0,

    // ---- counters ----
    total_hashes: Atomic(i64) = Atomic(i64).init(0),
    accepted: Atomic(i64) = Atomic(i64).init(0),
    rejected: Atomic(i64) = Atomic(i64).init(0),
    blocks: Atomic(i64) = Atomic(i64).init(0),
    submitted: Atomic(i64) = Atomic(i64).init(0),
    stale_drops: Atomic(i64) = Atomic(i64).init(0),

    // ---- config (set once at startup, read-only after) ----
    host: []const u8 = "dero.rabidmining.com",
    port: u16 = 10300,
    wallet: []const u8 = "",
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

    /// Miner found a candidate; stage it for submission (stale-gated by epoch).
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
        const jid = jobid[0..@min(jobid.len, MAX_JOBID)];
        @memcpy(self.submit_jobid[0..jid.len], jid);
        self.submit_jobid_len = jid.len;
        @memcpy(&self.submit_blob_hex, blob_hex);
        self.submit_epoch = epoch;
        self.submit_ready.store(true, .release);
    }

    pub const StagedShare = struct { jobid_len: usize, epoch: u64 };

    /// Network side: pop a staged share into caller buffers. Returns null if none or stale.
    pub fn takeStagedShare(self: *MinerState, out_jobid: []u8, out_blob_hex: []u8) ?StagedShare {
        if (!self.submit_ready.load(.acquire)) return null;
        self.submit_mutex.lock();
        defer self.submit_mutex.unlock();
        if (!self.submit_ready.load(.acquire)) return null;
        self.submit_ready.store(false, .release);

        if (self.submit_epoch != self.job_epoch.load(.acquire)) {
            _ = self.stale_drops.fetchAdd(1, .monotonic);
            return null;
        }
        @memcpy(out_jobid[0..self.submit_jobid_len], self.submit_jobid[0..self.submit_jobid_len]);
        @memcpy(out_blob_hex[0 .. BLOB_LEN * 2], &self.submit_blob_hex);
        return .{ .jobid_len = self.submit_jobid_len, .epoch = self.submit_epoch };
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
