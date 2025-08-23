const std = @import("std");

pub const Credentials = struct {
    access_key: []const u8,
    secret_key: []u8,
    session_token: ?[]const u8,
    // uint64_t expiration_timepoint_seconds);

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        access_key: []const u8,
        secret_key: []u8,
        session_token: ?[]const u8,
    ) Self {
        return .{
            .access_key = access_key,
            .secret_key = secret_key,
            .session_token = session_token,

            .allocator = allocator,
        };
    }
    pub fn deinit(self: Self) void {
        std.crypto.secureZero(u8, self.secret_key);
        self.allocator.free(self.secret_key);
        self.allocator.free(self.access_key);
        if (self.session_token) |t| self.allocator.free(t);
    }
};
