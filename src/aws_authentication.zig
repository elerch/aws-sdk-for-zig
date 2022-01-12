pub const Credentials = struct {
    access_key: []const u8,
    secret_key: []const u8,
    session_token: ?[]const u8,
    // uint64_t expiration_timepoint_seconds);
};
