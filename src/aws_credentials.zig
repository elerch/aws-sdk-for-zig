//! Implements the standard credential chain:
//! 1. Environment variables
//! 2. Web identity token from STS
//! 3. Credentials/config files
//! 4. ECS Container credentials, using AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
//! 5. EC2 instance profile credentials
const std = @import("std");
const builtin = @import("builtin");
const auth = @import("aws_authentication.zig");

pub fn getCredentials(allocator: std.mem.Allocator) !auth.Credentials {
    if (try getEnvironmentCredentials(allocator)) |cred| return cred;
    // TODO: 2-5
    return error.NotImplemented;
}

fn getEnvironmentCredentials(allocator: std.mem.Allocator) !?auth.Credentials {
    const secret_key = (try getEnvironmentVariable(allocator, "AWS_SECRET_ACCESS_KEY")) orelse return null;
    defer allocator.free(secret_key); //yes, we're not zeroing. But then, the secret key is in an environment var anyway
    const mutable_key = try allocator.dupe(u8, secret_key);
    // Use cross-platform API (requires allocation)
    return auth.Credentials.init(
        allocator,
        (try getEnvironmentVariable(allocator, "AWS_ACCESS_KEY_ID")) orelse return null,
        mutable_key,
        (try getEnvironmentVariable(allocator, "AWS_SESSION_TOKEN")) orelse
            try getEnvironmentVariable(allocator, "AWS_SECURITY_TOKEN"),
    );
}

fn getEnvironmentVariable(allocator: std.mem.Allocator, key: []const u8) !?[]const u8 {
    return std.process.getEnvVarOwned(allocator, key) catch |e| switch (e) {
        std.process.GetEnvVarOwnedError.EnvironmentVariableNotFound => return null,
        else => return e,
    };
}
