//! Implements the standard credential chain:
//! 1. Environment variables
//! 2. Web identity token from STS
//! 3. Credentials/config files
//! 4. ECS Container credentials, using AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
//! 5. EC2 instance profile credentials
const std = @import("std");
const auth = @import("aws_authentication.zig");

pub fn getCredentials(allocator: std.mem.Allocator) !auth.Credentials {
    _ = allocator;
    if (getEnvironmentCredentials()) |cred| return cred;
    // TODO: 2-5
    return error.NotImplemented;
}

fn getEnvironmentCredentials() ?auth.Credentials {
    return auth.Credentials{
        .access_key = std.os.getenv("AWS_ACCESS_KEY_ID") orelse return null,
        .secret_key = std.os.getenv("AWS_SECRET_ACCESS_KEY") orelse return null,
        .session_token = std.os.getenv("AWS_SESSION_TOKEN"),
    };
}
