const std = @import("std");
const aws = @import("aws");

pub const std_options: std.Options = .{
    .log_level = .info,

    // usually log_level is enough, but log_scope_levels can be used
    // for finer grained control
    .log_scope_levels = &[_]std.log.ScopeLevel{
        .{ .scope = .awshttp, .level = .warn },
    },
};

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const stdout_raw = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_raw);
    defer bw.flush() catch unreachable;
    const stdout = bw.writer();

    // To use a proxy, uncomment the following with your own configuration
    // const proxy = std.http.Proxy{
    //     .protocol = .plain,
    //     .host = "localhost",
    //     .port = 8080,
    // };
    //
    // var client = aws.Client.init(allocator, .{ .proxy = proxy });
    var client = aws.Client.init(allocator, .{});
    defer client.deinit();

    const options = aws.Options{
        .region = "us-west-2",
        .client = client,
    };

    // As of 2023-08-28, only ECS from this list supports TLS v1.3
    // AWS commitment is to enable all services by 2023-12-31
    const services = aws.Services(.{ .sts, .kms }){};
    try stdout.print("Calling KMS ListKeys, a TLS 1.3 enabled service\n", .{});
    try stdout.print("You likely have at least some AWS-generated keys in your account,\n", .{});
    try stdout.print("but if the account has not had many services used, this may return 0 keys\n\n", .{});
    const call_kms = try aws.Request(services.kms.list_keys).call(.{}, options);
    try stdout.print("\trequestId: {s}\n", .{call_kms.response_metadata.request_id});
    try stdout.print("\tkey count: {d}\n", .{call_kms.response.keys.?.len});
    for (call_kms.response.keys.?) |key| {
        try stdout.print("\t\tkey id: {s}\n", .{key.key_id.?});
        try stdout.print("\t\tkey arn: {s}\n", .{key.key_arn.?});
    }
    defer call_kms.deinit();

    try stdout.print("\n\n\nCalling STS GetCallerIdentity. This does not have TLS 1.3 in September 2023\n", .{});
    try stdout.print("A failure may occur\n\n", .{});
    const call = try aws.Request(services.sts.get_caller_identity).call(.{}, options);
    defer call.deinit();
    try stdout.print("\tarn: {s}\n", .{call.response.arn.?});
    try stdout.print("\tid: {s}\n", .{call.response.user_id.?});
    try stdout.print("\taccount: {s}\n", .{call.response.account.?});
    try stdout.print("\trequestId: {s}\n", .{call.response_metadata.request_id});
}
