const std = @import("std");
const aws = @import("aws.zig");

pub fn log(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    // Ignore awshttp messages
    if (scope == .awshttp and @enumToInt(level) >= @enumToInt(std.log.Level.debug))
        return;

    const scope_prefix = "(" ++ @tagName(scope) ++ "): ";
    const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;

    // Print the message to stderr, silently ignoring any errors
    const held = std.debug.getStderrMutex().acquire();
    defer held.release();
    const stderr = std.io.getStdErr().writer();
    nosuspend stderr.print(prefix ++ format ++ "\n", args) catch return;
}

pub fn main() anyerror!void {
    // Uncomment if you want to log allocations
    // const file = try std.fs.cwd().createFile("/tmp/allocations.log", .{ .truncate = true });
    // defer file.close();
    // var child_allocator = std.heap.c_allocator;
    // const allocator = &std.heap.loggingAllocator(child_allocator, file.writer()).allocator;
    const allocator = std.heap.c_allocator;

    const options = aws.Options{
        .region = "us-west-2",
    };
    std.log.info("Start", .{});

    var client = aws.Aws.init(allocator);
    defer client.deinit();
    const resp = try client.call(aws.services.sts.get_caller_identity.Request{}, options);
    // TODO: This is a bit wonky. Root cause is lack of declarations in
    //       comptime-generated types
    defer aws.Aws.responseDeinit(resp.raw_response, resp.response_metadata);

    // Flip to true to run a second time. This will help debug
    // allocation/deallocation issues
    const test_twice = false;
    if (test_twice) {
        std.time.sleep(1000 * std.time.ns_per_ms);
        std.log.info("second request", .{});

        var client2 = aws.Aws.init(allocator);
        defer client2.deinit();
        const resp2 = try client2.call(aws.services.sts.get_caller_identity.Request{}, options); // catch here and try alloc?
        defer aws.Aws.responseDeinit(resp2.raw_response, resp2.response_metadata);
    }

    std.log.info("arn: {s}", .{resp.arn});
    std.log.info("id: {s}", .{resp.user_id});
    std.log.info("account: {s}", .{resp.account});
    std.log.info("requestId: {s}", .{resp.response_metadata.request_id});

    std.log.info("Departing main", .{});
}
