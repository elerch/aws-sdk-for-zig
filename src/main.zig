const std = @import("std");
const aws = @import("aws.zig");
const json = @import("json.zig");

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

    // Flip to true to run a second time. This will help debug
    // allocation/deallocation issues
    const test_twice = false;

    // Flip to true to run through the json parsing changes made to stdlib
    const test_json = false;
    if (test_json) try jsonFun();

    const c_allocator = std.heap.c_allocator;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){
        .backing_allocator = c_allocator,
    };
    defer if (!gpa.deinit()) @panic("memory leak detected");
    const allocator = &gpa.allocator;
    // const allocator = std.heap.c_allocator;

    const options = aws.Options{
        .region = "us-west-2",
    };
    std.log.info("Start", .{});

    var client = aws.Aws.init(allocator);
    defer client.deinit();
    const services = aws.Services(.{.sts}){};
    const resp = try client.call(services.sts.get_caller_identity.Request{}, options);
    // TODO: This is a bit wonky. Root cause is lack of declarations in
    //       comptime-generated types
    defer resp.deinit();

    if (test_twice) {
        std.time.sleep(1000 * std.time.ns_per_ms);
        std.log.info("second request", .{});

        var client2 = aws.Aws.init(allocator);
        defer client2.deinit();
        const resp2 = try client2.call(services.sts.get_caller_identity.Request{}, options); // catch here and try alloc?
        defer resp2.deinit();
    }

    std.log.info("arn: {s}", .{resp.response.arn});
    std.log.info("id: {s}", .{resp.response.user_id});
    std.log.info("account: {s}", .{resp.response.account});
    std.log.info("requestId: {s}", .{resp.response_metadata.request_id});

    std.log.info("Departing main", .{});
}

pub fn jsonFun() !void {
    // Standard behavior
    const payload =
        \\{"GetCallerIdentityResponse":{"GetCallerIdentityResult":{"Account":"0123456789","Arn":"arn:aws:iam::0123456789:user/test","UserId":"MYUSERID"},"ResponseMetadata":{"RequestId":"3b80a99b-7df8-4bcb-96ee-b2759878a5f2"}}}
    ;
    const Ret3 = struct {
        getCallerIdentityResponse: struct { getCallerIdentityResult: struct { account: []u8, arn: []u8, user_id: []u8 }, responseMetadata: struct { requestId: []u8 } },
    };
    var stream3 = json.TokenStream.init(payload);
    const res3 = json.parse(Ret3, &stream3, .{
        .allocator = std.heap.c_allocator,
        .allow_camel_case_conversion = true, // new option
        .allow_snake_case_conversion = true, // new option
        .allow_unknown_fields = true, // new option
    }) catch unreachable;
    std.log.info("{}", .{res3});
    std.log.info("{s}", .{res3.getCallerIdentityResponse.getCallerIdentityResult.user_id});
}
