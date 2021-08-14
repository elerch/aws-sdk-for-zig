const std = @import("std");
const aws = @import("aws.zig");
const json = @import("json.zig");

var verbose = false;

pub fn log(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    // Ignore awshttp messages
    if (!verbose and scope == .awshttp and @enumToInt(level) >= @enumToInt(std.log.Level.debug))
        return;
    const scope_prefix = "(" ++ @tagName(scope) ++ "): ";
    const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;

    // Print the message to stderr, silently ignoring any errors
    const held = std.debug.getStderrMutex().acquire();
    defer held.release();
    const stderr = std.io.getStdErr().writer();
    nosuspend stderr.print(prefix ++ format ++ "\n", args) catch return;
}

const Tests = enum {
    query_no_input,
    query_with_input,
    ec2_query_no_input,
    json_1_0_query_with_input,
    json_1_0_query_no_input,
    json_1_1_query_with_input,
    json_1_1_query_no_input,
    rest_json_1_query_no_input,
    rest_json_1_query_with_input,
};

pub fn main() anyerror!void {
    const c_allocator = std.heap.c_allocator;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){
        .backing_allocator = c_allocator,
    };
    defer _ = gpa.deinit();
    const allocator = &gpa.allocator;
    var tests = std.ArrayList(Tests).init(allocator);
    defer tests.deinit();
    var args = std.process.args();
    while (args.next(allocator)) |arg_or_error| {
        const arg = try arg_or_error;
        defer allocator.free(arg);
        if (std.mem.eql(u8, "-v", arg)) {
            verbose = true;
            continue;
        }
        inline for (@typeInfo(Tests).Enum.fields) |f| {
            if (std.mem.eql(u8, f.name, arg)) {
                try tests.append(@field(Tests, f.name));
                break;
            }
        }
    }
    if (tests.items.len == 0) {
        inline for (@typeInfo(Tests).Enum.fields) |f|
            try tests.append(@field(Tests, f.name));
    }

    const options = aws.Options{
        .region = "us-west-2",
    };
    std.log.info("Start\n", .{});
    var client = aws.Aws.init(allocator);
    defer client.deinit();

    const services = aws.Services(.{ .sts, .ec2, .dynamo_db, .ecs, .lambda }){};

    for (tests.items) |t| {
        std.log.info("===== Start Test: {s} =====", .{@tagName(t)});
        switch (t) {
            .query_no_input => {
                const call = try client.call(services.sts.get_caller_identity.Request{}, options);
                defer call.deinit();
                std.log.info("arn: {s}", .{call.response.arn});
                std.log.info("id: {s}", .{call.response.user_id});
                std.log.info("account: {s}", .{call.response.account});
                std.log.info("requestId: {s}", .{call.response_metadata.request_id});
            },
            .query_with_input => {
                // TODO: Find test without sensitive info
                const call = try client.call(services.sts.get_session_token.Request{
                    .duration_seconds = 900,
                }, options);
                defer call.deinit();
                std.log.info("call key: {s}", .{call.response.credentials.?.access_key_id});
            },
            .json_1_0_query_with_input => {
                const call = try client.call(services.dynamo_db.list_tables.Request{
                    .limit = 1,
                }, options);
                defer call.deinit();
                std.log.info("request id: {s}", .{call.response_metadata.request_id});
                std.log.info("account has call: {b}", .{call.response.table_names.?.len > 0});
            },
            .json_1_0_query_no_input => {
                const call = try client.call(services.dynamo_db.describe_limits.Request{}, options);
                defer call.deinit();
                std.log.info("account read capacity limit: {d}", .{call.response.account_max_read_capacity_units});
            },
            .json_1_1_query_with_input => {
                const call = try client.call(services.ecs.list_clusters.Request{
                    .max_results = 1,
                }, options);
                defer call.deinit();
                std.log.info("request id: {s}", .{call.response_metadata.request_id});
                std.log.info("account has call: {b}", .{call.response.cluster_arns.?.len > 0});
            },
            .json_1_1_query_no_input => {
                const call = try client.call(services.ecs.list_clusters.Request{}, options);
                defer call.deinit();
                std.log.info("request id: {s}", .{call.response_metadata.request_id});
                std.log.info("account has call: {b}", .{call.response.cluster_arns.?.len > 0});
            },
            .rest_json_1_query_with_input => {
                const call = try client.call(services.lambda.list_functions.Request{
                    .max_items = 1,
                }, options);
                defer call.deinit();
                std.log.info("request id: {s}", .{call.response_metadata.request_id});
                std.log.info("account has call: {b}", .{call.response.functions.?.len > 0});
            },
            .rest_json_1_query_no_input => {
                const call = try client.call(services.lambda.list_functions.Request{}, options);
                defer call.deinit();
                std.log.info("request id: {s}", .{call.response_metadata.request_id});
                std.log.info("account has call: {b}", .{call.response.functions.?.len > 0});
            },
            .ec2_query_no_input => {
                std.log.err("EC2 Test disabled due to compiler bug", .{});
                // const instances = try client.call(services.ec2.describe_instances.Request{}, options);
                // defer instances.deinit();
                // std.log.info("reservation count: {d}", .{instances.response.reservations.len});
            },
        }
        std.log.info("===== End Test: {s} =====\n", .{@tagName(t)});
    }

    // if (test_twice) {
    //     std.time.sleep(1000 * std.time.ns_per_ms);
    //     std.log.info("second request", .{});
    //
    //     var client2 = aws.Aws.init(allocator);
    //     defer client2.deinit();
    //     const resp2 = try client2.call(services.sts.get_caller_identity.Request{}, options); // catch here and try alloc?
    //     defer resp2.deinit();
    // }

    std.log.info("===== Tests complete =====", .{});
}

// TODO: Move into json.zig
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
