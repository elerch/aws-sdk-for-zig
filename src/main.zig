const std = @import("std");
const aws = @import("aws.zig");
const json = @import("json.zig");
const version = @import("git_version.zig");

var verbose = true;

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
    std.debug.getStderrMutex().lock();
    defer std.debug.getStderrMutex().unlock();
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
    rest_json_1_work_with_lambda,
};

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    var tests = std.ArrayList(Tests).init(allocator);
    defer tests.deinit();
    var args = std.process.args();
    var first = true;
    while (args.next(allocator)) |arg_or_error| {
        const arg = try arg_or_error;
        defer allocator.free(arg);
        if (first)
            std.log.info("{s} {s}", .{ arg, version.pretty_version });
        first = false;
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

    std.log.info("Start\n", .{});
    var client = aws.Client.init(allocator);
    const options = aws.Options{
        .region = "us-west-2",
        .client = client,
    };
    defer client.deinit();

    const services = aws.Services(.{ .sts, .ec2, .dynamo_db, .ecs, .lambda }){};

    for (tests.items) |t| {
        std.log.info("===== Start Test: {s} =====", .{@tagName(t)});
        switch (t) {
            .query_no_input => {
                const call = try aws.Request(services.sts.get_caller_identity).call(.{}, options);
                // const call = try client.call(services.sts.get_caller_identity.Request{}, options);
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
                std.log.info("access key: {s}", .{call.response.credentials.?.access_key_id});
            },
            .json_1_0_query_with_input => {
                const call = try client.call(services.dynamo_db.list_tables.Request{
                    .limit = 1,
                }, options);
                defer call.deinit();
                std.log.info("request id: {s}", .{call.response_metadata.request_id});
                std.log.info("account has tables: {b}", .{call.response.table_names.?.len > 0});
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
                std.log.info("account has clusters: {b}", .{call.response.cluster_arns.?.len > 0});
            },
            .json_1_1_query_no_input => {
                const call = try client.call(services.ecs.list_clusters.Request{}, options);
                defer call.deinit();
                std.log.info("request id: {s}", .{call.response_metadata.request_id});
                std.log.info("account has clusters: {b}", .{call.response.cluster_arns.?.len > 0});
            },
            .rest_json_1_query_with_input => {
                const call = try client.call(services.lambda.list_functions.Request{
                    .max_items = 1,
                }, options);
                defer call.deinit();
                std.log.info("request id: {s}", .{call.response_metadata.request_id});
                std.log.info("account has functions: {b}", .{call.response.functions.?.len > 0});
            },
            .rest_json_1_query_no_input => {
                const call = try client.call(services.lambda.list_functions.Request{}, options);
                defer call.deinit();
                std.log.info("request id: {s}", .{call.response_metadata.request_id});
                std.log.info("account has functions: {b}", .{call.response.functions.?.len > 0});
            },
            .rest_json_1_work_with_lambda => {
                const call = try client.call(services.lambda.list_functions.Request{}, options);
                defer call.deinit();
                std.log.info("list request id: {s}", .{call.response_metadata.request_id});
                if (call.response.functions) |fns| {
                    if (fns.len > 0) {
                        const func = fns[0];
                        const arn = func.function_arn.?;
                        // This is a bit ugly. Maybe a helper function in the library would help?
                        var tags = try std.ArrayList(@typeInfo(try typeForField(services.lambda.tag_resource.Request, "tags")).Pointer.child).initCapacity(allocator, 1);
                        defer tags.deinit();
                        tags.appendAssumeCapacity(.{ .key = "Foo", .value = "Bar" });
                        const req = services.lambda.tag_resource.Request{ .resource = arn, .tags = tags.items };
                        const addtag = try aws.Request(services.lambda.tag_resource).call(req, options);
                        defer addtag.deinit();
                        // const addtag = try client.call(services.lambda.tag_resource.Request{ .resource = arn, .tags = &.{.{ .key = "Foo", .value = "Bar" }} }, options);
                        std.log.info("add tag request id: {s}", .{addtag.response_metadata.request_id});
                        var keys = [_][]const u8{"Foo"}; // Would love to have a way to express this without burning a var here
                        const deletetag = try aws.Request(services.lambda.untag_resource).call(.{ .tag_keys = keys[0..], .resource = arn }, options);
                        defer deletetag.deinit();
                        std.log.info("delete tag request id: {s}", .{deletetag.response_metadata.request_id});
                    } else {
                        std.log.err("no functions to work with", .{});
                    }
                } else {
                    std.log.err("no functions to work with", .{});
                }
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
fn typeForField(comptime T: type, field_name: []const u8) !type {
    const ti = @typeInfo(T);
    switch (ti) {
        .Struct => {
            inline for (ti.Struct.fields) |field| {
                if (std.mem.eql(u8, field.name, field_name))
                    return field.field_type;
            }
        },
        else => return error.TypeIsNotAStruct, // should not hit this
    }
    return error.FieldNotFound;
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
