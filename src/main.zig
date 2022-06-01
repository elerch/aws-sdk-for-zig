const std = @import("std");
const aws = @import("aws.zig");
const json = @import("json.zig");
const version = @import("git_version.zig");

var verbose: u8 = 0;

pub fn log(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    // Ignore aws_signing messages
    if (verbose < 2 and scope == .aws_signing and @enumToInt(level) >= @enumToInt(std.log.Level.debug))
        return;
    // Ignore aws_credentials messages
    if (verbose < 2 and scope == .aws_credentials and @enumToInt(level) >= @enumToInt(std.log.Level.debug))
        return;
    // Ignore xml_shaper messages
    if (verbose < 2 and scope == .xml_shaper and @enumToInt(level) >= @enumToInt(std.log.Level.debug))
        return;
    // Ignore date messages
    if (verbose < 2 and scope == .date and @enumToInt(level) >= @enumToInt(std.log.Level.debug))
        return;
    // Ignore awshttp messages
    if (verbose < 1 and scope == .awshttp and @enumToInt(level) >= @enumToInt(std.log.Level.debug))
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
    ec2_query_with_input,
    json_1_0_query_with_input,
    json_1_0_query_no_input,
    json_1_1_query_with_input,
    json_1_1_query_no_input,
    rest_json_1_query_no_input,
    rest_json_1_query_with_input,
    rest_json_1_work_with_lambda,
    rest_xml_no_input,
    rest_xml_anything_but_s3,
    rest_xml_work_with_s3,
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
            verbose += 1;
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
    var client = try aws.Client.init(allocator, .{});
    const options = aws.Options{
        .region = "us-west-2",
        .client = client,
    };
    defer client.deinit();

    const services = aws.Services(.{ .sts, .ec2, .dynamo_db, .ecs, .lambda, .sqs, .s3, .cloudfront }){};

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
                const call = try client.call(services.sqs.list_queues.Request{
                    .queue_name_prefix = "s",
                }, options);
                defer call.deinit();
                std.log.info("request id: {s}", .{call.response_metadata.request_id});
                std.log.info("account has queues with prefix 's': {b}", .{call.response.queue_urls != null});
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
                // Describe regions is a simpler request and easier to debug
                const result = try client.call(services.ec2.describe_regions.Request{}, options);
                defer result.deinit();
                std.log.info("request id: {s}", .{result.response_metadata.request_id});
                std.log.info("region count: {d}", .{result.response.regions.?.len});
            },
            .ec2_query_with_input => {
                // Describe instances is more interesting
                const result = try client.call(services.ec2.describe_instances.Request{ .max_results = 6 }, options);
                defer result.deinit();
                std.log.info("reservation count: {d}", .{result.response.reservations.?.len});
                var items: usize = 0;
                for (result.response.reservations.?) |reservation| {
                    items += reservation.instances.?.len;
                }
                std.log.info("items count: {d}", .{items});
                var next = result.response.next_token;
                while (next) |next_token| {
                    std.log.info("more results available: fetching again", .{});

                    const more = try aws.Request(services.ec2.describe_instances)
                        .call(.{ .next_token = next_token, .max_results = 6 }, options);
                    defer more.deinit();
                    std.log.info("reservation count: {d}", .{more.response.reservations.?.len});
                    var batch_items: usize = 0;
                    for (more.response.reservations.?) |reservation| {
                        batch_items += reservation.instances.?.len;
                    }
                    std.log.info("items count: {d}", .{batch_items});
                    items += batch_items;
                    std.log.info("total items count: {d}", .{items});
                    next = more.response.next_token;
                }
            },
            .rest_xml_no_input => {
                const result = try client.call(services.s3.list_buckets.Request{}, options);
                defer result.deinit();
                std.log.info("request id: {s}", .{result.response_metadata.request_id});
                std.log.info("bucket count: {d}", .{result.response.buckets.?.len});
            },
            .rest_xml_anything_but_s3 => {
                const result = try client.call(services.cloudfront.list_key_groups.Request{}, options);
                defer result.deinit();
                std.log.info("request id: {s}", .{result.response_metadata.request_id});
                const list = result.response.key_group_list.?;
                std.log.info("key group list max: {d}", .{list.max_items});
                std.log.info("key group quantity: {d}", .{list.quantity});
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
