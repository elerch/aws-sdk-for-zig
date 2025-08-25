const builtin = @import("builtin");
const std = @import("std");

const date = @import("date");
const json = @import("json");

const aws = @import("aws.zig");
const awshttp = @import("aws_http.zig");

const Services = aws.Services;

const log = std.log.scoped(.aws_test);

var test_error_log_enabled = true;

// TODO: Where does this belong really?
fn typeForField(comptime T: type, comptime field_name: []const u8) !type {
    const ti = @typeInfo(T);
    switch (ti) {
        .@"struct" => {
            inline for (ti.@"struct".fields) |field| {
                if (std.mem.eql(u8, field.name, field_name))
                    return field.type;
            }
        },
        else => return error.TypeIsNotAStruct, // should not hit this
    }
    return error.FieldNotFound;
}
pub fn StringCaseInsensitiveHashMap(comptime V: type) type {
    return std.HashMap([]const u8, V, StringInsensitiveContext, std.hash_map.default_max_load_percentage);
}
pub const StringInsensitiveContext = struct {
    pub fn hash(self: @This(), s: []const u8) u64 {
        _ = self;
        var buf: [1024]u8 = undefined;
        if (s.len > buf.len) unreachable; // tolower has a debug assert, but we want non-debug check too
        const lower_s = std.ascii.lowerString(buf[0..], s);
        return std.hash.Wyhash.hash(0, lower_s);
    }
    pub fn eql(self: @This(), a: []const u8, b: []const u8) bool {
        _ = self;
        return std.ascii.eqlIgnoreCase(a, b);
    }
};

test "custom serialization for map objects" {
    const allocator = std.testing.allocator;
    var buffer = std.Io.Writer.Allocating.init(allocator);
    defer buffer.deinit();
    const services = Services(.{.lambda}){};
    var tags = try std.ArrayList(@typeInfo(try typeForField(services.lambda.tag_resource.Request, "tags")).pointer.child).initCapacity(allocator, 2);
    defer tags.deinit(allocator);
    tags.appendAssumeCapacity(.{ .key = "Foo", .value = "Bar" });
    tags.appendAssumeCapacity(.{ .key = "Baz", .value = "Qux" });

    const lambda = (Services(.{.lambda}){}).lambda;
    const req = lambda.TagResourceRequest{ .resource = "hello", .tags = tags.items };
    try buffer.writer.print("{f}", .{std.json.fmt(req, .{ .whitespace = .indent_4 })});

    const parsed_body = try std.json.parseFromSlice(struct {
        Resource: []const u8,
        Tags: struct {
            Foo: []const u8,
            Baz: []const u8,
        },
    }, std.testing.allocator, buffer.written(), .{});
    defer parsed_body.deinit();

    try std.testing.expectEqualStrings("hello", parsed_body.value.Resource);
    try std.testing.expectEqualStrings("Bar", parsed_body.value.Tags.Foo);
    try std.testing.expectEqualStrings("Qux", parsed_body.value.Tags.Baz);
}

test "proper serialization for kms" {
    // Github issue #8
    // https://github.com/elerch/aws-sdk-for-zig/issues/8
    const allocator = std.testing.allocator;
    var buffer = std.Io.Writer.Allocating.init(allocator);
    defer buffer.deinit();
    const kms = (Services(.{.kms}){}).kms;
    const req = kms.encrypt.Request{
        .encryption_algorithm = "SYMMETRIC_DEFAULT",
        // Since encryption_context is not null, we expect "{}" to be the value
        // here, not "[]", because this is our special AWS map pattern
        .encryption_context = &.{},
        .key_id = "42",
        .plaintext = "foo",
        .dry_run = false,
        .grant_tokens = &[_][]const u8{},
    };
    try buffer.writer.print("{f}", .{std.json.fmt(req, .{ .whitespace = .indent_4 })});

    {
        const parsed_body = try std.json.parseFromSlice(struct {
            KeyId: []const u8,
            Plaintext: []const u8,
            EncryptionContext: struct {},
            GrantTokens: [][]const u8,
            EncryptionAlgorithm: []const u8,
            DryRun: bool,
        }, std.testing.allocator, buffer.written(), .{});
        defer parsed_body.deinit();

        try std.testing.expectEqualStrings("42", parsed_body.value.KeyId);
        try std.testing.expectEqualStrings("foo", parsed_body.value.Plaintext);
        try std.testing.expectEqual(0, parsed_body.value.GrantTokens.len);
        try std.testing.expectEqualStrings("SYMMETRIC_DEFAULT", parsed_body.value.EncryptionAlgorithm);
        try std.testing.expectEqual(false, parsed_body.value.DryRun);
    }

    var buffer_null = std.Io.Writer.Allocating.init(allocator);
    defer buffer_null.deinit();
    const req_null = kms.encrypt.Request{
        .encryption_algorithm = "SYMMETRIC_DEFAULT",
        // Since encryption_context here *IS* null, we expect simply "null" to be the value
        .encryption_context = null,
        .key_id = "42",
        .plaintext = "foo",
        .dry_run = false,
        .grant_tokens = &[_][]const u8{},
    };

    try buffer_null.writer.print("{f}", .{std.json.fmt(req_null, .{ .whitespace = .indent_4 })});

    {
        const parsed_body = try std.json.parseFromSlice(struct {
            KeyId: []const u8,
            Plaintext: []const u8,
            EncryptionContext: ?struct {},
            GrantTokens: [][]const u8,
            EncryptionAlgorithm: []const u8,
            DryRun: bool,
        }, std.testing.allocator, buffer_null.written(), .{});
        defer parsed_body.deinit();

        try std.testing.expectEqualStrings("42", parsed_body.value.KeyId);
        try std.testing.expectEqualStrings("foo", parsed_body.value.Plaintext);
        try std.testing.expectEqual(null, parsed_body.value.EncryptionContext);
        try std.testing.expectEqual(0, parsed_body.value.GrantTokens.len);
        try std.testing.expectEqualStrings("SYMMETRIC_DEFAULT", parsed_body.value.EncryptionAlgorithm);
        try std.testing.expectEqual(false, parsed_body.value.DryRun);
    }
}

test "basic json request serialization" {
    const allocator = std.testing.allocator;
    const svs = Services(.{.dynamo_db}){};
    const request = svs.dynamo_db.list_tables.Request{
        .limit = 1,
    };
    var buffer = std.Io.Writer.Allocating.init(allocator);
    defer buffer.deinit();

    // The transformer needs to allocate stuff out of band, but we
    // can guarantee we don't need the memory after this call completes,
    // so we'll use an arena allocator to whack everything.
    // TODO: Determine if sending in null values is ok, or if we need another
    //       tweak to the stringify function to exclude. According to the
    //       smithy spec, "A null value MAY be provided or omitted
    //       for a boxed member with no observable difference." But we're
    //       seeing a lot of differences here between spec and reality
    //
    try buffer.writer.print("{f}", .{std.json.fmt(request, .{ .whitespace = .indent_4 })});
    try std.testing.expectEqualStrings(
        \\{
        \\    "ExclusiveStartTableName": null,
        \\    "Limit": 1
        \\}
    , buffer.written());
}
test "layer object only" {
    const TestResponse = struct {
        arn: ?[]const u8 = null,
        // uncompressed_code_size: ?i64 = null,

        pub fn jsonFieldNameFor(_: @This(), comptime field_name: []const u8) []const u8 {
            const mappings = .{
                .arn = "Arn",
            };
            return @field(mappings, field_name);
        }
    };
    const response =
        \\        {
        \\          "UncompressedCodeSize": 2,
        \\          "Arn": "blah"
        \\        }
    ;
    // const response =
    //     \\        {
    //     \\          "UncompressedCodeSize": 22599541,
    //     \\          "Arn": "arn:aws:lambda:us-west-2:123456789012:layer:PollyNotes-lib:4"
    //     \\        }
    // ;
    const allocator = std.testing.allocator;
    var stream = json.TokenStream.init(response);
    const parser_options = json.ParseOptions{
        .allocator = allocator,
        .allow_camel_case_conversion = true, // new option
        .allow_snake_case_conversion = true, // new option
        .allow_unknown_fields = true, // new option. Cannot yet handle non-struct fields though
        .allow_missing_fields = false, // new option. Cannot yet handle non-struct fields though
    };
    const r = try json.parse(TestResponse, &stream, parser_options);
    json.parseFree(TestResponse, r, parser_options);
}

// Use for debugging json responses of specific requests
// test "dummy request" {
//     const allocator = std.testing.allocator;
//     const svs = Services(.{.sts}){};
//     const request = svs.sts.get_session_token.Request{
//         .duration_seconds = 900,
//     };
//     const FullR = FullResponse(request);
//     const response =
//     var stream = json.TokenStream.init(response);
//
//     const parser_options = json.ParseOptions{
//         .allocator = allocator,
//         .allow_camel_case_conversion = true, // new option
//         .allow_snake_case_conversion = true, // new option
//         .allow_unknown_fields = true, // new option. Cannot yet handle non-struct fields though
//         .allow_missing_fields = false, // new option. Cannot yet handle non-struct fields though
//     };
//     const SResponse = ServerResponse(request);
//     const r = try json.parse(SResponse, &stream, parser_options);
//     json.parseFree(SResponse, r, parser_options);

test {
    // To run nested container tests, either, call `refAllDecls` which will
    // reference all declarations located in the given argument.
    // `@This()` is a builtin function that returns the innermost container it is called from.
    // In this example, the innermost container is this file (implicitly a struct).
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(awshttp);
    std.testing.refAllDecls(json);
    std.testing.refAllDecls(@import("url.zig"));
    std.testing.refAllDecls(@import("case"));
    std.testing.refAllDecls(date);
    std.testing.refAllDecls(@import("servicemodel.zig"));
    std.testing.refAllDecls(@import("xml_shaper.zig"));
}

const TestOptions = struct {
    allocator: std.mem.Allocator,
    server_response: []const u8 = "unset",
    server_response_status: std.http.Status = .ok,
    server_response_headers: []const std.http.Header = &.{},
    server_response_transfer_encoding: ?std.http.TransferEncoding = null,
};
const TestSetup = struct {
    allocator: std.mem.Allocator,
    options: TestOptions,
    creds: aws_auth.Credentials,
    client: aws.Client,
    call_options: *aws.Options,

    request_actuals: ?*RequestActuals = null,
    response_actuals: ?*ResponseActuals = null,

    pub const RequestActuals = struct {
        request: *std.http.Client.Request,
        trace: []const u8,

        // Looks like uri might be getting trounced before deinit
        request_uri: []const u8,

        /// Body only exists if and when sendBodyComplete is called
        body: ?[]u8 = null,

        /// extra_headers are copied from request call
        extra_headers: []const std.http.Header,

        fn expectHeader(self: RequestActuals, name: []const u8, value: []const u8) !void {
            for (self.extra_headers) |h|
                if (std.ascii.eqlIgnoreCase(name, h.name) and
                    std.mem.eql(u8, value, h.value)) return;
            return error.HeaderOrValueNotFound;
        }
        fn expectNoDuplicateHeaders(self: RequestActuals, allocator: std.mem.Allocator) !void {
            // As header keys are
            var hm = StringCaseInsensitiveHashMap(void).init(allocator);
            try hm.ensureTotalCapacity(@intCast(self.request.extra_headers.len));
            defer hm.deinit();
            // TODO: How should we deal with the standard headers?
            for (self.extra_headers) |h| {
                if (hm.getKey(h.name)) |_| {
                    log.err("Duplicate key detected. Key name: {s}", .{h.name});
                    return error.duplicateKeyDetected;
                }
                try hm.put(h.name, {});
            }
        }
        fn deinit(self: *RequestActuals, allocator: std.mem.Allocator) void {
            if (self.body) |b| allocator.free(b);
            for (self.extra_headers) |h| {
                allocator.free(h.name);
                allocator.free(h.value);
            }
            allocator.free(self.extra_headers);

            allocator.free(self.trace);
            allocator.free(self.request_uri);
            allocator.destroy(self.request.reader.in);
            allocator.destroy(self.request);
        }
    };

    pub const ResponseActuals = struct {
        body: []const u8,
        response: std.http.Client.Response,
    };
    const Self = @This();

    const aws_creds = @import("aws_credentials.zig");
    const aws_auth = @import("aws_authentication.zig");
    const signing_time =
        date.dateTimeToTimestamp(
            date.parseIso8601ToDateTime("20230908T170252Z") catch @compileError("Cannot parse date"),
        ) catch @compileError("Cannot parse date");

    fn request(
        self_ptr: usize,
        method: std.http.Method,
        uri: std.Uri,
        options: std.http.Client.RequestOptions,
    ) std.http.Client.RequestError!std.http.Client.Request {
        const self: *Self = @ptrFromInt(self_ptr);
        if (self.request_actuals) |r| {
            std.debug.print("request has been called twice. Previous stack trace:\n", .{});
            var stderr = std.fs.File.stderr().writer(&.{});
            stderr.interface.writeAll(r.trace) catch @panic("could not write to stderr");
            std.debug.print("Current stack trace:\n", .{});
            std.debug.dumpCurrentStackTrace(null);
            return error.ConnectionRefused; // we should not be called twice
        }
        const acts = try self.allocator.create(RequestActuals);
        errdefer self.allocator.destroy(acts);
        var aw = std.Io.Writer.Allocating.init(self.allocator);
        defer aw.deinit();
        std.debug.dumpCurrentStackTraceToWriter(null, &aw.writer) catch return error.OutOfMemory;
        const req = try self.allocator.create(std.http.Client.Request);
        errdefer self.allocator.destroy(req);
        const reader = try self.allocator.create(std.Io.Reader);
        errdefer self.allocator.destroy(reader);
        reader.* = .fixed(self.options.server_response);
        req.* = .{
            .uri = uri,
            .client = undefined,
            .connection = options.connection,
            .reader = .{
                .in = reader,
                .interface = reader.*,
                .state = .ready,
                .max_head_len = 1024,
            },
            .keep_alive = true,
            .method = method,
            .transfer_encoding = .none,
            .redirect_behavior = options.redirect_behavior,
            .handle_continue = options.handle_continue,
            .headers = options.headers,
            .extra_headers = options.extra_headers,
            .privileged_headers = options.privileged_headers,
        };
        var al = try std.ArrayList(std.http.Header).initCapacity(self.allocator, options.extra_headers.len);
        defer al.deinit(self.allocator);
        for (options.extra_headers) |h|
            al.appendAssumeCapacity(.{
                .name = try self.allocator.dupe(u8, h.name),
                .value = try self.allocator.dupe(u8, h.value),
            });

        acts.* = .{
            .trace = try self.allocator.dupe(u8, aw.written()),
            .request = req,
            .request_uri = try std.fmt.allocPrint(self.allocator, "{f}", .{uri}),
            .extra_headers = try al.toOwnedSlice(self.allocator),
        };
        self.request_actuals = acts;
        return acts.request.*;
    }
    fn sendBodyComplete(self_ptr: usize, body: []u8) std.io.Writer.Error!void {
        const self: *Self = @ptrFromInt(self_ptr);
        if (self.request_actuals == null) return error.WriteFailed; // invalid state - must be called after request
        self.request_actuals.?.body = self.allocator.dupe(u8, body) catch return error.WriteFailed;
    }
    fn receiveHead(self_ptr: usize) std.http.Client.Request.ReceiveHeadError!std.http.Client.Response {
        const self: *Self = @ptrFromInt(self_ptr);
        if (self.request_actuals == null) return error.WriteFailed; // invalid state - must be called after request
        const req = self.request_actuals.?.request;

        var response_body = try std.Io.Writer.Allocating.initCapacity(self.allocator, 256);
        defer response_body.deinit();
        const writer = &response_body.writer;

        try writer.print("HTTP/1.1 {d} {?s}\r\n", .{ @intFromEnum(self.options.server_response_status), self.options.server_response_status.phrase() });
        for (self.options.server_response_headers) |header|
            try writer.print("{s}: {s}\r\n", .{ header.name, header.value });
        try writer.print("\r\n", .{});
        try writer.print("{s}", .{self.options.server_response});
        // server_response_transfer_encoding: ?std.http.TransferEncoding = null,
        // This is the real work here - now we have to do the server side of this and end up with a raw response
        //
        // const acts = self.request_actuals.?;
        // acts.response = .{
        //     .request = acts.request,
        //     .head = std.http.Client.Response.Head.parse() catch return error.HttpHeadersInvalid,
        // };
        const body = try response_body.toOwnedSlice();
        errdefer self.allocator.free(body);

        const actual_response = try self.allocator.create(ResponseActuals);
        errdefer self.allocator.destroy(actual_response);
        actual_response.* = .{
            .body = body,
            .response = .{
                .request = req,
                .head = std.http.Client.Response.Head.parse(body) catch return error.HttpHeadersInvalid,
            },
        };
        req.reader.state = .received_head;
        self.response_actuals = actual_response;
        return actual_response.response;
    }
    pub fn readerDecompressing(self_ptr: usize) *std.Io.Reader {
        // At the end, this has to provide a reader that supports streamRemaining
        const self: *Self = @ptrFromInt(self_ptr);
        std.debug.assert(self.request_actuals != null); // invalid state - must be called after request
        std.debug.assert(self.response_actuals != null); // invalid state - must be called after receiveHead
        return self.request_actuals.?.request.reader.in;
    }
    fn init(options: TestOptions) !*Self {
        const client = aws.Client.init(options.allocator, .{});
        const call_options = try options.allocator.create(aws.Options);
        const self = try options.allocator.create(Self);
        call_options.* = .{
            .region = "us-west-2",
            .client = client,

            // Test specific stuff
            .mock = .{
                .signing_time = signing_time,
                .request_fn = request,
                .send_body_complete = sendBodyComplete,
                .receive_head = receiveHead,
                .reader_decompressing = readerDecompressing,
                .context = @intFromPtr(self),
            },
        };
        self.* = .{
            .options = options,
            .allocator = options.allocator,
            .creds = aws_auth.Credentials.init(
                options.allocator,
                try options.allocator.dupe(u8, "ACCESS"),
                try options.allocator.dupe(u8, "SECRET"),
                null,
            ),
            .client = client,
            .call_options = call_options,
        };
        aws_creds.static_credentials = self.creds;
        return self;
    }
    fn deinit(self: *Self) void {
        if (self.response_actuals) |r| {
            self.allocator.free(r.body);
            self.allocator.destroy(r);
        }
        if (self.request_actuals) |r| {
            r.deinit(self.allocator);
            self.allocator.destroy(r);
        }
        self.allocator.destroy(self.call_options);
        self.call_options = undefined;
        self.allocator.destroy(self);
    }
};
test "query_no_input: sts getCallerIdentity comptime" {
    const allocator = std.testing.allocator;
    const test_harness = try TestSetup.init(.{
        .allocator = allocator,
        .server_response =
        \\{"GetCallerIdentityResponse":{"GetCallerIdentityResult":{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/admin","UserId":"AIDAYAM4POHXHRVANDQBQ"},"ResponseMetadata":{"RequestId":"8f0d54da-1230-40f7-b4ac-95015c4b84cd"}}}
        ,
        .server_response_headers = &.{
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "x-amzn-RequestId", .value = "8f0d54da-1230-40f7-b4ac-95015c4b84cd" },
        },
    });
    defer test_harness.deinit();
    const sts = (Services(.{.sts}){}).sts;
    const call = try aws.Request(sts.get_caller_identity).call(.{}, test_harness.call_options.*);
    defer call.deinit();

    // Request expectations
    if (test_harness.request_actuals == null) return error.NoCallMade;
    const req_actuals = test_harness.request_actuals.?;
    try std.testing.expectEqual(std.http.Method.POST, req_actuals.request.method);
    try std.testing.expectEqualStrings("https://sts.us-west-2.amazonaws.com/", req_actuals.request_uri);
    try std.testing.expectEqualStrings(
        \\Action=GetCallerIdentity&Version=2011-06-15
    , req_actuals.body.?);
    // Response expectations
    try std.testing.expectEqualStrings(
        "arn:aws:iam::123456789012:user/admin",
        call.response.arn.?,
    );
    try std.testing.expectEqualStrings("AIDAYAM4POHXHRVANDQBQ", call.response.user_id.?);
    try std.testing.expectEqualStrings("123456789012", call.response.account.?);
    try std.testing.expectEqualStrings("8f0d54da-1230-40f7-b4ac-95015c4b84cd", call.response_metadata.request_id);
}

test "query_with_input: iam getRole runtime" {
    // sqs switched from query to json in aws sdk for go v2 commit f5a08768ef820ff5efd62a49ba50c61c9ca5dbcb
    const allocator = std.testing.allocator;
    var test_harness = try TestSetup.init(.{
        .allocator = allocator,
        .server_response =
        \\<GetRoleResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\<GetRoleResult>
        \\  <Role>
        \\    <Path>/application_abc/component_xyz/</Path>
        \\    <Arn>arn:aws:iam::123456789012:role/application_abc/component_xyz/S3Access</Arn>
        \\    <RoleName>S3Access</RoleName>
        \\    <AssumeRolePolicyDocument>
        \\      {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
        \\      "Principal":{"Service":["ec2.amazonaws.com"]},"Action":["sts:AssumeRole"]}]}
        \\    </AssumeRolePolicyDocument>
        \\    <CreateDate>2012-05-08T23:34:01Z</CreateDate>
        \\    <RoleId>AROADBQP57FF2AEXAMPLE</RoleId>
        \\    <RoleLastUsed>
        \\      <LastUsedDate>2019-11-20T17:09:20Z</LastUsedDate>
        \\      <Region>us-east-1</Region>
        \\    </RoleLastUsed>
        \\  </Role>
        \\</GetRoleResult>
        \\<ResponseMetadata>
        \\  <RequestId>df37e965-9967-11e1-a4c3-270EXAMPLE04</RequestId>
        \\</ResponseMetadata>
        \\</GetRoleResponse>
        ,
        .server_response_headers = &.{
            .{ .name = "Content-Type", .value = "text/xml" },
            .{ .name = "x-amzn-RequestId", .value = "df37e965-9967-11e1-a4c3-270EXAMPLE04" },
        },
    });
    defer test_harness.deinit();
    const iam = (Services(.{.iam}){}).iam;
    const call = try test_harness.client.call(iam.get_role.Request{
        .role_name = "S3Access",
    }, test_harness.call_options.*);
    defer call.deinit();
    // Request expectations
    if (test_harness.request_actuals == null) return error.NoCallMade;
    const req_actuals = test_harness.request_actuals.?;
    try std.testing.expectEqual(std.http.Method.POST, req_actuals.request.method);
    try std.testing.expectEqualStrings("https://iam.amazonaws.com/", req_actuals.request_uri);
    try std.testing.expectEqualStrings(
        \\Action=GetRole&Version=2010-05-08&RoleName=S3Access
    , req_actuals.body.?);
    // Response expectations
    try std.testing.expectEqualStrings("arn:aws:iam::123456789012:role/application_abc/component_xyz/S3Access", call.response.role.arn);
    try std.testing.expectEqualStrings("df37e965-9967-11e1-a4c3-270EXAMPLE04", call.response_metadata.request_id);
}
test "query_with_input: sts getAccessKeyInfo runtime" {
    // sqs switched from query to json in aws sdk for go v2 commit f5a08768ef820ff5efd62a49ba50c61c9ca5dbcb
    const allocator = std.testing.allocator;
    var test_harness = try TestSetup.init(.{
        .allocator = allocator,
        .server_response =
        \\<GetAccessKeyInfoResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
        \\  <GetAccessKeyInfoResult>
        \\    <Account>123456789012</Account>
        \\  </GetAccessKeyInfoResult>
        \\  <ResponseMetadata>
        \\    <RequestId>ec85bf29-1ef0-459a-930e-6446dd14a286</RequestId>
        \\  </ResponseMetadata>
        \\</GetAccessKeyInfoResponse>
        ,
        .server_response_headers = &.{
            .{ .name = "Content-Type", .value = "text/xml" },
            .{ .name = "x-amzn-RequestId", .value = "ec85bf29-1ef0-459a-930e-6446dd14a286" },
        },
    });
    defer test_harness.deinit();
    const sts = (Services(.{.sts}){}).sts;
    const call = try test_harness.client.call(sts.get_access_key_info.Request{
        .access_key_id = "ASIAYAM4POHXJNKTYFUN",
    }, test_harness.call_options.*);
    defer call.deinit();
    // Request expectations
    if (test_harness.request_actuals == null) return error.NoCallMade;
    const req_actuals = test_harness.request_actuals.?;
    try std.testing.expectEqual(std.http.Method.POST, req_actuals.request.method);
    try std.testing.expectEqualStrings("https://sts.us-west-2.amazonaws.com/", req_actuals.request_uri);
    try std.testing.expectEqualStrings(
        \\Action=GetAccessKeyInfo&Version=2011-06-15&AccessKeyId=ASIAYAM4POHXJNKTYFUN
    , req_actuals.body.?);
    // Response expectations
    try std.testing.expect(call.response.account != null);
    try std.testing.expectEqualStrings("123456789012", call.response.account.?);
    try std.testing.expectEqualStrings("ec85bf29-1ef0-459a-930e-6446dd14a286", call.response_metadata.request_id);
}
test "json_1_0_query_with_input: dynamodb listTables runtime" {
    const allocator = std.testing.allocator;
    var test_harness = try TestSetup.init(.{
        .allocator = allocator,
        .server_response =
        \\{"LastEvaluatedTableName":"Customer","TableNames":["Customer"]}
        ,
        .server_response_headers = &.{
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "x-amzn-RequestId", .value = "QBI72OUIN8U9M9AG6PCSADJL4JVV4KQNSO5AEMVJF66Q9ASUAAJG" },
        },
    });
    defer test_harness.deinit();
    const dynamo_db = (Services(.{.dynamo_db}){}).dynamo_db;
    const call = try test_harness.client.call(dynamo_db.list_tables.Request{
        .limit = 1,
    }, test_harness.call_options.*);
    defer call.deinit();
    // Request expectations
    if (test_harness.request_actuals == null) return error.NoCallMade;
    const req_actuals = test_harness.request_actuals.?;
    try std.testing.expectEqual(std.http.Method.POST, req_actuals.request.method);
    try std.testing.expectEqualStrings("https://dynamodb.us-west-2.amazonaws.com/", req_actuals.request_uri);
    try req_actuals.expectHeader("X-Amz-Target", "DynamoDB_20120810.ListTables");

    const parsed_body = try std.json.parseFromSlice(struct {
        ExclusiveStartTableName: ?[]const u8,
        Limit: u8,
    }, std.testing.allocator, req_actuals.body.?, .{});
    defer parsed_body.deinit();

    try std.testing.expectEqual(null, parsed_body.value.ExclusiveStartTableName);
    try std.testing.expectEqual(1, parsed_body.value.Limit);

    // Response expectations
    try std.testing.expectEqualStrings("QBI72OUIN8U9M9AG6PCSADJL4JVV4KQNSO5AEMVJF66Q9ASUAAJG", call.response_metadata.request_id);
    try std.testing.expectEqual(@as(usize, 1), call.response.table_names.?.len);
    try std.testing.expectEqualStrings("Customer", call.response.table_names.?[0]);
}

test "json_1_0_query_no_input: dynamodb listTables runtime" {
    const allocator = std.testing.allocator;
    var test_harness = try TestSetup.init(.{
        .allocator = allocator,
        .server_response =
        \\{"AccountMaxReadCapacityUnits":80000,"AccountMaxWriteCapacityUnits":80000,"TableMaxReadCapacityUnits":40000,"TableMaxWriteCapacityUnits":40000}
        ,
        .server_response_headers = &.{
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "x-amzn-RequestId", .value = "QBI72OUIN8U9M9AG6PCSADJL4JVV4KQNSO5AEMVJF66Q9ASUAAJG" },
        },
    });
    defer test_harness.deinit();
    const dynamo_db = (Services(.{.dynamo_db}){}).dynamo_db;
    const call = try test_harness.client.call(dynamo_db.describe_limits.Request{}, test_harness.call_options.*);
    defer call.deinit();
    // Request expectations
    if (test_harness.request_actuals == null) return error.NoCallMade;
    const req_actuals = test_harness.request_actuals.?;
    try std.testing.expectEqual(std.http.Method.POST, req_actuals.request.method);
    try std.testing.expectEqualStrings("https://dynamodb.us-west-2.amazonaws.com/", req_actuals.request_uri);
    try req_actuals.expectHeader("X-Amz-Target", "DynamoDB_20120810.DescribeLimits");
    try std.testing.expectEqualStrings(
        \\{}
    , req_actuals.body.?);
    // Response expectations
    try std.testing.expectEqualStrings("QBI72OUIN8U9M9AG6PCSADJL4JVV4KQNSO5AEMVJF66Q9ASUAAJG", call.response_metadata.request_id);
    try std.testing.expectEqual(@as(i64, 80000), call.response.account_max_read_capacity_units.?);
}
test "json_1_1_query_with_input: ecs listClusters runtime" {
    const allocator = std.testing.allocator;
    var test_harness = try TestSetup.init(.{
        .allocator = allocator,
        .server_response =
        \\{"clusterArns":["arn:aws:ecs:us-west-2:550620852718:cluster/web-applicationehjaf-cluster"],"nextToken":"czE0Og=="}
        ,
        .server_response_headers = &.{
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "x-amzn-RequestId", .value = "b2420066-ff67-4237-b782-721c4df60744" },
        },
    });
    defer test_harness.deinit();
    const ecs = (Services(.{.ecs}){}).ecs;
    const call = try test_harness.client.call(ecs.list_clusters.Request{
        .max_results = 1,
    }, test_harness.call_options.*);
    defer call.deinit();
    // Request expectations
    if (test_harness.request_actuals == null) return error.NoCallMade;
    const req_actuals = test_harness.request_actuals.?;
    try std.testing.expectEqual(std.http.Method.POST, req_actuals.request.method);
    try std.testing.expectEqualStrings("https://ecs.us-west-2.amazonaws.com/", req_actuals.request_uri);
    try req_actuals.expectHeader("X-Amz-Target", "AmazonEC2ContainerServiceV20141113.ListClusters");

    const parsed_body = try std.json.parseFromSlice(struct {
        nextToken: ?[]const u8,
        maxResults: u8,
    }, std.testing.allocator, req_actuals.body.?, .{});
    defer parsed_body.deinit();

    try std.testing.expectEqual(null, parsed_body.value.nextToken);
    try std.testing.expectEqual(1, parsed_body.value.maxResults);

    // Response expectations
    try std.testing.expectEqualStrings("b2420066-ff67-4237-b782-721c4df60744", call.response_metadata.request_id);
    try std.testing.expectEqual(@as(usize, 1), call.response.cluster_arns.?.len);
    try std.testing.expectEqualStrings("arn:aws:ecs:us-west-2:550620852718:cluster/web-applicationehjaf-cluster", call.response.cluster_arns.?[0]);
}
test "json_1_1_query_no_input: ecs listClusters runtime" {
    // const old = std.testing.log_level;
    // defer std.testing.log_level = old;
    // std.testing.log_level = .debug;
    const allocator = std.testing.allocator;
    var test_harness = try TestSetup.init(.{
        .allocator = allocator,
        .server_response =
        \\{"clusterArns":["arn:aws:ecs:us-west-2:550620852718:cluster/web-applicationehjaf-cluster"],"nextToken":"czE0Og=="}
        ,
        .server_response_headers = &.{
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "x-amzn-RequestId", .value = "e65322b2-0065-45f2-ba37-f822bb5ce395" },
        },
    });
    defer test_harness.deinit();
    const ecs = (Services(.{.ecs}){}).ecs;
    const call = try test_harness.client.call(ecs.list_clusters.Request{}, test_harness.call_options.*);
    defer call.deinit();
    // Request expectations
    if (test_harness.request_actuals == null) return error.NoCallMade;
    const req_actuals = test_harness.request_actuals.?;
    try std.testing.expectEqual(std.http.Method.POST, req_actuals.request.method);
    try std.testing.expectEqualStrings("https://ecs.us-west-2.amazonaws.com/", req_actuals.request_uri);
    try req_actuals.expectHeader("X-Amz-Target", "AmazonEC2ContainerServiceV20141113.ListClusters");

    const parsed_body = try std.json.parseFromSlice(struct {
        nextToken: ?[]const u8,
        maxResults: ?u8,
    }, std.testing.allocator, req_actuals.body.?, .{});
    defer parsed_body.deinit();

    try std.testing.expectEqual(null, parsed_body.value.nextToken);
    try std.testing.expectEqual(null, parsed_body.value.maxResults);

    // Response expectations
    try std.testing.expectEqualStrings("e65322b2-0065-45f2-ba37-f822bb5ce395", call.response_metadata.request_id);
    try std.testing.expectEqual(@as(usize, 1), call.response.cluster_arns.?.len);
    try std.testing.expectEqualStrings("arn:aws:ecs:us-west-2:550620852718:cluster/web-applicationehjaf-cluster", call.response.cluster_arns.?[0]);
}
test "rest_json_1_query_with_input: lambda listFunctions runtime" {
    const allocator = std.testing.allocator;
    var test_harness = try TestSetup.init(.{
        .allocator = allocator,
        .server_response =
        \\{"Functions":[{"Description":"AWS CDK resource provider framework - onEvent (DevelopmentFrontendStack-g650u/com.amazonaws.cdk.custom-resources.amplify-asset-deployment-provider/amplify-asset-deployment-handler-provider)","TracingConfig":{"Mode":"PassThrough"},"VpcConfig":null,"SigningJobArn":null,"SnapStart":{"OptimizationStatus":"Off","ApplyOn":"None"},"RevisionId":"0c62fc74-a692-403d-9206-5fcbad406424","LastModified":"2023-03-01T18:13:15.704+0000","FileSystemConfigs":null,"FunctionName":"DevelopmentFrontendStack--amplifyassetdeploymentha-aZqB9IbZLIKU","Runtime":"nodejs14.x","Version":"$LATEST","PackageType":"Zip","LastUpdateStatus":null,"Layers":null,"FunctionArn":"arn:aws:lambda:us-west-2:550620852718:function:DevelopmentFrontendStack--amplifyassetdeploymentha-aZqB9IbZLIKU","KMSKeyArn":null,"MemorySize":128,"ImageConfigResponse":null,"LastUpdateStatusReason":null,"DeadLetterConfig":null,"Timeout":900,"Handler":"framework.onEvent","CodeSha256":"m4tt+M0l3p8bZvxIDj83dwGrwRW6atCfS/q8AiXCD3o=","Role":"arn:aws:iam::550620852718:role/DevelopmentFrontendStack-amplifyassetdeploymentha-1782JF7WAPXZ3","SigningProfileVersionArn":null,"MasterArn":null,"RuntimeVersionConfig":null,"CodeSize":4307,"State":null,"StateReason":null,"Environment":{"Variables":{"USER_ON_EVENT_FUNCTION_ARN":"arn:aws:lambda:us-west-2:550620852718:function:DevelopmentFrontendStack--amplifyassetdeploymenton-X9iZJSCSPYDH","WAITER_STATE_MACHINE_ARN":"arn:aws:states:us-west-2:550620852718:stateMachine:amplifyassetdeploymenthandlerproviderwaiterstatemachineB3C2FCBE-Ltggp5wBcHWO","USER_IS_COMPLETE_FUNCTION_ARN":"arn:aws:lambda:us-west-2:550620852718:function:DevelopmentFrontendStack--amplifyassetdeploymentis-jaHopLrSSARV"},"Error":null},"EphemeralStorage":{"Size":512},"StateReasonCode":null,"LastUpdateStatusReasonCode":null,"Architectures":["x86_64"]}],"NextMarker":"lslTXFcbLQKkb0vP9Kgh5hUL7C3VghELNGbWgZfxrRCk3eiDRMkct7D8EmptWfHSXssPdS7Bo66iQPTMpVOHZgANewpgGgFGGr4pVjd6VgLUO6qPe2EMAuNDBjUTxm8z6N28yhlUwEmKbrAV/m0k5qVzizwoxFwvyruMbuMx9kADFACSslcabxXl3/jDI4rfFnIsUVdzTLBgPF1hzwrE1f3lcdkBvUp+QgY+Pn3w5QuJmwsp/di8COzFemY89GgOHbLNqsrBsgR/ee2eXoJp0ZkKM4EcBK3HokqBzefLfgR02PnfNOdXwqTlhkSPW0TKiKGIYu3Bw7lSNrLd+q3+wEr7ZakqOQf0BVo3FMRhMHlVYgwUJzwi3ActyH2q6fuqGG1sS0B8Oa/prUpe5fmp3VaA3WpazioeHtrKF78JwCi6/nfQsrj/8ZtXGQOxlwEgvT1CIUaF+CdHY3biezrK0tRZNpkCtHnkPtF9lq2U7+UiKXSW9yzxT8P2b0M/Qh4IVdnw4rncQK/doYriAeOdrs1wjMEJnHWq9lAaEyipoxYcVr/z5+yaC6Gwxdg45p9X1vIAaYMf6IZxyFuua43SYi0Ls+IBk4VvpR2io7T0dCxHAr3WAo3D2dm0y8OsbM59"}
        ,
        .server_response_headers = &.{
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "x-amzn-RequestId", .value = "c4025199-226f-4a16-bb1f-48618e9d2ea6" },
        },
    });
    defer test_harness.deinit();
    const lambda = (Services(.{.lambda}){}).lambda;
    const call = try test_harness.client.call(lambda.list_functions.Request{
        .max_items = 1,
    }, test_harness.call_options.*);
    defer call.deinit();
    // Request expectations
    if (test_harness.request_actuals == null) return error.NoCallMade;
    const req_actuals = test_harness.request_actuals.?;
    try std.testing.expectEqual(std.http.Method.GET, req_actuals.request.method);
    try std.testing.expectEqualStrings("https://lambda.us-west-2.amazonaws.com/2015-03-31/functions?MaxItems=1", req_actuals.request_uri);
    try std.testing.expect(req_actuals.body == null); // should be sent bodiless, so harness will not even trigger
    // Response expectations
    try std.testing.expectEqualStrings("c4025199-226f-4a16-bb1f-48618e9d2ea6", call.response_metadata.request_id);
    try std.testing.expectEqual(@as(usize, 1), call.response.functions.?.len);
    try std.testing.expectEqualStrings(
        "DevelopmentFrontendStack--amplifyassetdeploymentha-aZqB9IbZLIKU",
        call.response.functions.?[0].function_name.?,
    );
}
test "rest_json_1_query_no_input: lambda listFunctions runtime" {
    const allocator = std.testing.allocator;
    var test_harness = try TestSetup.init(.{
        .allocator = allocator,
        .server_response = @embedFile("test_rest_json_1_query_no_input.response"),
        .server_response_headers = &.{
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "x-amzn-RequestId", .value = "b2aad11f-36fc-4d0d-ae92-fe0167fb0f40" },
        },
    });
    defer test_harness.deinit();
    const lambda = (Services(.{.lambda}){}).lambda;
    const call = try test_harness.client.call(lambda.list_functions.Request{}, test_harness.call_options.*);
    defer call.deinit();
    // Request expectations
    if (test_harness.request_actuals == null) return error.NoCallMade;
    const req_actuals = test_harness.request_actuals.?;
    try std.testing.expectEqual(std.http.Method.GET, req_actuals.request.method);
    try std.testing.expectEqualStrings("https://lambda.us-west-2.amazonaws.com/2015-03-31/functions", req_actuals.request_uri);
    try std.testing.expect(req_actuals.body == null); // should be sent bodiless, so harness will not even trigger
    // Response expectations
    try std.testing.expectEqualStrings("b2aad11f-36fc-4d0d-ae92-fe0167fb0f40", call.response_metadata.request_id);
    try std.testing.expectEqual(@as(usize, 24), call.response.functions.?.len);
    try std.testing.expectEqualStrings(
        "DevelopmentFrontendStack--amplifyassetdeploymentha-aZqB9IbZLIKU",
        call.response.functions.?[0].function_name.?,
    );
    try std.testing.expectEqualStrings(
        "amplify-login-create-auth-challenge-b4883e4c",
        call.response.functions.?[12].function_name.?,
    );
}
test "rest_json_1_work_with_lambda: lambda tagResource (only), to excercise zig issue 17015" {
    const allocator = std.testing.allocator;
    var test_harness = try TestSetup.init(.{
        .allocator = allocator,
        .server_response = "",
        .server_response_status = .no_content,
        .server_response_headers = &.{
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "x-amzn-RequestId", .value = "a521e152-6e32-4e67-9fb3-abc94e34551b" },
        },
    });
    defer test_harness.deinit();
    const lambda = (Services(.{.lambda}){}).lambda;
    var tags = try std.ArrayList(@typeInfo(try typeForField(lambda.tag_resource.Request, "tags")).pointer.child).initCapacity(allocator, 1);
    defer tags.deinit(allocator);
    tags.appendAssumeCapacity(.{ .key = "Foo", .value = "Bar" });
    const req = lambda.tag_resource.Request{ .resource = "arn:aws:lambda:us-west-2:550620852718:function:awsome-lambda-LambdaStackawsomeLambda", .tags = tags.items };
    const call = try aws.Request(lambda.tag_resource).call(req, test_harness.call_options.*);
    defer call.deinit();
    // Request expectations
    if (test_harness.request_actuals == null) return error.NoCallMade;
    const req_actuals = test_harness.request_actuals.?;
    try std.testing.expectEqual(std.http.Method.POST, req_actuals.request.method);

    const parsed_body = try std.json.parseFromSlice(struct {
        Tags: struct {
            Foo: []const u8,
        },
    }, std.testing.allocator, req_actuals.body.?, .{ .ignore_unknown_fields = true });
    defer parsed_body.deinit();

    try std.testing.expectEqualStrings("Bar", parsed_body.value.Tags.Foo);

    // Due to 17015, we see %253A instead of %3A
    try std.testing.expectEqualStrings("https://lambda.us-west-2.amazonaws.com/2017-03-31/tags/arn%3Aaws%3Alambda%3Aus-west-2%3A550620852718%3Afunction%3Aawsome-lambda-LambdaStackawsomeLambda", req_actuals.request_uri);
    // Response expectations
    try std.testing.expectEqualStrings("a521e152-6e32-4e67-9fb3-abc94e34551b", call.response_metadata.request_id);
}
test "rest_json_1_url_parameters_not_in_request: lambda update_function_code" {
    const allocator = std.testing.allocator;
    var test_harness = try TestSetup.init(.{
        .allocator = allocator,
        .server_response = "{\"CodeSize\": 42}",
        .server_response_status = .ok,
        .server_response_headers = &.{
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "x-amzn-RequestId", .value = "a521e152-6e32-4e67-9fb3-abc94e34551b" },
        },
    });
    defer test_harness.deinit();
    const lambda = (Services(.{.lambda}){}).lambda;
    const architectures = [_][]const u8{"x86_64"};
    const arches: [][]const u8 = @constCast(architectures[0..]);
    const req = lambda.update_function_code.Request{
        .function_name = "functionname",
        .architectures = arches,
        .zip_file = "zipfile",
    };
    const call = try aws.Request(lambda.update_function_code).call(req, test_harness.call_options.*);
    defer call.deinit();
    // Request expectations
    if (test_harness.request_actuals == null) return error.NoCallMade;
    const req_actuals = test_harness.request_actuals.?;
    try std.testing.expectEqual(std.http.Method.PUT, req_actuals.request.method);

    const parsed_body = try std.json.parseFromSlice(struct {
        ZipFile: []const u8,
        Architectures: [][]const u8,
    }, std.testing.allocator, req_actuals.body.?, .{
        .ignore_unknown_fields = true,
    });
    defer parsed_body.deinit();

    try std.testing.expectEqualStrings("zipfile", parsed_body.value.ZipFile);
    try std.testing.expectEqual(1, parsed_body.value.Architectures.len);
    try std.testing.expectEqualStrings("x86_64", parsed_body.value.Architectures[0]);

    // Due to 17015, we see %253A instead of %3A
    try std.testing.expectEqualStrings("https://lambda.us-west-2.amazonaws.com/2015-03-31/functions/functionname/code", req_actuals.request_uri);
    // Response expectations
    try std.testing.expectEqualStrings("a521e152-6e32-4e67-9fb3-abc94e34551b", call.response_metadata.request_id);
}
test "ec2_query_no_input: EC2 describe regions" {
    const allocator = std.testing.allocator;
    var test_harness = try TestSetup.init(.{
        .allocator = allocator,
        .server_response = @embedFile("test_ec2_query_no_input.response"),
        .server_response_headers = &.{
            .{ .name = "Content-Type", .value = "text/xml;charset=UTF-8" },
            .{ .name = "x-amzn-RequestId", .value = "4cdbdd69-800c-49b5-8474-ae4c17709782" },
        },
        .server_response_transfer_encoding = .chunked,
    });
    defer test_harness.deinit();
    const ec2 = (Services(.{.ec2}){}).ec2;
    const call = try test_harness.client.call(ec2.describe_regions.Request{}, test_harness.call_options.*);
    defer call.deinit();
    // Request expectations
    if (test_harness.request_actuals == null) return error.NoCallMade;
    const req_actuals = test_harness.request_actuals.?;
    try std.testing.expectEqual(std.http.Method.POST, req_actuals.request.method);
    try std.testing.expectEqualStrings("https://ec2.us-west-2.amazonaws.com/?Action=DescribeRegions&Version=2016-11-15", req_actuals.request_uri);
    try std.testing.expectEqualStrings(
        \\Action=DescribeRegions&Version=2016-11-15
    , req_actuals.body.?);
    // Response expectations
    try std.testing.expectEqualStrings("4cdbdd69-800c-49b5-8474-ae4c17709782", call.response_metadata.request_id);
    try std.testing.expectEqual(@as(usize, 17), call.response.regions.?.len);
}
// LLVM hates this test. Depending on the platform, it will consume all memory
// on the compilation host. Windows x86_64 and Linux riscv64 seem to be a problem so far
// riscv64-linux also seems to have another problem with LLVM basically infinitely
// doing something. My guess is the @embedFile is freaking out LLVM
test "ec2_query_with_input: EC2 describe instances" {
    if (builtin.cpu.arch == .riscv64 and builtin.os.tag == .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var test_harness = try TestSetup.init(.{
        .allocator = allocator,
        .server_response = @embedFile("test_ec2_query_with_input.response"),
        .server_response_headers = &.{
            .{ .name = "Content-Type", .value = "text/xml;charset=UTF-8" },
            .{ .name = "x-amzn-RequestId", .value = "150a14cc-785d-476f-a4c9-2aa4d03b14e2" },
        },
    });
    defer test_harness.deinit();
    const ec2 = (Services(.{.ec2}){}).ec2;
    const call = try test_harness.client.call(ec2.describe_instances.Request{
        .max_results = 6,
    }, test_harness.call_options.*);
    defer call.deinit();
    // Request expectations
    if (test_harness.request_actuals == null) return error.NoCallMade;
    const req_actuals = test_harness.request_actuals.?;
    try std.testing.expectEqual(std.http.Method.POST, req_actuals.request.method);
    try std.testing.expectEqualStrings("https://ec2.us-west-2.amazonaws.com/?Action=DescribeInstances&Version=2016-11-15", req_actuals.request_uri);
    try std.testing.expectEqualStrings(
        \\Action=DescribeInstances&Version=2016-11-15&MaxResults=6
    , req_actuals.body.?);
    // Response expectations
    try std.testing.expectEqualStrings("150a14cc-785d-476f-a4c9-2aa4d03b14e2", call.response_metadata.request_id);
    try std.testing.expectEqual(@as(usize, 6), call.response.reservations.?.len);
    try std.testing.expectEqualStrings("i-0212d7d1f62b96676", call.response.reservations.?[1].instances.?[0].instance_id.?);
    try std.testing.expectEqualStrings("123456789012:found-me", call.response.reservations.?[1].instances.?[0].tags.?[0].value.?);
}
test "rest_xml_with_input_s3: S3 create bucket" {
    const allocator = std.testing.allocator;
    var test_harness = try TestSetup.init(.{
        .allocator = allocator,
        .server_response =
        \\
        ,
        .server_response_headers = &.{ // I don't see content type coming back in actual S3 requests
            .{ .name = "x-amzn-RequestId", .value = "9PEYBAZ9J7TPRX43" },
            .{ .name = "x-amz-id-2", .value = "u7lzgW0tIyRP15vSUsVOXxJ37OfVCO8lZmLIVuqeq5EE4tNp9qebb5fy+/kendlZpR4YQE+y4Xg=" },
        },
    });
    defer test_harness.deinit();
    errdefer test_harness.creds.deinit();
    const s3 = (Services(.{.s3}){}).s3;
    const call = try test_harness.client.call(s3.create_bucket.Request{
        .bucket = "",
        .create_bucket_configuration = .{
            .location_constraint = "us-west-2",
        },
    }, test_harness.call_options.*);
    defer call.deinit();
    // Request expectations
    if (test_harness.request_actuals == null) return error.NoCallMade;
    const req_actuals = test_harness.request_actuals.?;
    try std.testing.expectEqual(std.http.Method.PUT, req_actuals.request.method);
    try std.testing.expectEqualStrings("https://s3.us-west-2.amazonaws.com/", req_actuals.request_uri);
    try std.testing.expectEqualStrings(
        \\<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        \\  <LocationConstraint>us-west-2</LocationConstraint>
        \\</CreateBucketConfiguration>
    , req_actuals.body.?);
    // Response expectations
    try std.testing.expectEqualStrings(
        "9PEYBAZ9J7TPRX43, host_id: u7lzgW0tIyRP15vSUsVOXxJ37OfVCO8lZmLIVuqeq5EE4tNp9qebb5fy+/kendlZpR4YQE+y4Xg=",
        call.response_metadata.request_id,
    );
}
test "rest_xml_no_input: S3 list buckets" {
    const allocator = std.testing.allocator;
    var test_harness = try TestSetup.init(.{
        .allocator = allocator,
        .server_response =
        \\<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>3367189aa775bd98da38e55093705f2051443c1e775fc0971d6d77387a47c8d0</ID><DisplayName>emilerch+sub1</DisplayName></Owner><Buckets><Bucket><Name>550620852718-backup</Name><CreationDate>2020-06-17T16:26:51.000Z</CreationDate></Bucket><Bucket><Name>amplify-letmework-staging-185741-deployment</Name><CreationDate>2023-03-10T18:57:49.000Z</CreationDate></Bucket><Bucket><Name>aws-cloudtrail-logs-550620852718-224022a7</Name><CreationDate>2021-06-21T18:32:44.000Z</CreationDate></Bucket><Bucket><Name>aws-sam-cli-managed-default-samclisourcebucket-1gy0z00mj47xe</Name><CreationDate>2021-10-05T16:38:07.000Z</CreationDate></Bucket><Bucket><Name>awsomeprojectstack-pipelineartifactsbucketaea9a05-1uzwo6c86ecr</Name><CreationDate>2021-10-05T22:55:09.000Z</CreationDate></Bucket><Bucket><Name>cdk-hnb659fds-assets-550620852718-us-west-2</Name><CreationDate>2023-02-28T21:49:36.000Z</CreationDate></Bucket><Bucket><Name>cf-templates-12iy6putgdxtk-us-west-2</Name><CreationDate>2020-06-26T02:31:59.000Z</CreationDate></Bucket><Bucket><Name>codepipeline-us-west-2-46714083637</Name><CreationDate>2021-09-14T18:43:07.000Z</CreationDate></Bucket><Bucket><Name>elasticbeanstalk-us-west-2-550620852718</Name><CreationDate>2022-04-15T16:22:42.000Z</CreationDate></Bucket><Bucket><Name>lobo-west</Name><CreationDate>2021-06-21T17:17:22.000Z</CreationDate></Bucket><Bucket><Name>lobo-west-2</Name><CreationDate>2021-11-19T20:12:31.000Z</CreationDate></Bucket><Bucket><Name>logging-backup-550620852718-us-east-2</Name><CreationDate>2022-05-29T21:55:16.000Z</CreationDate></Bucket><Bucket><Name>mysfitszj3t6webstack-hostingbucketa91a61fe-1ep3ezkgwpxr0</Name><CreationDate>2023-03-01T04:53:55.000Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>
        ,
        .server_response_headers = &.{
            .{ .name = "Content-Type", .value = "application/xml" },
            .{ .name = "x-amzn-RequestId", .value = "9PEYBAZ9J7TPRX43" },
        },
    });
    defer test_harness.deinit();
    const s3 = (Services(.{.s3}){}).s3;
    const call = try test_harness.client.call(s3.list_buckets.Request{}, test_harness.call_options.*);
    defer call.deinit();
    // Request expectations
    if (test_harness.request_actuals == null) return error.NoCallMade;
    const req_actuals = test_harness.request_actuals.?;
    try std.testing.expectEqual(std.http.Method.GET, req_actuals.request.method);
    // This changed in rev 830202d722c904c7e3da40e8dde7b9338d08752c of the go sdk, and
    // contrary to the documentation, a query string argument was added. My guess is that
    // there is no functional reason, and that this is strictly for some AWS reporting function.
    // Alternatively, it could be to support some customization mechanism, as the commit
    // title of that commit is "Merge customizations for S3"
    try std.testing.expectEqualStrings("https://s3.us-west-2.amazonaws.com/?x-id=ListBuckets", req_actuals.request_uri);
    try std.testing.expect(req_actuals.body == null); // should be sent bodiless, so harness will not even trigger
    // Response expectations
    try std.testing.expectEqualStrings("9PEYBAZ9J7TPRX43", call.response_metadata.request_id);
    try std.testing.expectEqual(@as(usize, 13), call.response.buckets.?.len);
}
test "rest_xml_anything_but_s3: CloudFront list key groups" {
    const allocator = std.testing.allocator;
    var test_harness = try TestSetup.init(.{
        .allocator = allocator,
        .server_response =
        \\{"Items":null,"MaxItems":100,"NextMarker":null,"Quantity":0}
        ,
        .server_response_headers = &.{
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "x-amzn-RequestId", .value = "d3382082-5291-47a9-876b-8df3accbb7ea" },
        },
    });
    defer test_harness.deinit();
    const cloudfront = (Services(.{.cloudfront}){}).cloudfront;
    const call = try test_harness.client.call(cloudfront.list_key_groups.Request{}, test_harness.call_options.*);
    defer call.deinit();
    // Request expectations
    if (test_harness.request_actuals == null) return error.NoCallMade;
    const req_actuals = test_harness.request_actuals.?;
    try std.testing.expectEqual(std.http.Method.GET, req_actuals.request.method);
    try std.testing.expectEqualStrings("https://cloudfront.amazonaws.com/2020-05-31/key-group", req_actuals.request_uri);
    try std.testing.expect(req_actuals.body == null); // should be sent bodiless, so harness will not even trigger
    // Response expectations
    try std.testing.expectEqualStrings("d3382082-5291-47a9-876b-8df3accbb7ea", call.response_metadata.request_id);
    try std.testing.expectEqual(@as(i64, 100), call.response.key_group_list.?.max_items);
}
test "rest_xml_with_input: S3 put object" {
    // const old = std.testing.log_level;
    // defer std.testing.log_level = old;
    // std.testing.log_level = .debug;
    const allocator = std.testing.allocator;
    var test_harness = try TestSetup.init(.{
        .allocator = allocator,
        .server_response = "",
        .server_response_headers = &.{
            // .{ "Content-Type", "application/xml" },
            .{ .name = "x-amzn-RequestId", .value = "9PEYBAZ9J7TPRX43" },
            .{ .name = "x-amz-id-2", .value = "jdRDo30t7Ge9lf6F+4WYpg+YKui8z0mz2+rwinL38xDZzvloJqrmpCAiKG375OSvHA9OBykJS44=" },
            .{ .name = "x-amz-server-side-encryption", .value = "AES256" },
            .{ .name = "ETag", .value = "37b51d194a7513e45b56f6524f2d51f2" },
        },
    });
    defer test_harness.deinit();
    const s3opts = aws.Options{
        .region = "us-west-2",
        .client = test_harness.call_options.client,
        .mock = test_harness.call_options.mock,
    };
    const s3 = (Services(.{.s3}){}).s3;
    const result = try aws.Request(s3.put_object).call(.{
        .bucket = "mysfitszj3t6webstack-hostingbucketa91a61fe-1ep3ezkgwpxr0",
        .key = "i/am/a/teapot/foo",
        .content_type = "text/plain",
        .body = "bar",
        .storage_class = "STANDARD",
    }, s3opts);
    defer result.deinit();
    if (test_harness.request_actuals == null) return error.NoCallMade;
    const req_actuals = test_harness.request_actuals.?;
    // for (test_harness.request_options.request_headers) |header| {
    //     std.log.info("Request header: {s}: {s}", .{ header.name, header.value });
    // }
    try req_actuals.expectNoDuplicateHeaders(std.testing.allocator);
    // std.log.info("PutObject Request id: {s}", .{result.response_metadata.request_id});
    // std.log.info("PutObject etag: {s}", .{result.response.e_tag.?});
    //mysfitszj3t6webstack-hostingbucketa91a61fe-1ep3ezkgwpxr0.s3.us-west-2.amazonaws.com
    // Request expectations
    try std.testing.expectEqual(std.http.Method.PUT, req_actuals.request.method);
    // I don't think this will work since we're overriding the url
    // try req_actuals.expectHeader("Host", "mysfitszj3t6webstack-hostingbucketa91a61fe-1ep3ezkgwpxr0.s3.us-west-2.amazonaws.com");
    try req_actuals.expectHeader("x-amz-storage-class", "STANDARD");
    try std.testing.expectEqualStrings("https://mysfitszj3t6webstack-hostingbucketa91a61fe-1ep3ezkgwpxr0.s3.us-west-2.amazonaws.com/i/am/a/teapot/foo?x-id=PutObject", req_actuals.request_uri);
    try std.testing.expectEqualStrings("bar", req_actuals.body.?);
    // Response expectations
    try std.testing.expectEqualStrings("9PEYBAZ9J7TPRX43, host_id: jdRDo30t7Ge9lf6F+4WYpg+YKui8z0mz2+rwinL38xDZzvloJqrmpCAiKG375OSvHA9OBykJS44=", result.response_metadata.request_id);
    try std.testing.expectEqualStrings("AES256", result.response.server_side_encryption.?);
    try std.testing.expectEqualStrings("37b51d194a7513e45b56f6524f2d51f2", result.response.e_tag.?);
}
test "raw ECR timestamps" {
    // This is a way to test the json parsing. Ultimately the more robust tests
    // should be preferred, but in this case we were tracking down an issue
    // for which the root cause was the incorrect type being passed to the parse
    // routine
    const allocator = std.testing.allocator;
    const ecr = (Services(.{.ecr}){}).ecr;
    const options = json.ParseOptions{
        .allocator = allocator,
        .allow_camel_case_conversion = true, // new option
        .allow_snake_case_conversion = true, // new option
        .allow_unknown_fields = true, // new option. Cannot yet handle non-struct fields though
        .allow_missing_fields = false, // new option. Cannot yet handle non-struct fields though
    };
    var stream = json.TokenStream.init(
        \\{"authorizationData":[{"authorizationToken":"***","expiresAt":1.7385984915E9,"proxyEndpoint":"https://146325435496.dkr.ecr.us-west-2.amazonaws.com"}]}
    );
    const ptr = try json.parse(ecr.get_authorization_token.Response, &stream, options);
    defer json.parseFree(ecr.get_authorization_token.Response, ptr, options);
}
test "json_1_1: ECR timestamps" {
    // See: https://github.com/elerch/aws-sdk-for-zig/issues/5
    // const old = std.testing.log_level;
    // defer std.testing.log_level = old;
    // std.testing.log_level = .debug;
    const allocator = std.testing.allocator;

    var test_harness = try TestSetup.init(.{
        .allocator = allocator,
        .server_response =
        \\{"authorizationData":[{"authorizationToken":"***","expiresAt":"2022-05-17T06:56:13.652000+00:00","proxyEndpoint":"https://146325435496.dkr.ecr.us-west-2.amazonaws.com"}]}
        // \\{"authorizationData":[{"authorizationToken":"***","expiresAt":1.738598491557E9,"proxyEndpoint":"https://146325435496.dkr.ecr.us-west-2.amazonaws.com"}]}
        ,
        .server_response_headers = &.{
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "x-amzn-RequestId", .value = "QBI72OUIN8U9M9AG6PCSADJL4JVV4KQNSO5AEMVJF66Q9ASUAAJG" },
        },
    });
    defer test_harness.deinit();
    const ecr = (Services(.{.ecr}){}).ecr;
    std.log.debug("Typeof response {}", .{@TypeOf(ecr.get_authorization_token.Response{})});
    const call = try test_harness.client.call(ecr.get_authorization_token.Request{}, test_harness.call_options.*);
    defer call.deinit();
    // Request expectations
    if (test_harness.request_actuals == null) return error.NoCallMade;
    const req_actuals = test_harness.request_actuals.?;
    try std.testing.expectEqual(std.http.Method.POST, req_actuals.request.method);
    try std.testing.expectEqualStrings("https://api.ecr.us-west-2.amazonaws.com/", req_actuals.request_uri);
    try req_actuals.expectHeader("X-Amz-Target", "AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken");
    // Response expectations
    try std.testing.expectEqualStrings("QBI72OUIN8U9M9AG6PCSADJL4JVV4KQNSO5AEMVJF66Q9ASUAAJG", call.response_metadata.request_id);
    try std.testing.expectEqual(@as(usize, 1), call.response.authorization_data.?.len);
    try std.testing.expectEqualStrings("***", call.response.authorization_data.?[0].authorization_token.?);
    try std.testing.expectEqualStrings("https://146325435496.dkr.ecr.us-west-2.amazonaws.com", call.response.authorization_data.?[0].proxy_endpoint.?);
    // try std.testing.expectEqual(@as(i64, 1.73859841557E9), call.response.authorization_data.?[0].expires_at.?);

    const zeit = @import("zeit");
    const expected_ins = try zeit.instant(.{
        .source = .{ .iso8601 = "2022-05-17T06:56:13.652000+00:00" },
    });
    const expected_ts: date.Timestamp = @enumFromInt(expected_ins.timestamp);

    try std.testing.expectEqual(expected_ts, call.response.authorization_data.?[0].expires_at.?);
}

test "jsonStringify: structure + enums" {
    const media_convert = (Services(.{.media_convert}){}).media_convert;
    const request = media_convert.PutPolicyRequest{
        .policy = .{
            .http_inputs = "foo",
            .https_inputs = "bar",
            .s3_inputs = "baz",
        },
    };

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const request_json = try std.fmt.allocPrint(std.testing.allocator, "{f}", .{std.json.fmt(request, .{})});
    defer std.testing.allocator.free(request_json);

    const parsed = try std.json.parseFromSlice(struct {
        policy: struct {
            httpInputs: []const u8,
            httpsInputs: []const u8,
            s3Inputs: []const u8,
        },
    }, std.testing.allocator, request_json, .{});
    defer parsed.deinit();

    try std.testing.expectEqualStrings("foo", parsed.value.policy.httpInputs);
    try std.testing.expectEqualStrings("bar", parsed.value.policy.httpsInputs);
    try std.testing.expectEqualStrings("baz", parsed.value.policy.s3Inputs);
}

test "jsonStringify: strings" {
    const media_convert = (Services(.{.media_convert}){}).media_convert;
    const request = media_convert.AssociateCertificateRequest{
        .arn = "1234",
    };

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const request_json = try std.fmt.allocPrint(std.testing.allocator, "{f}", .{std.json.fmt(request, .{})});
    defer std.testing.allocator.free(request_json);

    try std.testing.expectEqualStrings("{\"arn\":\"1234\"}", request_json);
}

test "jsonStringify" {
    const media_convert = (Services(.{.media_convert}){}).media_convert;
    var tags = [_]media_convert.MapOfStringKeyValue{
        .{
            .key = "foo",
            .value = "bar",
        },
    };

    const request = media_convert.TagResourceRequest{
        .arn = "1234",
        .tags = &tags,
    };

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const request_json = try std.fmt.allocPrint(std.testing.allocator, "{f}", .{std.json.fmt(request, .{})});
    defer std.testing.allocator.free(request_json);

    const json_parsed = try std.json.parseFromSlice(struct {
        arn: []const u8,
        tags: struct {
            foo: []const u8,
        },
    }, std.testing.allocator, request_json, .{});
    defer json_parsed.deinit();

    try std.testing.expectEqualStrings("1234", json_parsed.value.arn);
    try std.testing.expectEqualStrings("bar", json_parsed.value.tags.foo);
}

test "jsonStringify nullable object" {
    // structure is not null
    {
        const lambda = (Services(.{.lambda}){}).lambda;
        const request = lambda.CreateAliasRequest{
            .function_name = "foo",
            .function_version = "bar",
            .name = "baz",
            .routing_config = lambda.AliasRoutingConfiguration{
                .additional_version_weights = null,
            },
        };

        const request_json = try std.fmt.allocPrint(std.testing.allocator, "{f}", .{std.json.fmt(request, .{})});
        defer std.testing.allocator.free(request_json);

        const json_parsed = try std.json.parseFromSlice(struct {
            FunctionName: []const u8,
            FunctionVersion: []const u8,
            Name: []const u8,
            RoutingConfig: struct {
                AdditionalVersionWeights: ?struct {},
            },
        }, std.testing.allocator, request_json, .{ .ignore_unknown_fields = true });
        defer json_parsed.deinit();

        try std.testing.expectEqualStrings("foo", json_parsed.value.FunctionName);
        try std.testing.expectEqualStrings("bar", json_parsed.value.FunctionVersion);
        try std.testing.expectEqualStrings("baz", json_parsed.value.Name);
        try std.testing.expectEqual(null, json_parsed.value.RoutingConfig.AdditionalVersionWeights);
    }

    // structure is null
    {
        const kms = (Services(.{.kms}){}).kms;
        const request = kms.DecryptRequest{
            .key_id = "foo",
            .ciphertext_blob = "bar",
        };

        const request_json = try std.fmt.allocPrint(std.testing.allocator, "{f}", .{std.json.fmt(request, .{})});
        defer std.testing.allocator.free(request_json);

        const json_parsed = try std.json.parseFromSlice(struct {
            KeyId: []const u8,
            CiphertextBlob: []const u8,
        }, std.testing.allocator, request_json, .{ .ignore_unknown_fields = true });
        defer json_parsed.deinit();

        try std.testing.expectEqualStrings("foo", json_parsed.value.KeyId);
        try std.testing.expectEqualStrings("bar", json_parsed.value.CiphertextBlob);
    }
}
