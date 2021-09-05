const std = @import("std");

const awshttp = @import("awshttp.zig");
const json = @import("json.zig");
const url = @import("url.zig");
const case = @import("case.zig");
const servicemodel = @import("servicemodel.zig");

const log = std.log.scoped(.aws);

pub const Options = struct {
    region: []const u8 = "aws-global",
    dualstack: bool = false,
    success_http_code: i64 = 200,
    client: Client,
};

/// Using this constant may blow up build times. Recommed using Services()
/// function directly, e.g. const services = Services(.{.sts, .ec2, .s3, .ddb}){};
pub const services = servicemodel.services;

/// Get a service model by importing specific services only. As an example:
/// const services = Services(.{.sts, .ec2, .s3, .ddb}){};
///
/// This will give you a constant with service data for sts, ec2, s3 and ddb only
pub const Services = servicemodel.Services;

pub const Client = struct {
    allocator: *std.mem.Allocator,
    aws_http: awshttp.AwsHttp,

    const Self = @This();

    pub fn init(allocator: *std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .aws_http = awshttp.AwsHttp.init(allocator),
        };
    }
    pub fn deinit(self: *Client) void {
        self.aws_http.deinit();
    }

    /// Calls AWS. Use a comptime request and options. For a runtime interface,
    /// see Request
    pub fn call(_: Self, comptime request: anytype, options: Options) !FullResponse(@TypeOf(request).metaInfo().action) {
        const action = @TypeOf(request).metaInfo().action;
        return Request(action).call(request, options);
    }
};

/// Establish an AWS request that can be later called with runtime-known
/// parameters. If all parameters are known at comptime, the call function
/// may be simpler to use. request parameter here refers to the action
/// constant from the model, e.g. Request(services.lambda.list_functions)
pub fn Request(comptime action: anytype) type {
    return struct {
        const ActionRequest = action.Request;
        const FullResponseType = FullResponse(action);
        const Self = @This();
        const action = action;
        const meta_info = ActionRequest.metaInfo();
        const service_meta = meta_info.service_metadata;

        pub fn call(request: ActionRequest, options: Options) !FullResponseType {
            // every codegenned request object includes a metaInfo function to get
            // pointers to service and action

            log.debug("call: prefix {s}, sigv4 {s}, version {s}, action {s}", .{
                Self.service_meta.endpoint_prefix,
                Self.service_meta.sigv4_name,
                Self.service_meta.version,
                action.action_name,
            });
            log.debug("proto: {s}", .{Self.service_meta.aws_protocol});

            // It seems as though there are 3 major branches of the 6 protocols.
            // 1. query/ec2_query, which are identical until you get to complex
            //    structures. EC2 query does not allow us to request json though,
            //    so we need to handle xml returns from this.
            // 2. *json*: These three appear identical for input (possible difference
            //    for empty body serialization), but differ in error handling.
            //    We're not doing a lot of error handling here, though.
            // 3. rest_xml: This is a one-off for S3, never used since
            switch (Self.service_meta.aws_protocol) {
                .query => return Self.callQuery(request, options),
                // .query, .ec2_query => return self.callQuery(request, Self.service_meta, action, options),
                .json_1_0, .json_1_1 => return Self.callJson(request, options),
                .rest_json_1 => return Self.callRestJson(request, options),
                .ec2_query, .rest_xml => @compileError("XML responses may be blocked on a zig compiler bug scheduled to be fixed in 0.9.0"),
            }
        }

        /// Rest Json is the most complex and so we handle this seperately
        fn callRestJson(request: ActionRequest, options: Options) !FullResponseType {
            const Action = @TypeOf(action);
            var aws_request: awshttp.HttpRequest = .{
                .method = Action.http_config.method,
                .content_type = "application/json",
                .path = Action.http_config.uri,
            };

            log.debug("Rest JSON v1 method: '{s}'", .{aws_request.method});
            log.debug("Rest JSON v1 success code: '{d}'", .{Action.http_config.success_code});
            log.debug("Rest JSON v1 raw uri: '{s}'", .{Action.http_config.uri});
            aws_request.path = try buildPath(options.client.allocator, Action.http_config.uri, ActionRequest, request);
            defer options.client.allocator.free(aws_request.path);
            log.debug("Rest JSON v1 processed uri: '{s}'", .{aws_request.path});
            aws_request.query = try buildQuery(options.client.allocator, request);
            log.debug("Rest JSON v1 query: '{s}'", .{aws_request.query});
            defer options.client.allocator.free(aws_request.query);
            // We don't know if we need a body...guessing here, this should cover most
            var buffer = std.ArrayList(u8).init(options.client.allocator);
            defer buffer.deinit();
            var nameAllocator = std.heap.ArenaAllocator.init(options.client.allocator);
            defer nameAllocator.deinit();
            if (std.mem.eql(u8, "PUT", aws_request.method) or std.mem.eql(u8, "POST", aws_request.method)) {
                try json.stringify(request, .{ .whitespace = .{} }, buffer.writer());
            }
            aws_request.body = buffer.items;

            return try Self.callAws(aws_request, .{
                .success_http_code = Action.http_config.success_code,
                .region = options.region,
                .dualstack = options.dualstack,
                .client = options.client,
            });
        }

        /// Calls using one of the json protocols (json_1_0, json_1_1)
        fn callJson(request: ActionRequest, options: Options) !FullResponseType {
            const target =
                try std.fmt.allocPrint(options.client.allocator, "{s}.{s}", .{
                Self.service_meta.name,
                action.action_name,
            });
            defer options.client.allocator.free(target);

            var buffer = std.ArrayList(u8).init(options.client.allocator);
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
            var nameAllocator = std.heap.ArenaAllocator.init(options.client.allocator);
            defer nameAllocator.deinit();
            try json.stringify(request, .{ .whitespace = .{} }, buffer.writer());

            var content_type: []const u8 = undefined;
            switch (Self.service_meta.aws_protocol) {
                .json_1_0 => content_type = "application/x-amz-json-1.0",
                .json_1_1 => content_type = "application/x-amz-json-1.1",
                else => unreachable,
            }
            return try Self.callAws(.{
                .query = "",
                .body = buffer.items,
                .content_type = content_type,
                .headers = &[_]awshttp.Header{.{ .name = "X-Amz-Target", .value = target }},
            }, options);
        }

        // Call using query protocol. This is documented as an XML protocol, but
        // throwing a JSON accept header seems to work. EC2Query is very simliar to
        // Query, so we'll handle both here. Realistically we probably don't effectively
        // handle lists and maps properly anyway yet, so we'll go for it and see
        // where it breaks. PRs and/or failing test cases appreciated.
        fn callQuery(request: ActionRequest, options: Options) !FullResponseType {
            var buffer = std.ArrayList(u8).init(options.client.allocator);
            defer buffer.deinit();
            const writer = buffer.writer();
            try url.encode(request, writer, .{
                .field_name_transformer = &queryFieldTransformer,
                .allocator = options.client.allocator,
            });
            const continuation = if (buffer.items.len > 0) "&" else "";

            const query = if (Self.service_meta.aws_protocol == .query)
                try std.fmt.allocPrint(options.client.allocator, "", .{})
            else // EC2
                try std.fmt.allocPrint(options.client.allocator, "?Action={s}&Version={s}", .{
                    action.action_name,
                    Self.service_meta.version,
                });
            defer options.client.allocator.free(query);

            const body = if (Self.service_meta.aws_protocol == .query)
                try std.fmt.allocPrint(options.client.allocator, "Action={s}&Version={s}{s}{s}", .{
                    action.action_name,
                    Self.service_meta.version,
                    continuation,
                    buffer.items,
                })
            else // EC2
                try std.fmt.allocPrint(options.client.allocator, "{s}", .{buffer.items});
            defer options.client.allocator.free(body);
            return try Self.callAws(.{
                .query = query,
                .body = body,
                .content_type = "application/x-www-form-urlencoded",
            }, options);
        }

        fn callAws(aws_request: awshttp.HttpRequest, options: Options) !FullResponseType {
            const response = try options.client.aws_http.callApi(
                Self.service_meta.endpoint_prefix,
                aws_request,
                .{
                    .region = options.region,
                    .dualstack = options.dualstack,
                    .sigv4_service_name = Self.service_meta.sigv4_name,
                },
            );
            defer response.deinit();
            if (response.response_code != options.success_http_code) {
                try reportTraffic(options.client.allocator, "Call Failed", aws_request, response, log.err);
                return error.HttpFailure;
            }
            // EC2 ignores our accept type, but technically query protocol only
            // returns XML as well. So, we'll ignore the protocol here and just
            // look at the return type
            var isJson: bool = undefined;
            for (response.headers) |h| {
                if (std.mem.eql(u8, "Content-Type", h.name)) {
                    if (std.mem.startsWith(u8, h.value, "application/json")) {
                        isJson = true;
                    } else if (std.mem.startsWith(u8, h.value, "application/x-amz-json-1.0")) {
                        isJson = true;
                    } else if (std.mem.startsWith(u8, h.value, "application/x-amz-json-1.1")) {
                        isJson = true;
                    } else if (std.mem.startsWith(u8, h.value, "text/xml")) {
                        isJson = false;
                    } else {
                        log.err("Unexpected content type: {s}", .{h.value});
                        return error.UnexpectedContentType;
                    }
                    break;
                }
            }

            // TODO: Handle XML
            if (!isJson) return error.XmlUnimplemented;

            const SResponse = if (Self.service_meta.aws_protocol != .query and Self.service_meta.aws_protocol != .ec2_query)
                action.Response
            else
                ServerResponse(action);

            const parser_options = json.ParseOptions{
                .allocator = options.client.allocator,
                .allow_camel_case_conversion = true, // new option
                .allow_snake_case_conversion = true, // new option
                .allow_unknown_fields = true, // new option. Cannot yet handle non-struct fields though
                .allow_missing_fields = false, // new option. Cannot yet handle non-struct fields though
            };
            if (std.meta.fields(SResponse).len == 0) // We don't care about the body if there are no fields
                // Do we care if an unexpected body comes in?
                return FullResponseType{
                    .response = .{},
                    .response_metadata = .{
                        .request_id = try requestIdFromHeaders(aws_request, response, options),
                    },
                    .parser_options = parser_options,
                    .raw_parsed = .{ .raw = .{} },
                };

            var stream = json.TokenStream.init(response.body);

            const parsed_response = json.parse(SResponse, &stream, parser_options) catch |e| {
                log.err(
                    \\Call successful, but unexpected response from service.
                    \\This could be the result of a bug or a stale set of code generated
                    \\service models.
                    \\
                    \\Model Type: {s}
                    \\
                    \\Response from server:
                    \\
                    \\{s}
                    \\
                , .{ SResponse, response.body });
                return e;
            };

            if (Self.service_meta.aws_protocol != .query and Self.service_meta.aws_protocol != .ec2_query) {
                return FullResponseType{
                    .response = parsed_response,
                    .response_metadata = .{
                        .request_id = try requestIdFromHeaders(aws_request, response, options),
                    },
                    .parser_options = parser_options,
                    .raw_parsed = .{ .raw = parsed_response },
                };
            }

            // Grab the first (and only) object from the server. Server shape expected to be:
            // { ActionResponse: {ActionResult: {...}, ResponseMetadata: {...} } }
            //                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
            //                          Next line of code pulls this portion
            //
            //
            // And the response property below will pull whatever is the ActionResult object
            // We can grab index [0] as structs are guaranteed by zig to be returned in the order
            // declared, and we're declaring in that order in ServerResponse().
            const real_response = @field(parsed_response, @typeInfo(SResponse).Struct.fields[0].name);
            return FullResponseType{
                .response = @field(real_response, @typeInfo(@TypeOf(real_response)).Struct.fields[0].name),
                .response_metadata = .{
                    .request_id = try options.client.allocator.dupe(u8, real_response.ResponseMetadata.RequestId),
                },
                .parser_options = parser_options,
                .raw_parsed = .{ .server = parsed_response },
            };
        }
    };
}

fn requestIdFromHeaders(request: awshttp.HttpRequest, response: awshttp.HttpResult, options: Options) ![]u8 {
    var request_id: []u8 = undefined;
    var found = false;
    for (response.headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "X-Amzn-RequestId")) {
            found = true;
            request_id = try std.fmt.allocPrint(options.client.allocator, "{s}", .{h.value}); // will be freed in FullR.deinit()
        }
    }
    if (!found) {
        try reportTraffic(options.client.allocator, "Request ID not found", request, response, log.err);
        return error.RequestIdNotFound;
    }
    return request_id;
}
fn ServerResponse(comptime action: anytype) type {
    const T = action.Response;
    // NOTE: The non-standard capitalization here is used as a performance
    // enhancement and to reduce allocations in json.zig. These fields are
    // not (nor are they ever intended to be) exposed outside this codebase
    const ResponseMetadata = struct {
        RequestId: []u8,
    };
    const Result = @Type(.{
        .Struct = .{
            .layout = .Auto,
            .fields = &[_]std.builtin.TypeInfo.StructField{
                .{
                    .name = action.action_name ++ "Result",
                    .field_type = T,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = 0,
                },
                .{
                    .name = "ResponseMetadata",
                    .field_type = ResponseMetadata,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = 0,
                },
            },
            .decls = &[_]std.builtin.TypeInfo.Declaration{},
            .is_tuple = false,
        },
    });
    return @Type(.{
        .Struct = .{
            .layout = .Auto,
            .fields = &[_]std.builtin.TypeInfo.StructField{
                .{
                    .name = action.action_name ++ "Response",
                    .field_type = Result,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = 0,
                },
            },
            .decls = &[_]std.builtin.TypeInfo.Declaration{},
            .is_tuple = false,
        },
    });
}
fn FullResponse(comptime action: anytype) type {
    return struct {
        response: action.Response,
        response_metadata: struct {
            request_id: []u8,
        },
        parser_options: json.ParseOptions,
        raw_parsed: union(enum) {
            server: ServerResponse(action),
            raw: action.Response,
        },
        // raw_parsed: ServerResponse(request),

        const Self = @This();
        pub fn deinit(self: Self) void {
            switch (self.raw_parsed) {
                .server => json.parseFree(ServerResponse(action), self.raw_parsed.server, self.parser_options),
                .raw => json.parseFree(action.Response, self.raw_parsed.raw, self.parser_options),
            }

            self.parser_options.allocator.?.free(self.response_metadata.request_id);
        }
    };
}
fn queryFieldTransformer(field_name: []const u8, encoding_options: url.EncodingOptions) anyerror![]const u8 {
    return try case.snakeToPascal(encoding_options.allocator.?, field_name);
}

fn buildPath(allocator: *std.mem.Allocator, raw_uri: []const u8, comptime ActionRequest: type, request: anytype) ![]const u8 {
    var buffer = try std.ArrayList(u8).initCapacity(allocator, raw_uri.len);
    // const writer = buffer.writer();
    defer buffer.deinit();
    var in_var = false;
    var start: u64 = 0;
    for (raw_uri) |c, inx| {
        switch (c) {
            '{' => {
                in_var = true;
                start = inx + 1;
            },
            '}' => {
                in_var = false;
                const replacement_var = raw_uri[start..inx];
                inline for (std.meta.fields(ActionRequest)) |field| {
                    if (std.mem.eql(u8, request.jsonFieldNameFor(field.name), replacement_var)) {
                        var replacement_buffer = try std.ArrayList(u8).initCapacity(allocator, raw_uri.len);
                        defer replacement_buffer.deinit();
                        var encoded_buffer = try std.ArrayList(u8).initCapacity(allocator, raw_uri.len);
                        defer encoded_buffer.deinit();
                        const replacement_writer = replacement_buffer.writer();
                        // std.mem.replacementSize
                        try json.stringify(
                            @field(request, field.name),
                            .{},
                            replacement_writer,
                        );
                        const trimmed_replacement_val = std.mem.trim(u8, replacement_buffer.items, "\"");
                        try uriEncode(trimmed_replacement_val, encoded_buffer.writer());
                        try buffer.appendSlice(encoded_buffer.items);
                    }
                }
            },
            else => if (!in_var) {
                try buffer.append(c);
            } else {},
        }
    }
    return buffer.toOwnedSlice();
}

fn uriEncode(input: []const u8, writer: anytype) !void {
    for (input) |c|
        try uriEncodeByte(c, writer);
}

fn uriEncodeByte(char: u8, writer: anytype) !void {
    switch (char) {
        '!' => _ = try writer.write("%21"),
        '#' => _ = try writer.write("%23"),
        '$' => _ = try writer.write("%24"),
        '&' => _ = try writer.write("%26"),
        '\'' => _ = try writer.write("%27"),
        '(' => _ = try writer.write("%28"),
        ')' => _ = try writer.write("%29"),
        '*' => _ = try writer.write("%2A"),
        '+' => _ = try writer.write("%2B"),
        ',' => _ = try writer.write("%2C"),
        '/' => _ = try writer.write("%2F"),
        ':' => _ = try writer.write("%3A"),
        ';' => _ = try writer.write("%3B"),
        '=' => _ = try writer.write("%3D"),
        '?' => _ = try writer.write("%3F"),
        '@' => _ = try writer.write("%40"),
        '[' => _ = try writer.write("%5B"),
        ']' => _ = try writer.write("%5D"),
        '%' => _ = try writer.write("%25"),
        else => {
            _ = try writer.writeByte(char);
        },
    }
}

fn buildQuery(allocator: *std.mem.Allocator, request: anytype) ![]const u8 {
    // query should look something like this:
    // pub const http_query = .{
    //     .master_region = "MasterRegion",
    //     .function_version = "FunctionVersion",
    //     .marker = "Marker",
    // };
    var buffer = std.ArrayList(u8).init(allocator);
    const writer = buffer.writer();
    defer buffer.deinit();
    var prefix = "?";
    const Req = @TypeOf(request);
    if (declaration(Req, "http_query") == null)
        return buffer.toOwnedSlice();
    const query_arguments = Req.http_query;
    inline for (@typeInfo(@TypeOf(query_arguments)).Struct.fields) |arg| {
        const val = @field(request, arg.name);
        if (try addQueryArg(arg.field_type, prefix, @field(query_arguments, arg.name), val, writer))
            prefix = "&";
    }
    return buffer.toOwnedSlice();
}

fn declaration(comptime T: type, name: []const u8) ?std.builtin.TypeInfo.Declaration {
    for (std.meta.declarations(T)) |decl| {
        if (std.mem.eql(u8, name, decl.name))
            return decl;
    }
    return null;
}

fn addQueryArg(comptime ValueType: type, prefix: []const u8, key: []const u8, value: anytype, writer: anytype) !bool {
    switch (@typeInfo(@TypeOf(value))) {
        .Optional => {
            if (value) |v|
                return try addQueryArg(ValueType, prefix, key, v, writer);
            return false;
        },
        // if this is a pointer, we want to make sure it is more than just a string
        .Pointer => |ptr| {
            if (ptr.child == u8 or ptr.size != .Slice) {
                // This is just a string
                return try addBasicQueryArg(prefix, key, value, writer);
            }
            var p = prefix;
            for (value) |li| {
                if (try addQueryArg(ValueType, p, key, li, writer))
                    p = "&";
            }
            return std.mem.eql(u8, "&", p);
        },
        .Array => |arr| {
            if (arr.child == u8)
                return try addBasicQueryArg(prefix, key, value, writer);
            var p = prefix;
            for (value) |li| {
                if (try addQueryArg(ValueType, p, key, li, writer))
                    p = "&";
            }
            return std.mem.eql(u8, "&", p);
        },
        else => {
            return try addBasicQueryArg(prefix, key, value, writer);
        },
    }
}
fn addBasicQueryArg(prefix: []const u8, key: []const u8, value: anytype, writer: anytype) !bool {
    _ = try writer.write(prefix);
    // TODO: url escaping
    try uriEncode(key, writer);
    _ = try writer.write("=");
    try json.stringify(value, .{}, ignoringWriter(uriEncodingWriter(writer).writer(), '"').writer());
    return true;
}
pub fn uriEncodingWriter(child_stream: anytype) UriEncodingWriter(@TypeOf(child_stream)) {
    return .{ .child_stream = child_stream };
}

/// A Writer that ignores a character
pub fn UriEncodingWriter(comptime WriterType: type) type {
    return struct {
        child_stream: WriterType,

        pub const Error = WriterType.Error;
        pub const Writer = std.io.Writer(*Self, Error, write);

        const Self = @This();

        pub fn write(self: *Self, bytes: []const u8) Error!usize {
            try uriEncode(bytes, self.child_stream);
            return bytes.len; // We say that all bytes are "written", even if they're not, as caller may be retrying
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }
    };
}

pub fn ignoringWriter(child_stream: anytype, ignore: u8) IgnoringWriter(@TypeOf(child_stream)) {
    return .{ .child_stream = child_stream, .ignore = ignore };
}

/// A Writer that ignores a character
pub fn IgnoringWriter(comptime WriterType: type) type {
    return struct {
        child_stream: WriterType,
        ignore: u8,

        pub const Error = WriterType.Error;
        pub const Writer = std.io.Writer(*Self, Error, write);

        const Self = @This();

        pub fn write(self: *Self, bytes: []const u8) Error!usize {
            for (bytes) |b| {
                if (b != self.ignore)
                    try self.child_stream.writeByte(b);
            }
            return bytes.len; // We say that all bytes are "written", even if they're not, as caller may be retrying
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }
    };
}

fn reportTraffic(allocator: *std.mem.Allocator, info: []const u8, request: awshttp.HttpRequest, response: awshttp.HttpResult, comptime reporter: fn (comptime []const u8, anytype) void) !void {
    var msg = std.ArrayList(u8).init(allocator);
    defer msg.deinit();
    const writer = msg.writer();
    try writer.print("{s}\n\n", .{info});
    try writer.print("Return status: {d}\n\n", .{response.response_code});
    if (request.query.len > 0) try writer.print("Request Query:\n  \t{s}\n", .{request.query});
    _ = try writer.write("Unique Request Headers:\n");
    if (request.headers.len > 0) {
        for (request.headers) |h|
            try writer.print("\t{s}: {s}\n", .{ h.name, h.value });
    }
    try writer.print("\tContent-Type: {s}\n\n", .{request.content_type});

    _ = try writer.write("Request Body:\n");
    try writer.print("-------------\n{s}\n", .{request.body});
    _ = try writer.write("-------------\n");
    _ = try writer.write("Response Headers:\n");
    for (response.headers) |h|
        try writer.print("\t{s}: {s}\n", .{ h.name, h.value });

    _ = try writer.write("Response Body:\n");
    try writer.print("--------------\n{s}\n", .{response.body});
    _ = try writer.write("--------------\n");
    reporter("{s}\n", .{msg.items});
}

// TODO: Where does this belong really?
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

test "custom serialization for map objects" {
    const allocator = std.testing.allocator;
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    var tags = try std.ArrayList(@typeInfo(try typeForField(services.lambda.tag_resource.Request, "tags")).Pointer.child).initCapacity(allocator, 2);
    defer tags.deinit();
    tags.appendAssumeCapacity(.{ .key = "Foo", .value = "Bar" });
    tags.appendAssumeCapacity(.{ .key = "Baz", .value = "Qux" });
    const req = services.lambda.tag_resource.Request{ .resource = "hello", .tags = tags.items };
    try json.stringify(req, .{ .whitespace = .{} }, buffer.writer());
    try std.testing.expectEqualStrings(
        \\{
        \\    "Resource": "hello",
        \\    "Tags": {
        \\        "Foo": "Bar",
        \\        "Baz": "Qux"
        \\    }
        \\}
    , buffer.items);
}

test "REST Json v1 builds proper queries" {
    const allocator = std.testing.allocator;
    const svs = Services(.{.lambda}){};
    const request = svs.lambda.list_functions.Request{
        .max_items = 1,
    };
    const query = try buildQuery(allocator, request);
    defer allocator.free(query);
    try std.testing.expectEqualStrings("?MaxItems=1", query);
}
test "REST Json v1 handles reserved chars in queries" {
    const allocator = std.testing.allocator;
    const svs = Services(.{.lambda}){};
    var keys = [_][]const u8{"Foo?I'm a crazy%dude"}; // Would love to have a way to express this without burning a var here
    const request = svs.lambda.untag_resource.Request{
        .tag_keys = keys[0..],
        .resource = "hello",
    };
    const query = try buildQuery(allocator, request);
    defer allocator.free(query);
    try std.testing.expectEqualStrings("?tagKeys=Foo%3FI%27m a crazy%25dude", query);
}
test "REST Json v1 serializes lists in queries" {
    const allocator = std.testing.allocator;
    const svs = Services(.{.lambda}){};
    var keys = [_][]const u8{ "Foo", "Bar" }; // Would love to have a way to express this without burning a var here
    const request = svs.lambda.untag_resource.Request{
        .tag_keys = keys[0..],
        .resource = "hello",
    };
    const query = try buildQuery(allocator, request);
    defer allocator.free(query);
    try std.testing.expectEqualStrings("?tagKeys=Foo&tagKeys=Bar", query);
}
test "REST Json v1 buildpath substitutes" {
    const allocator = std.testing.allocator;
    const svs = Services(.{.lambda}){};
    const request = svs.lambda.list_functions.Request{
        .max_items = 1,
    };
    const input_path = "https://myhost/{MaxItems}/";
    const output_path = try buildPath(allocator, input_path, @TypeOf(request), request);
    defer allocator.free(output_path);
    try std.testing.expectEqualStrings("https://myhost/1/", output_path);
}
test "REST Json v1 buildpath handles restricted characters" {
    const allocator = std.testing.allocator;
    const svs = Services(.{.lambda}){};
    const request = svs.lambda.list_functions.Request{
        .marker = ":",
    };
    const input_path = "https://myhost/{Marker}/";
    const output_path = try buildPath(allocator, input_path, @TypeOf(request), request);
    defer allocator.free(output_path);
    try std.testing.expectEqualStrings("https://myhost/%3A/", output_path);
}
test "basic json request serialization" {
    const allocator = std.testing.allocator;
    const svs = Services(.{.dynamo_db}){};
    const request = svs.dynamo_db.list_tables.Request{
        .limit = 1,
    };
    var buffer = std.ArrayList(u8).init(allocator);
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
    var nameAllocator = std.heap.ArenaAllocator.init(allocator);
    defer nameAllocator.deinit();
    try json.stringify(request, .{ .whitespace = .{} }, buffer.writer());
    try std.testing.expectEqualStrings(
        \\{
        \\    "ExclusiveStartTableName": null,
        \\    "Limit": 1
        \\}
    , buffer.items);
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
    //     \\          "Arn": "arn:aws:lambda:us-west-2:550620852718:layer:PollyNotes-lib:4"
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
// }
