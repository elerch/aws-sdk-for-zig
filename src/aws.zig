const builtin = @import("builtin");
const std = @import("std");

const case = @import("case");
const date = @import("date");
const json = @import("json");
const zeit = @import("zeit");

const awshttp = @import("aws_http.zig");
const url = @import("url.zig");
const servicemodel = @import("servicemodel.zig");
const xml_shaper = @import("xml_shaper.zig");
const xml_serializer = @import("xml_serializer.zig");

const scoped_log = std.log.scoped(.aws);

/// control all logs directly/indirectly used by aws sdk. Not recommended for
/// use under normal circumstances, but helpful for times when the zig logging
/// controls are insufficient (e.g. use in build script)
pub fn globalLogControl(aws_level: std.log.Level, http_level: std.log.Level, signing_level: std.log.Level, off: bool) void {
    const signing = @import("aws_signing.zig");
    const credentials = @import("aws_credentials.zig");
    logs_off = off;
    signing.logs_off = off;
    credentials.logs_off = off;
    awshttp.logs_off = off;
    log_level = aws_level;
    awshttp.log_level = http_level;
    signing.log_level = signing_level;
    credentials.log_level = signing_level;
}
/// Specifies logging level. This should not be touched unless the normal
/// zig logging capabilities are inaccessible (e.g. during a build)
pub var log_level: std.log.Level = .debug;

/// Turn off logging completely
pub var logs_off: bool = false;
const log = struct {
    /// Log an error message. This log level is intended to be used
    /// when something has gone wrong. This might be recoverable or might
    /// be followed by the program exiting.
    pub fn err(
        comptime format: []const u8,
        args: anytype,
    ) void {
        if (!logs_off and @intFromEnum(std.log.Level.err) <= @intFromEnum(log_level))
            scoped_log.err(format, args);
    }

    /// Log a warning message. This log level is intended to be used if
    /// it is uncertain whether something has gone wrong or not, but the
    /// circumstances would be worth investigating.
    pub fn warn(
        comptime format: []const u8,
        args: anytype,
    ) void {
        if (!logs_off and @intFromEnum(std.log.Level.warn) <= @intFromEnum(log_level))
            scoped_log.warn(format, args);
    }

    /// Log an info message. This log level is intended to be used for
    /// general messages about the state of the program.
    pub fn info(
        comptime format: []const u8,
        args: anytype,
    ) void {
        if (!logs_off and @intFromEnum(std.log.Level.info) <= @intFromEnum(log_level))
            scoped_log.info(format, args);
    }

    /// Log a debug message. This log level is intended to be used for
    /// messages which are only useful for debugging.
    pub fn debug(
        comptime format: []const u8,
        args: anytype,
    ) void {
        if (!logs_off and @intFromEnum(std.log.Level.debug) <= @intFromEnum(log_level))
            scoped_log.debug(format, args);
    }
};

pub const Options = struct {
    region: []const u8 = "aws-global",
    dualstack: bool = false,
    success_http_code: i64 = 200,
    client: Client,

    diagnostics: ?*Diagnostics = null,

    mock: ?awshttp.Mock = null,
};

pub const Diagnostics = struct {
    http_code: i64,
    response_body: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Diagnostics) void {
        self.allocator.free(self.response_body);
        self.response_body = undefined;
    }
};

/// Using this constant may blow up build times. Recommed using Services()
/// function directly, e.g. const services = Services(.{.sts, .ec2, .s3, .ddb}){};
pub const services = servicemodel.services;

/// Get a service model by importing specific services only. As an example:
/// const services = Services(.{.sts, .ec2, .s3, .ddb}){};
///
/// This will give you a constant with service data for sts, ec2, s3 and ddb only
pub const Services = servicemodel.Services;

pub const ClientOptions = struct {
    proxy: ?std.http.Client.Proxy = null,
};
pub const Client = struct {
    allocator: std.mem.Allocator,
    aws_http: awshttp.AwsHttp,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, options: ClientOptions) Self {
        return Self{
            .allocator = allocator,
            .aws_http = awshttp.AwsHttp.init(allocator, options.proxy),
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
pub fn Request(comptime request_action: anytype) type {
    return struct {
        const ActionRequest = action.Request;
        const FullResponseType = FullResponse(action);
        const Self = @This();
        const action = request_action;
        const meta_info = ActionRequest.metaInfo();
        const service_meta = meta_info.service_metadata;

        pub fn call(request: ActionRequest, options: Options) !FullResponseType {
            // every codegenned request object includes a metaInfo function to get
            // pointers to service and action

            log.debug("call: prefix {s}, sigv4 {s}, version {?s}, action {s}", .{
                Self.service_meta.endpoint_prefix,
                Self.service_meta.sigv4_name,
                Self.service_meta.version,
                action.action_name,
            });
            log.debug("proto: {}", .{Self.service_meta.aws_protocol});

            // It seems as though there are 3 major branches of the 6 protocols.
            // 1. query/ec2_query, which are identical until you get to complex
            //    structures. EC2 query does not allow us to request json though,
            //    so we need to handle xml returns from this.
            // 2. *json*: These three appear identical for input (possible difference
            //    for empty body serialization), but differ in error handling.
            //    We're not doing a lot of error handling here, though.
            // 3. rest_xml: This is a one-off for S3, never used since
            switch (Self.service_meta.aws_protocol) {
                .query, .ec2_query => return Self.callQuery(request, options),
                .json_1_0, .json_1_1 => return Self.callJson(request, options),
                .rest_json_1, .rest_xml => return Self.callRest(request, options),
            }
        }

        /// Rest Json is the most complex and so we handle this seperately
        /// Oddly, Xml is similar enough we can route rest_xml through here as well
        fn callRest(request: ActionRequest, options: Options) !FullResponseType {
            // TODO: Does it work to merge restXml into this?
            const Action = @TypeOf(action);
            var aws_request: awshttp.HttpRequest = .{
                .method = Action.http_config.method,
                .content_type = "application/json",
                .path = Action.http_config.uri,
                .headers = try headersFor(options.client.allocator, request),
            };
            defer freeHeadersFor(options.client.allocator, request, aws_request.headers);

            log.debug("Rest method: '{s}'", .{aws_request.method});
            log.debug("Rest success code: '{d}'", .{Action.http_config.success_code});
            log.debug("Rest raw uri: '{s}'", .{Action.http_config.uri});
            var al = std.ArrayList([]const u8){};
            defer al.deinit(options.client.allocator);
            aws_request.path = try buildPath(
                options.client.allocator,
                Action.http_config.uri,
                ActionRequest,
                request,
                !std.mem.eql(u8, Self.service_meta.sdk_id, "S3"),
                &al,
            );
            defer options.client.allocator.free(aws_request.path);
            log.debug("Rest processed uri: '{s}'", .{aws_request.path});
            // TODO: Make sure this doesn't get escaped here for S3
            aws_request.query = try buildQuery(options.client.allocator, request);
            if (aws_request.query.len == 0) {
                if (std.mem.indexOf(u8, aws_request.path, "?")) |inx| {
                    log.debug("Detected query in path. Adjusting", .{});
                    // Sometimes (looking at you, s3), the uri in the model
                    // has a query string shoved into it. If that's the case,
                    // we need to parse and straighten this all out
                    const orig_path = aws_request.path; // save as we'll need to dealloc
                    const orig_query = aws_request.query; // save as we'll need to dealloc
                    // We need to chop the query off because apparently the other one whacks the
                    // query string. TODO: RTFM on zig to figure out why
                    aws_request.query = try options.client.allocator.dupe(u8, aws_request.path[inx..]);
                    aws_request.path = try options.client.allocator.dupe(u8, aws_request.path[0..inx]);
                    // log.debug("inx: {d}\n\tnew path: {s}\n\tnew query: {s}", .{ inx, aws_request.path, aws_request.query });
                    options.client.allocator.free(orig_path);
                    options.client.allocator.free(orig_query);
                }
            }
            log.debug("Rest query: '{s}'", .{aws_request.query});
            defer options.client.allocator.free(aws_request.query);
            // We don't know if we need a body...guessing here, this should cover most
            var buffer = std.Io.Writer.Allocating.init(options.client.allocator);
            defer buffer.deinit();
            if (Self.service_meta.aws_protocol == .rest_json_1) {
                if (std.mem.eql(u8, "PUT", aws_request.method) or std.mem.eql(u8, "POST", aws_request.method))
                    try buffer.writer.print("{f}", .{std.json.fmt(request, .{ .whitespace = .indent_4 })});
            }
            aws_request.body = buffer.written();
            var rest_xml_body: ?[]const u8 = null;
            defer if (rest_xml_body) |b| options.client.allocator.free(b);
            if (Self.service_meta.aws_protocol == .rest_xml) {
                if (std.mem.eql(u8, "PUT", aws_request.method) or std.mem.eql(u8, "POST", aws_request.method)) {
                    if (@hasDecl(ActionRequest, "http_payload")) {
                        // We will assign the body to the value of the field denoted by
                        // the http_payload declaration on the request type.
                        // Hopefully these will always be ?[]const u8, otherwise
                        // we should see a compile error on this line
                        const payload = @field(request, ActionRequest.http_payload);
                        const T = @TypeOf(payload);
                        var body_assigned = false;
                        if (T == ?[]const u8) {
                            aws_request.body = payload.?;
                            body_assigned = true;
                        }
                        if (T == []const u8) {
                            aws_request.body = payload;
                            body_assigned = true;
                        }

                        if (!body_assigned) {
                            const sm = ActionRequest.metaInfo().service_metadata;
                            if (!std.mem.eql(u8, sm.endpoint_prefix, "s3"))
                                // Because the attributes below are most likely only
                                // applicable to s3, we are better off to fail
                                // early. This portion of the code base should
                                // only be executed for s3 as no other known
                                // service uses this protocol
                                return error.NotImplemented;

                            const attrs = try std.fmt.allocPrint(
                                options.client.allocator,
                                "xmlns=\"http://{s}.amazonaws.com/doc/{s}/\"",
                                .{ sm.endpoint_prefix, sm.version.? },
                            ); // Version required for the protocol, we should panic if it is not present
                            defer options.client.allocator.free(attrs); // once serialized, the value should be copied over

                            // Need to serialize this
                            rest_xml_body = try xml_serializer.stringifyAlloc(
                                options.client.allocator,
                                payload,
                                .{
                                    .whitespace = .indent_2,
                                    .root_name = request.fieldNameFor(ActionRequest.http_payload),
                                    .root_attributes = attrs,
                                    .emit_null_optional_fields = false,
                                    .include_declaration = false,
                                },
                            );
                            aws_request.body = rest_xml_body.?;
                        }
                    } else {
                        return error.NotImplemented;
                    }
                }
            }

            return try Self.callAws(aws_request, .{
                .success_http_code = Action.http_config.success_code,
                .region = options.region,
                .dualstack = options.dualstack,
                .client = options.client,
                .diagnostics = options.diagnostics,
                .mock = options.mock,
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

            // The transformer needs to allocate stuff out of band, but we
            // can guarantee we don't need the memory after this call completes,
            // so we'll use an arena allocator to whack everything.
            // TODO: Determine if sending in null values is ok, or if we need another
            //       tweak to the stringify function to exclude. According to the
            //       smithy spec, "A null value MAY be provided or omitted
            //       for a boxed member with no observable difference." But we're
            //       seeing a lot of differences here between spec and reality

            const body = try std.fmt.allocPrint(
                options.client.allocator,
                "{f}",
                .{std.json.fmt(request, .{ .whitespace = .indent_4 })},
            );
            defer options.client.allocator.free(body);

            var content_type: []const u8 = undefined;
            switch (Self.service_meta.aws_protocol) {
                .json_1_0 => content_type = "application/x-amz-json-1.0",
                .json_1_1 => content_type = "application/x-amz-json-1.1",
                else => unreachable,
            }
            return try Self.callAws(.{
                .query = "",
                .body = body,
                .content_type = content_type,
                .headers = @constCast(&[_]awshttp.Header{.{ .name = "X-Amz-Target", .value = target }}),
            }, options);
        }

        // Call using query protocol. This is documented as an XML protocol, but
        // throwing a JSON accept header seems to work. EC2Query is very simliar to
        // Query, so we'll handle both here. Realistically we probably don't effectively
        // handle lists and maps properly anyway yet, so we'll go for it and see
        // where it breaks. PRs and/or failing test cases appreciated.
        fn callQuery(request: ActionRequest, options: Options) !FullResponseType {
            var aw: std.Io.Writer.Allocating = .init(options.client.allocator);
            defer aw.deinit();
            const writer = &aw.writer;
            try url.encode(options.client.allocator, request, writer, .{
                .field_name_transformer = queryFieldTransformer,
            });
            const continuation = if (aw.written().len > 0) "&" else "";

            const query = if (Self.service_meta.aws_protocol == .query)
                ""
            else // EC2
                try std.fmt.allocPrint(options.client.allocator, "?Action={s}&Version={s}", .{
                    action.action_name,
                    Self.service_meta.version.?, // Version required for the protocol, we should panic if it is not present
                });

            defer if (Self.service_meta.aws_protocol != .query) {
                options.client.allocator.free(query);
            };

            // Note: EC2 avoided the Action={s}&Version={s} in the body, but it's
            // but it's required, so I'm not sure why that code was put in
            // originally?
            const body =
                try std.fmt.allocPrint(options.client.allocator, "Action={s}&Version={s}{s}{s}", .{
                    action.action_name,
                    Self.service_meta.version.?, // Version required for the protocol, we should panic if it is not present
                    continuation,
                    aw.written(),
                });
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
                    .mock = options.mock,
                },
            );
            defer response.deinit();

            if (response.response_code != options.success_http_code and response.response_code != 404) {
                try reportTraffic(options.client.allocator, "Call Failed", aws_request, response, log.err);
                if (options.diagnostics) |d| {
                    d.http_code = response.response_code;
                    d.response_body = try d.allocator.dupe(u8, response.body);
                }
                return error.HttpFailure;
            }

            var full_response = try getFullResponseFromBody(aws_request, response, options);
            errdefer full_response.deinit();

            // Fill in any fields that require a header. Note doing it post-facto
            // assumes all response header fields are optional, which may be incorrect
            if (@hasDecl(action.Response, "http_header")) {
                log.debug("Checking headers based on type: {s}", .{@typeName(action.Response)});
                const HeaderInfo = struct {
                    name: []const u8,
                    T: type,
                    header_name: []const u8,
                };
                comptime var fields = [_]?HeaderInfo{null} ** std.meta.fields(@TypeOf(action.Response.http_header)).len;
                inline for (std.meta.fields(@TypeOf(action.Response.http_header)), 0..) |f, inx| {
                    fields[inx] = HeaderInfo{
                        .name = f.name,
                        .T = @TypeOf(@field(full_response.response, f.name)),
                        .header_name = @field(action.Response.http_header, f.name),
                    };
                }

                inline for (fields) |f| {
                    for (response.headers) |header| {
                        if (std.mem.eql(u8, header.name, f.?.header_name)) {
                            log.debug("Response header {s} configured for field. Setting {s} = {s}", .{ header.name, f.?.name, header.value });
                            // TODO: Revisit return for this function. At the moment, there
                            // is something in the compiler that is causing the inline for
                            // surrounding this to start repeating elements
                            //
                            // https://github.com/ziglang/zig/issues/10507
                            //
                            // This bug is also relevant to some of the many,
                            // many different methods used to try to work around:
                            // https://github.com/ziglang/zig/issues/10029
                            //
                            // Note: issues found on zig 0.9.0
                            setHeaderValue(
                                full_response.arena.allocator(),
                                &full_response.response,
                                f.?.name,
                                f.?.T,
                                header.value,
                            ) catch |e| {
                                log.err("Could not set header value: Response header {s}. Field {s}. Value {s}", .{ header.name, f.?.name, header.value });
                                log.err("Error: {}", .{e});
                                if (@errorReturnTrace()) |trace| {
                                    std.debug.dumpStackTrace(trace.*);
                                }
                            };

                            break;
                        }
                    }
                }
            }
            return full_response;
        }

        fn setHeaderValue(
            allocator: std.mem.Allocator,
            response: anytype,
            comptime field_name: []const u8,
            comptime field_type: type,
            value: []const u8,
        ) !void {
            // TODO: Fix this. We need to make this much more robust
            // The deal is we have to do the dupe though
            // Also, this is a memory leak atm
            if (field_type == ?[]const u8) {
                @field(response, field_name) = try allocator.dupe(u8, value);
            } else {
                @field(response, field_name) = try coerceFromString(field_type, value);
            }
        }

        fn getFullResponseFromBody(aws_request: awshttp.HttpRequest, response: awshttp.HttpResult, options: Options) !FullResponseType {
            // First, we need to determine if we care about a response at all
            // If the expected result has no fields, there's no sense in
            // doing any more work. Let's bail early
            const fields = @typeInfo(action.Response).@"struct".fields;
            var expected_body_field_len = fields.len;

            if (@hasDecl(action.Response, "http_header")) {
                expected_body_field_len -= std.meta.fields(@TypeOf(action.Response.http_header)).len;
            }

            var buf_request_id: [256]u8 = undefined;
            const request_id = try requestIdFromHeaders(&buf_request_id, options.client.allocator, aws_request, response);

            const arena = std.heap.ArenaAllocator.init(options.client.allocator);

            if (@hasDecl(action.Response, "http_payload")) {
                var rc = try FullResponseType.init(.{
                    .arena = arena,
                    .response = .{},
                    .request_id = request_id,
                    .raw_parsed = .{ .raw = .{} },
                });

                const body_field = @field(rc.response, action.Response.http_payload);
                const BodyField = @TypeOf(body_field);

                if (BodyField == []const u8 or BodyField == ?[]const u8) {
                    expected_body_field_len = 0;
                    // We can't use body_field for this set - only @field will work
                    @field(rc.response, action.Response.http_payload) = try rc.arena.allocator().dupe(u8, response.body);
                    return rc;
                }
                rc.deinit();
            }

            // We don't care about the body if there are no fields we expect there...
            if (fields.len == 0 or expected_body_field_len == 0 or response.body.len == 0) {
                // Makes sure we can't get here with an `action.Response` that has required fields
                // Without this block there is a compilation error when running tests
                // Perhaps there is a better way to handle this
                {
                    comptime var required_fields = 0;

                    inline for (fields) |field| {
                        const field_type_info = @typeInfo(field.type);
                        if (field_type_info != .optional and field.defaultValue() == null) {
                            required_fields += 1;
                        }
                    }

                    if (required_fields > 0) unreachable;
                }

                // Do we care if an unexpected body comes in?
                return try FullResponseType.init(.{
                    .arena = arena,
                    .request_id = request_id,
                    .response = .{},
                });
            }

            const content_type = try getContentType(response.headers);
            return switch (content_type) {
                .json => try jsonReturn(aws_request, options, response),
                .xml => try xmlReturn(aws_request, options, response),
            };
        }

        fn jsonReturn(aws_request: awshttp.HttpRequest, options: Options, response: awshttp.HttpResult) !FullResponseType {
            var arena = std.heap.ArenaAllocator.init(options.client.allocator);

            const parser_options = json.ParseOptions{
                .allocator = arena.allocator(),
                .allow_camel_case_conversion = true, // new option
                .allow_snake_case_conversion = true, // new option
                .allow_unknown_fields = true, // new option. Cannot yet handle non-struct fields though
                .allow_missing_fields = false, // new option. Cannot yet handle non-struct fields though
            };

            // Get our possible response types. There are 3:
            //
            // 1. A result wrapped with metadata like request ID. This is ServerResponse(action)
            // 2. A "Normal" result, which starts with { "MyActionResponse": {...} }
            // 3. A "Raw" result, which is simply {...} without decoration
            const response_types = jsonResponseTypesForAction();

            // Parse the server data. Function will determine which of the three
            // responses we have, and do the right thing
            const parsed_data = try parseJsonData(response_types, response.body, options, parser_options);
            defer parsed_data.deinit();

            const parsed_response = parsed_data.parsed_response_ptr.*;

            if (response_types.NormalResponse == ServerResponse(action)) {
                // This should only apply to query results, but we're in comptime
                // type land, so the only thing that matters is whether our
                // response is a ServerResponse
                //
                // Grab the first (and only) object from the data. Server shape expected to be:
                // { ActionResponse: {ActionResult: {...}, ResponseMetadata: {...} } }
                //                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                //                          Next line of code pulls this portion
                //
                //
                // And the response property below will pull whatever is the ActionResult object
                // We can grab index [0] as structs are guaranteed by zig to be returned in the order
                // declared, and we're declaring in that order in ServerResponse().
                const real_response = @field(parsed_response, @typeInfo(response_types.NormalResponse).@"struct".fields[0].name);

                return try FullResponseType.init(.{
                    .arena = arena,
                    .response = @field(real_response, @typeInfo(@TypeOf(real_response)).@"struct".fields[0].name),
                    .request_id = real_response.ResponseMetadata.RequestId,
                    .raw_parsed = .{ .server = parsed_response },
                });
            } else {
                // Conditions 2 or 3 (no wrapping)
                var buf_request_id: [256]u8 = undefined;
                const request_id = try requestIdFromHeaders(&buf_request_id, options.client.allocator, aws_request, response);

                return try FullResponseType.init(.{
                    .arena = arena,
                    .response = parsed_response,
                    .request_id = request_id,
                    .raw_parsed = .{ .raw = parsed_response },
                });
            }
        }

        fn findResult(element: *xml_shaper.Element, options: xml_shaper.ParseOptions) *xml_shaper.Element {
            _ = options;
            // We're looking for a very specific pattern here. We want only two direct
            // children. The first one must end with "Result", and the second should
            // be our ResponseMetadata node
            var children = element.elements();
            var found_metadata = false;
            var result_child: ?*xml_shaper.Element = null;
            var inx: usize = 0;
            while (children.next()) |child| : (inx += 1) {
                if (std.mem.eql(u8, child.tag, "ResponseMetadata")) {
                    found_metadata = true;
                    continue;
                }
                if (std.mem.endsWith(u8, child.tag, "Result")) {
                    result_child = child;
                    continue;
                }
                if (inx > 1) return element;
                return element; // It should only be those two
            }
            return result_child orelse element;
        }

        fn xmlReturn(request: awshttp.HttpRequest, options: Options, result: awshttp.HttpResult) !FullResponseType {
            // Server shape be all like:
            //
            // <?xml version="1.0" encoding="UTF-8"?>
            // <DescribeRegionsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
            //     <requestId>0efe31c6-cad5-4882-b275-dfea478cf039</requestId>
            //     <regionInfo>
            //         <item>
            //             <regionName>eu-north-1</regionName>
            //             <regionEndpoint>ec2.eu-north-1.amazonaws.com</regionEndpoint>
            //             <optInStatus>opt-in-not-required</optInStatus>
            //         </item>
            //     </regionInfo>
            // </DescribeRegionsResponse>
            //
            // While our stuff be like:
            //
            // struct {
            //   regions: []struct {
            //     region_name: []const u8,
            //   }
            // }
            //
            // Big thing is that requestid, which we'll need to fetch "manually"
            var arena = std.heap.ArenaAllocator.init(options.client.allocator);

            const xml_options = xml_shaper.ParseOptions{
                .allocator = arena.allocator(),
                .elementToParse = findResult,
            };

            var body: []const u8 = result.body;
            var free_body = false;
            if (result.body.len < 20) {
                std.log.err(
                    "Unexpected response from server. Looking for XML that ends in 'Response' or 'Result'. Found:\n{s}␃\n===",
                    .{result.body},
                );
                return error.UnexpectedResponse;
            }
            if (std.mem.lastIndexOf(u8, result.body[result.body.len - 20 ..], "Response>") == null and
                std.mem.lastIndexOf(u8, result.body[result.body.len - 20 ..], "Result>") == null)
            {
                free_body = true;
                // chop the "<?xml version="1.0"?>" from the front
                const start = if (std.mem.indexOf(u8, result.body, "?>")) |i| i else 0;
                body = try std.fmt.allocPrint(options.client.allocator, "<ActionResponse>{s}</ActionResponse>", .{body[start..]});
            }
            defer if (free_body) options.client.allocator.free(body);
            const parsed = try xml_shaper.parse(action.Response, body, xml_options);
            errdefer parsed.deinit();

            var buf_request_id: [256]u8 = undefined;
            const request_id = blk: {
                if (parsed.document.root.getCharData("requestId")) |elem| {
                    break :blk elem;
                }
                break :blk try requestIdFromHeaders(&buf_request_id, options.client.allocator, request, result);
            };

            return try FullResponseType.init(.{
                .arena = arena,
                .response = parsed.parsed_value,
                .request_id = request_id,
                .raw_parsed = .{ .xml = parsed },
            });
        }

        const ServerResponseTypes = struct {
            NormalResponse: type,
            RawResponse: type,
            isRawPossible: bool,
        };

        fn jsonResponseTypesForAction() ServerResponseTypes {
            // The shape of the data coming back from the server will
            // vary quite a bit based on the exact protocol being used,
            // age of the service, etc. Before we parse the data, we need
            // to understand what we're expecting. Because types are handled
            // at comptime, we are restricted in how we handle them. They must
            // be constants, so first we'll set up an unreasonable "NullType"
            // we can use in our conditionals below
            const NullType: type = u0;

            // Next, we'll provide a "SResponse", or Server Response, for a
            // "normal" return that modern AWS services provide, that includes
            // meta information and a result inside it. This could be the
            // response as described in our models, or it could be a wrapped
            // response that's only applicable to aws_query smithy protocol
            // services
            const SResponse = if (Self.service_meta.aws_protocol != .query)
                action.Response
            else
                ServerResponse(action);

            // Now, we want to also establish a "SRawResponse", or a raw
            // response. Some older services (like CloudFront) respect
            // that we desire application/json data even though they're
            // considered "rest_xml" protocol. However, they don't wrap
            // anything, so we actually want to parse the only field in
            // the response structure. In this case we have to manually
            // create the type, parse, then set the field. For example:
            //
            // Response: type = struct {
            //     key_group_list: ?struct {...
            //
            // Normal responses would start parsing on the Response type,
            // but raw responses need to create an instance of the response
            // type, and parse "key_group_list" directly before attaching.
            //
            // Because we cannot change types at runtime, we need to create
            // both a SResponse and SRawResponse type in anticipation of either
            // scenario, then parse as appropriate later
            const SRawResponse = if (Self.service_meta.aws_protocol != .query and
                std.meta.fields(action.Response).len == 1)
                std.meta.fields(action.Response)[0].type
            else
                NullType;

            return .{
                .NormalResponse = SResponse,
                .RawResponse = SRawResponse,
                .isRawPossible = SRawResponse != NullType,
            };
        }

        fn ParsedJsonData(comptime T: type) type {
            return struct {
                parsed_response_ptr: *T,
                allocator: std.mem.Allocator,

                const MySelf = @This();

                pub fn deinit(self: MySelf) void {
                    self.allocator.destroy(self.parsed_response_ptr);
                }
            };
        }

        fn parseJsonData(comptime response_types: ServerResponseTypes, data: []const u8, options: Options, parser_options: json.ParseOptions) !ParsedJsonData(response_types.NormalResponse) {
            // Now it's time to start looking at the actual data. Job 1 will
            // be to figure out if this is a raw response or wrapped
            const allocator = options.client.allocator;

            // Extract the first json key
            const key = firstJsonKey(data);
            const found_normal_json_response =
                std.mem.eql(u8, key, action.action_name ++ "Response") or
                std.mem.eql(u8, key, action.action_name ++ "Result") or
                isOtherNormalResponse(response_types.NormalResponse, key);
            var stream = json.TokenStream.init(data);
            const parsed_response_ptr = blk: {
                const ptr = try allocator.create(response_types.NormalResponse);
                errdefer allocator.destroy(ptr);

                if (!response_types.isRawPossible or found_normal_json_response) {
                    ptr.* = (json.parse(response_types.NormalResponse, &stream, parser_options) catch |e| {
                        log.err(
                            \\Call successful, but unexpected response from service.
                            \\This could be the result of a bug or a stale set of code generated
                            \\service models.
                            \\
                            \\Model Type: {}
                            \\
                            \\Response from server:
                            \\
                            \\{s}
                            \\
                        , .{ action.Response, data });
                        return e;
                    });

                    break :blk ptr;
                }

                log.debug("Appears server has provided a raw response", .{});
                @field(ptr.*, std.meta.fields(action.Response)[0].name) =
                    json.parse(response_types.RawResponse, &stream, parser_options) catch |e| {
                        log.err(
                            \\Call successful, but unexpected response from service.
                            \\This could be the result of a bug or a stale set of code generated
                            \\service models.
                            \\
                            \\Model Type: {}
                            \\
                            \\Response from server:
                            \\
                            \\{s}
                            \\
                        , .{ action.Response, data });
                        return e;
                    };
                break :blk ptr;
            };
            return ParsedJsonData(response_types.NormalResponse){
                .parsed_response_ptr = parsed_response_ptr,
                .allocator = allocator,
            };
        }
    };
}

fn isOtherNormalResponse(comptime T: type, first_key: []const u8) bool {
    const fields = std.meta.fields(T);
    if (fields.len != 1) return false;
    const first_field = fields[0];
    if (!@hasDecl(T, "fieldNameFor")) return false;
    const expected_key = T.fieldNameFor(undefined, first_field.name);
    return std.mem.eql(u8, first_key, expected_key);
}
fn coerceFromString(comptime T: type, val: []const u8) anyerror!T {
    if (@typeInfo(T) == .optional) return try coerceFromString(@typeInfo(T).optional.child, val);
    // TODO: This is terrible...fix it
    switch (T) {
        bool => return std.ascii.eqlIgnoreCase(val, "true"),
        i64, i128 => return parseInt(T, val) catch |e| {
            log.err("Invalid string representing {s}: {s}", .{ @typeName(T), val });
            return e;
        },
        f64, f128 => return std.fmt.parseFloat(T, val) catch |e| {
            log.err("Invalid string representing {s}: {s}", .{ @typeName(T), val });
            return e;
        },
        date.Timestamp => return date.Timestamp.parse(val) catch |e| {
            log.debug("Failed to parse timestamp from string '{s}': {}", .{ val, e });
            return e;
        },
        else => return val,
    }
}
fn parseInt(comptime T: type, val: []const u8) !T {
    const rc = std.fmt.parseInt(T, val, 10);
    if (!std.meta.isError(rc)) return rc;

    if (T == i64) {
        return date.parseEnglishToTimestamp(val) catch |e| {
            log.err("Error coercing date string '{s}' to timestamp value", .{val});
            return e;
        };
    }
    if (T == f128) {
        return @as(f128, date.parseEnglishToTimestamp(val)) catch |e| {
            log.err("Error coercing date string '{s}' to timestamp value", .{val});
            return e;
        };
    }
    log.err("Error parsing string '{s}' to integer", .{val});
    return rc;
}

/// generalAllocPrint is specific to http headers, which are documented
/// at  https://smithy.io/2.0/spec/http-bindings.html#httpheader-trait
fn generalAllocPrint(allocator: std.mem.Allocator, val: anytype) !?[]const u8 {
    const T = @TypeOf(val);
    switch (@typeInfo(T)) {
        .optional => if (val) |v| return generalAllocPrint(allocator, v) else return null,
        .array, .pointer => switch (@typeInfo(T)) {
            .array => return try std.fmt.allocPrint(allocator, "{s}", .{val}),
            .pointer => |info| switch (info.size) {
                .one => return try std.fmt.allocPrint(allocator, "{s}", .{val}),
                .many => return try std.fmt.allocPrint(allocator, "{s}", .{val}),
                .slice => {
                    if (T == [][]const u8) {
                        // This would be a list type, which is the described on the first bullet
                        // of httpHeader trait serialization rules. An example can be found
                        // in S3 ListObjects API (see the OptionalObjectAttributes property)
                        // https://smithy.io/2.0/spec/http-bindings.html#serialization-rules
                        //
                        // S3 ListObjects REST API: https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjects.html
                        //
                        // This also applies to v2, but I don't have usage example here, we're just
                        // following the spec
                        //
                        // tl;dr below, we're putting commas between values
                        //
                        // TODO: we need a unit test for this
                        var vals_len: usize = 0;
                        for (val, 0..) |v, i| vals_len += v.len + if (i + 1 < v.len) @as(usize, 1) else @as(usize, 0);
                        var aw = try std.Io.Writer.Allocating.initCapacity(allocator, vals_len);
                        defer aw.deinit();
                        const writer = &aw.writer;
                        for (val, 0..) |v, i|
                            try writer.print("{s}{s}", .{ v, if (i + 1 < v.len) "," else "" }); // change v to val to trigger compile error (when unit test is written)
                        return try aw.toOwnedSlice();
                    }
                    return try std.fmt.allocPrint(allocator, "{s}", .{val});
                },
                .c => return try std.fmt.allocPrint(allocator, "{s}", .{val}),
            },
            else => {},
        },
        else => return try std.fmt.allocPrint(allocator, "{any}", .{val}),
    }
}
fn headersFor(allocator: std.mem.Allocator, request: anytype) ![]awshttp.Header {
    log.debug("Checking for headers to include for type {}", .{@TypeOf(request)});
    if (!@hasDecl(@TypeOf(request), "http_header")) return &[_]awshttp.Header{};
    const http_header = @TypeOf(request).http_header;
    const fields = std.meta.fields(@TypeOf(http_header));
    log.debug("Found {d} possible custom headers", .{fields.len});
    // It would be awesome to have a fixed array, but we can't because
    // it depends on a runtime value based on whether these variables are null
    var headers = try std.ArrayList(awshttp.Header).initCapacity(allocator, fields.len);
    defer headers.deinit(allocator);
    inline for (fields) |f| {
        // Header name = value of field
        // Header value = value of the field of the request based on field name
        const val = @field(request, f.name);
        const final_val: ?[]const u8 = try generalAllocPrint(allocator, val);
        if (final_val) |v| {
            headers.appendAssumeCapacity(.{
                .name = @field(http_header, f.name),
                .value = v,
            });
        }
    }
    return headers.toOwnedSlice(allocator);
}

fn freeHeadersFor(allocator: std.mem.Allocator, request: anytype, headers: []const awshttp.Header) void {
    if (!@hasDecl(@TypeOf(request), "http_header")) return;
    const http_header = @TypeOf(request).http_header;
    const fields = std.meta.fields(@TypeOf(http_header));
    inline for (fields) |f| {
        const header_name = @field(http_header, f.name);
        for (headers) |h| {
            if (std.mem.eql(u8, h.name, header_name)) {
                allocator.free(h.value);
                break;
            }
        }
    }
    allocator.free(headers);
}

fn firstJsonKey(data: []const u8) []const u8 {
    const start = std.mem.indexOf(u8, data, "\"") orelse 0; // Should never be 0
    if (start == 0) log.warn("Response body missing json key?!", .{});
    var end = std.mem.indexOf(u8, data[start + 1 ..], "\"") orelse 0;
    if (end == 0) log.warn("Response body only has one double quote?!", .{});
    end = end + start + 1;

    const key = data[start + 1 .. end];
    log.debug("First json key: {s}", .{key});
    return key;
}

pub const ContentType = enum {
    json,
    xml,
};

fn getContentType(headers: []const awshttp.Header) !ContentType {
    // EC2 ignores our accept type, but technically query protocol only
    // returns XML as well. So, we'll ignore the protocol here and just
    // look at the return type
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase("Content-Type", h.name)) {
            if (std.mem.startsWith(u8, h.value, "application/json")) {
                return .json;
            } else if (std.mem.startsWith(u8, h.value, "application/x-amz-json-1.0")) {
                return .json;
            } else if (std.mem.startsWith(u8, h.value, "application/x-amz-json-1.1")) {
                return .json;
            } else if (std.mem.startsWith(u8, h.value, "text/xml")) {
                return .xml;
            } else if (std.mem.startsWith(u8, h.value, "application/xml")) {
                return .xml;
            } else {
                log.err("Unexpected content type: {s}", .{h.value});
                return error.UnexpectedContentType;
            }
            break;
        }
    }

    return error.ContentTypeNotFound;
}
/// Get request ID from headers.
/// Allocation is only used in case of an error. Caller does not need to free the returned buffer.
fn requestIdFromHeaders(buf: []u8, allocator: std.mem.Allocator, request: awshttp.HttpRequest, response: awshttp.HttpResult) ![]u8 {
    var rid: ?[]const u8 = null;
    // This "thing" is called:
    // * Host ID
    // * Extended Request ID
    // * Request ID 2
    //
    // I suspect it identifies the S3 frontend server and they are
    // trying to obscure that fact. But several SDKs go with host id,
    // so we'll use that
    var host_id: ?[]const u8 = null;
    for (response.headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "x-amzn-requestid")) // CloudFront
            rid = header.value;
        if (std.ascii.eqlIgnoreCase(header.name, "x-amz-request-id")) // S3
            rid = header.value;
        if (std.ascii.eqlIgnoreCase(header.name, "x-amz-id-2")) // S3
            host_id = header.value;
    }
    if (rid) |r| {
        if (host_id) |h| {
            return try std.fmt.bufPrint(buf, "{s}, host_id: {s}", .{ r, h });
        }

        @memcpy(buf[0..r.len], r);
        return buf[0..r.len];
    }
    try reportTraffic(allocator, "Request ID not found", request, response, log.err);
    return error.RequestIdNotFound;
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
        .@"struct" = .{
            .layout = .auto,
            .fields = &[_]std.builtin.Type.StructField{
                .{
                    .name = action.action_name ++ "Result",
                    .type = T,
                    .default_value_ptr = null,
                    .is_comptime = false,
                    .alignment = std.meta.alignment(T),
                },
                .{
                    .name = "ResponseMetadata",
                    .type = ResponseMetadata,
                    .default_value_ptr = null,
                    .is_comptime = false,
                    .alignment = std.meta.alignment(ResponseMetadata),
                },
            },
            .decls = &[_]std.builtin.Type.Declaration{},
            .is_tuple = false,
        },
    });
    return @Type(.{
        .@"struct" = .{
            .layout = .auto,
            .fields = &[_]std.builtin.Type.StructField{
                .{
                    .name = action.action_name ++ "Response",
                    .type = Result,
                    .default_value_ptr = null,
                    .is_comptime = false,
                    .alignment = std.meta.alignment(Result),
                },
            },
            .decls = &[_]std.builtin.Type.Declaration{},
            .is_tuple = false,
        },
    });
}
fn FullResponse(comptime action: anytype) type {
    return struct {
        pub const ResponseMetadata = struct {
            request_id: []const u8,
        };

        pub const RawParsed = union(enum) {
            server: ServerResponse(action),
            raw: action.Response,
            xml: xml_shaper.Parsed(action.Response),
        };

        pub const FullResponseOptions = struct {
            response: action.Response = undefined,
            request_id: []const u8,
            raw_parsed: RawParsed = .{ .raw = undefined },
            arena: std.heap.ArenaAllocator,
        };

        response: action.Response = undefined,
        raw_parsed: RawParsed = .{ .raw = undefined },
        response_metadata: ResponseMetadata,
        arena: std.heap.ArenaAllocator,

        const Self = @This();

        pub fn init(options: FullResponseOptions) !Self {
            var arena = options.arena;
            const request_id = try arena.allocator().dupe(u8, options.request_id);

            return Self{
                .arena = arena,
                .response = options.response,
                .raw_parsed = options.raw_parsed,
                .response_metadata = .{
                    .request_id = request_id,
                },
            };
        }

        pub fn deinit(self: Self) void {
            self.arena.deinit();
        }
    };
}
fn safeFree(allocator: std.mem.Allocator, obj: anytype) void {
    switch (@typeInfo(@TypeOf(obj))) {
        .pointer => allocator.free(obj),
        .optional => if (obj) |o| safeFree(allocator, o),
        else => {},
    }
}
fn queryFieldTransformer(allocator: std.mem.Allocator, field_name: []const u8) anyerror![]const u8 {
    var reader = std.Io.Reader.fixed(field_name);
    var aw = try std.Io.Writer.Allocating.initCapacity(allocator, 100);
    defer aw.deinit();
    const writer = &aw.writer;
    try case.to(.pascal, &reader, writer);
    return aw.toOwnedSlice();
    // return try case.snakeToPascal(allocator, field_name);
}

fn buildPath(
    allocator: std.mem.Allocator,
    raw_uri: []const u8,
    comptime ActionRequest: type,
    request: anytype,
    encode_slash: bool,
    replaced_fields: *std.ArrayList([]const u8),
) ![]const u8 {
    var buffer = try std.ArrayList(u8).initCapacity(allocator, raw_uri.len);
    defer buffer.deinit(allocator);
    var in_label = false;
    var start: usize = 0;
    for (raw_uri, 0..) |c, inx| {
        switch (c) {
            '{' => {
                in_label = true;
                start = inx + 1;
            },
            '}' => {
                in_label = false;
                // The label may be "greedy" (uses a '+' at the end), but
                // it's not clear if that effects this processing
                var end = inx;
                if (raw_uri[inx - 1] == '+') end -= 1;
                const replacement_label = raw_uri[start..end];
                inline for (std.meta.fields(ActionRequest)) |field| {
                    if (std.mem.eql(u8, request.fieldNameFor(field.name), replacement_label)) {
                        try replaced_fields.append(allocator, replacement_label);
                        var replacement_buffer = try std.Io.Writer.Allocating.initCapacity(allocator, raw_uri.len);
                        defer replacement_buffer.deinit();

                        try (&replacement_buffer.writer).print(
                            "{f}",
                            .{std.json.fmt(
                                @field(request, field.name),
                                .{ .whitespace = .indent_4 },
                            )},
                        );
                        const trimmed_replacement_val = std.mem.trim(u8, replacement_buffer.written(), "\"");

                        // NOTE: We have to encode here as it is a portion of the rest JSON protocol.
                        // This makes the encoding in the standard library wrong
                        var encoded_buffer = try std.Io.Writer.Allocating.initCapacity(allocator, raw_uri.len);
                        defer encoded_buffer.deinit();
                        try uriEncode(trimmed_replacement_val, &encoded_buffer.writer, encode_slash);
                        try buffer.appendSlice(allocator, encoded_buffer.written());
                    }
                }
            },
            else => if (!in_label) {
                try buffer.append(allocator, c);
            } else {},
        }
    }
    return buffer.toOwnedSlice(allocator);
}

fn uriEncode(input: []const u8, writer: *std.Io.Writer, encode_slash: bool) !void {
    for (input) |c|
        try uriEncodeByte(c, writer, encode_slash);
}

fn uriEncodeByte(char: u8, writer: *std.Io.Writer, encode_slash: bool) !void {
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
        '/' => _ = if (encode_slash) try writer.write("%2F") else try writer.write("/"),
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

fn buildQuery(allocator: std.mem.Allocator, request: anytype) error{ WriteFailed, OutOfMemory }![]const u8 {
    // query should look something like this:
    // pub const http_query = .{
    //     .master_region = "MasterRegion",
    //     .function_version = "FunctionVersion",
    //     .marker = "Marker",
    // };
    var buffer = std.Io.Writer.Allocating.init(allocator);
    defer buffer.deinit();
    const writer = &buffer.writer;
    var prefix = "?";
    if (@hasDecl(@TypeOf(request), "http_query")) {
        const query_arguments = @field(@TypeOf(request), "http_query");
        inline for (@typeInfo(@TypeOf(query_arguments)).@"struct".fields) |arg| {
            const val = @field(request, arg.name);
            if (try addQueryArg(arg.type, prefix, @field(query_arguments, arg.name), val, writer))
                prefix = "&";
        }
    }
    return buffer.toOwnedSlice();
}

fn addQueryArg(comptime ValueType: type, prefix: []const u8, key: []const u8, value: anytype, writer: *std.Io.Writer) std.Io.Writer.Error!bool {
    switch (@typeInfo(@TypeOf(value))) {
        .optional => {
            if (value) |v|
                return try addQueryArg(ValueType, prefix, key, v, writer);
            return false;
        },
        // if this is a pointer, we want to make sure it is more than just a string
        .pointer => |ptr| {
            if (ptr.child == u8 or ptr.size != .slice) {
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
        .array => |arr| {
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
fn addBasicQueryArg(prefix: []const u8, key: []const u8, value: anytype, writer: *std.Io.Writer) std.Io.Writer.Error!bool {
    _ = try writer.write(prefix);
    // TODO: url escaping
    try uriEncode(key, writer, true);
    _ = try writer.write("=");
    var encoding_writer = UriEncodingWriter.init(writer);
    var ignoring_writer = IgnoringWriter.init(&encoding_writer.writer, '"');
    try ignoring_writer.writer.print("{f}", .{std.json.fmt(value, .{})});
    return true;
}

const UriEncodingWriter = struct {
    child_writer: *std.Io.Writer,
    writer: std.Io.Writer,

    pub fn init(child: *std.Io.Writer) UriEncodingWriter {
        return .{
            .child_writer = child,
            .writer = .{
                .buffer = &.{},
                .vtable = &.{
                    .drain = drain,
                },
            },
        };
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        if (splat > 1) return error.WriteFailed; // no splat support
        const self: *UriEncodingWriter = @fieldParentPtr("writer", w);
        var total: usize = 0;
        for (data) |bytes| {
            try uriEncode(bytes, self.child_writer, true);
            total += bytes.len;
        }
        return total; // We say that all bytes are "written", even if they're not, as caller may be retrying
    }
};

/// A Writer that ignores a character
const IgnoringWriter = struct {
    child_writer: *std.Io.Writer,
    ignore: u8,
    writer: std.Io.Writer,

    pub fn init(child: *std.Io.Writer, ignore: u8) IgnoringWriter {
        return .{
            .child_writer = child,
            .ignore = ignore,
            .writer = .{
                .buffer = &.{},
                .vtable = &.{
                    .drain = drain,
                },
            },
        };
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        if (splat > 1) return error.WriteFailed; // no splat support
        const self: *IgnoringWriter = @fieldParentPtr("writer", w);
        var total: usize = 0;
        for (data) |bytes| {
            for (bytes) |b|
                if (b != self.ignore)
                    try self.child_writer.writeByte(b);
            total += bytes.len;
        }
        return total; // We say that all bytes are "written", even if they're not, as caller may be retrying
    }
};

fn reportTraffic(
    allocator: std.mem.Allocator,
    info: []const u8,
    request: awshttp.HttpRequest,
    response: awshttp.HttpResult,
    comptime reporter: fn (comptime []const u8, anytype) void,
) !void {
    var msg = try std.Io.Writer.Allocating.initCapacity(allocator, 256);
    defer msg.deinit();
    const writer = &msg.writer;
    try writer.print("{s}\n\n", .{info});
    try writer.print("Return status: {d}\n\n", .{response.response_code});
    if (request.query.len > 0) try writer.print("Request Query:\n  \t{s}\n", .{request.query});
    _ = try writer.write("Unique Request Headers:\n");
    if (request.headers.len > 0) {
        for (request.headers) |h|
            try writer.print("\t{s}: {s}\n", .{ h.name, h.value });
    }
    try writer.print("\tContent-Type: {s}\n\n", .{request.content_type});

    try writer.print("Request URL: {s}\n", .{request.path});
    try writer.writeAll("Request Body:\n");
    try writer.print("-------------\n{s}\n", .{request.body});
    _ = try writer.write("-------------\n");
    _ = try writer.write("Response Headers:\n");
    for (response.headers) |h|
        try writer.print("\t{s}: {s}\n", .{ h.name, h.value });

    _ = try writer.write("Response Body:\n");
    try writer.print("--------------\n{s}\n", .{response.body});
    _ = try writer.write("--------------\n");
    reporter("{s}\n", .{msg.written()});
}

test {
    _ = @import("aws_test.zig");
}

// buildQuery/buildPath tests, which are here as they are a) generic and b) private
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
    var al = std.ArrayList([]const u8){};
    defer al.deinit(allocator);
    const svs = Services(.{.lambda}){};
    const request = svs.lambda.list_functions.Request{
        .max_items = 1,
    };
    const input_path = "https://myhost/{MaxItems}/";
    const output_path = try buildPath(allocator, input_path, @TypeOf(request), request, true, &al);
    defer allocator.free(output_path);
    try std.testing.expectEqualStrings("https://myhost/1/", output_path);
}
test "REST Json v1 buildpath handles restricted characters" {
    const allocator = std.testing.allocator;
    var al = std.ArrayList([]const u8){};
    defer al.deinit(allocator);
    const svs = Services(.{.lambda}){};
    const request = svs.lambda.list_functions.Request{
        .marker = ":",
    };
    const input_path = "https://myhost/{Marker}/";
    const output_path = try buildPath(allocator, input_path, @TypeOf(request), request, true, &al);
    defer allocator.free(output_path);
    try std.testing.expectEqualStrings("https://myhost/%3A/", output_path);
}
