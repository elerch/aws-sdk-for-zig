const std = @import("std");

const awshttp = @import("aws_http.zig");
const json = @import("json.zig");
const url = @import("url.zig");
const case = @import("case.zig");
const date = @import("date.zig");
const servicemodel = @import("servicemodel.zig");
const xml_shaper = @import("xml_shaper.zig");

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

pub const ClientOptions = struct {};
pub const Client = struct {
    allocator: std.mem.Allocator,
    aws_http: awshttp.AwsHttp,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, options: ClientOptions) !Self {
        _ = options;
        return Self{
            .allocator = allocator,
            .aws_http = try awshttp.AwsHttp.init(allocator),
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

            log.debug("call: prefix {s}, sigv4 {s}, version {s}, action {s}", .{
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
            aws_request.path = try buildPath(
                options.client.allocator,
                Action.http_config.uri,
                ActionRequest,
                request,
                !std.mem.eql(u8, Self.service_meta.sdk_id, "S3"),
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
            var buffer = std.ArrayList(u8).init(options.client.allocator);
            defer buffer.deinit();
            var nameAllocator = std.heap.ArenaAllocator.init(options.client.allocator);
            defer nameAllocator.deinit();
            if (Self.service_meta.aws_protocol == .rest_json_1) {
                if (std.mem.eql(u8, "PUT", aws_request.method) or std.mem.eql(u8, "POST", aws_request.method)) {
                    try json.stringify(request, .{ .whitespace = .{} }, buffer.writer());
                }
            }
            aws_request.body = buffer.items;
            if (Self.service_meta.aws_protocol == .rest_xml) {
                if (std.mem.eql(u8, "PUT", aws_request.method) or std.mem.eql(u8, "POST", aws_request.method)) {
                    if (@hasDecl(ActionRequest, "http_payload")) {
                        // We will assign the body to the value of the field denoted by
                        // the http_payload declaration on the request type.
                        // Hopefully these will always be ?[]const u8, otherwise
                        // we should see a compile error on this line
                        aws_request.body = @field(request, ActionRequest.http_payload).?;
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
                .headers = @constCast(&[_]awshttp.Header{.{ .name = "X-Amz-Target", .value = target }}),
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
            try url.encode(options.client.allocator, request, writer, .{
                .field_name_transformer = &queryFieldTransformer,
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

            // Note: EC2 avoided the Action={s}&Version={s} in the body, but it's
            // but it's required, so I'm not sure why that code was put in
            // originally?
            const body =
                try std.fmt.allocPrint(options.client.allocator, "Action={s}&Version={s}{s}{s}", .{
                action.action_name,
                Self.service_meta.version,
                continuation,
                buffer.items,
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
                },
            );
            defer response.deinit();
            if (response.response_code != options.success_http_code) {
                try reportTraffic(options.client.allocator, "Call Failed", aws_request, response, log.err);
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
                                options.client.allocator,
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
            var expected_body_field_len = std.meta.fields(action.Response).len;
            if (@hasDecl(action.Response, "http_header"))
                expected_body_field_len -= std.meta.fields(@TypeOf(action.Response.http_header)).len;
            if (@hasDecl(action.Response, "http_payload")) {
                var rc = FullResponseType{
                    .response = .{},
                    .response_metadata = .{
                        .request_id = try requestIdFromHeaders(aws_request, response, options),
                    },
                    .parser_options = .{ .json = .{} },
                    .raw_parsed = .{ .raw = .{} },
                    .allocator = options.client.allocator,
                };
                var body_field = @field(rc.response, action.Response.http_payload);
                const BodyField = @TypeOf(body_field);
                if (BodyField == []const u8 or BodyField == ?[]const u8) {
                    expected_body_field_len = 0;
                    // We can't use body_field for this set - only @field will work
                    @field(rc.response, action.Response.http_payload) = try options.client.allocator.dupe(u8, response.body);
                    return rc;
                }
                rc.deinit();
            }

            // We don't care about the body if there are no fields we expect there...
            if (std.meta.fields(action.Response).len == 0 or expected_body_field_len == 0) {
                // ^^ This should be redundant, but is necessary. I suspect it's a compiler quirk
                //
                // Do we care if an unexpected body comes in?
                return FullResponseType{
                    .response = .{},
                    .response_metadata = .{
                        .request_id = try requestIdFromHeaders(aws_request, response, options),
                    },
                    .parser_options = .{ .json = .{} },
                    .raw_parsed = .{ .raw = .{} },
                    .allocator = options.client.allocator,
                };
            }
            const isJson = try isJsonResponse(response.headers);
            if (!isJson) return try xmlReturn(aws_request, options, response);
            return try jsonReturn(aws_request, options, response);
        }

        fn jsonReturn(aws_request: awshttp.HttpRequest, options: Options, response: awshttp.HttpResult) !FullResponseType {
            const parser_options = json.ParseOptions{
                .allocator = options.client.allocator,
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
                const real_response = @field(parsed_response, @typeInfo(response_types.NormalResponse).Struct.fields[0].name);
                return FullResponseType{
                    .response = @field(real_response, @typeInfo(@TypeOf(real_response)).Struct.fields[0].name),
                    .response_metadata = .{
                        .request_id = try options.client.allocator.dupe(u8, real_response.ResponseMetadata.RequestId),
                    },
                    .parser_options = .{ .json = parser_options },
                    .raw_parsed = .{ .server = parsed_response },
                    .allocator = options.client.allocator,
                };
            } else {
                // Conditions 2 or 3 (no wrapping)
                return FullResponseType{
                    .response = parsed_response,
                    .response_metadata = .{
                        .request_id = try requestIdFromHeaders(aws_request, response, options),
                    },
                    .parser_options = .{ .json = parser_options },
                    .raw_parsed = .{ .raw = parsed_response },
                    .allocator = options.client.allocator,
                };
            }
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
            const xml_options = xml_shaper.ParseOptions{ .allocator = options.client.allocator };
            var body: []const u8 = result.body;
            var free_body = false;
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
            // This needs to get into FullResponseType somehow: defer parsed.deinit();
            const request_id = blk: {
                if (parsed.document.root.getCharData("requestId")) |elem|
                    break :blk try options.client.allocator.dupe(u8, elem);
                break :blk try requestIdFromHeaders(request, result, options);
            };
            defer options.client.allocator.free(request_id);

            return FullResponseType{
                .response = parsed.parsed_value,
                .response_metadata = .{
                    .request_id = try options.client.allocator.dupe(u8, request_id),
                },
                .parser_options = .{ .xml = xml_options },
                .raw_parsed = .{ .xml = parsed },
                .allocator = options.client.allocator,
            };
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
                raw_response_parsed: bool,
                parsed_response_ptr: *T,
                allocator: std.mem.Allocator,

                const MySelf = @This();

                pub fn deinit(self: MySelf) void {
                    // This feels like it should result in a use after free, but it
                    // seems to be working?
                    if (self.raw_response_parsed)
                        self.allocator.destroy(self.parsed_response_ptr);
                }
            };
        }

        fn parseJsonData(comptime response_types: ServerResponseTypes, data: []const u8, options: Options, parser_options: json.ParseOptions) !ParsedJsonData(response_types.NormalResponse) {
            // Now it's time to start looking at the actual data. Job 1 will
            // be to figure out if this is a raw response or wrapped

            // Extract the first json key
            const key = firstJsonKey(data);
            const found_normal_json_response = std.mem.eql(u8, key, action.action_name ++ "Response") or
                std.mem.eql(u8, key, action.action_name ++ "Result");
            var raw_response_parsed = false;
            var stream = json.TokenStream.init(data);
            const parsed_response_ptr = blk: {
                if (!response_types.isRawPossible or found_normal_json_response)
                    break :blk &(json.parse(response_types.NormalResponse, &stream, parser_options) catch |e| {
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

                log.debug("Appears server has provided a raw response", .{});
                raw_response_parsed = true;
                const ptr = try options.client.allocator.create(response_types.NormalResponse);
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
                .raw_response_parsed = raw_response_parsed,
                .parsed_response_ptr = @constCast(parsed_response_ptr), //TODO: why doesn't changing const->var above fix this?
                .allocator = options.client.allocator,
            };
        }
    };
}

fn coerceFromString(comptime T: type, val: []const u8) anyerror!T {
    if (@typeInfo(T) == .Optional) return try coerceFromString(@typeInfo(T).Optional.child, val);
    // TODO: This is terrible...fix it
    switch (T) {
        bool => return std.ascii.eqlIgnoreCase(val, "true"),
        i64 => return parseInt(T, val) catch |e| {
            log.err("Invalid string representing i64: {s}", .{val});
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
    log.err("Error parsing string '{s}' to integer", .{val});
    return rc;
}

fn generalAllocPrint(allocator: std.mem.Allocator, val: anytype) !?[]const u8 {
    switch (@typeInfo(@TypeOf(val))) {
        .Optional => if (val) |v| return generalAllocPrint(allocator, v) else return null,
        .Array, .Pointer => return try std.fmt.allocPrint(allocator, "{s}", .{val}),
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
    return headers.toOwnedSlice();
}

fn freeHeadersFor(allocator: std.mem.Allocator, request: anytype, headers: []awshttp.Header) void {
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
fn isJsonResponse(headers: []awshttp.Header) !bool {
    // EC2 ignores our accept type, but technically query protocol only
    // returns XML as well. So, we'll ignore the protocol here and just
    // look at the return type
    var isJson: ?bool = null;
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase("Content-Type", h.name)) {
            if (std.mem.startsWith(u8, h.value, "application/json")) {
                isJson = true;
            } else if (std.mem.startsWith(u8, h.value, "application/x-amz-json-1.0")) {
                isJson = true;
            } else if (std.mem.startsWith(u8, h.value, "application/x-amz-json-1.1")) {
                isJson = true;
            } else if (std.mem.startsWith(u8, h.value, "text/xml")) {
                isJson = false;
            } else if (std.mem.startsWith(u8, h.value, "application/xml")) {
                isJson = false;
            } else {
                log.err("Unexpected content type: {s}", .{h.value});
                return error.UnexpectedContentType;
            }
            break;
        }
    }
    if (isJson == null) return error.ContentTypeNotFound;
    return isJson.?;
}
/// Get request ID from headers. Caller responsible for freeing memory
fn requestIdFromHeaders(request: awshttp.HttpRequest, response: awshttp.HttpResult, options: Options) ![]u8 {
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
        if (host_id) |h|
            return try std.fmt.allocPrint(options.client.allocator, "{s}, host_id: {s}", .{ r, h });
        return try options.client.allocator.dupe(u8, r);
    }
    try reportTraffic(options.client.allocator, "Request ID not found", request, response, log.err);
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
        .Struct = .{
            .layout = .Auto,
            .fields = &[_]std.builtin.Type.StructField{
                .{
                    .name = action.action_name ++ "Result",
                    .type = T,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = 0,
                },
                .{
                    .name = "ResponseMetadata",
                    .type = ResponseMetadata,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = 0,
                },
            },
            .decls = &[_]std.builtin.Type.Declaration{},
            .is_tuple = false,
        },
    });
    return @Type(.{
        .Struct = .{
            .layout = .Auto,
            .fields = &[_]std.builtin.Type.StructField{
                .{
                    .name = action.action_name ++ "Response",
                    .type = Result,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = 0,
                },
            },
            .decls = &[_]std.builtin.Type.Declaration{},
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
        parser_options: union(enum) {
            json: json.ParseOptions,
            xml: xml_shaper.ParseOptions,
        },
        raw_parsed: union(enum) {
            server: ServerResponse(action),
            raw: action.Response,
            xml: xml_shaper.Parsed(action.Response),
        },
        allocator: std.mem.Allocator,

        const Self = @This();
        pub fn deinit(self: Self) void {
            switch (self.raw_parsed) {
                // Server is json only (so far)
                .server => json.parseFree(ServerResponse(action), self.raw_parsed.server, self.parser_options.json),
                // Raw is json only (so far)
                .raw => json.parseFree(action.Response, self.raw_parsed.raw, self.parser_options.json),
                .xml => |xml| xml.deinit(),
            }

            self.allocator.free(self.response_metadata.request_id);
            const Response = @TypeOf(self.response);
            if (@hasDecl(Response, "http_header")) {
                inline for (std.meta.fields(@TypeOf(Response.http_header))) |f| {
                    safeFree(self.allocator, @field(self.response, f.name));
                }
            }
            if (@hasDecl(Response, "http_payload")) {
                var body_field = @field(self.response, Response.http_payload);
                const BodyField = @TypeOf(body_field);
                if (BodyField == []const u8) {
                    self.allocator.free(body_field);
                }
                if (BodyField == ?[]const u8) {
                    if (body_field) |f|
                        self.allocator.free(f);
                }
            }
        }
    };
}
fn safeFree(allocator: std.mem.Allocator, obj: anytype) void {
    switch (@typeInfo(@TypeOf(obj))) {
        .Pointer => allocator.free(obj),
        .Optional => if (obj) |o| safeFree(allocator, o),
        else => {},
    }
}
fn queryFieldTransformer(allocator: std.mem.Allocator, field_name: []const u8, options: url.EncodingOptions) anyerror![]const u8 {
    _ = options;
    return try case.snakeToPascal(allocator, field_name);
}

fn buildPath(
    allocator: std.mem.Allocator,
    raw_uri: []const u8,
    comptime ActionRequest: type,
    request: anytype,
    encode_slash: bool,
) ![]const u8 {
    var buffer = try std.ArrayList(u8).initCapacity(allocator, raw_uri.len);
    // const writer = buffer.writer();
    defer buffer.deinit();
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
                        try uriEncode(trimmed_replacement_val, encoded_buffer.writer(), encode_slash);
                        try buffer.appendSlice(encoded_buffer.items);
                    }
                }
            },
            else => if (!in_label) {
                try buffer.append(c);
            } else {},
        }
    }
    return buffer.toOwnedSlice();
}

fn uriEncode(input: []const u8, writer: anytype, encode_slash: bool) !void {
    for (input) |c|
        try uriEncodeByte(c, writer, encode_slash);
}

fn uriEncodeByte(char: u8, writer: anytype, encode_slash: bool) !void {
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

fn buildQuery(allocator: std.mem.Allocator, request: anytype) ![]const u8 {
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
    if (@hasDecl(@TypeOf(request), "http_query")) {
        const query_arguments = @field(@TypeOf(request), "http_query");
        inline for (@typeInfo(@TypeOf(query_arguments)).Struct.fields) |arg| {
            const val = @field(request, arg.name);
            if (try addQueryArg(arg.type, prefix, @field(query_arguments, arg.name), val, writer))
                prefix = "&";
        }
    }
    return buffer.toOwnedSlice();
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
    try uriEncode(key, writer, true);
    _ = try writer.write("=");
    var encoding_writer = uriEncodingWriter(writer);
    var ignoring_writer = ignoringWriter(encoding_writer.writer(), '"');
    try json.stringify(value, .{}, ignoring_writer.writer());
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
            try uriEncode(bytes, self.child_stream, true);
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

fn reportTraffic(allocator: std.mem.Allocator, info: []const u8, request: awshttp.HttpRequest, response: awshttp.HttpResult, comptime reporter: fn (comptime []const u8, anytype) void) !void {
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

////////////////////////////////////////////////////////////////////////
// All code below this line is for testing
////////////////////////////////////////////////////////////////////////

// TODO: Where does this belong really?
fn typeForField(comptime T: type, comptime field_name: []const u8) !type {
    const ti = @typeInfo(T);
    switch (ti) {
        .Struct => {
            inline for (ti.Struct.fields) |field| {
                if (std.mem.eql(u8, field.name, field_name))
                    return field.type;
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
    const output_path = try buildPath(allocator, input_path, @TypeOf(request), request, true);
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
    const output_path = try buildPath(allocator, input_path, @TypeOf(request), request, true);
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
    std.testing.refAllDecls(url);
    std.testing.refAllDecls(case);
    std.testing.refAllDecls(date);
    std.testing.refAllDecls(servicemodel);
    std.testing.refAllDecls(xml_shaper);
}
const TestOptions = struct {
    allocator: std.mem.Allocator,
    server_port: ?u16 = null,
    server_remaining_requests: usize = 1,
    server_response: []const u8 = "unset",
    server_response_headers: [][2][]const u8 = &[_][2][]const u8{},
    request_body: []u8 = "",
    request_method: std.http.Method = undefined,
    request_target: []const u8 = undefined,
    request_headers: *std.http.Headers = undefined,
    test_server_runtime_uri: ?[]u8 = null,
    server_ready: bool = false,
    requests_processed: usize = 0,

    const Self = @This();

    fn expectHeader(self: *Self, name: []const u8, value: []const u8) !void {
        for (self.request_headers.list.items) |h|
            if (std.ascii.eqlIgnoreCase(name, h.name) and
                std.mem.eql(u8, value, h.value)) return;
        return error.HeaderOrValueNotFound;
    }
    fn waitForReady(self: *Self) !void {
        // While this doesn't return an error, we can use !void
        // to prepare for addition of timeout
        while (!self.server_ready)
            std.time.sleep(100);
    }

    fn deinit(self: Self) void {
        if (self.requests_processed > 0) {
            self.allocator.free(self.request_body);
            self.allocator.free(self.request_target);
            self.request_headers.deinit();
            self.allocator.destroy(self.request_headers);
        }
        if (self.test_server_runtime_uri) |_|
            self.allocator.free(self.test_server_runtime_uri.?);
    }
};

/// This starts a test server. We're not testing the server itself,
/// so the main tests will start this thing up and create an arena around the
/// whole thing so we can just deallocate everything at once at the end,
/// leaks be damned
fn threadMain(options: *TestOptions) !void {
    var server = std.http.Server.init(options.allocator, .{ .reuse_address = true });
    // defer server.deinit();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    try server.listen(address);
    options.server_port = server.socket.listen_address.in.getPort();

    options.test_server_runtime_uri = try std.fmt.allocPrint(options.allocator, "http://127.0.0.1:{d}", .{options.server_port.?});
    log.debug("server listening at {s}", .{options.test_server_runtime_uri.?});
    defer server.deinit();
    log.info("starting server thread, tid {d}", .{std.Thread.getCurrentId()});
    // var arena = std.heap.ArenaAllocator.init(options.allocator);
    // defer arena.deinit();
    // var aa = arena.allocator();
    // We're in control of all requests/responses, so this flag will tell us
    // when it's time to shut down
    while (options.server_remaining_requests > 0) {
        options.server_remaining_requests -= 1;
        processRequest(options, &server) catch |e| {
            log.err("Unexpected error processing request: {any}", .{e});
            if (@errorReturnTrace()) |trace| {
                std.debug.dumpStackTrace(trace.*);
            }
        };
    }
}

fn processRequest(options: *TestOptions, server: *std.http.Server) !void {
    options.server_ready = true;
    errdefer options.server_ready = false;
    log.debug(
        "tid {d} (server): server waiting to accept. requests remaining: {d}",
        .{ std.Thread.getCurrentId(), options.server_remaining_requests + 1 },
    );
    var res = try server.accept(.{ .allocator = options.allocator });
    options.server_ready = false;
    defer res.deinit();
    defer if (res.headers.owned and res.headers.list.items.len > 0) res.headers.deinit();
    defer _ = res.reset();
    try res.wait(); // wait for client to send a complete request head

    const errstr = "Internal Server Error\n";
    var errbuf: [errstr.len]u8 = undefined;
    @memcpy(&errbuf, errstr);
    var response_bytes: []const u8 = errbuf[0..];

    options.requests_processed += 1;
    if (res.request.content_length) |l|
        options.request_body = try res.reader().readAllAlloc(options.allocator, @as(usize, l))
    else
        options.request_body = try options.allocator.dupe(u8, "");
    options.request_method = res.request.method;
    options.request_target = try options.allocator.dupe(u8, res.request.target);
    options.request_headers = try options.allocator.create(std.http.Headers);
    options.request_headers.allocator = options.allocator;
    options.request_headers.list = .{};
    options.request_headers.index = .{};
    options.request_headers.owned = true;
    for (res.request.headers.list.items) |f|
        try options.request_headers.append(f.name, f.value);
    log.debug(
        "tid {d} (server): {d} bytes read from request",
        .{ std.Thread.getCurrentId(), options.request_body.len },
    );

    // try response.headers.append("content-type", "text/plain");
    response_bytes = serve(options, &res) catch |e| brk: {
        res.status = .internal_server_error;
        // TODO: more about this particular request
        log.err("Unexpected error from executor processing request: {any}", .{e});
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace.*);
        }
        break :brk "Unexpected error generating request to lambda";
    };
    res.transfer_encoding = .{ .content_length = response_bytes.len };
    try res.do();
    _ = try res.writer().writeAll(response_bytes);
    try res.finish();
    log.debug(
        "tid {d} (server): sent response",
        .{std.Thread.getCurrentId()},
    );
}

fn serve(options: *TestOptions, res: *std.http.Server.Response) ![]const u8 {
    for (options.server_response_headers) |h|
        try res.headers.append(h[0], h[1]);
    // try res.headers.append("content-length", try std.fmt.allocPrint(allocator, "{d}", .{server_response.len}));
    return options.server_response;
}

////////////////////////////////////////////////////////////////////////
// These will replicate the tests that were in src/main.zig
// The server_response and server_response_headers come from logs of
// a previous run of src/main.zig, with redactions
////////////////////////////////////////////////////////////////////////

const TestSetup = struct {
    allocator: std.mem.Allocator,
    request_options: TestOptions,
    server_thread: std.Thread = undefined,
    creds: aws_auth.Credentials = undefined,
    client: *Client = undefined,
    started: bool = false,

    const Self = @This();

    const aws_creds = @import("aws_credentials.zig");
    const aws_auth = @import("aws_authentication.zig");

    fn init(allocator: std.mem.Allocator, options: TestOptions) Self {
        return .{
            .allocator = allocator,
            .request_options = options,
        };
    }

    fn start(self: *Self) !Options {
        self.server_thread = try std.Thread.spawn(
            .{},
            threadMain,
            .{&self.request_options},
        );
        self.started = true;
        try self.request_options.waitForReady();
        awshttp.endpoint_override = self.request_options.test_server_runtime_uri;
        self.creds = aws_auth.Credentials.init(
            self.allocator,
            try self.allocator.dupe(u8, "ACCESS"),
            try self.allocator.dupe(u8, "SECRET"),
            null,
        );
        aws_creds.static_credentials = self.creds;
        var client = try Client.init(self.allocator, .{});
        self.client = &client;
        return .{
            .region = "us-west-2",
            .client = client,
        };
    }

    fn stop(self: *Self) void {
        self.server_thread.join();
    }

    fn deinit(self: Self) void {
        self.request_options.deinit();

        if (!self.started) return;
        awshttp.endpoint_override = null;
        // creds.deinit(); Creds will get deinited in the course of the call. We don't want to do it twice
        aws_creds.static_credentials = null; // we do need to reset the static creds for the next user though
        self.client.deinit();
    }
};

test "query_no_input: sts getCallerIdentity comptime" {
    const allocator = std.testing.allocator;
    var test_harness = TestSetup.init(allocator, .{
        .allocator = allocator,
        .server_response =
        \\{"GetCallerIdentityResponse":{"GetCallerIdentityResult":{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/admin","UserId":"AIDAYAM4POHXHRVANDQBQ"},"ResponseMetadata":{"RequestId":"8f0d54da-1230-40f7-b4ac-95015c4b84cd"}}}
        ,
        .server_response_headers = @constCast(&[_][2][]const u8{
            .{ "Content-Type", "application/json" },
            .{ "x-amzn-RequestId", "8f0d54da-1230-40f7-b4ac-95015c4b84cd" },
        }),
    });
    defer test_harness.deinit();
    const options = try test_harness.start();
    const sts = (Services(.{.sts}){}).sts;
    const call = try Request(sts.get_caller_identity).call(.{}, options);
    // const call = try client.call(services.sts.get_caller_identity.Request{}, options);
    defer call.deinit();
    test_harness.stop();
    // Request expectations
    try std.testing.expectEqual(std.http.Method.POST, test_harness.request_options.request_method);
    try std.testing.expectEqualStrings("/", test_harness.request_options.request_target);
    try std.testing.expectEqualStrings(
        \\Action=GetCallerIdentity&Version=2011-06-15
    , test_harness.request_options.request_body);
    // Response expectations
    try std.testing.expectEqualStrings(
        "arn:aws:iam::123456789012:user/admin",
        call.response.arn.?,
    );
    try std.testing.expectEqualStrings("AIDAYAM4POHXHRVANDQBQ", call.response.user_id.?);
    try std.testing.expectEqualStrings("123456789012", call.response.account.?);
    try std.testing.expectEqualStrings("8f0d54da-1230-40f7-b4ac-95015c4b84cd", call.response_metadata.request_id);
}
test "query_with_input: sqs listQueues runtime" {
    const allocator = std.testing.allocator;
    var test_harness = TestSetup.init(allocator, .{
        .allocator = allocator,
        .server_response =
        \\{"ListQueuesResponse":{"ListQueuesResult":{"NextExclusiveStartQueueName":null,"NextToken":null,"queueUrls":null},"ResponseMetadata":{"RequestId":"a85e390b-b866-590e-8cae-645f2bbe59c5"}}}
        ,
        .server_response_headers = @constCast(&[_][2][]const u8{
            .{ "Content-Type", "application/json" },
            .{ "x-amzn-RequestId", "a85e390b-b866-590e-8cae-645f2bbe59c5" },
        }),
    });
    defer test_harness.deinit();
    const options = try test_harness.start();
    const sqs = (Services(.{.sqs}){}).sqs;
    const call = try test_harness.client.call(sqs.list_queues.Request{
        .queue_name_prefix = "s",
    }, options);
    defer call.deinit();
    test_harness.stop();
    // Request expectations
    try std.testing.expectEqual(std.http.Method.POST, test_harness.request_options.request_method);
    try std.testing.expectEqualStrings("/", test_harness.request_options.request_target);
    try std.testing.expectEqualStrings(
        \\Action=ListQueues&Version=2012-11-05&QueueNamePrefix=s
    , test_harness.request_options.request_body);
    // Response expectations
    // TODO: We can get a lot better with this under test
    try std.testing.expect(call.response.queue_urls == null);
    try std.testing.expectEqualStrings("a85e390b-b866-590e-8cae-645f2bbe59c5", call.response_metadata.request_id);
}
test "json_1_0_query_with_input: dynamodb listTables runtime" {
    const allocator = std.testing.allocator;
    var test_harness = TestSetup.init(allocator, .{
        .allocator = allocator,
        .server_response =
        \\{"LastEvaluatedTableName":"Customer","TableNames":["Customer"]}
        ,
        .server_response_headers = @constCast(&[_][2][]const u8{
            .{ "Content-Type", "application/json" },
            .{ "x-amzn-RequestId", "QBI72OUIN8U9M9AG6PCSADJL4JVV4KQNSO5AEMVJF66Q9ASUAAJG" },
        }),
    });
    defer test_harness.deinit();
    const options = try test_harness.start();
    const dynamo_db = (Services(.{.dynamo_db}){}).dynamo_db;
    const call = try test_harness.client.call(dynamo_db.list_tables.Request{
        .limit = 1,
    }, options);
    defer call.deinit();
    test_harness.stop();
    // Request expectations
    try std.testing.expectEqual(std.http.Method.POST, test_harness.request_options.request_method);
    try std.testing.expectEqualStrings("/", test_harness.request_options.request_target);
    try test_harness.request_options.expectHeader("X-Amz-Target", "DynamoDB_20120810.ListTables");
    try std.testing.expectEqualStrings(
        \\{
        \\    "ExclusiveStartTableName": null,
        \\    "Limit": 1
        \\}
    , test_harness.request_options.request_body);
    // Response expectations
    try std.testing.expectEqualStrings("QBI72OUIN8U9M9AG6PCSADJL4JVV4KQNSO5AEMVJF66Q9ASUAAJG", call.response_metadata.request_id);
    try std.testing.expectEqual(@as(usize, 1), call.response.table_names.?.len);
    try std.testing.expectEqualStrings("Customer", call.response.table_names.?[0]);
}

test "json_1_0_query_no_input: dynamodb listTables runtime" {
    const allocator = std.testing.allocator;
    var test_harness = TestSetup.init(allocator, .{
        .allocator = allocator,
        .server_response =
        \\{"AccountMaxReadCapacityUnits":80000,"AccountMaxWriteCapacityUnits":80000,"TableMaxReadCapacityUnits":40000,"TableMaxWriteCapacityUnits":40000}
        ,
        .server_response_headers = @constCast(&[_][2][]const u8{
            .{ "Content-Type", "application/json" },
            .{ "x-amzn-RequestId", "QBI72OUIN8U9M9AG6PCSADJL4JVV4KQNSO5AEMVJF66Q9ASUAAJG" },
        }),
    });
    defer test_harness.deinit();
    const options = try test_harness.start();
    const dynamo_db = (Services(.{.dynamo_db}){}).dynamo_db;
    const call = try test_harness.client.call(dynamo_db.describe_limits.Request{}, options);
    defer call.deinit();
    test_harness.stop();
    // Request expectations
    try std.testing.expectEqual(std.http.Method.POST, test_harness.request_options.request_method);
    try std.testing.expectEqualStrings("/", test_harness.request_options.request_target);
    try test_harness.request_options.expectHeader("X-Amz-Target", "DynamoDB_20120810.DescribeLimits");
    try std.testing.expectEqualStrings(
        \\{}
    , test_harness.request_options.request_body);
    // Response expectations
    try std.testing.expectEqualStrings("QBI72OUIN8U9M9AG6PCSADJL4JVV4KQNSO5AEMVJF66Q9ASUAAJG", call.response_metadata.request_id);
    try std.testing.expectEqual(@as(i64, 80000), call.response.account_max_read_capacity_units.?);
}
test "json_1_1_query_with_input: ecs listClusters runtime" {
    const allocator = std.testing.allocator;
    var test_harness = TestSetup.init(allocator, .{
        .allocator = allocator,
        .server_response =
        \\{"clusterArns":["arn:aws:ecs:us-west-2:550620852718:cluster/web-applicationehjaf-cluster"],"nextToken":"czE0Og=="}
        ,
        .server_response_headers = @constCast(&[_][2][]const u8{
            .{ "Content-Type", "application/json" },
            .{ "x-amzn-RequestId", "b2420066-ff67-4237-b782-721c4df60744" },
        }),
    });
    defer test_harness.deinit();
    const options = try test_harness.start();
    const ecs = (Services(.{.ecs}){}).ecs;
    const call = try test_harness.client.call(ecs.list_clusters.Request{
        .max_results = 1,
    }, options);
    defer call.deinit();
    test_harness.stop();
    // Request expectations
    try std.testing.expectEqual(std.http.Method.POST, test_harness.request_options.request_method);
    try std.testing.expectEqualStrings("/", test_harness.request_options.request_target);
    try test_harness.request_options.expectHeader("X-Amz-Target", "AmazonEC2ContainerServiceV20141113.ListClusters");
    try std.testing.expectEqualStrings(
        \\{
        \\    "nextToken": null,
        \\    "maxResults": 1
        \\}
    , test_harness.request_options.request_body);
    // Response expectations
    try std.testing.expectEqualStrings("b2420066-ff67-4237-b782-721c4df60744", call.response_metadata.request_id);
    try std.testing.expectEqual(@as(usize, 1), call.response.cluster_arns.?.len);
    try std.testing.expectEqualStrings("arn:aws:ecs:us-west-2:550620852718:cluster/web-applicationehjaf-cluster", call.response.cluster_arns.?[0]);
}
test "json_1_1_query_no_input: ecs listClusters runtime" {
    const allocator = std.testing.allocator;
    var test_harness = TestSetup.init(allocator, .{
        .allocator = allocator,
        .server_response =
        \\{"clusterArns":["arn:aws:ecs:us-west-2:550620852718:cluster/web-applicationehjaf-cluster"],"nextToken":"czE0Og=="}
        ,
        .server_response_headers = @constCast(&[_][2][]const u8{
            .{ "Content-Type", "application/json" },
            .{ "x-amzn-RequestId", "e65322b2-0065-45f2-ba37-f822bb5ce395" },
        }),
    });
    defer test_harness.deinit();
    const options = try test_harness.start();
    const ecs = (Services(.{.ecs}){}).ecs;
    const call = try test_harness.client.call(ecs.list_clusters.Request{}, options);
    defer call.deinit();
    test_harness.stop();
    // Request expectations
    try std.testing.expectEqual(std.http.Method.POST, test_harness.request_options.request_method);
    try std.testing.expectEqualStrings("/", test_harness.request_options.request_target);
    try test_harness.request_options.expectHeader("X-Amz-Target", "AmazonEC2ContainerServiceV20141113.ListClusters");
    try std.testing.expectEqualStrings(
        \\{
        \\    "nextToken": null,
        \\    "maxResults": null
        \\}
    , test_harness.request_options.request_body);
    // Response expectations
    try std.testing.expectEqualStrings("e65322b2-0065-45f2-ba37-f822bb5ce395", call.response_metadata.request_id);
    try std.testing.expectEqual(@as(usize, 1), call.response.cluster_arns.?.len);
    try std.testing.expectEqualStrings("arn:aws:ecs:us-west-2:550620852718:cluster/web-applicationehjaf-cluster", call.response.cluster_arns.?[0]);
}
test "rest_json_1_query_with_input: lambda listFunctions runtime" {
    const allocator = std.testing.allocator;
    var test_harness = TestSetup.init(allocator, .{
        .allocator = allocator,
        .server_response =
        \\{"Functions":[{"Description":"AWS CDK resource provider framework - onEvent (DevelopmentFrontendStack-g650u/com.amazonaws.cdk.custom-resources.amplify-asset-deployment-provider/amplify-asset-deployment-handler-provider)","TracingConfig":{"Mode":"PassThrough"},"VpcConfig":null,"SigningJobArn":null,"SnapStart":{"OptimizationStatus":"Off","ApplyOn":"None"},"RevisionId":"0c62fc74-a692-403d-9206-5fcbad406424","LastModified":"2023-03-01T18:13:15.704+0000","FileSystemConfigs":null,"FunctionName":"DevelopmentFrontendStack--amplifyassetdeploymentha-aZqB9IbZLIKU","Runtime":"nodejs14.x","Version":"$LATEST","PackageType":"Zip","LastUpdateStatus":null,"Layers":null,"FunctionArn":"arn:aws:lambda:us-west-2:550620852718:function:DevelopmentFrontendStack--amplifyassetdeploymentha-aZqB9IbZLIKU","KMSKeyArn":null,"MemorySize":128,"ImageConfigResponse":null,"LastUpdateStatusReason":null,"DeadLetterConfig":null,"Timeout":900,"Handler":"framework.onEvent","CodeSha256":"m4tt+M0l3p8bZvxIDj83dwGrwRW6atCfS/q8AiXCD3o=","Role":"arn:aws:iam::550620852718:role/DevelopmentFrontendStack-amplifyassetdeploymentha-1782JF7WAPXZ3","SigningProfileVersionArn":null,"MasterArn":null,"RuntimeVersionConfig":null,"CodeSize":4307,"State":null,"StateReason":null,"Environment":{"Variables":{"USER_ON_EVENT_FUNCTION_ARN":"arn:aws:lambda:us-west-2:550620852718:function:DevelopmentFrontendStack--amplifyassetdeploymenton-X9iZJSCSPYDH","WAITER_STATE_MACHINE_ARN":"arn:aws:states:us-west-2:550620852718:stateMachine:amplifyassetdeploymenthandlerproviderwaiterstatemachineB3C2FCBE-Ltggp5wBcHWO","USER_IS_COMPLETE_FUNCTION_ARN":"arn:aws:lambda:us-west-2:550620852718:function:DevelopmentFrontendStack--amplifyassetdeploymentis-jaHopLrSSARV"},"Error":null},"EphemeralStorage":{"Size":512},"StateReasonCode":null,"LastUpdateStatusReasonCode":null,"Architectures":["x86_64"]}],"NextMarker":"lslTXFcbLQKkb0vP9Kgh5hUL7C3VghELNGbWgZfxrRCk3eiDRMkct7D8EmptWfHSXssPdS7Bo66iQPTMpVOHZgANewpgGgFGGr4pVjd6VgLUO6qPe2EMAuNDBjUTxm8z6N28yhlUwEmKbrAV/m0k5qVzizwoxFwvyruMbuMx9kADFACSslcabxXl3/jDI4rfFnIsUVdzTLBgPF1hzwrE1f3lcdkBvUp+QgY+Pn3w5QuJmwsp/di8COzFemY89GgOHbLNqsrBsgR/ee2eXoJp0ZkKM4EcBK3HokqBzefLfgR02PnfNOdXwqTlhkSPW0TKiKGIYu3Bw7lSNrLd+q3+wEr7ZakqOQf0BVo3FMRhMHlVYgwUJzwi3ActyH2q6fuqGG1sS0B8Oa/prUpe5fmp3VaA3WpazioeHtrKF78JwCi6/nfQsrj/8ZtXGQOxlwEgvT1CIUaF+CdHY3biezrK0tRZNpkCtHnkPtF9lq2U7+UiKXSW9yzxT8P2b0M/Qh4IVdnw4rncQK/doYriAeOdrs1wjMEJnHWq9lAaEyipoxYcVr/z5+yaC6Gwxdg45p9X1vIAaYMf6IZxyFuua43SYi0Ls+IBk4VvpR2io7T0dCxHAr3WAo3D2dm0y8OsbM59"}
        ,
        .server_response_headers = @constCast(&[_][2][]const u8{
            .{ "Content-Type", "application/json" },
            .{ "x-amzn-RequestId", "c4025199-226f-4a16-bb1f-48618e9d2ea6" },
        }),
    });
    defer test_harness.deinit();
    const options = try test_harness.start();
    const lambda = (Services(.{.lambda}){}).lambda;
    const call = try test_harness.client.call(lambda.list_functions.Request{
        .max_items = 1,
    }, options);
    defer call.deinit();
    test_harness.stop();
    // Request expectations
    try std.testing.expectEqual(std.http.Method.GET, test_harness.request_options.request_method);
    try std.testing.expectEqualStrings("/2015-03-31/functions?MaxItems=1", test_harness.request_options.request_target);
    try std.testing.expectEqualStrings(
        \\
    , test_harness.request_options.request_body);
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
    var test_harness = TestSetup.init(allocator, .{
        .allocator = allocator,
        .server_response = @embedFile("test_rest_json_1_query_no_input.response"),
        .server_response_headers = @constCast(&[_][2][]const u8{
            .{ "Content-Type", "application/json" },
            .{ "x-amzn-RequestId", "b2aad11f-36fc-4d0d-ae92-fe0167fb0f40" },
        }),
    });
    defer test_harness.deinit();
    const options = try test_harness.start();
    const lambda = (Services(.{.lambda}){}).lambda;
    const call = try test_harness.client.call(lambda.list_functions.Request{}, options);
    defer call.deinit();
    test_harness.stop();
    // Request expectations
    try std.testing.expectEqual(std.http.Method.GET, test_harness.request_options.request_method);
    try std.testing.expectEqualStrings("/2015-03-31/functions", test_harness.request_options.request_target);
    try std.testing.expectEqualStrings(
        \\
    , test_harness.request_options.request_body);
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
test "rest_json_1_work_with_lambda: lambda multiple functions (blank test)" {
    // Replicating this test would not provide additional coverage. It is
    // here for completeness only
}
test "ec2_query_no_input: EC2 describe regions" {
    const allocator = std.testing.allocator;
    var test_harness = TestSetup.init(allocator, .{
        .allocator = allocator,
        .server_response = @embedFile("test_ec2_query_no_input.response"),
        .server_response_headers = @constCast(&[_][2][]const u8{
            .{ "Content-Type", "text/xml;charset=UTF-8" },
            .{ "x-amzn-RequestId", "4cdbdd69-800c-49b5-8474-ae4c17709782" },
        }),
    });
    defer test_harness.deinit();
    const options = try test_harness.start();
    const ec2 = (Services(.{.ec2}){}).ec2;
    const call = try test_harness.client.call(ec2.describe_regions.Request{}, options);
    defer call.deinit();
    test_harness.stop();
    // Request expectations
    try std.testing.expectEqual(std.http.Method.POST, test_harness.request_options.request_method);
    try std.testing.expectEqualStrings("/?Action=DescribeRegions&Version=2016-11-15", test_harness.request_options.request_target);
    try std.testing.expectEqualStrings(
        \\Action=DescribeRegions&Version=2016-11-15
    , test_harness.request_options.request_body);
    // Response expectations
    try std.testing.expectEqualStrings("4cdbdd69-800c-49b5-8474-ae4c17709782", call.response_metadata.request_id);
    try std.testing.expectEqual(@as(usize, 17), call.response.regions.?.len);
}
test "ec2_query_with_input: EC2 describe instances" {
    const allocator = std.testing.allocator;
    var test_harness = TestSetup.init(allocator, .{
        .allocator = allocator,
        .server_response = @embedFile("test_ec2_query_with_input.response"),
        .server_response_headers = @constCast(&[_][2][]const u8{
            .{ "Content-Type", "text/xml;charset=UTF-8" },
            .{ "x-amzn-RequestId", "150a14cc-785d-476f-a4c9-2aa4d03b14e2" },
        }),
    });
    defer test_harness.deinit();
    const options = try test_harness.start();
    const ec2 = (Services(.{.ec2}){}).ec2;
    const call = try test_harness.client.call(ec2.describe_instances.Request{
        .max_results = 6,
    }, options);
    defer call.deinit();
    test_harness.stop();
    // Request expectations
    try std.testing.expectEqual(std.http.Method.POST, test_harness.request_options.request_method);
    try std.testing.expectEqualStrings("/?Action=DescribeInstances&Version=2016-11-15", test_harness.request_options.request_target);
    try std.testing.expectEqualStrings(
        \\Action=DescribeInstances&Version=2016-11-15&MaxResults=6
    , test_harness.request_options.request_body);
    // Response expectations
    try std.testing.expectEqualStrings("150a14cc-785d-476f-a4c9-2aa4d03b14e2", call.response_metadata.request_id);
    try std.testing.expectEqual(@as(usize, 6), call.response.reservations.?.len);
    try std.testing.expectEqualStrings("i-0212d7d1f62b96676", call.response.reservations.?[1].instances.?[0].instance_id.?);
    try std.testing.expectEqualStrings("123456789012:found-me", call.response.reservations.?[1].instances.?[0].tags.?[0].value.?);
}
test "rest_xml_no_input: S3 list buckets" {
    const allocator = std.testing.allocator;
    var test_harness = TestSetup.init(allocator, .{
        .allocator = allocator,
        .server_response =
        \\<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>3367189aa775bd98da38e55093705f2051443c1e775fc0971d6d77387a47c8d0</ID><DisplayName>emilerch+sub1</DisplayName></Owner><Buckets><Bucket><Name>550620852718-backup</Name><CreationDate>2020-06-17T16:26:51.000Z</CreationDate></Bucket><Bucket><Name>amplify-letmework-staging-185741-deployment</Name><CreationDate>2023-03-10T18:57:49.000Z</CreationDate></Bucket><Bucket><Name>aws-cloudtrail-logs-550620852718-224022a7</Name><CreationDate>2021-06-21T18:32:44.000Z</CreationDate></Bucket><Bucket><Name>aws-sam-cli-managed-default-samclisourcebucket-1gy0z00mj47xe</Name><CreationDate>2021-10-05T16:38:07.000Z</CreationDate></Bucket><Bucket><Name>awsomeprojectstack-pipelineartifactsbucketaea9a05-1uzwo6c86ecr</Name><CreationDate>2021-10-05T22:55:09.000Z</CreationDate></Bucket><Bucket><Name>cdk-hnb659fds-assets-550620852718-us-west-2</Name><CreationDate>2023-02-28T21:49:36.000Z</CreationDate></Bucket><Bucket><Name>cf-templates-12iy6putgdxtk-us-west-2</Name><CreationDate>2020-06-26T02:31:59.000Z</CreationDate></Bucket><Bucket><Name>codepipeline-us-west-2-46714083637</Name><CreationDate>2021-09-14T18:43:07.000Z</CreationDate></Bucket><Bucket><Name>elasticbeanstalk-us-west-2-550620852718</Name><CreationDate>2022-04-15T16:22:42.000Z</CreationDate></Bucket><Bucket><Name>lobo-west</Name><CreationDate>2021-06-21T17:17:22.000Z</CreationDate></Bucket><Bucket><Name>lobo-west-2</Name><CreationDate>2021-11-19T20:12:31.000Z</CreationDate></Bucket><Bucket><Name>logging-backup-550620852718-us-east-2</Name><CreationDate>2022-05-29T21:55:16.000Z</CreationDate></Bucket><Bucket><Name>mysfitszj3t6webstack-hostingbucketa91a61fe-1ep3ezkgwpxr0</Name><CreationDate>2023-03-01T04:53:55.000Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>
        ,
        .server_response_headers = @constCast(&[_][2][]const u8{
            .{ "Content-Type", "application/xml" },
            .{ "x-amzn-RequestId", "9PEYBAZ9J7TPRX43" },
        }),
    });
    defer test_harness.deinit();
    const options = try test_harness.start();
    const s3 = (Services(.{.s3}){}).s3;
    const call = try test_harness.client.call(s3.list_buckets.Request{}, options);
    defer call.deinit();
    test_harness.stop();
    // Request expectations
    try std.testing.expectEqual(std.http.Method.GET, test_harness.request_options.request_method);
    try std.testing.expectEqualStrings("/", test_harness.request_options.request_target);
    try std.testing.expectEqualStrings("", test_harness.request_options.request_body);
    // Response expectations
    try std.testing.expectEqualStrings("9PEYBAZ9J7TPRX43", call.response_metadata.request_id);
    try std.testing.expectEqual(@as(usize, 13), call.response.buckets.?.len);
}
test "rest_xml_anything_but_s3: CloudFront list key groups" {
    const allocator = std.testing.allocator;
    var test_harness = TestSetup.init(allocator, .{
        .allocator = allocator,
        .server_response =
        \\{"Items":null,"MaxItems":100,"NextMarker":null,"Quantity":0}
        ,
        .server_response_headers = @constCast(&[_][2][]const u8{
            .{ "Content-Type", "application/json" },
            .{ "x-amzn-RequestId", "d3382082-5291-47a9-876b-8df3accbb7ea" },
        }),
    });
    defer test_harness.deinit();
    const options = try test_harness.start();
    const cloudfront = (Services(.{.cloudfront}){}).cloudfront;
    const call = try test_harness.client.call(cloudfront.list_key_groups.Request{}, options);
    defer call.deinit();
    test_harness.stop();
    // Request expectations
    try std.testing.expectEqual(std.http.Method.GET, test_harness.request_options.request_method);
    try std.testing.expectEqualStrings("/2020-05-31/key-group", test_harness.request_options.request_target);
    try std.testing.expectEqualStrings("", test_harness.request_options.request_body);
    // Response expectations
    try std.testing.expectEqualStrings("d3382082-5291-47a9-876b-8df3accbb7ea", call.response_metadata.request_id);
    try std.testing.expectEqual(@as(i64, 100), call.response.key_group_list.?.max_items);
}
test "rest_xml_with_input: S3 put object" {
    const allocator = std.testing.allocator;
    var test_harness = TestSetup.init(allocator, .{
        .allocator = allocator,
        .server_response = "",
        .server_response_headers = @constCast(&[_][2][]const u8{
            // .{ "Content-Type", "application/xml" },
            .{ "x-amzn-RequestId", "9PEYBAZ9J7TPRX43" },
            .{ "x-amz-id-2", "jdRDo30t7Ge9lf6F+4WYpg+YKui8z0mz2+rwinL38xDZzvloJqrmpCAiKG375OSvHA9OBykJS44=" },
            .{ "x-amz-server-side-encryption", "AES256" },
            .{ "ETag", "37b51d194a7513e45b56f6524f2d51f2" },
        }),
    });
    defer test_harness.deinit();
    const options = try test_harness.start();
    const s3opts = Options{
        .region = "us-west-2",
        .client = options.client,
    };
    const result = try Request(services.s3.put_object).call(.{
        .bucket = "mysfitszj3t6webstack-hostingbucketa91a61fe-1ep3ezkgwpxr0",
        .key = "i/am/a/teapot/foo",
        .content_type = "text/plain",
        .body = "bar",
        .storage_class = "STANDARD",
    }, s3opts);
    std.log.info("PutObject Request id: {any}", .{result.response_metadata.request_id});
    std.log.info("PutObject etag: {any}", .{result.response.e_tag.?});
    //mysfitszj3t6webstack-hostingbucketa91a61fe-1ep3ezkgwpxr0.s3.us-west-2.amazonaws.com
    defer result.deinit();
    test_harness.stop();
    // Request expectations
    try std.testing.expectEqual(std.http.Method.PUT, test_harness.request_options.request_method);
    // I don't think this will work since we're overriding the url
    // try test_harness.request_options.expectHeader("Host", "mysfitszj3t6webstack-hostingbucketa91a61fe-1ep3ezkgwpxr0.s3.us-west-2.amazonaws.com");
    try test_harness.request_options.expectHeader("x-amz-storage-class", "STANDARD");
    try std.testing.expectEqualStrings("/mysfitszj3t6webstack-hostingbucketa91a61fe-1ep3ezkgwpxr0/i/am/a/teapot/foo?x-id=PutObject", test_harness.request_options.request_target);
    try std.testing.expectEqualStrings("bar", test_harness.request_options.request_body);
    // Response expectations
    try std.testing.expectEqualStrings("9PEYBAZ9J7TPRX43, host_id: jdRDo30t7Ge9lf6F+4WYpg+YKui8z0mz2+rwinL38xDZzvloJqrmpCAiKG375OSvHA9OBykJS44=", result.response_metadata.request_id);
    try std.testing.expectEqualStrings("AES256", result.response.server_side_encryption.?);
    try std.testing.expectEqualStrings("37b51d194a7513e45b56f6524f2d51f2", result.response.e_tag.?);
}
