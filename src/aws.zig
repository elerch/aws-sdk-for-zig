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

pub const ClientOptions = struct {
    trust_pem: ?[]const u8 = awshttp.default_root_ca,
};
pub const Client = struct {
    allocator: std.mem.Allocator,
    aws_http: awshttp.AwsHttp,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, options: ClientOptions) !Self {
        return Self{
            .allocator = allocator,
            .aws_http = try awshttp.AwsHttp.init(allocator, options.trust_pem),
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
            aws_request.path = try buildPath(options.client.allocator, Action.http_config.uri, ActionRequest, request);
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
                inline for (std.meta.fields(@TypeOf(action.Response.http_header))) |f, inx| {
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
                std.meta.fields(action.Response)[0].field_type
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
                            \\Model Type: {s}
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
                        \\Model Type: {s}
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
                .parsed_response_ptr = parsed_response_ptr,
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
    log.debug("Checking for headers to include for type {s}", .{@TypeOf(request)});
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
                    const field_type = @TypeOf(@field(self.response, f.name));
                    // TODO: Fix this. We need to make this much more robust
                    // The deal is we have to do the dupe though
                    // Also, this is a memory leak atm
                    if (field_type == ?[]const u8) {
                        if (@field(self.response, f.name) != null) {
                            self.allocator.free(@field(self.response, f.name).?);
                        }
                    }
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
fn queryFieldTransformer(field_name: []const u8, encoding_options: url.EncodingOptions) anyerror![]const u8 {
    return try case.snakeToPascal(encoding_options.allocator.?, field_name);
}

fn buildPath(allocator: std.mem.Allocator, raw_uri: []const u8, comptime ActionRequest: type, request: anytype) ![]const u8 {
    var buffer = try std.ArrayList(u8).initCapacity(allocator, raw_uri.len);
    // const writer = buffer.writer();
    defer buffer.deinit();
    var in_label = false;
    var start: usize = 0;
    for (raw_uri) |c, inx| {
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
                        try uriEncode(trimmed_replacement_val, encoded_buffer.writer());
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
