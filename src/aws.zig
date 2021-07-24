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
};

/// Using this constant may blow up build times. Recommed using Services()
/// function directly, e.g. const services = Services(.{.sts, .ec2, .s3, .ddb}){};
pub const services = servicemodel.services;

/// Get a service model by importing specific services only. As an example:
/// const services = Services(.{.sts, .ec2, .s3, .ddb}){};
///
/// This will give you a constant with service data for sts, ec2, s3 and ddb only
pub const Services = servicemodel.Services;

pub const Aws = struct {
    allocator: *std.mem.Allocator,
    aws_http: awshttp.AwsHttp,

    const Self = @This();

    pub fn init(allocator: *std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .aws_http = awshttp.AwsHttp.init(allocator),
        };
    }
    pub fn deinit(self: *Aws) void {
        self.aws_http.deinit();
    }

    pub fn call(self: Self, comptime request: anytype, options: Options) !FullResponse(request) {
        // every codegenned request object includes a metaInfo function to get
        // pointers to service and action
        const meta_info = request.metaInfo();
        const service_meta = meta_info.service_metadata;
        const action = meta_info.action;

        log.debug("call: prefix {s}, sigv4 {s}, version {s}, action {s}", .{
            service_meta.endpoint_prefix,
            service_meta.sigv4_name,
            service_meta.version,
            action.action_name,
        });
        log.debug("proto: {s}", .{service_meta.aws_protocol});

        // It seems as though there are 3 major branches of the 6 protocols.
        // 1. query/ec2_query, which are identical until you get to complex
        //    structures. TBD if the shortcut we're taking for query to make
        //    it return json will work on EC2, but my guess is yes.
        // 2. *json*: These three appear identical for input (possible difference
        //    for empty body serialization), but differ in error handling.
        //    We're not doing a lot of error handling here, though.
        // 3. rest_xml: This is a one-off for S3, never used since
        switch (service_meta.aws_protocol) {
            .query, .ec2_query => return self.callQuery(request, service_meta, action, options),
            .rest_json_1, .json_1_0, .json_1_1 => @compileError("REST Json, Json 1.0/1.1 protocol not yet supported"),
            .rest_xml => @compileError("REST XML protocol not yet supported"),
        }
    }

    // Call using query protocol. This is documented as an XML protocol, but
    // throwing a JSON accept header seems to work. EC2Query is very simliar to
    // Query, so we'll handle both here. Realistically we probably don't effectively
    // handle lists and maps properly anyway yet, so we'll go for it and see
    // where it breaks. PRs and/or failing test cases appreciated.
    fn callQuery(self: Self, comptime request: anytype, service_meta: anytype, action: anytype, options: Options) !FullResponse(request) {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();
        const writer = buffer.writer();
        try url.encode(request, writer, .{
            .field_name_transformer = &queryFieldTransformer,
            .allocator = self.allocator,
        });
        const continuation = if (buffer.items.len > 0) "&" else "";

        const query = if (service_meta.aws_protocol == .query)
            try std.fmt.allocPrint(self.allocator, "", .{})
        else // EC2
            try std.fmt.allocPrint(self.allocator, "?Action={s}&Version={s}", .{
                action.action_name,
                service_meta.version,
            });
        defer self.allocator.free(query);

        const body = if (service_meta.aws_protocol == .query)
            try std.fmt.allocPrint(self.allocator, "Action={s}&Version={s}{s}{s}", .{
                action.action_name,
                service_meta.version,
                continuation,
                buffer.items,
            })
        else // EC2
            try std.fmt.allocPrint(self.allocator, "{s}", .{buffer.items});
        defer self.allocator.free(body);

        const FullR = FullResponse(request);
        const response = try self.aws_http.callApi(
            service_meta.endpoint_prefix,
            .{
                .body = body,
                .query = query,
            },
            .{
                .region = options.region,
                .dualstack = options.dualstack,
                .sigv4_service_name = service_meta.sigv4_name,
            },
        );
        // TODO: Can response handling be reused?
        defer response.deinit();
        if (response.response_code != 200) {
            log.err("call failed! return status: {d}", .{response.response_code});
            log.err("Request Query:\n  |{s}\n", .{query});
            log.err("Request Body:\n  |{s}\n", .{body});

            log.err("Response Headers:\n", .{});
            for (response.headers) |h|
                log.err("\t{s}:{s}\n", .{ h.name, h.value });
            log.err("Response Body:\n  |{s}", .{response.body});
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

        var stream = json.TokenStream.init(response.body);

        const parser_options = json.ParseOptions{
            .allocator = self.allocator,
            .allow_camel_case_conversion = true, // new option
            .allow_snake_case_conversion = true, // new option
            .allow_unknown_fields = true, // new option. Cannot yet handle non-struct fields though
            .allow_missing_fields = false, // new option. Cannot yet handle non-struct fields though
        };
        const SResponse = ServerResponse(request);
        const parsed_response = json.parse(SResponse, &stream, parser_options) catch |e| {
            log.err(
                \\Call successful, but unexpected response from service.
                \\This could be the result of a bug or a stale set of code generated
                \\service models. Response from server:
                \\
                \\{s}
                \\
            , .{response.body});
            return e;
        };

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
        return FullR{
            .response = @field(real_response, @typeInfo(@TypeOf(real_response)).Struct.fields[0].name),
            .response_metadata = .{
                .request_id = real_response.ResponseMetadata.RequestId,
            },
            .parser_options = parser_options,
            .raw_parsed = parsed_response,
        };
    }
};

fn ServerResponse(comptime request: anytype) type {
    const T = Response(request);
    const action = request.metaInfo().action;
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
fn FullResponse(comptime request: anytype) type {
    return struct {
        response: Response(request),
        response_metadata: struct {
            request_id: []u8,
        },
        parser_options: json.ParseOptions,
        raw_parsed: ServerResponse(request),

        const Self = @This();
        pub fn deinit(self: Self) void {
            json.parseFree(ServerResponse(request), self.raw_parsed, self.parser_options);
        }
    };
}
fn Response(comptime request: anytype) type {
    return request.metaInfo().action.Response;
}
fn queryFieldTransformer(field_name: []const u8, encoding_options: url.EncodingOptions) anyerror![]const u8 {
    return try case.snakeToPascal(encoding_options.allocator.?, field_name);
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
