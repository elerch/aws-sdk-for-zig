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
        const service = meta_info.service;
        const action = meta_info.action;
        const R = Response(request);

        log.debug("call: prefix {s}, sigv4 {s}, version {s}, action {s}", .{
            service.endpoint_prefix,
            service.sigv4_name,
            service.version,
            action.action_name,
        });
        log.debug("proto: {s}", .{service.aws_protocol});

        switch (service.aws_protocol) {
            .query => return self.callQuery(request, service, action, options),
            .ec2_query => @compileError("EC2 Query protocol not yet supported"),
            .rest_json_1 => @compileError("REST Json 1 protocol not yet supported"),
            .json_1_0 => @compileError("Json 1.0 protocol not yet supported"),
            .json_1_1 => @compileError("Json 1.1 protocol not yet supported"),
            .rest_xml => @compileError("REST XML protocol not yet supported"),
        }
    }

    // Call using query protocol. This is documented as an XML protocol, but
    // throwing a JSON accept header seems to work
    fn callQuery(self: Self, comptime request: anytype, service: anytype, action: anytype, options: Options) !FullResponse(request) {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();
        const writer = buffer.writer();
        const transformer = struct {
            allocator: *std.mem.Allocator,

            const This = @This();

            pub fn transform(this: This, name: []const u8) ![]const u8 {
                return try case.snakeToPascal(this.allocator, name);
            }
            pub fn transform_deinit(this: This, name: []const u8) void {
                this.allocator.free(name);
            }
        }{ .allocator = self.allocator };
        try url.encode(request, writer, .{ .field_name_transformer = transformer });
        const continuation = if (buffer.items.len > 0) "&" else "";

        const body = try std.fmt.allocPrint(self.allocator, "Action={s}&Version={s}{s}{s}\n", .{ action.action_name, service.version, continuation, buffer.items });
        defer self.allocator.free(body);
        const FullR = FullResponse(request);
        const response = try self.aws_http.callApi(
            service.endpoint_prefix,
            body,
            .{
                .region = options.region,
                .dualstack = options.dualstack,
                .sigv4_service_name = service.sigv4_name,
            },
        );
        defer response.deinit();
        if (response.response_code != 200) {
            log.err("call failed! return status: {d}", .{response.response_code});
            log.err("Request:\n  |{s}\nResponse:\n  |{s}", .{ body, response.body });
            return error.HttpFailure;
        }
        // TODO: Check status code for badness
        var stream = json.TokenStream.init(response.body);

        const parser_options = json.ParseOptions{
            .allocator = self.allocator,
            .allow_camel_case_conversion = true, // new option
            .allow_snake_case_conversion = true, // new option
            .allow_unknown_fields = true, // new option. Cannot yet handle non-struct fields though
        };
        const SResponse = ServerResponse(request);
        const parsed_response = try json.parse(SResponse, &stream, parser_options);

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
