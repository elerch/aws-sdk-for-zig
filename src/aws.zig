const std = @import("std");

const awshttp = @import("awshttp.zig");
const json = @import("json.zig");
const servicemodel = @import("servicemodel.zig");

const log = std.log.scoped(.aws);

pub const Options = awshttp.Options;

pub const services = servicemodel.services;

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
        const action_info = actionForRequest(request);
        // This is true weirdness, but we are running into compiler bugs. Touch only if
        // prepared...
        const service = @field(services, action_info.service);
        const action = @field(service, action_info.action);
        const R = Response(request);
        const FullR = FullResponse(request);

        log.debug("service {s}", .{action_info.service});
        log.debug("version {s}", .{service.version});
        log.debug("action {s}", .{action.action_name});
        const response = try self.aws_http.callApi(action_info.service, service.version, action.action_name, options);
        defer response.deinit();
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

fn actionForRequest(comptime request: anytype) struct { service: []const u8, action: []const u8, service_obj: anytype } {
    const type_name = @typeName(@TypeOf(request));
    var service_start: usize = 0;
    var service_end: usize = 0;
    var action_start: usize = 0;
    var action_end: usize = 0;
    for (type_name) |ch, i| {
        switch (ch) {
            '(' => service_start = i + 2,
            ')' => action_end = i - 1,
            ',' => {
                service_end = i - 1;
                action_start = i + 2;
            },
            else => continue,
        }
    }
    // const zero: usize = 0;
    // TODO: Figure out why if statement isn't working
    // if (serviceStart == zero or serviceEnd == zero or actionStart == zero or actionEnd == zero) {
    //     @compileLog("Type must be a function with two parameters \"service\" and \"action\". Found: " ++ type_name);
    //     // @compileError("Type must be a function with two parameters \"service\" and \"action\". Found: " ++ type_name);
    // }
    return .{
        .service = type_name[service_start..service_end],
        .action = type_name[action_start..action_end],
        .service_obj = @field(services, type_name[service_start..service_end]),
    };
}
fn ServerResponse(comptime request: anytype) type {
    const T = Response(request);
    const action_info = actionForRequest(request);
    const service = @field(services, action_info.service);
    const action = @field(service, action_info.action);
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
    const action_info = actionForRequest(request);
    const service = @field(services, action_info.service);
    const action = @field(service, action_info.action);
    return action.Response;
}
