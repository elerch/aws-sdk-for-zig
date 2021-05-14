const std = @import("std");

const awshttp = @import("awshttp.zig");
const json = @import("json.zig");

const log = std.log.scoped(.aws);

pub const Options = awshttp.Options;

// Code "generation" prototype
// TODO: Make generic
pub fn Services() type {
    const types = [_]type{
        Service("sts"),
    };
    return @Type(.{
        .Struct = .{
            .layout = .Auto,
            .fields = &[_]std.builtin.TypeInfo.StructField{
                .{
                    .name = "sts",
                    .field_type = types[0],
                    .default_value = new(types[0]),
                    .is_comptime = false,
                    .alignment = 0,
                },
            },
            .decls = &[_]std.builtin.TypeInfo.Declaration{},
            .is_tuple = false,
        },
    });
}

fn ServiceActionResponse(comptime service: []const u8, comptime action: []const u8) type {
    if (std.mem.eql(u8, service, "sts") and std.mem.eql(u8, action, "get_caller_identity")) {
        return struct {
            arn: []const u8,
            user_id: []const u8,
            account: []const u8,
        };
    }
    unreachable;
}

fn ServiceAction(comptime service: []const u8, comptime action: []const u8) type {
    if (std.mem.eql(u8, service, "sts") and std.mem.eql(u8, action, "get_caller_identity")) {
        return @Type(.{
            .Struct = .{
                .layout = .Auto,
                .fields = &[_]std.builtin.TypeInfo.StructField{
                    .{
                        .name = "Request",
                        .field_type = type,
                        .default_value = struct {},
                        .is_comptime = false,
                        .alignment = 0,
                    },
                    .{
                        .name = "action_name",
                        .field_type = @TypeOf("GetCallerIdentity"),
                        .default_value = "GetCallerIdentity",
                        .is_comptime = false,
                        .alignment = 0,
                    },
                    // TODO: maybe best is to separate requests from responses in whole other struct?
                    .{
                        .name = "Response",
                        .field_type = type,
                        .default_value = ServiceActionResponse("sts", "get_caller_identity"),
                        .is_comptime = false,
                        .alignment = 0,
                    },
                },
                .decls = &[_]std.builtin.TypeInfo.Declaration{},
                .is_tuple = false,
            },
        });
    }
    unreachable;
}

pub const services = Services(){};

fn new(comptime T: type) T {
    return T{};
}
fn Service(comptime service: []const u8) type {
    if (std.mem.eql(u8, "sts", service)) {
        return @Type(.{
            .Struct = .{
                .layout = .Auto,
                .fields = &[_]std.builtin.TypeInfo.StructField{
                    .{
                        .name = "version",
                        .field_type = @TypeOf("2011-06-15"),
                        .default_value = "2011-06-15",
                        .is_comptime = false,
                        .alignment = 0,
                    },
                    .{
                        .name = "get_caller_identity",
                        .field_type = ServiceAction("sts", "get_caller_identity"),
                        .default_value = new(ServiceAction("sts", "get_caller_identity")),
                        .is_comptime = false,
                        .alignment = 0,
                    },
                },
                .decls = &[_]std.builtin.TypeInfo.Declaration{},
                .is_tuple = false,
            },
        });
    }
    unreachable;
}
// End code "generation" prototype

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
