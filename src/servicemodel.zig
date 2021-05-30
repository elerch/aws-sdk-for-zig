const std = @import("std");
const models = @import("models.zig");
const json = @import("json.zig");

const Model = []struct {
    smithy: []const u8,
metadata: struct {
    suppressions: []struct {
        id: []const u8,
        namespace: []const u8,
        },
    },
    shapes: struct
};
const model = {
    var stream = json.TokenStream.init(models);
    const res = json.parse(Config, &stream, .{});
    // Assert no error can occur since we are
    // parsing this JSON at comptime!
    break :x res catch unreachable;
};
// TODO: Make generic
fn Services() type {
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
