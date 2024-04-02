const std = @import("std");
const service_list = @import("models/service_manifest.zig");
const expectEqualStrings = std.testing.expectEqualStrings;

pub fn Services(comptime service_imports: anytype) type {
    if (service_imports.len == 0) return services;
    // From here, the fields of our structure can be generated at comptime...
    var fields: [serviceCount(service_imports)]std.builtin.Type.StructField = undefined;

    for (&fields, 0..) |*item, i| {
        const import_field = @field(service_list, @tagName(service_imports[i]));
        item.* = .{
            .name = @tagName(service_imports[i]),
            .type = @TypeOf(import_field),
            .default_value = &import_field,
            .is_comptime = false,
            .alignment = 0,
        };
    }

    // finally, generate the type
    return @Type(.{
        .Struct = .{
            .layout = .Auto, // will be .auto in the future
            .fields = &fields,
            .decls = &[_]std.builtin.Type.Declaration{},
            .is_tuple = false,
        },
    });
}

fn serviceCount(desired_services: anytype) usize {
    if (desired_services.len == 0) return @TypeOf(service_list).Struct.fields.len;
    return desired_services.len;
}

/// Using this constant may blow up build times. Recommed using Services()
/// function directly, e.g. const services = Services(.{.sts, .ec2, .s3, .ddb}){};
pub const services = service_list;

test "services includes sts" {
    try expectEqualStrings("2011-06-15", services.sts.version);
}
test "sts includes get_caller_identity" {
    try expectEqualStrings("GetCallerIdentity", services.sts.get_caller_identity.action_name);
}
test "can get service and action name from request" {
    // get request object. This call doesn't have parameters
    const metadata = services.sts.get_caller_identity.Request.metaInfo();
    try expectEqualStrings("2011-06-15", metadata.service_metadata.version);
}
test "can filter services" {
    const filtered_services = Services(.{ .sts, .wafv2 }){};
    try expectEqualStrings("2011-06-15", filtered_services.sts.version);
}
