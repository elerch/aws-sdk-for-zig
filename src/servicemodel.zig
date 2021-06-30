const std = @import("std");
const service_list = @import("models/service_manifest.zig");
const expectEqualStrings = std.testing.expectEqualStrings;

pub fn Services(service_imports: anytype) type {
    if (service_imports.len == 0)
        return service_list;

    // From here, the fields of our structure can be generated at comptime...
    var fields: [serviceCount(service_imports)]std.builtin.TypeInfo.StructField = undefined;

    // This is run at comptime with multiple nested loops and a large (267 at
    // time of writing) number of services. 4 was chosen by trial and error,
    // but otherwise the branch count will be the product of field length,
    // service list length and the number of imports requested
    // @setEvalBranchQuota(4 * fields.len * service_list.len * std.math.min(service_imports.len, 1));
    for (fields) |*item, i| {
        const import_service = @field(service_list, @tagName(service_imports[i]));
        const import_field = @field(import_service, @tagName(service_imports[i]));
        item.* = .{
            .name = @tagName(service_imports[i]),
            .field_type = @TypeOf(import_field),
            .default_value = import_field,
            .is_comptime = false,
            .alignment = 0,
        };
    }

    // finally, generate the type
    return @Type(.{
        .Struct = .{
            .layout = .Auto,
            .fields = &fields,
            .decls = &[_]std.builtin.TypeInfo.Declaration{},
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
pub const services = Services(.{}){};

test "services includes sts" {
    try expectEqualStrings("2011-06-15", services.sts.version);
}
test "sts includes get_caller_identity" {
    try expectEqualStrings("GetCallerIdentity", services.sts.get_caller_identity.action_name);
}
test "can get service and action name from request" {
    // get request object. This call doesn't have parameters
    const req = services.sts.get_caller_identity.Request{};
    // const metadata = @TypeOf(req).metaInfo();
    const metadata = req.metaInfo();
    try expectEqualStrings("2011-06-15", metadata.service.version);
    // expectEqualStrings("GetCallerIdentity", metadata.action.action_name);
}
test "can filter services" {
    const filtered_services = Services(.{ .sts, .waf_v2 }){};
    // const filtered_services = Services(.{.sts}){};
    try expectEqualStrings("2011-06-15", filtered_services.sts.version);
}
