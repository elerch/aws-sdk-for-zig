const std = @import("std");
const service_list = @import("service_manifest");

pub fn Services(comptime service_imports: anytype) type {
    if (service_imports.len == 0) return services;
    // From here, the fields of our structure can be generated at comptime...
    const fields_len = serviceCount(service_imports);
    var field_names: [fields_len][]const u8 = undefined;
    var field_types: [fields_len]type = undefined;
    var field_attrs: [fields_len]std.builtin.Type.StructField.Attributes = undefined;

    for (0..fields_len) |i| {
        const import_field = @field(service_list, @tagName(service_imports[i]));
        field_names[i] = @tagName(service_imports[i]);
        field_types[i] = @TypeOf(import_field);
        field_attrs[i] = .{
            .default_value_ptr = &import_field,
            .@"comptime" = false,
            .@"align" = std.meta.alignment(field_types[i]),
        };
    }

    // finally, generate the type
    return @Struct(.auto, null, &field_names, &field_types, &field_attrs);
}

fn serviceCount(desired_services: anytype) usize {
    if (desired_services.len == 0) return @TypeOf(service_list).Struct.fields.len;
    return desired_services.len;
}

/// Using this constant may blow up build times. Recommed using Services()
/// function directly, e.g. const services = Services(.{.sts, .ec2, .s3, .ddb}){};
pub const services = service_list;

test "services includes sts" {
    try std.testing.expectEqualStrings("2011-06-15", services.sts.version.?);
}
test "sts includes get_caller_identity" {
    try std.testing.expectEqualStrings("GetCallerIdentity", services.sts.get_caller_identity.action_name);
}
test "can get service and action name from request" {
    // get request object. This call doesn't have parameters
    const metadata = services.sts.get_caller_identity.Request.metaInfo();
    try std.testing.expectEqualStrings("2011-06-15", metadata.service_metadata.version.?);
}
test "can filter services" {
    const filtered_services = Services(.{ .sts, .wafv2 }){};
    try std.testing.expectEqualStrings("2011-06-15", filtered_services.sts.version.?);
}
test "can reify type" {
    const F = Services(.{.lambda});
    const info = @typeInfo(F).@"struct";
    try std.testing.expectEqual(@as(usize, 1), info.fields.len);
    try std.testing.expectEqualStrings("lambda", info.fields[0].name);
}
