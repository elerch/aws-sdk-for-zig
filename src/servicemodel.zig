const std = @import("std");
const expectEqualStrings = std.testing.expectEqualStrings;

// TODO: Make generic
fn Services() type {
    // This service list can be imported from a master file of all services
    // provided by codegen
    const service_list = @import("codegen/service_manifest.zig").services;

    // From here, the fields of our structure can be generated at comptime...
    var fields: [service_list.len]std.builtin.TypeInfo.StructField = undefined;
    for (fields) |*item, i| {
        const import = @field(@import("codegen/models/" ++ service_list[i].file_name), service_list[i].export_name);
        item.* = .{
            .name = service_list[i].name,
            .field_type = @TypeOf(import),
            .default_value = import,
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
// TODO: One constant to rule them all is a bit much. We can keep this
// in the back pocket, but let's move to a factory style getService("blah");
pub const services = Services(){};

test "services includes sts" {
    expectEqualStrings("2011-06-15", services.sts.version);
}
test "sts includes get_caller_identity" {
    expectEqualStrings("GetCallerIdentity", services.sts.get_caller_identity.action_name);
}
test "can get service and action name from request" {
    // get request object. This call doesn't have parameters
    const req = services.sts.get_caller_identity.Request{};
    // const metadata = @TypeOf(req).metaInfo();
    const metadata = req.metaInfo();
    expectEqualStrings("2011-06-15", metadata.service.version);
    // expectEqualStrings("GetCallerIdentity", metadata.action.action_name);
}
