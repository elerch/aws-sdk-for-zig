const std = @import("std");
const expectEqualStrings = std.testing.expectEqualStrings;

pub fn Services(service_imports: anytype) type {
    // This service list can be imported from a master file of all services
    // provided by codegen
    const service_list = @import("codegen/service_manifest.zig").services;

    // From here, the fields of our structure can be generated at comptime...
    var fields: [serviceCount(service_list, service_imports)]std.builtin.TypeInfo.StructField = undefined;

    // This is run at comptime with multiple nested loops and a large (267 at
    // time of writing) number of services. 4 was chosen by trial and error,
    // but otherwise the branch count will be the product of field length,
    // service list length and the number of imports requested
    @setEvalBranchQuota(4 * fields.len * service_list.len * std.math.min(service_imports.len, 1));
    var inx = 0;
    for (fields) |*item, i| {
        if (service_imports.len == 0) {
            const import = @field(@import("codegen/models/" ++ service_list[i].file_name), service_list[i].export_name);
            item.* = .{
                .name = service_list[i].name,
                .field_type = @TypeOf(import),
                .default_value = import,
                .is_comptime = false,
                .alignment = 0,
            };
            continue;
        }

        var found = false;
        // we will loop through the big list and check each service
        // against the list of desired imports
        while (inx < service_list.len) {
            for (service_imports) |si| {
                if (std.mem.eql(u8, @tagName(si), service_list[inx].name)) {
                    const import = @field(@import("codegen/models/" ++ service_list[inx].file_name), service_list[inx].export_name);
                    item.* = .{
                        .name = service_list[inx].name,
                        .field_type = @TypeOf(import),
                        .default_value = import,
                        .is_comptime = false,
                        .alignment = 0,
                    };
                    found = true;
                    break;
                }
            }

            inx = inx + 1; // service found or not in list - move to next service
            if (found) break;
        }
        if (!found)
            @compileError("imported service(s) not found");
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

fn serviceCount(service_list: anytype, desired_services: anytype) usize {
    if (desired_services.len == 0) return service_list.len;
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
