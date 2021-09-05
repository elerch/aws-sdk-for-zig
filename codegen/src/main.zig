const std = @import("std");
const smithy = @import("smithy");
const snake = @import("snake.zig");
const json_zig = @embedFile("json.zig");

pub fn main() anyerror!void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = &arena.allocator;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const stdout = std.io.getStdOut().writer();
    const json_file = try std.fs.cwd().createFile("json.zig", .{});
    defer json_file.close();
    try json_file.writer().writeAll(json_zig);
    const manifest_file = try std.fs.cwd().createFile("service_manifest.zig", .{});
    defer manifest_file.close();
    const manifest = manifest_file.writer();
    var inx: u32 = 0;
    for (args) |arg| {
        if (inx == 0) {
            inx = inx + 1;
            continue;
        }
        try processFile(arg, stdout, manifest);
        inx = inx + 1;
    }

    if (args.len == 0)
        _ = try generateServices(allocator, ";", std.io.getStdIn(), stdout);
}

fn processFile(arg: []const u8, stdout: anytype, manifest: anytype) !void {
    // It's probably best to create our own allocator here so we can deint at the end and
    // toss all allocations related to the services in this file
    // I can't guarantee we're not leaking something, and at the end of the
    // day I'm not sure we want to track down leaks
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = &arena.allocator;
    var writer = &stdout;
    var file: std.fs.File = undefined;
    const filename = try std.fmt.allocPrint(allocator, "{s}.zig", .{arg});
    defer allocator.free(filename);
    file = try std.fs.cwd().createFile(filename, .{ .truncate = true });
    errdefer file.close();
    writer = &file.writer();
    _ = try writer.write("const std = @import(\"std\");\n");
    _ = try writer.write("const serializeMap = @import(\"json.zig\").serializeMap;\n");
    _ = try writer.write("const smithy = @import(\"smithy\");\n\n");
    std.log.info("Processing file: {s}", .{arg});
    const service_names = generateServicesForFilePath(allocator, ";", arg, writer) catch |err| {
        std.log.crit("Error processing file: {s}", .{arg});
        return err;
    };
    defer {
        for (service_names) |name| allocator.free(name);
        allocator.free(service_names);
    }
    file.close();
    for (service_names) |name| {
        try manifest.print("pub const {s} = @import(\"{s}\");\n", .{ name, std.fs.path.basename(filename) });
    }
}

fn generateServicesForFilePath(allocator: *std.mem.Allocator, comptime terminator: []const u8, path: []const u8, writer: anytype) ![][]const u8 {
    const file = try std.fs.cwd().openFile(path, .{ .read = true, .write = false });
    defer file.close();
    return try generateServices(allocator, terminator, file, writer);
}
fn generateServices(allocator: *std.mem.Allocator, comptime _: []const u8, file: std.fs.File, writer: anytype) ![][]const u8 {
    const json = try file.readToEndAlloc(allocator, 1024 * 1024 * 1024);
    defer allocator.free(json);
    const model = try smithy.parse(allocator, json);
    defer model.deinit();
    var shapes = std.StringHashMap(smithy.ShapeInfo).init(allocator);
    defer shapes.deinit();
    var services = std.ArrayList(smithy.ShapeInfo).init(allocator);
    defer services.deinit();
    for (model.shapes) |shape| {
        try shapes.put(shape.id, shape);
        switch (shape.shape) {
            .service => try services.append(shape),
            else => {},
        }
    }
    var constant_names = std.ArrayList([]const u8).init(allocator);
    defer constant_names.deinit();
    for (services.items) |service| {
        var sdk_id: []const u8 = undefined;
        var version: []const u8 = service.shape.service.version;
        var name: []const u8 = service.name;
        var arn_namespace: []const u8 = undefined;
        var sigv4_name: []const u8 = undefined;
        var endpoint_prefix: []const u8 = undefined;
        var aws_protocol: smithy.AwsProtocol = undefined;
        for (service.shape.service.traits) |trait| {
            // need the info/get the info
            switch (trait) {
                .aws_api_service => {
                    arn_namespace = trait.aws_api_service.arn_namespace;
                    sdk_id = trait.aws_api_service.sdk_id;
                    endpoint_prefix = trait.aws_api_service.endpoint_prefix;
                },
                .aws_auth_sigv4 => sigv4_name = trait.aws_auth_sigv4.name,
                .aws_protocol => aws_protocol = trait.aws_protocol,
                else => {},
            }
        }

        // Service struct
        // name of the field will be snake_case of whatever comes in from
        // sdk_id. Not sure this will simple...
        const constant_name = try constantName(allocator, sdk_id);
        try constant_names.append(constant_name);
        try writer.print("const Self = @This();\n", .{});
        try writer.print("pub const version: []const u8 = \"{s}\";\n", .{version});
        try writer.print("pub const sdk_id: []const u8 = \"{s}\";\n", .{sdk_id});
        try writer.print("pub const arn_namespace: []const u8 = \"{s}\";\n", .{arn_namespace});
        try writer.print("pub const endpoint_prefix: []const u8 = \"{s}\";\n", .{endpoint_prefix});
        try writer.print("pub const sigv4_name: []const u8 = \"{s}\";\n", .{sigv4_name});
        try writer.print("pub const name: []const u8 = \"{s}\";\n", .{name});
        // TODO: This really should just be ".whatevs". We're fully qualifying here, which isn't typical
        try writer.print("pub const aws_protocol: smithy.AwsProtocol = smithy.{s};\n\n", .{aws_protocol});
        _ = try writer.write("pub const service_metadata : struct {\n");
        try writer.print("    version: []const u8 = \"{s}\",\n", .{version});
        try writer.print("    sdk_id: []const u8 = \"{s}\",\n", .{sdk_id});
        try writer.print("    arn_namespace: []const u8 = \"{s}\",\n", .{arn_namespace});
        try writer.print("    endpoint_prefix: []const u8 = \"{s}\",\n", .{endpoint_prefix});
        try writer.print("    sigv4_name: []const u8 = \"{s}\",\n", .{sigv4_name});
        try writer.print("    name: []const u8 = \"{s}\",\n", .{name});
        // TODO: This really should just be ".whatevs". We're fully qualifying here, which isn't typical
        try writer.print("    aws_protocol: smithy.AwsProtocol = smithy.{s},\n", .{aws_protocol});
        _ = try writer.write("} = .{};\n");

        // Operations
        for (service.shape.service.operations) |op|
            try generateOperation(allocator, shapes.get(op).?, shapes, writer);
    }
    return constant_names.toOwnedSlice();
}
fn constantName(allocator: *std.mem.Allocator, id: []const u8) ![]const u8 {
    // There are some ids that don't follow consistent rules, so we'll
    // look for the exceptions and, if not found, revert to the snake case
    // algorithm

    // This one might be a bug in snake, but it's the only example so HPDL
    if (std.mem.eql(u8, id, "SESv2")) return try std.fmt.allocPrint(allocator, "ses_v2", .{});
    // IoT is an acryonym, but snake wouldn't know that. Interestingly not all
    // iot services are capitalizing that way.
    if (std.mem.eql(u8, id, "IoTSiteWise")) return try std.fmt.allocPrint(allocator, "iot_site_wise", .{}); //sitewise?
    if (std.mem.eql(u8, id, "IoTFleetHub")) return try std.fmt.allocPrint(allocator, "iot_fleet_hub", .{});
    if (std.mem.eql(u8, id, "IoTSecureTunneling")) return try std.fmt.allocPrint(allocator, "iot_secure_tunneling", .{});
    if (std.mem.eql(u8, id, "IoTThingsGraph")) return try std.fmt.allocPrint(allocator, "iot_things_graph", .{});
    // snake turns this into dev_ops, which is a little weird
    if (std.mem.eql(u8, id, "DevOps Guru")) return try std.fmt.allocPrint(allocator, "devops_guru", .{});
    if (std.mem.eql(u8, id, "FSx")) return try std.fmt.allocPrint(allocator, "fsx", .{});

    // Not a special case - just snake it
    return try snake.fromPascalCase(allocator, id);
}

const GenerationState = struct {
    type_stack: *std.ArrayList(*const smithy.ShapeInfo),
    // we will need some sort of "type decls needed" for recursive structures
    allocator: *std.mem.Allocator,
    indent_level: u64,
    all_required: bool,
};

fn outputIndent(state: GenerationState, writer: anytype) !void {
    const n_chars = 4 * state.indent_level;
    try writer.writeByteNTimes(' ', n_chars);
}
fn generateOperation(allocator: *std.mem.Allocator, operation: smithy.ShapeInfo, shapes: std.StringHashMap(smithy.ShapeInfo), writer: anytype) !void {
    const snake_case_name = try snake.fromPascalCase(allocator, operation.name);
    defer allocator.free(snake_case_name);

    var type_stack = std.ArrayList(*const smithy.ShapeInfo).init(allocator);
    defer type_stack.deinit();
    const state = GenerationState{
        .type_stack = &type_stack,
        .allocator = allocator,
        .indent_level = 1,
        .all_required = false,
    };
    var child_state = state;
    child_state.indent_level += 1;
    // indent should start at 4 spaces here
    const operation_name = avoidReserved(snake_case_name);
    try writer.print("pub const {s}: struct ", .{operation_name});
    _ = try writer.write("{\n");
    for (operation.shape.operation.traits) |trait| {
        if (trait == .http) {
            try outputIndent(state, writer);
            _ = try writer.write("pub const http_config = .{\n");
            try outputIndent(child_state, writer);
            try writer.print(".method = \"{s}\",\n", .{trait.http.method});
            try outputIndent(child_state, writer);
            try writer.print(".uri = \"{s}\",\n", .{trait.http.uri});
            try outputIndent(child_state, writer);
            try writer.print(".success_code = {d},\n", .{trait.http.code});
            try outputIndent(state, writer);
            _ = try writer.write("};\n\n");
        }
    }

    try outputIndent(state, writer);
    try writer.print("action_name: []const u8 = \"{s}\",\n", .{operation.name});
    try outputIndent(state, writer);
    _ = try writer.write("Request: type = ");
    if (operation.shape.operation.input) |member| {
        if (try generateTypeFor(member, shapes, writer, state, false)) unreachable; // we expect only structs here
        _ = try writer.write("\n");
        try generateMetadataFunction(operation_name, state, writer);
    } else {
        _ = try writer.write("struct {\n");
        try generateMetadataFunction(operation_name, state, writer);
    }
    _ = try writer.write(",\n");
    try outputIndent(state, writer);
    _ = try writer.write("Response: type = ");
    if (operation.shape.operation.output) |member| {
        if (try generateTypeFor(member, shapes, writer, state, true)) unreachable; // we expect only structs here
    } else _ = try writer.write("struct {}"); // we want to maintain consistency with other ops
    _ = try writer.write(",\n");

    if (operation.shape.operation.errors) |errors| {
        try outputIndent(state, writer);
        _ = try writer.write("ServiceError: type = error{\n");
        for (errors) |err| {
            const err_name = getErrorName(shapes.get(err).?.name); // need to remove "exception"
            try outputIndent(child_state, writer);
            try writer.print("{s},\n", .{err_name});
        }
        try outputIndent(state, writer);
        _ = try writer.write("},\n");
    }
    _ = try writer.write("} = .{};\n");
}

fn generateMetadataFunction(operation_name: []const u8, state: GenerationState, writer: anytype) !void {
    // TODO: Shove these lines in here, and also the else portion
    // pub fn metaInfo(self: @This()) struct { service: @TypeOf(sts), action: @TypeOf(sts.get_caller_identity) } {
    //     return .{ .service = sts, .action = sts.get_caller_identity };
    // }
    // We want to add a short "get my parents" function into the response
    var child_state = state;
    child_state.indent_level += 1;
    try outputIndent(child_state, writer);
    _ = try writer.write("pub fn metaInfo() struct { ");
    try writer.print("service_metadata: @TypeOf(service_metadata), action: @TypeOf({s})", .{operation_name});
    _ = try writer.write(" } {\n");
    child_state.indent_level += 1;
    try outputIndent(child_state, writer);
    _ = try writer.write("return .{ .service_metadata = service_metadata, ");
    try writer.print(".action = {s}", .{operation_name});
    _ = try writer.write(" };\n");
    child_state.indent_level -= 1;
    try outputIndent(child_state, writer);
    _ = try writer.write("}\n");
    try outputIndent(state, writer);
    try writer.writeByte('}');
}
fn getErrorName(err_name: []const u8) []const u8 {
    if (endsWith("Exception", err_name))
        return err_name[0 .. err_name.len - "Exception".len];

    if (endsWith("Fault", err_name))
        return err_name[0 .. err_name.len - "Fault".len];
    return err_name;
}

fn endsWith(item: []const u8, str: []const u8) bool {
    if (str.len < item.len) return false;
    return std.mem.eql(u8, item, str[str.len - item.len ..]);
}
/// return type is anyerror!void as this is a recursive function, so the compiler cannot properly infer error types
fn generateTypeFor(shape_id: []const u8, shapes: std.StringHashMap(smithy.ShapeInfo), writer: anytype, state: GenerationState, end_structure: bool) anyerror!bool {
    var rc = false;
    if (shapes.get(shape_id) == null) {
        std.debug.print("Shape ID not found. This is most likely a bug. Shape ID: {s}\n", .{shape_id});
        return error.InvalidType;
    }

    // We assume it must exist
    const shape_info = shapes.get(shape_id).?;
    const shape = shape_info.shape;
    // Check for ourselves up the stack
    var self_occurences: u8 = 0;
    for (state.type_stack.items) |i| {
        // NOTE: shapes.get isn't providing a consistent pointer - is it allocating each time?
        // we will therefore need to compare ids
        if (std.mem.eql(u8, i.*.id, shape_info.id))
            self_occurences = self_occurences + 1;
    }
    // Debugging
    // if (std.mem.eql(u8, shape_info.name, "Expression")) {
    //     std.log.info("  Type stack len: {d}, occurences: {d}\n", .{ type_stack.items.len, self_occurences });
    //     if (type_stack.items.len > 15) {
    //         std.log.info("  Type stack:\n", .{});
    //         for (type_stack.items) |i|
    //             std.log.info("  {s}: {*}", .{ i.*.id, i });
    //         return error.BugDetected;
    //     }
    // }
    // End Debugging
    if (self_occurences > 2) { // TODO: What's the appropriate number here?
        // TODO: Determine if this warrants the creation of another public
        // type to properly reference. Realistically, AWS or the service
        // must be blocking deep recursion somewhere or this would be a great
        // DOS attack
        try generateSimpleTypeFor("nothing", "[]const u8", writer);
        std.log.warn("Type cycle detected, limiting depth. Type: {s}", .{shape_id});
        // if (std.mem.eql(u8, "com.amazonaws.workmail#Timestamp", shape_id)) {
        //     std.log.info("  Type stack:\n", .{});
        //     for (state.type_stack.items) |i|
        //         std.log.info("  {s}", .{i.*.id});
        // }
        return false; // not a map
    }
    try state.type_stack.append(&shape_info);
    defer _ = state.type_stack.pop();
    switch (shape) {
        .structure => {
            try generateComplexTypeFor(shape_id, shape.structure.members, "struct", shapes, writer, state);
            if (end_structure) {
                // epilog
                try outputIndent(state, writer);
                _ = try writer.write("}");
            }
        },
        .uniontype => {
            try generateComplexTypeFor(shape_id, shape.uniontype.members, "union", shapes, writer, state);
            // epilog
            try outputIndent(state, writer);
            _ = try writer.write("}");
        },
        .string => |s| try generateSimpleTypeFor(s, "[]const u8", writer),
        .integer => |s| try generateSimpleTypeFor(s, "i64", writer),
        .list => {
            _ = try writer.write("[]");
            // The serializer will have to deal with the idea we might be an array
            return try generateTypeFor(shape.list.member_target, shapes, writer, state, true);
        },
        .set => {
            _ = try writer.write("[]");
            // The serializer will have to deal with the idea we might be an array
            return try generateTypeFor(shape.set.member_target, shapes, writer, state, true);
        },
        .timestamp => |s| try generateSimpleTypeFor(s, "i64", writer),
        .blob => |s| try generateSimpleTypeFor(s, "[]const u8", writer),
        .boolean => |s| try generateSimpleTypeFor(s, "bool", writer),
        .double => |s| try generateSimpleTypeFor(s, "f64", writer),
        .float => |s| try generateSimpleTypeFor(s, "f32", writer),
        .long => |s| try generateSimpleTypeFor(s, "i64", writer),
        .map => {
            _ = try writer.write("[]struct {\n");
            var child_state = state;
            child_state.indent_level += 1;
            try outputIndent(child_state, writer);
            _ = try writer.write("key: ");
            try writeOptional(shape.map.traits, writer, null);
            var sub_maps = std.ArrayList([]const u8).init(state.allocator);
            defer sub_maps.deinit();
            if (try generateTypeFor(shape.map.key, shapes, writer, child_state, true))
                try sub_maps.append("key");
            try writeOptional(shape.map.traits, writer, " = null");
            _ = try writer.write(",\n");
            try outputIndent(child_state, writer);
            _ = try writer.write("value: ");
            try writeOptional(shape.map.traits, writer, null);
            if (try generateTypeFor(shape.map.value, shapes, writer, child_state, true))
                try sub_maps.append("value");
            try writeOptional(shape.map.traits, writer, " = null");
            _ = try writer.write(",\n");
            if (sub_maps.items.len > 0) {
                _ = try writer.write("\n");
                try writeStringify(state, sub_maps.items, writer);
            }
            try outputIndent(state, writer);
            _ = try writer.write("}");

            rc = true;
        },
        else => {
            std.log.err("encountered unimplemented shape type {s} for shape_id {s}. Generated code will not compile", .{ @tagName(shape), shape_id });
            // Not sure we want to return here - I think we want an exhaustive list
            // return error{UnimplementedShapeType}.UnimplementedShapeType;
        },
    }
    return rc;
}

fn generateSimpleTypeFor(_: anytype, type_name: []const u8, writer: anytype) !void {
    _ = try writer.write(type_name); // This had required stuff but the problem was elsewhere. Better to leave as function just in case
}
fn generateComplexTypeFor(shape_id: []const u8, members: []smithy.TypeMember, type_type_name: []const u8, shapes: std.StringHashMap(smithy.ShapeInfo), writer: anytype, state: GenerationState) anyerror!void {
    _ = shape_id;
    const Mapping = struct { snake: []const u8, json: []const u8 };
    var json_field_name_mappings = try std.ArrayList(Mapping).initCapacity(state.allocator, members.len);
    defer {
        for (json_field_name_mappings.items) |mapping|
            state.allocator.free(mapping.snake);
        json_field_name_mappings.deinit();
    }
    // There is an httpQueryParams trait as well, but nobody is using it. API GW
    // pretends to, but it's an empty map
    //
    // Same with httpPayload
    //
    // httpLabel is interesting - right now we just assume anything can be used - do we need to track this?
    var http_query_mappings = try std.ArrayList(Mapping).initCapacity(state.allocator, members.len);
    defer {
        for (http_query_mappings.items) |mapping|
            state.allocator.free(mapping.snake);
        http_query_mappings.deinit();
    }
    var http_header_mappings = try std.ArrayList(Mapping).initCapacity(state.allocator, members.len);
    defer {
        for (http_header_mappings.items) |mapping|
            state.allocator.free(mapping.snake);
        http_header_mappings.deinit();
    }
    var map_fields = std.ArrayList([]const u8).init(state.allocator);
    defer {
        for (map_fields.items) |f| state.allocator.free(f);
        map_fields.deinit();
    }
    // prolog. We'll rely on caller to get the spacing correct here
    _ = try writer.write(type_type_name);
    _ = try writer.write(" {\n");
    var child_state = state;
    child_state.indent_level += 1;
    for (members) |member| {
        // This is our mapping
        const snake_case_member = try snake.fromPascalCase(state.allocator, member.name);
        // So it looks like some services have duplicate names?! Check out "httpMethod"
        // in API Gateway. Not sure what we're supposed to do there. Checking the go
        // sdk, they move this particular duplicate to 'http_method' - not sure yet
        // if this is a hard-coded exception`
        var found_name_trait = false;
        for (member.traits) |trait| {
            switch (trait) {
                .json_name => {
                    found_name_trait = true;
                    json_field_name_mappings.appendAssumeCapacity(.{ .snake = try state.allocator.dupe(u8, snake_case_member), .json = trait.json_name });
                },
                .http_query => http_query_mappings.appendAssumeCapacity(.{ .snake = try state.allocator.dupe(u8, snake_case_member), .json = trait.http_query }),
                .http_header => http_header_mappings.appendAssumeCapacity(.{ .snake = try state.allocator.dupe(u8, snake_case_member), .json = trait.http_header }),
                else => {},
            }
        }
        if (!found_name_trait)
            json_field_name_mappings.appendAssumeCapacity(.{ .snake = try state.allocator.dupe(u8, snake_case_member), .json = member.name });
        defer state.allocator.free(snake_case_member);
        try outputIndent(child_state, writer);
        const member_name = avoidReserved(snake_case_member);
        try writer.print("{s}: ", .{member_name});
        try writeOptional(member.traits, writer, null);
        if (try generateTypeFor(member.target, shapes, writer, child_state, true))
            try map_fields.append(try std.fmt.allocPrint(state.allocator, "{s}", .{member_name}));

        if (!std.mem.eql(u8, "union", type_type_name))
            try writeOptional(member.traits, writer, " = null");
        _ = try writer.write(",\n");
    }

    // Add in http query metadata (only relevant to REST JSON APIs - do we care?
    // pub const http_query = .{
    //     .master_region = "MasterRegion",
    //     .function_version = "FunctionVersion",
    //     .marker = "Marker",
    //     .max_items = "MaxItems",
    // };
    if (http_query_mappings.items.len > 0) _ = try writer.write("\n");
    try writeMappings(child_state, "pub ", "http_query", http_query_mappings, false, writer);
    if (http_query_mappings.items.len > 0 and http_header_mappings.items.len > 0) _ = try writer.write("\n");
    try writeMappings(child_state, "pub ", "http_header", http_header_mappings, false, writer);

    // Add in json mappings. The function looks like this:
    //
    // pub fn jsonFieldNameFor(_: @This(), comptime field_name: []const u8) []const u8 {
    //     const mappings = .{
    //         .exclusive_start_table_name = "ExclusiveStartTableName",
    //         .limit = "Limit",
    //     };
    //     return @field(mappings, field_name);
    // }
    //
    try writer.writeByte('\n');
    try outputIndent(child_state, writer);
    _ = try writer.write("pub fn jsonFieldNameFor(_: @This(), comptime field_name: []const u8) []const u8 {\n");
    var grandchild_state = child_state;
    grandchild_state.indent_level += 1;
    // We need to force output here becaseu we're referencing the field in the return statement below
    try writeMappings(grandchild_state, "", "mappings", json_field_name_mappings, true, writer);
    try outputIndent(grandchild_state, writer);
    _ = try writer.write("return @field(mappings, field_name);\n");
    try outputIndent(child_state, writer);
    _ = try writer.write("}\n");
    try writeStringify(child_state, map_fields.items, writer);
}

fn writeStringify(state: GenerationState, fields: [][]const u8, writer: anytype) !void {
    if (fields.len > 0) {
        // pub fn jsonStringifyField(self: @This(), comptime field_name: []const u8, options: anytype, out_stream: anytype) !bool {
        //     if (std.mem.eql(u8, "tags", field_name))
        //         return try serializeMap(self.tags, self.jsonFieldNameFor("tags"), options, out_stream);
        //     return false;
        // }
        var child_state = state;
        child_state.indent_level += 1;
        try writer.writeByte('\n');
        try outputIndent(state, writer);
        _ = try writer.write("pub fn jsonStringifyField(self: @This(), comptime field_name: []const u8, options: anytype, out_stream: anytype) !bool {\n");
        var return_state = child_state;
        return_state.indent_level += 1;
        for (fields) |field| {
            try outputIndent(child_state, writer);
            try writer.print("if (std.mem.eql(u8, \"{s}\", field_name))\n", .{field});
            try outputIndent(return_state, writer);
            try writer.print("return try serializeMap(self.{s}, self.jsonFieldNameFor(\"{s}\"), options, out_stream);\n", .{ field, field });
        }
        try outputIndent(child_state, writer);
        _ = try writer.write("return false;\n");
        try outputIndent(state, writer);
        _ = try writer.write("}\n");
    }
}

fn writeMappings(state: GenerationState, @"pub": []const u8, mapping_name: []const u8, mappings: anytype, force_output: bool, writer: anytype) !void {
    if (mappings.items.len == 0 and !force_output) return;
    try outputIndent(state, writer);
    if (mappings.items.len == 0) {
        try writer.print("{s}const {s} = ", .{ @"pub", mapping_name });
        _ = try writer.write(".{};\n");
        return;
    }
    try writer.print("{s}const {s} = .", .{ @"pub", mapping_name });
    _ = try writer.write("{\n");
    var child_state = state;
    child_state.indent_level += 1;
    for (mappings.items) |mapping| {
        try outputIndent(child_state, writer);
        try writer.print(".{s} = \"{s}\",\n", .{ avoidReserved(mapping.snake), mapping.json });
    }
    try outputIndent(state, writer);
    _ = try writer.write("};\n");
}

fn writeOptional(traits: ?[]smithy.Trait, writer: anytype, value: ?[]const u8) !void {
    if (traits) |ts| {
        for (ts) |t|
            if (t == .required) return;
    }

    // not required
    if (value) |v| {
        _ = try writer.write(v);
    } else _ = try writer.write("?");
}
fn camelCase(allocator: *std.mem.Allocator, name: []const u8) ![]const u8 {
    const first_letter = name[0] + ('a' - 'A');
    return try std.fmt.allocPrint(allocator, "{c}{s}", .{ first_letter, name[1..] });
}
fn avoidReserved(snake_name: []const u8) []const u8 {
    if (std.mem.eql(u8, snake_name, "error")) return "@\"error\"";
    if (std.mem.eql(u8, snake_name, "return")) return "@\"return\"";
    if (std.mem.eql(u8, snake_name, "not")) return "@\"not\"";
    if (std.mem.eql(u8, snake_name, "and")) return "@\"and\"";
    if (std.mem.eql(u8, snake_name, "or")) return "@\"or\"";
    if (std.mem.eql(u8, snake_name, "test")) return "@\"test\"";
    if (std.mem.eql(u8, snake_name, "null")) return "@\"null\"";
    return snake_name;
}
