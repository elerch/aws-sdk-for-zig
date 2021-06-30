const std = @import("std");
const smithy = @import("smithy.zig");
const snake = @import("snake.zig");

pub fn main() anyerror!void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = &arena.allocator;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const stdout = std.io.getStdOut().writer();
    const manifest_file = try std.fs.cwd().createFile("service_manifest.zig", .{});
    defer manifest_file.close();
    errdefer manifest_file.close();
    const manifest = manifest_file.writer();
    _ = try manifest.write("pub const services = [_]struct { name: []const u8, file_name: []const u8, export_name: []const u8 }{\n");
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
    _ = try manifest.write("};\n");
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
    _ = try writer.write("const smithy = @import(\"smithy.zig\");\n\n");
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
        _ = try manifest.write("    .{");
        try manifest.print(" .name = \"{s}\", .file_name = \"{s}\", .export_name = \"{s}\"", .{ name, std.fs.path.basename(filename), name });
        _ = try manifest.write(" },\n");
    }
}

fn generateServicesForFilePath(allocator: *std.mem.Allocator, comptime terminator: []const u8, path: []const u8, writer: anytype) ![][]const u8 {
    const file = try std.fs.cwd().openFile(path, .{ .read = true, .write = false });
    defer file.close();
    return try generateServices(allocator, terminator, file, writer);
}
fn generateServices(allocator: *std.mem.Allocator, comptime terminator: []const u8, file: std.fs.File, writer: anytype) ![][]const u8 {
    const json = try file.readToEndAlloc(allocator, 1024 * 1024 * 1024);
    defer allocator.free(json);
    const model = try smithy.parse(allocator, json);
    defer model.deinit();
    const ShapeInfo = @TypeOf(model.shapes[0]); // assume we have at least one shape
    var shapes = std.StringHashMap(ShapeInfo).init(allocator);
    defer shapes.deinit();
    var services = std.ArrayList(ShapeInfo).init(allocator);
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
        const constant_name = try snake.fromPascalCase(allocator, sdk_id);
        try constant_names.append(constant_name);
        try writer.print("pub const {s}: struct ", .{constant_name});
        _ = try writer.write("{\n");

        try writer.print("    version: []const u8 = \"{s}\",\n", .{service.shape.service.version});
        try writer.print("    sdk_id: []const u8 = \"{s}\",\n", .{sdk_id});
        try writer.print("    arn_namespace: []const u8 = \"{s}\",\n", .{arn_namespace});
        try writer.print("    endpoint_prefix: []const u8 = \"{s}\",\n", .{endpoint_prefix});
        try writer.print("    sigv4_name: []const u8 = \"{s}\",\n", .{sigv4_name});
        // TODO: This really should just be ".whatevs". We're fully qualifying here, which isn't typical
        try writer.print("    aws_protocol: smithy.AwsProtocol = smithy.{s},\n", .{aws_protocol});

        // Operations
        for (service.shape.service.operations) |op|
            try generateOperation(allocator, shapes.get(op).?, shapes, writer, constant_name);

        // End service
        _ = try writer.write("} = .{}" ++ terminator ++ " // end of service: ");
        try writer.print("{s}\n", .{arn_namespace}); // this var needs to match above
    }
    return constant_names.toOwnedSlice();
}
fn generateOperation(allocator: *std.mem.Allocator, operation: smithy.ShapeInfo, shapes: anytype, writer: anytype, service: []const u8) !void {
    const snake_case_name = try snake.fromPascalCase(allocator, operation.name);
    defer allocator.free(snake_case_name);

    comptime const prefix = "        ";
    var type_stack = std.ArrayList(*const smithy.ShapeInfo).init(allocator);
    defer type_stack.deinit();
    // indent should start at 4 spaces here
    const operation_name = avoidReserved(snake_case_name);
    try writer.print("    {s}: struct ", .{operation_name});
    _ = try writer.write("{\n");
    try writer.print("        action_name: []const u8 = \"{s}\",\n", .{operation.name});
    _ = try writer.write("        Request: type = ");
    if (operation.shape.operation.input) |member| {
        try generateTypeFor(allocator, member, shapes, writer, prefix, false, &type_stack, false);
        _ = try writer.write("\n");
        try generateMetadataFunction(service, operation_name, prefix, writer);
    } else {
        _ = try writer.write("struct {\n");
        try generateMetadataFunction(service, operation_name, prefix, writer);
    }
    _ = try writer.write(",\n");
    _ = try writer.write("        Response: type = ");
    if (operation.shape.operation.output) |member| {
        try generateTypeFor(allocator, member, shapes, writer, "        ", true, &type_stack, true);
    } else _ = try writer.write("struct {}"); // we want to maintain consistency with other ops
    _ = try writer.write(",\n");

    if (operation.shape.operation.errors) |errors| {
        _ = try writer.write("        ServiceError: type = error{\n");
        for (errors) |err| {
            const err_name = getErrorName(shapes.get(err).?.name); // need to remove "exception"
            try writer.print("            {s},\n", .{err_name});
        }
        _ = try writer.write("        },\n");
    }
    _ = try writer.write("    } = .{},\n");
}

fn generateMetadataFunction(service: []const u8, operation_name: []const u8, comptime prefix: []const u8, writer: anytype) !void {
    // TODO: Shove these lines in here, and also the else portion
    // pub fn metaInfo(self: @This()) struct { service: @TypeOf(sts), action: @TypeOf(sts.get_caller_identity) } {
    //     return .{ .service = sts, .action = sts.get_caller_identity };
    // }
    // We want to add a short "get my parents" function into the response
    try writer.print("{s}    ", .{prefix});
    _ = try writer.write("pub fn metaInfo(self: @This()) struct { ");
    try writer.print("service: @TypeOf({s}), action: @TypeOf({s}.{s})", .{ service, service, operation_name });
    _ = try writer.write(" } {\n" ++ prefix ++ "        return .{ ");
    try writer.print(".service = {s}, .action = {s}.{s}", .{ service, service, operation_name });
    _ = try writer.write(" };\n" ++ prefix ++ "    }\n" ++ prefix ++ "}");
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
fn generateTypeFor(allocator: *std.mem.Allocator, shape_id: []const u8, shapes: anytype, writer: anytype, prefix: []const u8, all_required: bool, type_stack: anytype, end_structure: bool) anyerror!void {
    if (shapes.get(shape_id) == null) {
        std.debug.print("Shape ID not found. This is most likely a bug. Shape ID: {s}\n", .{shape_id});
        return error.InvalidType;
    }

    // We assume it must exist
    const shape_info = shapes.get(shape_id).?;
    const shape = shape_info.shape;
    // Check for ourselves up the stack
    var self_occurences: u8 = 0;
    for (type_stack.items) |i| {
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
        try generateSimpleTypeFor("nothing", "[]const u8", writer, all_required);
        std.log.warn("Type cycle detected, limiting depth. Type: {s}", .{shape_id});
        // std.log.info("  Type stack:\n", .{});
        // for (type_stack.items) |i|
        //     std.log.info("  {s}", .{i.*.id});
        return;
    }
    try type_stack.append(&shape_info);
    switch (shape) {
        .structure => |s| {
            try generateComplexTypeFor(allocator, shape.structure.members, "struct", shapes, writer, prefix, all_required, type_stack);
            if (end_structure) {
                // epilog
                try writer.print("{s}", .{prefix});
                _ = try writer.write("}");
            }
        },
        .uniontype => |s| {
            try generateComplexTypeFor(allocator, shape.uniontype.members, "union", shapes, writer, prefix, all_required, type_stack);
            // epilog
            try writer.print("{s}", .{prefix});
            _ = try writer.write("}");
        },
        .string => |s| try generateSimpleTypeFor(s, "[]const u8", writer, all_required),
        .integer => |s| try generateSimpleTypeFor(s, "i64", writer, all_required),
        .list => |s| {
            _ = try writer.write("[]");
            try generateTypeFor(allocator, shape.list.member_target, shapes, writer, prefix, all_required, type_stack, true);
        },
        .set => |s| {
            _ = try writer.write("[]");
            try generateTypeFor(allocator, shape.set.member_target, shapes, writer, prefix, all_required, type_stack, true);
        },
        .timestamp => |s| try generateSimpleTypeFor(s, "i64", writer, all_required),
        .blob => |s| try generateSimpleTypeFor(s, "[]const u8", writer, all_required),
        .boolean => |s| try generateSimpleTypeFor(s, "bool", writer, all_required),
        .double => |s| try generateSimpleTypeFor(s, "f64", writer, all_required),
        .float => |s| try generateSimpleTypeFor(s, "f32", writer, all_required),
        .long => |s| try generateSimpleTypeFor(s, "i64", writer, all_required),
        .map => {
            _ = try writer.write("[]struct {\n");
            const new_prefix = try std.fmt.allocPrint(allocator, "    {s}", .{prefix});
            defer allocator.free(new_prefix);
            try writer.print("{s}    key: ", .{prefix});
            if (!all_required) try writeOptional(shape.map.traits, writer, null);
            try generateTypeFor(allocator, shape.map.key, shapes, writer, prefix, all_required, type_stack, true);
            if (!all_required) try writeOptional(shape.map.traits, writer, " = null");
            _ = try writer.write(",\n");
            try writer.print("{s}    value: ", .{prefix});
            if (!all_required) try writeOptional(shape.map.traits, writer, null);
            try generateTypeFor(allocator, shape.map.key, shapes, writer, prefix, all_required, type_stack, true);
            if (!all_required) try writeOptional(shape.map.traits, writer, " = null");
            _ = try writer.write(",\n");
            _ = try writer.write(prefix);
            _ = try writer.write("}");
        },
        else => {
            std.log.err("encountered unimplemented shape type {s} for shape_id {s}. Generated code will not compile", .{ @tagName(shape), shape_id });
            // Not sure we want to return here - I think we want an exhaustive list
            // return error{UnimplementedShapeType}.UnimplementedShapeType;
        },
    }
    _ = type_stack.pop();
}

fn generateSimpleTypeFor(shape: anytype, type_name: []const u8, writer: anytype, all_required: bool) !void {
    _ = try writer.write(type_name); // This had required stuff but the problem was elsewhere. Better to leave as function just in case
}

fn generateComplexTypeFor(allocator: *std.mem.Allocator, members: []smithy.TypeMember, type_type_name: []const u8, shapes: anytype, writer: anytype, prefix: []const u8, all_required: bool, type_stack: anytype) anyerror!void {
    // prolog. We'll rely on caller to get the spacing correct here
    _ = try writer.write(type_type_name);
    _ = try writer.write(" {\n");
    for (members) |member| {
        const new_prefix = try std.fmt.allocPrint(allocator, "    {s}", .{prefix});
        defer allocator.free(new_prefix);
        const snake_case_member = try snake.fromPascalCase(allocator, member.name);
        defer allocator.free(snake_case_member);
        try writer.print("{s}    {s}: ", .{ prefix, avoidReserved(snake_case_member) });
        if (!all_required) try writeOptional(member.traits, writer, null);
        try generateTypeFor(allocator, member.target, shapes, writer, new_prefix, all_required, type_stack, true);
        if (!all_required and !std.mem.eql(u8, "union", type_type_name))
            try writeOptional(member.traits, writer, " = null");
        _ = try writer.write(",\n");
    }
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
