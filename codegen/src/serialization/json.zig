const std = @import("std");
const smithy = @import("smithy");
const smithy_tools = @import("../smithy_tools.zig");
const support = @import("../support.zig");

const GenerationState = @import("../GenerationState.zig");
const GenerateTypeOptions = @import("../GenerateTypeOptions.zig");
const Allocator = std.mem.Allocator;

const Shape = smithy_tools.Shape;

const JsonMember = struct {
    field_name: []const u8,
    json_key: []const u8,
    target: []const u8,
    type_member: smithy.TypeMember,
    shape_info: smithy.ShapeInfo,
};

pub fn generateToJsonFunction(shape_id: []const u8, writer: std.io.AnyWriter, state: GenerationState, comptime options: GenerateTypeOptions) !void {
    _ = options;
    const allocator = state.allocator;

    const shape_info = try smithy_tools.getShapeInfo(shape_id, state.file_state.shapes);
    const shape = shape_info.shape;

    if (try getJsonMembers(allocator, shape, state)) |json_members| {
        if (json_members.items.len > 0) {
            try writer.writeAll("pub fn jsonStringify(self: @This(), jw: anytype) !void {\n");
            try writer.writeAll("try jw.beginObject();\n");
            try writer.writeAll("{\n");

            for (json_members.items) |member| {
                const member_value = try getMemberValueJson(allocator, "self", member);
                defer allocator.free(member_value);

                try writer.print("try jw.objectField(\"{s}\");\n", .{member.json_key});
                try writeMemberJson(
                    .{
                        .shape_id = member.target,
                        .field_name = member.field_name,
                        .field_value = member_value,
                        .state = state.indent(),
                        .member = member.type_member,
                    },
                    writer,
                );
            }

            try writer.writeAll("}\n");
            try writer.writeAll("try jw.endObject();\n");
            try writer.writeAll("}\n\n");
        }
    }
}

fn getJsonMembers(allocator: Allocator, shape: Shape, state: GenerationState) !?std.ArrayListUnmanaged(JsonMember) {
    const is_json_shape = switch (state.file_state.protocol) {
        .json_1_0, .json_1_1, .rest_json_1 => true,
        else => false,
    };

    if (!is_json_shape) {
        return null;
    }

    var hash_map = std.StringHashMapUnmanaged(smithy.TypeMember){};

    const shape_members = smithy_tools.getShapeMembers(shape);
    for (shape_members) |member| {
        try hash_map.putNoClobber(state.allocator, member.name, member);
    }

    for (shape_members) |member| {
        for (member.traits) |trait| {
            switch (trait) {
                .http_header, .http_query => {
                    std.debug.assert(hash_map.remove(member.name));
                    break;
                },
                else => continue,
            }
        }
    }

    if (hash_map.count() == 0) {
        return null;
    }

    var json_members = std.ArrayListUnmanaged(JsonMember){};

    var iter = hash_map.iterator();
    while (iter.next()) |kvp| {
        const member = kvp.value_ptr.*;

        const key = blk: {
            if (smithy_tools.findTrait(.json_name, member.traits)) |trait| {
                break :blk trait.json_name;
            }

            break :blk member.name;
        };

        try json_members.append(allocator, .{
            .field_name = try support.constantName(allocator, member.name, .snake),
            .json_key = key,
            .target = member.target,
            .type_member = member,
            .shape_info = try smithy_tools.getShapeInfo(member.target, state.file_state.shapes),
        });
    }

    return json_members;
}

fn getMemberValueJson(allocator: std.mem.Allocator, source: []const u8, member: JsonMember) ![]const u8 {
    const member_value = try std.fmt.allocPrint(allocator, "@field({s}, \"{s}\")", .{ source, member.field_name });
    defer allocator.free(member_value);

    var output_block = std.ArrayListUnmanaged(u8){};
    const writer = output_block.writer(allocator);

    try writeMemberValue(
        writer,
        member_value,
    );

    return output_block.toOwnedSlice(allocator);
}

fn getShapeJsonValueType(shape: Shape) []const u8 {
    return switch (shape) {
        .string, .@"enum", .blob, .document, .timestamp => ".string",
        .boolean => ".bool",
        .integer, .bigInteger, .short, .long => ".integer",
        .float, .double, .bigDecimal => ".float",
        else => std.debug.panic("Unexpected shape: {}", .{shape}),
    };
}

fn writeMemberValue(
    writer: anytype,
    member_value: []const u8,
) !void {
    try writer.writeAll(member_value);
}

const WriteMemberJsonParams = struct {
    shape_id: []const u8,
    field_name: []const u8,
    field_value: []const u8,
    state: GenerationState,
    member: smithy.TypeMember,
};

fn writeStructureJson(params: WriteMemberJsonParams, writer: std.io.AnyWriter) !void {
    const shape_type = "structure";
    const allocator = params.state.allocator;
    const state = params.state;

    const shape_info = try smithy_tools.getShapeInfo(params.shape_id, state.file_state.shapes);
    const shape = shape_info.shape;

    const structure_name = try std.fmt.allocPrint(params.state.allocator, "{s}_{s}_{d}", .{ params.field_name, shape_type, state.indent_level });
    defer params.state.allocator.free(structure_name);

    const object_value_capture = try std.fmt.allocPrint(allocator, "{s}_capture", .{structure_name});
    defer allocator.free(object_value_capture);

    try writer.print("\n// start {s}: {s}\n", .{ shape_type, structure_name });
    defer writer.print("// end {s}: {s}\n", .{ shape_type, structure_name }) catch std.debug.panic("Unreachable", .{});

    if (try getJsonMembers(allocator, shape, state)) |json_members| {
        if (json_members.items.len > 0) {
            const is_optional = smithy_tools.shapeIsOptional(params.member.traits);

            var object_value = params.field_value;

            if (is_optional) {
                object_value = object_value_capture;

                try writer.print("if ({s}) |{s}|", .{ params.field_value, object_value_capture });
                try writer.writeAll("{\n");
            }

            try writer.writeAll("try jw.beginObject();\n");
            try writer.writeAll("{\n");

            // this is a workaround in case a child structure doesn't have any fields
            // and therefore doesn't use the structure variable so we capture it here.
            // the compiler should optimize this away
            try writer.print("const unused_capture_{s} = {s};\n", .{ structure_name, object_value });
            try writer.print("_ = unused_capture_{s};\n", .{structure_name});

            for (json_members.items) |member| {
                const member_value = try getMemberValueJson(allocator, object_value, member);
                defer allocator.free(member_value);

                try writer.print("try jw.objectField(\"{s}\");\n", .{member.json_key});
                try writeMemberJson(
                    .{
                        .shape_id = member.target,
                        .field_name = member.field_name,
                        .field_value = member_value,
                        .state = state.indent(),
                        .member = member.type_member,
                    },
                    writer,
                );
            }

            try writer.writeAll("}\n");
            try writer.writeAll("try jw.endObject();\n");

            if (is_optional) {
                try writer.writeAll("}\n");
            }
        }
    }
}

fn writeListJson(list: smithy_tools.ListShape, params: WriteMemberJsonParams, writer: std.io.AnyWriter) anyerror!void {
    const state = params.state;
    const allocator = state.allocator;

    const list_name = try std.fmt.allocPrint(allocator, "{s}_list_{d}", .{ params.field_name, state.indent_level });
    defer state.allocator.free(list_name);

    try writer.print("\n// start list: {s}\n", .{list_name});
    defer writer.print("// end list: {s}\n", .{list_name}) catch std.debug.panic("Unreachable", .{});

    const list_each_value = try std.fmt.allocPrint(allocator, "{s}_value", .{list_name});
    defer allocator.free(list_each_value);

    const list_capture = try std.fmt.allocPrint(allocator, "{s}_capture", .{list_name});
    defer allocator.free(list_capture);

    {
        const list_is_optional = smithy_tools.shapeIsOptional(list.traits);

        var list_value = params.field_value;

        if (list_is_optional) {
            list_value = list_capture;

            try writer.print("if ({s}) |{s}| ", .{
                params.field_value,
                list_capture,
            });
            try writer.writeAll("{\n");
        }

        // start loop
        try writer.writeAll("try jw.beginArray();\n");
        try writer.print("for ({s}) |{s}|", .{ list_value, list_each_value });
        try writer.writeAll("{\n");
        try writer.writeAll("try jw.write(");
        try writeMemberValue(
            writer,
            list_each_value,
        );
        try writer.writeAll(");\n");
        try writer.writeAll("}\n");
        try writer.writeAll("try jw.endArray();\n");
        // end loop

        if (list_is_optional) {
            try writer.writeAll("} else {\n");
            try writer.writeAll("try jw.write(null);\n");
            try writer.writeAll("}\n");
        }
    }
}

fn writeMapJson(map: smithy_tools.MapShape, params: WriteMemberJsonParams, writer: std.io.AnyWriter) anyerror!void {
    const state = params.state;
    const name = params.field_name;
    const value = params.field_value;
    const allocator = state.allocator;

    const map_name = try std.fmt.allocPrint(allocator, "{s}_object_map_{d}", .{ name, state.indent_level });
    defer allocator.free(map_name);

    try writer.print("\n// start map: {s}\n", .{map_name});
    defer writer.print("// end map: {s}\n", .{map_name}) catch std.debug.panic("Unreachable", .{});

    const map_value_capture = try std.fmt.allocPrint(allocator, "{s}_kvp", .{map_name});
    defer allocator.free(map_value_capture);

    const map_capture_key = try std.fmt.allocPrint(allocator, "{s}.key", .{map_value_capture});
    defer allocator.free(map_capture_key);

    const map_capture_value = try std.fmt.allocPrint(allocator, "{s}.value", .{map_value_capture});
    defer allocator.free(map_capture_value);

    const value_shape_info = try smithy_tools.getShapeInfo(map.value, state.file_state.shapes);

    const value_member = smithy.TypeMember{
        .name = "value",
        .target = map.value,
        .traits = smithy_tools.getShapeTraits(value_shape_info.shape),
    };

    const map_capture = try std.fmt.allocPrint(state.allocator, "{s}_capture", .{map_name});

    {
        const map_member = params.member;
        const map_is_optional = !smithy_tools.hasTrait(.required, map_member.traits);

        var map_value = value;

        if (map_is_optional) {
            map_value = map_capture;

            try writer.print("if ({s}) |{s}| ", .{
                value,
                map_capture,
            });
            try writer.writeAll("{\n");
        }

        try writer.writeAll("try jw.beginObject();\n");
        try writer.writeAll("{\n");

        // start loop
        try writer.print("for ({s}) |{s}|", .{ map_value, map_value_capture });
        try writer.writeAll("{\n");
        try writer.print("try jw.objectField({s});\n", .{map_capture_key});

        try writeMemberJson(.{
            .shape_id = map.value,
            .field_name = "value",
            .field_value = map_capture_value,
            .state = state.indent(),
            .member = value_member,
        }, writer);

        try writer.writeAll("}\n");
        // end loop

        try writer.writeAll("}\n");
        try writer.writeAll("try jw.endObject();\n");

        if (map_is_optional) {
            try writer.writeAll("} else {\n");
            try writer.writeAll("try jw.write(null);\n");
            try writer.writeAll("}\n");
        }
    }
}

fn writeScalarJson(comment: []const u8, params: WriteMemberJsonParams, writer: std.io.AnyWriter) anyerror!void {
    try writer.print("try jw.write({s}); // {s}\n\n", .{ params.field_value, comment });
}

fn writeMemberJson(params: WriteMemberJsonParams, writer: std.io.AnyWriter) anyerror!void {
    const shape_id = params.shape_id;
    const state = params.state;
    const shape_info = try smithy_tools.getShapeInfo(shape_id, state.file_state.shapes);
    const shape = shape_info.shape;

    if (state.getTypeRecurrenceCount(shape_id) > 2) {
        return;
    }

    try state.appendToTypeStack(&shape_info);
    defer state.popFromTypeStack();

    switch (shape) {
        .structure, .uniontype => try writeStructureJson(params, writer),
        .list => |l| try writeListJson(l, params, writer),
        .map => |m| try writeMapJson(m, params, writer),
        .timestamp => try writeScalarJson("timestamp", params, writer),
        .string => try writeScalarJson("string", params, writer),
        .@"enum" => try writeScalarJson("enum", params, writer),
        .document => try writeScalarJson("document", params, writer),
        .blob => try writeScalarJson("blob", params, writer),
        .boolean => try writeScalarJson("bool", params, writer),
        .float => try writeScalarJson("float", params, writer),
        .integer => try writeScalarJson("integer", params, writer),
        .long => try writeScalarJson("long", params, writer),
        .double => try writeScalarJson("double", params, writer),
        .bigDecimal => try writeScalarJson("bigDecimal", params, writer),
        .bigInteger => try writeScalarJson("bigInteger", params, writer),
        .unit => try writeScalarJson("unit", params, writer),
        .byte => try writeScalarJson("byte", params, writer),
        .short => try writeScalarJson("short", params, writer),
        .service, .resource, .operation, .member, .set => std.debug.panic("Shape type not supported: {}", .{shape}),
    }
}
