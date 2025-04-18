const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// Options for controlling XML serialization behavior
pub const StringifyOptions = struct {
    /// Controls whitespace insertion for easier human readability
    whitespace: Whitespace = .minified,

    /// Should optional fields with null value be written?
    emit_null_optional_fields: bool = true,

    // TODO: Implement
    /// Arrays/slices of u8 are typically encoded as strings. This option emits them as arrays of numbers instead. Does not affect calls to objectField*().
    emit_strings_as_arrays: bool = false,

    /// Controls whether to include XML declaration at the beginning
    include_declaration: bool = true,

    /// Root element name to use when serializing a value that doesn't have a natural name
    root_name: ?[]const u8 = "root",

    /// Function to determine the element name for an array item based on the element
    /// name of the array containing the elements. See arrayElementPluralToSingluarTransformation
    /// and arrayElementNoopTransformation functions for examples
    arrayElementNameConversion: *const fn (allocator: std.mem.Allocator, name: ?[]const u8) error{OutOfMemory}!?[]const u8 = arrayElementPluralToSingluarTransformation,

    pub const Whitespace = enum {
        minified,
        indent_1,
        indent_2,
        indent_3,
        indent_4,
        indent_8,
        indent_tab,
    };
};

/// Error set for XML serialization
pub const XmlSerializeError = error{
    /// Unsupported type for XML serialization
    UnsupportedType,
    /// Out of memory
    OutOfMemory,
    /// Write error
    WriteError,
};

/// Serializes a value to XML and writes it to the provided writer
pub fn stringify(
    value: anytype,
    options: StringifyOptions,
    writer: anytype,
) !void {
    // Write XML declaration if requested
    if (options.include_declaration)
        try writer.writeAll("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");

    // Start serialization with the root element
    const root_name = options.root_name;
    try serializeValue(value, root_name, options, writer.any(), 0);
}

/// Serializes a value to XML and returns an allocated string
pub fn stringifyAlloc(
    allocator: Allocator,
    value: anytype,
    options: StringifyOptions,
) ![]u8 {
    var list = std.ArrayList(u8).init(allocator);
    errdefer list.deinit();

    try stringify(value, options, list.writer());
    return list.toOwnedSlice();
}

/// Internal function to serialize a value with proper indentation
fn serializeValue(
    value: anytype,
    element_name: ?[]const u8,
    options: StringifyOptions,
    writer: anytype,
    depth: usize,
) !void {
    const T = @TypeOf(value);

    try writeIndent(writer, depth, options.whitespace);

    // const write_outer_element =
    //     @typeInfo(T) != .optional or
    //     options.emit_strings_as_arrays == false or
    //     (@typeInfo(T) == .optional and element_name != null) or
    //     (options.emit_strings_as_arrays and (@typeInfo(T) != .array or @typeInfo(T).array.child != u8));
    // Start element tag
    if (@typeInfo(T) != .optional and @typeInfo(T) != .array) {
        if (element_name) |n| {
            try writer.writeAll("<");
            try writer.writeAll(n);
            try writer.writeAll(">");
        }
    }

    // Handle different types
    switch (@typeInfo(T)) {
        .bool => try writer.writeAll(if (value) "true" else "false"),
        .int, .comptime_int, .float, .comptime_float => try writer.print("{}", .{value}),
        .pointer => |ptr_info| {
            switch (ptr_info.size) {
                .one => {
                    // We don't want to write the opening tag a second time, so
                    // we will pass null, then come back and close before returning
                    //
                    // ...but...in the event of a *[]const u8, we do want to pass that in,
                    // but only if emit_strings_as_arrays is true
                    const child_ti = @typeInfo(ptr_info.child);
                    const el_name = if (options.emit_strings_as_arrays and child_ti == .array and child_ti.array.child == u8)
                        element_name
                    else
                        null;
                    try serializeValue(value.*, el_name, options, writer, depth);
                    try writeClose(writer, element_name);
                    return;
                },
                .slice => {
                    if (ptr_info.child == u8) {
                        // String type
                        try serializeString(writer, element_name, value, options, depth);
                    } else {
                        // Array of values
                        if (options.whitespace != .minified) {
                            try writer.writeByte('\n');
                        }

                        var buf: [256]u8 = undefined;
                        var fba = std.heap.FixedBufferAllocator.init(&buf);
                        const alloc = fba.allocator();
                        const item_name = try options.arrayElementNameConversion(alloc, element_name);

                        for (value) |item| {
                            try serializeValue(item, item_name, options, writer, depth + 1);
                            if (options.whitespace != .minified) {
                                try writer.writeByte('\n');
                            }
                        }

                        try writeIndent(writer, depth, options.whitespace);
                    }
                },
                else => return error.UnsupportedType,
            }
        },
        .array => |array_info| {
            if (!options.emit_strings_as_arrays or array_info.child != u8) {
                if (element_name) |n| {
                    try writer.writeAll("<");
                    try writer.writeAll(n);
                    try writer.writeAll(">");
                }
            }
            if (array_info.child == u8) {
                // Fixed-size string
                const slice = &value;
                try serializeString(writer, element_name, slice, options, depth);
            } else {
                // Fixed-size array
                if (options.whitespace != .minified) {
                    try writer.writeByte('\n');
                }

                var buf: [256]u8 = undefined;
                var fba = std.heap.FixedBufferAllocator.init(&buf);
                const alloc = fba.allocator();
                const item_name = try options.arrayElementNameConversion(alloc, element_name);

                for (value) |item| {
                    try serializeValue(item, item_name, options, writer, depth + 1);
                    if (options.whitespace != .minified) {
                        try writer.writeByte('\n');
                    }
                }

                try writeIndent(writer, depth, options.whitespace);
            }
            if (!options.emit_strings_as_arrays or array_info.child != u8)
                try writeClose(writer, element_name);
            return;
        },
        .@"struct" => |struct_info| {
            if (options.whitespace != .minified) {
                try writer.writeByte('\n');
            }

            inline for (struct_info.fields) |field| {
                const field_name =
                    if (std.meta.hasFn(T, "fieldNameFor"))
                        value.fieldNameFor(field.name)
                    else
                        field.name; // TODO: field mapping

                try serializeValue(
                    @field(value, field.name),
                    field_name,
                    options,
                    writer,
                    depth + 1,
                );

                if (options.whitespace != .minified) {
                    try writer.writeByte('\n');
                }
            }

            try writeIndent(writer, depth, options.whitespace);
        },
        .optional => {
            if (options.emit_null_optional_fields or value != null) {
                if (element_name) |n| {
                    try writer.writeAll("<");
                    try writer.writeAll(n);
                    try writer.writeAll(">");
                }
            }
            if (value) |payload| {
                try serializeValue(payload, null, options, writer, depth);
            } else {
                // For null values, we'll write an empty element
                // We've already written the opening tag, so just close it immediately
                if (options.emit_null_optional_fields)
                    try writeClose(writer, element_name);
                return;
            }
        },
        .null => {
            // Empty element
        },
        .@"enum" => {
            try std.fmt.format(writer, "{s}", .{@tagName(value)});
        },
        .@"union" => |union_info| {
            if (union_info.tag_type) |_| {
                inline for (union_info.fields) |field| {
                    if (@field(std.meta.Tag(T), field.name) == std.meta.activeTag(value)) {
                        try serializeValue(
                            @field(value, field.name),
                            field.name,
                            options,
                            writer,
                            depth,
                        );
                        break;
                    }
                }
            } else {
                return error.UnsupportedType;
            }
        },
        else => return error.UnsupportedType,
    }

    try writeClose(writer, element_name);
}

fn writeClose(writer: anytype, element_name: ?[]const u8) !void {
    // Close element tag
    if (element_name) |n| {
        try writer.writeAll("</");
        try writer.writeAll(n);
        try writer.writeAll(">");
    }
}

/// Writes indentation based on depth and indent level
fn writeIndent(writer: anytype, depth: usize, whitespace: StringifyOptions.Whitespace) @TypeOf(writer).Error!void {
    var char: u8 = ' ';
    const n_chars = switch (whitespace) {
        .minified => return,
        .indent_1 => 1 * depth,
        .indent_2 => 2 * depth,
        .indent_3 => 3 * depth,
        .indent_4 => 4 * depth,
        .indent_8 => 8 * depth,
        .indent_tab => blk: {
            char = '\t';
            break :blk depth;
        },
    };
    try writer.writeByteNTimes(char, n_chars);
}

fn serializeString(
    writer: anytype,
    element_name: ?[]const u8,
    value: []const u8,
    options: StringifyOptions,
    depth: usize,
) @TypeOf(writer).Error!void {
    if (options.emit_strings_as_arrays) {
        // if (true) return error.seestackrun;
        for (value) |c| {
            try writeIndent(writer, depth + 1, options.whitespace);

            var buf: [256]u8 = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&buf);
            const alloc = fba.allocator();
            const item_name = try options.arrayElementNameConversion(alloc, element_name);
            if (item_name) |n| {
                try writer.writeAll("<");
                try writer.writeAll(n);
                try writer.writeAll(">");
            }
            try writer.print("{d}", .{c});
            try writeClose(writer, item_name);
            if (options.whitespace != .minified) {
                try writer.writeByte('\n');
            }
        }
        return;
    }
    try escapeString(writer, value);
}
/// Escapes special characters in XML strings
fn escapeString(writer: anytype, value: []const u8) @TypeOf(writer).Error!void {
    for (value) |c| {
        switch (c) {
            '&' => try writer.writeAll("&amp;"),
            '<' => try writer.writeAll("&lt;"),
            '>' => try writer.writeAll("&gt;"),
            '"' => try writer.writeAll("&quot;"),
            '\'' => try writer.writeAll("&apos;"),
            else => try writer.writeByte(c),
        }
    }
}

/// Does no transformation on the input array
pub fn arrayElementNoopTransformation(allocator: std.mem.Allocator, name: ?[]const u8) !?[]const u8 {
    _ = allocator;
    return name;
}

/// Attempts to convert a plural name to singular for array items
pub fn arrayElementPluralToSingluarTransformation(allocator: std.mem.Allocator, name: ?[]const u8) !?[]const u8 {
    if (name == null or name.?.len < 3) return name;

    const n = name.?;
    // There are a ton of these words, I'm just adding two for now
    // https://wordmom.com/nouns/end-e
    const es_exceptions = &[_][]const u8{
        "types",
        "bytes",
    };
    for (es_exceptions) |exception| {
        if (std.mem.eql(u8, exception, n)) {
            return n[0 .. n.len - 1];
        }
    }
    // Very basic English pluralization rules
    if (std.mem.endsWith(u8, n, "s")) {
        if (std.mem.endsWith(u8, n, "ies")) {
            // e.g., "entries" -> "entry"
            return try std.mem.concat(allocator, u8, &[_][]const u8{ n[0 .. n.len - 3], "y" });
        } else if (std.mem.endsWith(u8, n, "es")) {
            return n[0 .. n.len - 2]; // e.g., "boxes" -> "box"
        } else {
            return n[0 .. n.len - 1]; // e.g., "items" -> "item"
        }
    }

    return name; // Not recognized as plural
}

// Tests
test "stringify basic types" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test boolean
    {
        const result = try stringifyAlloc(allocator, true, .{});
        defer allocator.free(result);
        try testing.expectEqualStrings("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root>true</root>", result);
    }

    // Test comptime integer
    {
        const result = try stringifyAlloc(allocator, 42, .{});
        defer allocator.free(result);
        try testing.expectEqualStrings("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root>42</root>", result);
    }

    // Test integer
    {
        const result = try stringifyAlloc(allocator, @as(usize, 42), .{});
        defer allocator.free(result);
        try testing.expectEqualStrings("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root>42</root>", result);
    }

    // Test float
    {
        const result = try stringifyAlloc(allocator, 3.14, .{});
        defer allocator.free(result);
        try testing.expectEqualStrings("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root>3.14e0</root>", result);
    }

    // Test string
    {
        const result = try stringifyAlloc(allocator, "hello", .{});
        // @compileLog(@typeInfo(@TypeOf("hello")).pointer.size);
        // @compileLog(@typeName(@typeInfo(@TypeOf("hello")).pointer.child));
        defer allocator.free(result);
        try testing.expectEqualStrings("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root>hello</root>", result);
    }

    // Test string with special characters
    {
        const result = try stringifyAlloc(allocator, "hello & world < > \" '", .{});
        defer allocator.free(result);
        try testing.expectEqualStrings("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root>hello &amp; world &lt; &gt; &quot; &apos;</root>", result);
    }
}

test "stringify arrays" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test array of integers
    {
        const arr = [_]i32{ 1, 2, 3 };
        const result = try stringifyAlloc(allocator, arr, .{});
        defer allocator.free(result);
        try testing.expectEqualStrings("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root><root>1</root><root>2</root><root>3</root></root>", result);
    }

    // Test array of strings
    {
        const arr = [_][]const u8{ "one", "two", "three" };
        const result = try stringifyAlloc(allocator, arr, .{});
        defer allocator.free(result);
        try testing.expectEqualStrings("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root><root>one</root><root>two</root><root>three</root></root>", result);
    }

    // Test array with custom root name
    {
        const arr = [_]i32{ 1, 2, 3 };
        const result = try stringifyAlloc(allocator, arr, .{ .root_name = "items" });
        defer allocator.free(result);
        try testing.expectEqualStrings("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<items><item>1</item><item>2</item><item>3</item></items>", result);
    }
}

test "stringify structs" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const Person = struct {
        name: []const u8,
        age: u32,
        is_active: bool,
    };

    // Test basic struct
    {
        const person = Person{
            .name = "John",
            .age = 30,
            .is_active = true,
        };

        const result = try stringifyAlloc(allocator, person, .{});
        defer allocator.free(result);
        try testing.expectEqualStrings("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root><name>John</name><age>30</age><is_active>true</is_active></root>", result);
    }

    // Test struct with pretty printing
    {
        const person = Person{
            .name = "John",
            .age = 30,
            .is_active = true,
        };

        const result = try stringifyAlloc(allocator, person, .{ .whitespace = .indent_4 });
        defer allocator.free(result);
        try testing.expectEqualStrings("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root>\n    <name>John</name>\n    <age>30</age>\n    <is_active>true</is_active>\n</root>", result);
    }

    // Test nested struct
    {
        const Address = struct {
            street: []const u8,
            city: []const u8,
        };

        const PersonWithAddress = struct {
            name: []const u8,
            address: Address,
        };

        const person = PersonWithAddress{
            .name = "John",
            .address = Address{
                .street = "123 Main St",
                .city = "Anytown",
            },
        };

        const result = try stringifyAlloc(allocator, person, .{ .whitespace = .indent_4 });
        defer allocator.free(result);
        try testing.expectEqualStrings("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root>\n    <name>John</name>\n    <address>\n        <street>123 Main St</street>\n        <city>Anytown</city>\n    </address>\n</root>", result);
    }
}

test "stringify optional values" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const Person = struct {
        name: []const u8,
        middle_name: ?[]const u8,
    };

    // Test with present optional
    {
        const person = Person{
            .name = "John",
            .middle_name = "Robert",
        };

        const result = try stringifyAlloc(allocator, person, .{});
        defer allocator.free(result);
        try testing.expectEqualStrings("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root><name>John</name><middle_name>Robert</middle_name></root>", result);
    }

    // Test with null optional
    {
        const person = Person{
            .name = "John",
            .middle_name = null,
        };

        const result = try stringifyAlloc(allocator, person, .{});
        defer allocator.free(result);
        try testing.expectEqualStrings("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root><name>John</name><middle_name></middle_name></root>", result);
    }
}

test "stringify optional values with emit_null_optional_fields == false" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const Person = struct {
        name: []const u8,
        middle_name: ?[]const u8,
    };

    // Test with present optional
    {
        const person = Person{
            .name = "John",
            .middle_name = "Robert",
        };

        const result = try stringifyAlloc(allocator, person, .{ .emit_null_optional_fields = false });
        defer allocator.free(result);
        try testing.expectEqualStrings("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root><name>John</name><middle_name>Robert</middle_name></root>", result);
    }

    // Test with null optional
    {
        const person = Person{
            .name = "John",
            .middle_name = null,
        };

        const result = try stringifyAlloc(allocator, person, .{ .emit_null_optional_fields = false });
        defer allocator.free(result);
        try testing.expectEqualStrings("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root><name>John</name></root>", result);
    }
}

test "stringify with custom options" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const Person = struct {
        first_name: []const u8,
        last_name: []const u8,
    };

    const person = Person{
        .first_name = "John",
        .last_name = "Doe",
    };

    // Test without XML declaration
    {
        const result = try stringifyAlloc(allocator, person, .{ .include_declaration = false });
        defer allocator.free(result);
        try testing.expectEqualStrings("<root><first_name>John</first_name><last_name>Doe</last_name></root>", result);
    }

    // Test with custom root name
    {
        const result = try stringifyAlloc(allocator, person, .{ .root_name = "person" });
        defer allocator.free(result);
        try testing.expectEqualStrings("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<person><first_name>John</first_name><last_name>Doe</last_name></person>", result);
    }

    // Test with custom indent level
    {
        const result = try stringifyAlloc(allocator, person, .{ .whitespace = .indent_2 });
        defer allocator.free(result);
        try testing.expectEqualStrings(
            \\<?xml version="1.0" encoding="UTF-8"?>
            \\<root>
            \\  <first_name>John</first_name>
            \\  <last_name>Doe</last_name>
            \\</root>
        , result);
    }

    // Test with output []u8 as array
    {
        // pointer, size 1, child == .array, child.array.child == u8
        // @compileLog(@typeInfo(@typeInfo(@TypeOf("foo")).pointer.child));
        const result = try stringifyAlloc(allocator, "foo", .{ .emit_strings_as_arrays = true, .root_name = "bytes" });
        defer allocator.free(result);
        try testing.expectEqualStrings("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<bytes><byte>102</byte><byte>111</byte><byte>111</byte></bytes>", result);
    }
}

test "structs with custom field names" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const Person = struct {
        first_name: []const u8,
        last_name: []const u8,

        pub fn fieldNameFor(_: @This(), comptime field_name: []const u8) []const u8 {
            if (std.mem.eql(u8, field_name, "first_name")) return "GivenName";
            if (std.mem.eql(u8, field_name, "last_name")) return "FamilyName";
            unreachable;
        }
    };

    const person = Person{
        .first_name = "John",
        .last_name = "Doe",
    };

    {
        const result = try stringifyAlloc(allocator, person, .{ .whitespace = .indent_2 });
        defer allocator.free(result);
        try testing.expectEqualStrings(
            \\<?xml version="1.0" encoding="UTF-8"?>
            \\<root>
            \\  <GivenName>John</GivenName>
            \\  <FamilyName>Doe</FamilyName>
            \\</root>
        , result);
    }
}
