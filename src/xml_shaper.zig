const std = @import("std");
const xml = @import("xml.zig");

fn Parsed(comptime T: type) type {
    return struct {
        allocator: *std.mem.Allocator,
        parsed_value: T,

        const Self = @This();

        pub fn init(allocator: *std.mem.Allocator, parsedObj: T) Self {
            return .{
                .allocator = allocator,
                .parsed_value = parsedObj,
            };
        }

        pub fn deinit(self: Self) void {
            deinitObject(self.allocator, self.parsed_value);
        }

        fn deinitObject(allocator: *std.mem.Allocator, obj: anytype) void {
            switch (@typeInfo(@TypeOf(obj))) {
                .Optional => if (obj) |o| deinitObject(allocator, o),
                .Union => |union_info| {
                    inline for (union_info.fields) |field| {
                        std.debug.print("{s}", field); // need to find active field and deinit it
                    }
                },
                .Struct => |struct_info| {
                    inline for (struct_info.fields) |field| {
                        deinitObject(allocator, @field(obj, field.name));
                    }
                },
                .Array => {}, // Not implemented below
                .Pointer => |ptr_info| {
                    switch (ptr_info.size) {
                        .One => {
                            deinitObject(allocator, obj.*);
                            allocator.free(obj);
                        },
                        .Many => {},
                        .C => {},
                        .Slice => {
                            allocator.free(obj);
                        },
                    }
                },
                //.Bool, .Float, .ComptimeFloat, .Int, .ComptimeInt, .Enum, .Opaque => {}, // no allocations here
                else => {},
            }
        }
    };
}

pub fn Parser(comptime T: type) type {
    return struct {
        ParseType: type = T,
        ReturnType: type = Parsed(T),

        const Self = @This();

        pub fn parse(source: []const u8, options: ParseOptions) !Parsed(T) {
            if (options.allocator == null)
                return error.AllocatorRequired; // we are only leaving it be null for compatibility with json
            const allocator = options.allocator.?;
            const parse_allocator = std.heap.ArenaAllocator.init(allocator);
            const parsed = try xml.parse(allocator, source);
            defer parsed.deinit();
            defer parse_allocator.deinit();
            return Parsed(T).init(allocator, try parseInternal(T, parsed.root, options));
        }
    };
}
// should we just use json parse options?
pub const ParseOptions = struct {
    allocator: ?*std.mem.Allocator = null,
    match_predicate: ?fn (a: []const u8, b: []const u8, options: xml.PredicateOptions) anyerror!bool = null,
};

pub fn parse(comptime T: type, source: []const u8, options: ParseOptions) !Parsed(T) {
    if (options.allocator == null)
        return error.AllocatorRequired; // we are only leaving it be null for compatibility with json
    const allocator = options.allocator.?;
    const parse_allocator = std.heap.ArenaAllocator.init(allocator);
    const parsed = try xml.parse(allocator, source);
    defer parsed.deinit();
    defer parse_allocator.deinit();
    return Parsed(T).init(allocator, try parseInternal(T, parsed.root, options));
}

fn parseInternal(comptime T: type, element: *xml.Element, options: ParseOptions) !T {
    switch (@typeInfo(T)) {
        .Bool => {
            if (std.ascii.eqlIgnoreCase("true", element.children.items[0].CharData))
                return true;
            if (std.ascii.eqlIgnoreCase("false", element.children.items[0].CharData))
                return false;
            return error.UnexpectedToken;
        },
        .Float, .ComptimeFloat => {
            return try std.fmt.parseFloat(T, element.children.items[0].CharData);
        },
        .Int, .ComptimeInt => {
            return try std.fmt.parseInt(T, element.children.items[0].CharData, 10);
        },
        .Optional => |optional_info| {
            if (element.children.items.len == 0) {
                // This is almost certainly incomplete. Empty strings? xsi:nil?
                return null;
            } else {
                // return try parseInternal(optional_info.child, element.elements().next().?, options);
                return try parseInternal(optional_info.child, element, options);
            }
        },
        .Enum => |enum_info| {
            const numeric: ?enum_info.tag_type = std.fmt.parseInt(enumInfo.tag_type, element.children.items[0].CharData, 10) catch null;
            if (numeric) |num| {
                return std.meta.intToEnum(T, num);
            } else {
                // json parser handles escaping - could this happen here or does chardata handle?
                return std.meta.stringToEnum(T, element.CharData);
            }
        },
        .Union => |union_info| {
            if (union_info.tag_type) |_| {
                // try each of the union fields until we find one that matches
                inline for (union_info.fields) |u_field| {
                    // take a copy of tokens so we can withhold mutations until success
                    var tokens_copy = tokens.*;
                    if (parseInternal(u_field.field_type, token, &tokens_copy, options)) |value| {
                        tokens.* = tokens_copy;
                        return @unionInit(T, u_field.name, value);
                    } else |err| {
                        // Bubble up error.OutOfMemory
                        // Parsing some types won't have OutOfMemory in their
                        // error-sets, for the condition to be valid, merge it in.
                        if (@as(@TypeOf(err) || error{OutOfMemory}, err) == error.OutOfMemory) return err;
                        // Bubble up AllocatorRequired, as it indicates missing option
                        if (@as(@TypeOf(err) || error{AllocatorRequired}, err) == error.AllocatorRequired) return err;
                        // otherwise continue through the `inline for`
                    }
                }
                return error.NoUnionMembersMatched;
            } else {
                @compileError("Unable to parse into untagged union '" ++ @typeName(T) ++ "'");
            }
        },
        .Struct => |struct_info| {
            var r: T = undefined;
            var fields_seen = [_]bool{false} ** struct_info.fields.len;
            var fields_set: u64 = 0;
            // errdefer {
            //     // TODO: why so high here? This was needed for ec2 describe instances
            //     @setEvalBranchQuota(100000);
            //     inline for (struct_info.fields) |field, i| {
            //         if (fields_seen[i] and !field.is_comptime) {
            //             parseFree(field.field_type, @field(r, field.name), options);
            //         }
            //     }
            // }

            // XML parser provides CharData for whitespace around elements.
            // We shall ignore extra data for the moment as a performance thing
            // if (element.children.items.len > struct_info.fields.len) {
            //     std.debug.print("element children: {d}, struct fields: {d}\n", .{ element.children.items.len, struct_info.fields.len });
            //     for (element.children.items) |child, i| {
            //         switch (child) {
            //             .CharData => std.debug.print("{d}: {s}\n", .{ i, child }),
            //             .Comment => {},
            //             .Element => {},
            //         }
            //     }
            //     return error.MoreElementsThanFields;
            // }

            inline for (struct_info.fields) |field, i| {
                // std.debug.print("Field name: {s}, Element: {s}\n", .{ field.name, element.tag });
                var iterator = element.findChildrenByTag(field.name);
                if (options.match_predicate) |predicate| {
                    iterator.predicate = predicate;
                    iterator.predicate_options = .{ .allocator = options.allocator.? };
                }
                if (try iterator.next()) |child| {
                    // I don't know that we would use comptime here. I'm also
                    // not sure the nuance of setting this...
                    // if (field.is_comptime) {
                    //     if (!try parsesTo(field.field_type, field.default_value.?, tokens, options)) {
                    //         return error.UnexpectedValue;
                    //     }
                    // } else {
                    @field(r, field.name) = try parseInternal(field.field_type, child, options);
                    fields_seen[i] = true;
                    fields_set = fields_set + 1;
                    // }

                } else {
                    return error.NoValueForField;
                }
            }
            if (fields_set != struct_info.fields.len)
                return error.FieldElementMismatch; // see fields_seen for details
            return r;
        },
        .Array => //|array_info| {
        return error.ArrayNotImplemented,
        // switch (token) {
        //     .ArrayBegin => {
        //         var r: T = undefined;
        //         var i: usize = 0;
        //         errdefer {
        //             while (true) : (i -= 1) {
        //                 parseFree(arrayInfo.child, r[i], options);
        //                 if (i == 0) break;
        //             }
        //         }
        //         while (i < r.len) : (i += 1) {
        //             r[i] = try parse(arrayInfo.child, tokens, options);
        //         }
        //         const tok = (try tokens.next()) orelse return error.UnexpectedEndOfJson;
        //         switch (tok) {
        //             .ArrayEnd => {},
        //             else => return error.UnexpectedToken,
        //         }
        //         return r;
        //     },
        //     .String => |stringToken| {
        //         if (arrayInfo.child != u8) return error.UnexpectedToken;
        //         var r: T = undefined;
        //         const source_slice = stringToken.slice(tokens.slice, tokens.i - 1);
        //         switch (stringToken.escapes) {
        //             .None => mem.copy(u8, &r, source_slice),
        //             .Some => try unescapeValidString(&r, source_slice),
        //         }
        //         return r;
        //     },
        //     else => return error.UnexpectedToken,
        // }
        // },
        .Pointer => |ptr_info| {
            const allocator = options.allocator orelse return error.AllocatorRequired;
            switch (ptr_info.size) {
                .One => {
                    const r: T = try allocator.create(ptrInfo.child);
                    errdefer allocator.free(r);
                    r.* = try parseInternal(ptrInfo.child, element, options);
                    return r;
                },
                .Slice => {
                    // TODO: Detect and deal with arrays. This will require two
                    //       passes through the element children - one to
                    //       determine if it is an array, one to parse the elements
                    // <Items>
                    //   <Item>foo</Item>
                    //   <Item>bar</Item>
                    // <Items>
                    if (ptr_info.child != u8) return error.UnexpectedToken;
                    return try std.mem.dupe(allocator, u8, element.children.items[0].CharData);
                },
                .Many => {
                    return error.ManyPointerSizeNotImplemented;
                },
                .C => {
                    return error.CPointerSizeNotImplemented;
                },
            }
        },
        else => @compileError("Unable to parse into type '" ++ @typeName(T) ++ "'"),
        // }
        // },
        // else => @compileError("Unable to parse into type '" ++ @typeName(T) ++ "'"),
    }
    unreachable;
}
pub fn fuzzyEqual(a: []const u8, b: []const u8, options: xml.PredicateOptions) !bool {
    const allocator = options.allocator orelse return error.AllocatorRequired;
    // std.debug.print("raw: a = '{s}', b = '{s}'\n", .{ a, b });
    const lower_a = try std.ascii.allocLowerString(allocator, a);
    defer allocator.free(lower_a);
    const lower_b = try std.ascii.allocLowerString(allocator, b);
    defer allocator.free(lower_b);
    // std.debug.print("lower: a = '{s}', b = '{s}'\n", .{ lower_a, lower_b });
    const normal_a = normalize(lower_a);
    const normal_b = normalize(lower_b);

    // std.debug.print("normal: a = '{s}', b = '{s}'\n", .{ normal_a, normal_b });
    return std.mem.eql(u8, normal_a, normal_b);
}

fn normalize(val: []u8) []u8 {
    var underscores: u64 = 0;
    for (val) |ch, i| {
        if (ch == '_') {
            underscores = underscores + 1;
        } else {
            val[i - underscores] = ch;
        }
    }
    return val[0 .. val.len - underscores];
}

const testing = std.testing;
test "can parse a simple type" {
    const allocator = std.testing.allocator;
    // defer allocator.free(snake_case);
    const data =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<Example xmlns="http://example.example.com/doc/2016-11-15/">
        \\    <fooBar>bar</fooBar>
        \\</Example>
    ;
    const Example = struct {
        foo_bar: []const u8,
    };
    // std.debug.print("{s}", .{data});
    const parsed_data = try parse(Example, data, .{ .allocator = allocator, .match_predicate = fuzzyEqual });
    defer parsed_data.deinit();
    try testing.expectEqualStrings("bar", parsed_data.parsed_value.foo_bar);
}

test "can parse a boolean type" {
    const allocator = std.testing.allocator;
    // defer allocator.free(snake_case);
    const data =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<Example xmlns="http://example.example.com/doc/2016-11-15/">
        \\    <fooBar>true</fooBar>
        \\</Example>
    ;
    const Example = struct {
        foo_bar: bool,
    };
    // std.debug.print("{s}", .{data});
    const parsed_data = try parse(Example, data, .{ .allocator = allocator, .match_predicate = fuzzyEqual });
    defer parsed_data.deinit();
    try testing.expectEqual(true, parsed_data.parsed_value.foo_bar);
}
test "can parse an integer type" {
    const allocator = std.testing.allocator;
    // defer allocator.free(snake_case);
    const data =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<Example xmlns="http://example.example.com/doc/2016-11-15/">
        \\    <fooBar>42</fooBar>
        \\</Example>
    ;
    const Example = struct {
        foo_bar: u8,
    };
    // std.debug.print("{s}", .{data});
    const parsed_data = try parse(Example, data, .{ .allocator = allocator, .match_predicate = fuzzyEqual });
    defer parsed_data.deinit();
    try testing.expectEqual(@as(u8, 42), parsed_data.parsed_value.foo_bar);
}
test "can parse a boolean type" {
    const allocator = std.testing.allocator;
    // defer allocator.free(snake_case);
    const data =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<Example xmlns="http://example.example.com/doc/2016-11-15/">
        \\    <fooBar>true</fooBar>
        \\</Example>
    ;
    const Example = struct {
        foo_bar: bool,
    };
    // std.debug.print("{s}", .{data});
    const parsed_data = try parse(Example, data, .{ .allocator = allocator, .match_predicate = fuzzyEqual });
    defer parsed_data.deinit();
    try testing.expectEqual(true, parsed_data.parsed_value.foo_bar);
}
test "can parse an optional boolean type" {
    const allocator = std.testing.allocator;
    // defer allocator.free(snake_case);
    const data =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<Example xmlns="http://example.example.com/doc/2016-11-15/">
        \\    <fooBar>true</fooBar>
        \\</Example>
    ;
    const Example = struct {
        foo_bar: ?bool = null,
    };
    // std.debug.print("{s}", .{data});
    const parsed_data = try parse(Example, data, .{ .allocator = allocator, .match_predicate = fuzzyEqual });
    defer parsed_data.deinit();
    try testing.expectEqual(@as(?bool, true), parsed_data.parsed_value.foo_bar);
}
test "can parse a nested type" {
    const allocator = std.testing.allocator;
    // defer allocator.free(snake_case);
    const data =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<Example xmlns="http://example.example.com/doc/2016-11-15/">
        \\    <foo>
        \\        <bar>baz</bar>
        \\    </foo>
        \\</Example>
    ;
    const Example = struct {
        foo: struct {
            bar: []const u8,
        },
    };
    // std.debug.print("{s}", .{data});
    const parsed_data = try parse(Example, data, .{ .allocator = allocator, .match_predicate = fuzzyEqual });
    defer parsed_data.deinit();
    try testing.expectEqualStrings("baz", parsed_data.parsed_value.foo.bar);
}
