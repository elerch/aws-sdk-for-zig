const std = @import("std");
const xml = @import("xml.zig");
const date = @import("date");

const log = std.log.scoped(.xml_shaper);

pub const Element = xml.Element;

pub fn Parsed(comptime T: type) type {
    return struct {
        // Forcing an arean allocator isn't my favorite choice here, but
        // is the simplest way to handle deallocation in the event of
        // an error
        allocator: std.heap.ArenaAllocator,
        parsed_value: T,
        document: xml.Document,

        const Self = @This();

        pub fn init(allocator: std.heap.ArenaAllocator, parsedObj: T, document: xml.Document) Self {
            return .{
                .allocator = allocator,
                .parsed_value = parsedObj,
                .document = document,
            };
        }

        pub fn deinit(self: Self) void {
            self.allocator.deinit();
            // deinitObject(self.allocator, self.parsed_value);
            // self.document.deinit();
        }
    };
}

// This is dead code and can be removed with the move to ArenaAllocator
fn deinitObject(allocator: std.mem.Allocator, obj: anytype) void {
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
                    for (obj) |child|
                        deinitObject(allocator, child);
                    allocator.free(obj);
                },
            }
        },
        //.Bool, .Float, .ComptimeFloat, .Int, .ComptimeInt, .Enum, .Opaque => {}, // no allocations here
        else => {},
    }
}

// should we just use json parse options?
pub const ParseOptions = struct {
    allocator: ?std.mem.Allocator = null,
    match_predicate_ptr: ?*const fn (a: []const u8, b: []const u8, options: xml.PredicateOptions) anyerror!bool = null,
    /// defines a function to use to locate an element other than the root of the document for parsing
    elementToParse: ?*const fn (element: *Element, options: ParseOptions) *Element = null,
};

pub fn parse(comptime T: type, source: []const u8, options: ParseOptions) !Parsed(T) {
    if (options.allocator == null)
        return error.AllocatorRequired; // we are only leaving it be null for compatibility with json
    const allocator = options.allocator.?;
    var arena_allocator = std.heap.ArenaAllocator.init(allocator);
    const aa = arena_allocator.allocator();
    errdefer arena_allocator.deinit();
    const parsed = try xml.parse(aa, source);
    errdefer parsed.deinit();
    const opts = ParseOptions{
        .allocator = aa,
        .match_predicate_ptr = options.match_predicate_ptr,
    };

    const root = if (options.elementToParse) |e| e(parsed.root, opts) else parsed.root;
    return Parsed(T).init(arena_allocator, try parseInternal(T, root, opts), parsed);
}

fn parseInternal(comptime T: type, element: *xml.Element, options: ParseOptions) !T {
    switch (@typeInfo(T)) {
        .bool => {
            if (std.ascii.eqlIgnoreCase("true", element.children.items[0].CharData))
                return true;
            if (std.ascii.eqlIgnoreCase("false", element.children.items[0].CharData))
                return false;
            return error.UnexpectedToken;
        },
        .float, .comptime_float => {
            return std.fmt.parseFloat(T, element.children.items[0].CharData) catch |e| {
                if (element.children.items[0].CharData[element.children.items[0].CharData.len - 1] == 'Z') {
                    // We have an iso8601 in an integer field (we think)
                    // Try to coerce this into our type
                    const timestamp = try date.parseIso8601ToTimestamp(element.children.items[0].CharData);
                    return @floatFromInt(timestamp);
                }
                if (log_parse_traces) {
                    std.log.err(
                        "Could not parse '{s}' as float in element '{s}': {any}",
                        .{
                            element.children.items[0].CharData,
                            element.tag,
                            e,
                        },
                    );
                    if (@errorReturnTrace()) |trace| {
                        std.debug.dumpStackTrace(trace.*);
                    }
                }
                return e;
            };
        },
        .int, .comptime_int => {
            // 2021-10-05T16:39:45.000Z
            return std.fmt.parseInt(T, element.children.items[0].CharData, 10) catch |e| {
                if (element.children.items[0].CharData[element.children.items[0].CharData.len - 1] == 'Z') {
                    // We have an iso8601 in an integer field (we think)
                    // Try to coerce this into our type
                    const timestamp = try date.parseIso8601ToTimestamp(element.children.items[0].CharData);
                    return std.math.cast(T, timestamp).?;
                }
                if (log_parse_traces) {
                    std.log.err(
                        "Could not parse '{s}' as integer in element '{s}': {any}",
                        .{
                            element.children.items[0].CharData,
                            element.tag,
                            e,
                        },
                    );
                    if (@errorReturnTrace()) |trace| {
                        std.debug.dumpStackTrace(trace.*);
                    }
                }
                return e;
            };
        },
        .optional => |optional_info| {
            if (element.children.items.len == 0) {
                // This is almost certainly incomplete. Empty strings? xsi:nil?
                return null;
            }
            if (element.children.items.len > 0) {
                // return try parseInternal(optional_info.child, element.elements().next().?, options);
                return try parseInternal(optional_info.child, element, options);
            }
        },
        .@"enum" => {
            if (T == date.Timestamp) {
                return try date.Timestamp.parse(element.children.items[0].CharData);
            }
            // const numeric: ?enum_info.tag_type = std.fmt.parseInt(enum_info.tag_type, element.children.items[0].CharData, 10) catch null;
            // if (numeric) |num| {
            //     return std.meta.intToEnum(T, num);
            // } else {
            //     // json parser handles escaping - could this happen here or does chardata handle?
            //     return std.meta.stringToEnum(T, element.CharData);
            // }
        },
        .@"union" => |union_info| {
            if (union_info.tag_type) |_| {
                // try each of the union fields until we find one that matches
                // inline for (union_info.fields) |u_field| {
                //     // take a copy of tokens so we can withhold mutations until success
                //     var tokens_copy = tokens.*;
                //     if (parseInternal(u_field.type, token, &tokens_copy, options)) |value| {
                //         tokens.* = tokens_copy;
                //         return @unionInit(T, u_field.name, value);
                //     } else |err| {
                //         // Bubble up error.OutOfMemory
                //         // Parsing some types won't have OutOfMemory in their
                //         // error-sets, for the condition to be valid, merge it in.
                //         if (@as(@TypeOf(err) || error{OutOfMemory}, err) == error.OutOfMemory) return err;
                //         // Bubble up AllocatorRequired, as it indicates missing option
                //         if (@as(@TypeOf(err) || error{AllocatorRequired}, err) == error.AllocatorRequired) return err;
                //         // otherwise continue through the `inline for`
                //     }
                // }
                return error.NoUnionMembersMatched;
            }
            @compileError("Unable to parse into untagged union '" ++ @typeName(T) ++ "'");
        },
        .@"struct" => |struct_info| {
            var r: T = undefined;
            var fields_seen = [_]bool{false} ** struct_info.fields.len;
            var fields_set: u64 = 0;
            // errdefer {
            //     // TODO: why so high here? This was needed for ec2 describe instances
            //     @setEvalBranchQuota(100000);
            //     inline for (struct_info.fields) |field, i| {
            //         if (fields_seen[i] and !field.is_comptime) {
            //             parseFree(field.type, @field(r, field.name), options);
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

            log.debug("Processing fields in struct: {s}", .{@typeName(T)});
            inline for (struct_info.fields, 0..) |field, i| {
                var name: []const u8 = field.name;
                var found_value = false;
                if (comptime std.meta.hasFn(T, "fieldNameFor"))
                    name = r.fieldNameFor(field.name);
                log.debug("Field name: {s}, Element: {s}, Adjusted field name: {s}", .{ field.name, element.tag, name });
                var iterator = element.findChildrenByTag(name);
                if (options.match_predicate_ptr) |predicate_ptr| {
                    iterator.predicate = predicate_ptr;
                    iterator.predicate_options = .{ .allocator = options.allocator.? };
                }
                if (try iterator.next()) |child| {
                    // I don't know that we would use comptime here. I'm also
                    // not sure the nuance of setting this...
                    // if (field.is_comptime) {
                    //     if (!try parsesTo(field.type, field.default_value.?, tokens, options)) {
                    //         return error.UnexpectedValue;
                    //     }
                    // } else {
                    log.debug("Found child element {s}", .{child.tag});
                    // TODO: how do we errdefer this?
                    @field(r, field.name) = try parseInternal(field.type, child, options);
                    fields_seen[i] = true;
                    fields_set = fields_set + 1;
                    found_value = true;
                }
                if (@typeInfo(field.type) == .optional) {
                    // Test "compiler assertion failure 2"
                    // Zig compiler bug circa 0.9.0. Using "and !found_value"
                    // in the if statement above will trigger assertion failure
                    if (!found_value) {
                        log.debug("Child element not found, but field optional. Setting {s}=null", .{field.name});
                        // @compileLog("Optional: Field name ", field.name, ", type ", field.type);
                        @field(r, field.name) = null;
                        fields_set = fields_set + 1;
                        found_value = true;
                    }
                }
                // Using this else clause breaks zig, so we'll use a boolean instead
                if (!found_value) {
                    log.err("Could not find a value for field {s}. Looking for {s} in element {s}", .{ field.name, name, element.tag });
                    return error.NoValueForField;
                }
                // } else {
                //     return error.NoValueForField;
                // }
            }
            if (fields_set != struct_info.fields.len)
                return error.FieldElementMismatch; // see fields_seen for details
            return r;
        },
        .array => //|array_info| {
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
        .pointer => |ptr_info| {
            const allocator = options.allocator orelse return error.AllocatorRequired;
            switch (ptr_info.size) {
                .one => {
                    const r: T = try allocator.create(ptr_info.child);
                    errdefer allocator.free(r);
                    r.* = try parseInternal(ptr_info.child, element, options);
                    return r;
                },
                .slice => {
                    // TODO: Detect and deal with arrays. This will require two
                    //       passes through the element children - one to
                    //       determine if it is an array, one to parse the elements
                    // <Items>
                    //   <Item>foo</Item>
                    //   <Item>bar</Item>
                    // <Items>
                    if (ptr_info.child != u8) {
                        log.debug("type = {s}, ptr_info.child == {s}, element = {s}", .{ @typeName(T), @typeName(ptr_info.child), element.tag });
                        var iterator = element.elements();
                        var children = std.ArrayList(ptr_info.child).init(allocator);
                        defer children.deinit();
                        while (iterator.next()) |child_element| {
                            try children.append(try parseInternal(ptr_info.child, child_element, options));
                        }
                        return children.toOwnedSlice();
                        // var inx: usize = 0;
                        // while (inx < children.len) {
                        //     switch (element.children.items[inx]) {
                        //         .Element => children[inx] = try parseInternal(ptr_info.child, element.children.items[inx].Element, options),
                        //         .CharData => children[inx] = try allocator.dupe(u8, element.children.items[inx].CharData),
                        //         .Comment => children[inx] = try allocator.dupe(u8, element.children.items[inx].Comment), // This might be an error...
                        //     }
                        //     inx += 1;
                        // }
                    }
                    return try allocator.dupe(u8, element.children.items[0].CharData);
                },
                .many => {
                    return error.ManyPointerSizeNotImplemented;
                },
                .c => {
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
    var underscores: usize = 0;
    for (val, 0..) |ch, i| {
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
    const parsed_data = try parse(Example, data, .{ .allocator = allocator, .match_predicate_ptr = fuzzyEqual });
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
    const parsed_data = try parse(Example, data, .{ .allocator = allocator, .match_predicate_ptr = fuzzyEqual });
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
    const parsed_data = try parse(Example, data, .{ .allocator = allocator, .match_predicate_ptr = fuzzyEqual });
    defer parsed_data.deinit();
    try testing.expectEqual(@as(u8, 42), parsed_data.parsed_value.foo_bar);
}
test "can parse an optional boolean type" {
    const allocator = std.testing.allocator;
    const data =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<Example xmlns="http://example.example.com/doc/2016-11-15/">
        \\    <fooBar>true</fooBar>
        \\</Example>
    ;
    const ExampleDoesNotMatter = struct {
        foo_bar: ?bool = null,
    };
    const parsed_data = try parse(ExampleDoesNotMatter, data, .{ .allocator = allocator, .match_predicate_ptr = fuzzyEqual });
    defer parsed_data.deinit();
    try testing.expectEqual(@as(?bool, true), parsed_data.parsed_value.foo_bar);
}

test "can coerce 8601 date to integer" {
    const allocator = std.testing.allocator;
    const data =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<Example xmlns="http://example.example.com/doc/2016-11-15/">
        \\    <fooBar>2021-10-05T16:39:45.000Z</fooBar>
        \\</Example>
    ;
    const ExampleDoesNotMatter = struct {
        foo_bar: ?i64 = null,
    };
    const parsed_data = try parse(ExampleDoesNotMatter, data, .{ .allocator = allocator, .match_predicate_ptr = fuzzyEqual });
    defer parsed_data.deinit();
    try testing.expectEqual(@as(i64, 1633451985), parsed_data.parsed_value.foo_bar.?);
}
// This is the simplest test so far that breaks zig (circa 0.9.0)
// See "Using this else clause breaks zig, so we'll use a boolean instead"
test "can parse a boolean type (two fields)" {
    const allocator = std.testing.allocator;
    const data =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<Example xmlns="http://example.example.com/doc/2016-11-15/">
        \\    <fooBar>true</fooBar>
        \\    <fooBaz>true</fooBaz>
        \\</Example>
    ;
    const ExampleDoesNotMatter = struct {
        foo_bar: bool,
        foo_baz: bool,
    };
    const parsed_data = try parse(ExampleDoesNotMatter, data, .{ .allocator = allocator, .match_predicate_ptr = fuzzyEqual });
    defer parsed_data.deinit();
    try testing.expectEqual(@as(bool, true), parsed_data.parsed_value.foo_bar);
}
var log_parse_traces = true;
test "can error without leaking memory" {
    const allocator = std.testing.allocator;
    const data =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<Example xmlns="http://example.example.com/doc/2016-11-15/">
        \\    <fooBar>true</fooBar>
        \\    <fooBaz>12.345</fooBaz>
        \\</Example>
    ;
    const ExampleDoesNotMatter = struct {
        foo_bar: bool,
        foo_baz: u64,
    };
    log_parse_traces = false;
    defer log_parse_traces = true;
    try std.testing.expectError(
        error.InvalidCharacter,
        parse(ExampleDoesNotMatter, data, .{ .allocator = allocator, .match_predicate_ptr = fuzzyEqual }),
    );
}

test "can parse a nested type" {
    const allocator = std.testing.allocator;
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
    const parsed_data = try parse(Example, data, .{ .allocator = allocator, .match_predicate_ptr = fuzzyEqual });
    defer parsed_data.deinit();
    try testing.expectEqualStrings("baz", parsed_data.parsed_value.foo.bar);
}
test "can parse a nested type - two fields" {
    const allocator = std.testing.allocator;
    const data =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<Example xmlns="http://example.example.com/doc/2016-11-15/">
        \\    <foo>
        \\        <bar>baz</bar>
        \\        <qux>baz</qux>
        \\    </foo>
        \\</Example>
    ;
    const Example = struct {
        foo: struct {
            bar: []const u8,
            qux: []const u8,
        },
    };
    const parsed_data = try parse(Example, data, .{ .allocator = allocator, .match_predicate_ptr = fuzzyEqual });
    defer parsed_data.deinit();
    try testing.expectEqualStrings("baz", parsed_data.parsed_value.foo.bar);
    try testing.expectEqualStrings("baz", parsed_data.parsed_value.foo.qux);
}

const service_metadata: struct {
    version: []const u8 = "2016-11-15",
    sdk_id: []const u8 = "EC2",
    arn_namespace: []const u8 = "ec2",
    endpoint_prefix: []const u8 = "ec2",
    sigv4_name: []const u8 = "ec2",
    name: []const u8 = "AmazonEC2",
} = .{};

const describe_regions: struct {
    action_name: []const u8 = "DescribeRegions",
    Request: type = struct {
        // filters: ?[]Filter = null,
        region_names: ?[][]const u8 = null,
        dry_run: ?bool = null,
        all_regions: ?bool = null,

        pub fn fieldNameFor(_: @This(), comptime field_name: []const u8) []const u8 {
            const mappings = .{
                .filters = "Filter",
                .region_names = "RegionName",
                .dry_run = "dryRun",
                .all_regions = "AllRegions",
            };
            return @field(mappings, field_name);
        }

        pub fn metaInfo() struct { service_metadata: @TypeOf(service_metadata), action: @TypeOf(describe_regions) } {
            return .{ .service_metadata = service_metadata, .action = describe_regions };
        }
    },
    Response: type = struct {
        regions: ?[]struct {
            // Having two of these causes the zig compiler bug
            // Only one of them works fine. This leads me to believe that
            // it has something to do with the inline for
            endpoint: ?[]const u8 = null,
            region_name: ?[]const u8 = null,

            pub fn fieldNameFor(_: @This(), comptime field_name: []const u8) []const u8 {
                const mappings = .{
                    .endpoint = "regionEndpoint",
                    .region_name = "regionName",
                    .opt_in_status = "optInStatus",
                };
                return @field(mappings, field_name);
            }
        } = null,

        pub fn fieldNameFor(_: @This(), comptime field_name: []const u8) []const u8 {
            const mappings = .{
                .regions = "regionInfo",
            };
            return @field(mappings, field_name);
        }
    },
} = .{};

test "can parse something serious" {
    // std.testing.log_level = .debug;
    log.debug("", .{});

    const allocator = std.testing.allocator;
    const data =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<DescribeRegionsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
        \\    <requestId>8d6bfc99-978b-4146-ba23-2e5fe5b65406</requestId>
        \\    <regionInfo>
        \\        <item>
        \\            <regionName>eu-north-1</regionName>
        \\            <regionEndpoint>ec2.eu-north-1.amazonaws.com</regionEndpoint>
        \\        </item>
        \\        <item>
        \\            <regionName>ap-south-1</regionName>
        \\            <regionEndpoint>ec2.ap-south-1.amazonaws.com</regionEndpoint>
        \\        </item>
        \\    </regionInfo>
        \\</DescribeRegionsResponse>
    ;
    // const ServerResponse = struct { DescribeRegionsResponse: describe_regions.Response, };
    const parsed_data = try parse(describe_regions.Response, data, .{ .allocator = allocator, .elementToParse = findResult });
    defer parsed_data.deinit();
    try testing.expect(parsed_data.parsed_value.regions != null);
    try testing.expectEqualStrings("eu-north-1", parsed_data.parsed_value.regions.?[0].region_name.?);
    try testing.expectEqualStrings("ec2.eu-north-1.amazonaws.com", parsed_data.parsed_value.regions.?[0].endpoint.?);
}
const StsGetAccesskeyInfoResponse: type = struct {
    account: ?[]const u8 = null,

    pub fn fieldNameFor(_: @This(), comptime field_name: []const u8) []const u8 {
        const mappings = .{
            .account = "Account",
        };
        return @field(mappings, field_name);
    }
};
fn findResult(element: *xml.Element, options: ParseOptions) *xml.Element {
    _ = options;
    // We're looking for a very specific pattern here. We want only two direct
    // children. The first one must end with "Result", and the second should
    // be our ResponseMetadata node
    var children = element.elements();
    var found_metadata = false;
    var result_child: ?*xml.Element = null;
    var inx: usize = 0;
    while (children.next()) |child| : (inx += 1) {
        if (std.mem.eql(u8, child.tag, "ResponseMetadata")) {
            found_metadata = true;
            continue;
        }
        if (std.mem.endsWith(u8, child.tag, "Result")) {
            result_child = child;
            continue;
        }
        if (inx > 1) return element;
        return element; // It should only be those two
    }
    return result_child orelse element;
}
test "can parse a result within a response" {
    log.debug("", .{});

    const allocator = std.testing.allocator;
    const data =
        \\<GetAccessKeyInfoResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
        \\  <GetAccessKeyInfoResult>
        \\    <Account>123456789012</Account>
        \\  </GetAccessKeyInfoResult>
        \\  <ResponseMetadata>
        \\    <RequestId>ec85bf29-1ef0-459a-930e-6446dd14a286</RequestId>
        \\  </ResponseMetadata>
        \\</GetAccessKeyInfoResponse>
    ;
    const parsed_data = try parse(StsGetAccesskeyInfoResponse, data, .{ .allocator = allocator, .elementToParse = findResult });
    defer parsed_data.deinit();
    // Response expectations
    try std.testing.expect(parsed_data.parsed_value.account != null);
    try std.testing.expectEqualStrings("123456789012", parsed_data.parsed_value.account.?);
}

test "compiler assertion failure 2" {
    // std.testing.log_level = .debug;
    // log.debug("", .{});
    // Actually, we only care here that the code compiles
    const allocator = std.testing.allocator;
    const Response: type = struct {
        key_group_list: ?struct {
            quantity: i64, // Making this optional will make the code compile
            items: ?[]struct {
                key_group: []const u8,
            } = null,
            pub fn fieldNameFor(_: @This(), comptime field_name: []const u8) []const u8 {
                const mappings = .{
                    .quantity = "Quantity",
                    .items = "Items",
                };
                return @field(mappings, field_name);
            }
        } = null,

        pub fn fieldNameFor(_: @This(), comptime field_name: []const u8) []const u8 {
            const mappings = .{
                .key_group_list = "KeyGroupList",
            };
            return @field(mappings, field_name);
        }
    };
    const data =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<AnythingAtAll xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
        \\    <KeyGroupList>
        \\        <Quantity>42</Quantity>
        \\    </KeyGroupList>
        \\</AnythingAtAll>
    ;
    const parsed_data = try parse(Response, data, .{ .allocator = allocator });
    defer parsed_data.deinit();
    try testing.expect(parsed_data.parsed_value.key_group_list.?.quantity == 42);
}
