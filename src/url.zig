const std = @import("std");

fn defaultTransformer(allocator: std.mem.Allocator, field_name: []const u8) anyerror![]const u8 {
    _ = allocator;
    return field_name;
}

pub const fieldNameTransformerFn = *const fn (std.mem.Allocator, []const u8) anyerror![]const u8;

pub const EncodingOptions = struct {
    field_name_transformer: fieldNameTransformerFn = defaultTransformer,
};

pub fn encode(allocator: std.mem.Allocator, obj: anytype, writer: anytype, comptime options: EncodingOptions) !void {
    _ = try encodeInternal(allocator, "", "", true, obj, writer, options);
}

fn encodeStruct(
    allocator: std.mem.Allocator,
    parent: []const u8,
    first: bool,
    obj: anytype,
    writer: anytype,
    comptime options: EncodingOptions,
) !bool {
    var rc = first;
    inline for (@typeInfo(@TypeOf(obj)).@"struct".fields) |field| {
        const field_name = try options.field_name_transformer(allocator, field.name);
        defer if (options.field_name_transformer.* != defaultTransformer)
            allocator.free(field_name);
        // @compileLog(@typeInfo(field.field_type).Pointer);
        rc = try encodeInternal(allocator, parent, field_name, rc, @field(obj, field.name), writer, options);
    }
    return rc;
}

pub fn encodeInternal(
    allocator: std.mem.Allocator,
    parent: []const u8,
    field_name: []const u8,
    first: bool,
    obj: anytype,
    writer: anytype,
    comptime options: EncodingOptions,
) !bool {
    // @compileLog(@typeName(@TypeOf(obj)));
    // @compileLog(@typeInfo(@TypeOf(obj)));
    var rc = first;
    switch (@typeInfo(@TypeOf(obj))) {
        .optional => if (obj) |o| {
            rc = try encodeInternal(allocator, parent, field_name, first, o, writer, options);
        },
        .pointer => |ti| if (ti.size == .One) {
            rc = try encodeInternal(allocator, parent, field_name, first, obj.*, writer, options);
        } else {
            if (!first) _ = try writer.write("&");
            // @compileLog(@typeInfo(@TypeOf(obj)));
            if (ti.child == []const u8 or ti.child == u8)
                try writer.print("{s}{s}={s}", .{ parent, field_name, obj })
            else
                try writer.print("{s}{s}={any}", .{ parent, field_name, obj });
            rc = false;
        },
        .@"struct" => if (std.mem.eql(u8, "", field_name)) {
            rc = try encodeStruct(allocator, parent, first, obj, writer, options);
        } else {
            // TODO: It would be lovely if we could concat at compile time or allocPrint at runtime
            // XOR have compile time allocator support. Alas, neither are possible:
            // https://github.com/ziglang/zig/issues/868: Comptime detection (feels like foot gun)
            // https://github.com/ziglang/zig/issues/1291: Comptime allocator
            const new_parent = try std.fmt.allocPrint(allocator, "{s}{s}.", .{ parent, field_name });
            defer allocator.free(new_parent);
            rc = try encodeStruct(allocator, new_parent, first, obj, writer, options);
            // try encodeStruct(parent ++ field_name ++ ".", first, obj,  writer, options);
        },
        .array => {
            if (!first) _ = try writer.write("&");
            try writer.print("{s}{s}={s}", .{ parent, field_name, obj });
            rc = false;
        },
        .int, .comptime_int, .float, .comptime_float => {
            if (!first) _ = try writer.write("&");
            try writer.print("{s}{s}={d}", .{ parent, field_name, obj });
            rc = false;
        },
        // BUGS! any doesn't work - a lot. Check this out:
        // https://github.com/ziglang/zig/blob/master/lib/std/fmt.zig#L424
        else => {
            if (!first) _ = try writer.write("&");
            try writer.print("{s}{s}={any}", .{ parent, field_name, obj });
            rc = false;
        },
    }
    return rc;
}

fn testencode(allocator: std.mem.Allocator, expected: []const u8, value: anytype, comptime options: EncodingOptions) !void {
    const ValidationWriter = struct {
        const Self = @This();
        pub const Writer = std.io.Writer(*Self, Error, write);
        pub const Error = error{
            TooMuchData,
            DifferentData,
        };

        expected_remaining: []const u8,

        fn init(exp: []const u8) Self {
            return .{ .expected_remaining = exp };
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }

        fn write(self: *Self, bytes: []const u8) Error!usize {
            // std.debug.print("{s}\n", .{bytes});
            if (self.expected_remaining.len < bytes.len) {
                std.log.warn(
                    \\====== expected this output: =========
                    \\{s}
                    \\======== instead found this: =========
                    \\{s}
                    \\======================================
                , .{
                    self.expected_remaining,
                    bytes,
                });
                return error.TooMuchData;
            }
            if (!std.mem.eql(u8, self.expected_remaining[0..bytes.len], bytes)) {
                std.log.warn(
                    \\====== expected this output: =========
                    \\{s}
                    \\======== instead found this: =========
                    \\{s}
                    \\======================================
                , .{
                    self.expected_remaining[0..bytes.len],
                    bytes,
                });
                return error.DifferentData;
            }
            self.expected_remaining = self.expected_remaining[bytes.len..];
            return bytes.len;
        }
    };

    var vos = ValidationWriter.init(expected);
    try encode(allocator, value, vos.writer(), options);
    if (vos.expected_remaining.len > 0) return error.NotEnoughData;
}

test "can urlencode an object" {
    try testencode(
        std.testing.allocator,
        "Action=GetCallerIdentity&Version=2021-01-01",
        .{ .Action = "GetCallerIdentity", .Version = "2021-01-01" },
        .{},
    );
}
test "can urlencode an object with integer" {
    try testencode(
        std.testing.allocator,
        "Action=GetCallerIdentity&Duration=32",
        .{ .Action = "GetCallerIdentity", .Duration = 32 },
        .{},
    );
}
const UnsetValues = struct {
    action: ?[]const u8 = null,
    duration: ?i64 = null,
    val1: ?i64 = null,
    val2: ?[]const u8 = null,
};
test "can urlencode an object with unset values" {
    // var buffer = std.ArrayList(u8).init(std.testing.allocator);
    // defer buffer.deinit();
    // const writer = buffer.writer();
    // try encode(
    //     std.testing.allocator,
    //     UnsetValues{ .action = "GetCallerIdentity", .duration = 32 },
    //     writer,
    //     .{},
    // );
    // std.debug.print("\n\nEncoded as '{s}'\n", .{buffer.items});
    try testencode(
        std.testing.allocator,
        "action=GetCallerIdentity&duration=32",
        UnsetValues{ .action = "GetCallerIdentity", .duration = 32 },
        .{},
    );
}
test "can urlencode a complex object" {
    try testencode(
        std.testing.allocator,
        "Action=GetCallerIdentity&Version=2021-01-01&complex.innermember=foo",
        .{ .Action = "GetCallerIdentity", .Version = "2021-01-01", .complex = .{ .innermember = "foo" } },
        .{},
    );
}

const Filter = struct {
    name: ?[]const u8 = null,
    values: ?[][]const u8 = null,

    pub fn fieldNameFor(_: @This(), comptime field_name: []const u8) []const u8 {
        const mappings = .{
            .name = "Name",
            .values = "Value",
        };
        return @field(mappings, field_name);
    }
};

const Request: type = struct {
    filters: ?[]Filter = null,
    region_names: ?[][]const u8 = null,
    dry_run: ?bool = null,
    all_regions: ?bool = null,
};
test "can urlencode an EC2 Filter" {
    // TODO: Fix this encoding...
    testencode(
        std.testing.allocator,
        "filters={ url.Filter{ .name = { 102, 111, 111 }, .values = { { ... } } } }",
        Request{
            .filters = @constCast(&[_]Filter{.{ .name = "foo", .values = @constCast(&[_][]const u8{"bar"}) }}),
        },
        .{},
    ) catch |err| {
        var al = std.ArrayList(u8).init(std.testing.allocator);
        defer al.deinit();
        try encode(
            std.testing.allocator,
            Request{
                .filters = @constCast(&[_]Filter{.{ .name = "foo", .values = @constCast(&[_][]const u8{"bar"}) }}),
            },
            al.writer(),
            .{},
        );
        std.log.warn("Error found. Full encoding is '{s}'", .{al.items});
        return err;
    };
}
