const std = @import("std");

pub fn encode(obj: anytype, writer: anytype, options: anytype) !void {
    try encodeStruct("", obj, writer, options);
}

fn encodeStruct(parent: []const u8, obj: anytype, writer: anytype, options: anytype) !void {
    var first = true;
    inline for (@typeInfo(@TypeOf(obj)).Struct.fields) |field| {
        const field_name = if (@hasField(@TypeOf(options), "field_name_transformer")) try options.field_name_transformer.transform(field.name) else field.name;
        defer {
            if (@hasField(@TypeOf(options), "field_name_transformer"))
                options.field_name_transformer.transform_deinit(field_name);
        }
        if (!first) _ = try writer.write("&");
        switch (@typeInfo(field.field_type)) {
            .Struct => {
                try encodeStruct(field_name ++ ".", @field(obj, field.name), writer);
            },
            else => try writer.print("{s}{s}={s}", .{ parent, field_name, @field(obj, field.name) }),
        }
        first = false;
    }
}

fn testencode(expected: []const u8, value: anytype, options: anytype) !void {
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
            // std.debug.print("{s}", .{bytes});
            if (self.expected_remaining.len < bytes.len) {
                std.debug.warn(
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
                std.debug.warn(
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
    try encode(value, vos.writer(), options);
    if (vos.expected_remaining.len > 0) return error.NotEnoughData;
}

test "can url encode an object" {
    try testencode(
        "Action=GetCallerIdentity&Version=2021-01-01",
        .{ .Action = "GetCallerIdentity", .Version = "2021-01-01" },
        .{},
    );
}
test "can url encode a complex object" {
    try testencode(
        "Action=GetCallerIdentity&Version=2021-01-01&complex.innermember=foo",
        .{ .Action = "GetCallerIdentity", .Version = "2021-01-01", .complex = .{ .innermember = "foo" } },
        .{},
    );
}
