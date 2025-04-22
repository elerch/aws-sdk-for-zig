const std = @import("std");
const zeit = @import("zeit");

const DateFormat = enum {
    rfc1123,
    iso8601,
};

pub const Timestamp = enum(zeit.Nanoseconds) {
    _,

    pub fn jsonStringify(value: Timestamp, options: anytype, out_stream: anytype) !void {
        _ = options;

        const instant = try zeit.instant(.{
            .source = .{
                .unix_nano = @intFromEnum(value),
            },
        });

        try out_stream.writeAll("\"");
        try instant.time().gofmt(out_stream, "Mon, 02 Jan 2006 15:04:05 GMT");
        try out_stream.writeAll("\"");
    }

    pub fn parse(val: []const u8) !Timestamp {
        const date_format = blk: {
            if (std.ascii.isDigit(val[0])) {
                break :blk DateFormat.iso8601;
            } else {
                break :blk DateFormat.rfc1123;
            }
        };

        const ins = try zeit.instant(.{
            .source = switch (date_format) {
                DateFormat.iso8601 => .{
                    .iso8601 = val,
                },
                DateFormat.rfc1123 => .{
                    .rfc1123 = val,
                },
            },
        });

        return @enumFromInt(ins.timestamp);
    }
};

test Timestamp {
    const http_date = try Timestamp.parse("Mon, 02 Jan 2006 15:04:05 GMT");
    try std.testing.expectEqual(1136214245000, http_date);
}
