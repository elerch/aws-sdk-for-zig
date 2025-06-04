const std = @import("std");
const zeit = @import("zeit");

pub const DateFormat = enum {
    rfc1123,
    iso8601,
};

pub const Timestamp = enum(zeit.Nanoseconds) {
    _,

    pub fn jsonStringify(value: Timestamp, jw: anytype) !void {
        const instant = zeit.instant(.{
            .source = .{
                .unix_nano = @intFromEnum(value),
            },
        }) catch std.debug.panic("Failed to parse timestamp to instant: {d}", .{value});

        const fmt = "Mon, 02 Jan 2006 15:04:05 GMT";
        var buf = std.mem.zeroes([fmt.len]u8);

        var fbs = std.io.fixedBufferStream(&buf);
        instant.time().gofmt(fbs.writer(), fmt) catch std.debug.panic("Failed to format instant: {d}", .{instant.timestamp});

        try jw.write(&buf);
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
    const in_date = "Wed, 23 Apr 2025 11:23:45 GMT";

    const expected_ts: Timestamp = @enumFromInt(1745407425000000000);
    const actual_ts = try Timestamp.parse(in_date);

    try std.testing.expectEqual(expected_ts, actual_ts);

    var buf: [100]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    var counting_writer = std.io.countingWriter(fbs.writer());
    try Timestamp.jsonStringify(expected_ts, .{}, counting_writer.writer());

    const expected_json = "\"" ++ in_date ++ "\"";
    const actual_json = buf[0..counting_writer.bytes_written];

    try std.testing.expectEqualStrings(expected_json, actual_json);
}
