const std = @import("std");
const zeit = @import("zeit");
const json = @import("json");

pub const DateFormat = enum {
    rfc1123,
    iso8601,
};

pub const Timestamp = enum(zeit.Nanoseconds) {
    _,

    pub fn jsonStringify(value: Timestamp, options: json.StringifyOptions, out_stream: anytype) !void {
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
