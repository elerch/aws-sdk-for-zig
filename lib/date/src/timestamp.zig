const std = @import("std");
const zeit = @import("zeit");

pub const DateFormat = enum {
    rfc1123,
    iso8601,
};

pub const Timestamp = enum(zeit.Nanoseconds) {
    _,

    pub fn jsonStringify(value: Timestamp, jw: anytype) !void {
        const instant = instantWithoutIo(.{
            .source = .{
                .unix_nano = @intFromEnum(value),
            },
        }) catch std.debug.panic("Failed to parse timestamp to instant: {d}", .{value});

        const fmt = "Mon, 02 Jan 2006 15:04:05 GMT";
        var buf: [fmt.len]u8 = undefined;

        var fbs = std.Io.Writer.fixed(&buf);
        instant.time().gofmt(&fbs, fmt) catch std.debug.panic("Failed to format instant: {d}", .{instant.timestamp});

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

        const ins = try instantWithoutIo(.{
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

/// create a new Instant
pub fn instantWithoutIo(cfg: zeit.Instant.Config) !zeit.Instant {
    const ts: zeit.Nanoseconds = switch (cfg.source) {
        .now => return error.UseZeitInstantWithIoForNowInstants,
        .unix_timestamp => |unix| @as(i128, unix) * std.time.ns_per_s,
        .unix_nano => |nano| nano,
        .time => |time| time.instant().timestamp,
        .iso8601,
        .rfc3339,
        => |iso| blk: {
            const t = try zeit.Time.fromISO8601(iso);
            break :blk t.instant().timestamp;
        },
        .rfc2822,
        .rfc5322,
        => |eml| blk: {
            const t = try zeit.Time.fromRFC5322(eml);
            break :blk t.instant().timestamp;
        },
        .rfc1123 => |http_date| blk: {
            const t = try zeit.Time.fromRFC1123(http_date);
            break :blk t.instant().timestamp;
        },
    };
    return .{
        .timestamp = ts,
        .timezone = cfg.timezone,
    };
}

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
