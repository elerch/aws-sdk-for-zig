const std = @import("std");
const log = std.log.scoped(.date);
const zeit = @import("zeit");

pub const DateTime = struct {
    day: u8,
    month: u8,
    year: u16,
    hour: u8,
    minute: u8,
    second: u8,

    pub fn fromInstant(val: zeit.Instant) DateTime {
        return fromTime(val.time());
    }

    pub fn fromTime(val: zeit.Time) DateTime {
        return DateTime{
            .day = val.day,
            .month = @intFromEnum(val.month),
            .year = @intCast(val.year),
            .hour = val.hour,
            .minute = val.minute,
            .second = val.second,
        };
    }

    pub fn time(self: DateTime) zeit.Time {
        return zeit.Time{
            .day = @intCast(self.day),
            .month = @enumFromInt(self.month),
            .year = self.year,
            .hour = @intCast(self.hour),
            .minute = @intCast(self.minute),
            .second = @intCast(self.second),
        };
    }

    pub fn instant(self: DateTime) !zeit.Instant {
        return try zeit.instant(.{ .source = .{ .time = self.time() } });
    }
};

pub fn timestampToDateTime(timestamp: zeit.Seconds) DateTime {
    const ins = zeit.instant(.{ .source = .{ .unix_timestamp = timestamp } }) catch @panic("Failed to create instant from timestamp");
    return DateTime.fromInstant(ins);
}

pub fn parseEnglishToTimestamp(data: []const u8) !i64 {
    return try dateTimeToTimestamp(try parseEnglishToDateTime(data));
}

/// Converts a string to a timestamp value. May not handle dates before the
/// epoch. Dates should look like "Fri, 03 Jun 2022 18:12:36 GMT"
pub fn parseEnglishToDateTime(data: []const u8) !DateTime {
    const ins = try zeit.instant(.{ .source = .{ .rfc1123 = data } });
    return DateTime.fromInstant(ins);
}

pub fn parseIso8601ToTimestamp(data: []const u8) !i64 {
    return try dateTimeToTimestamp(try parseIso8601ToDateTime(data));
}

/// Converts a string to a timestamp value. May not handle dates before the
/// epoch
pub fn parseIso8601ToDateTime(data: []const u8) !DateTime {
    const ins = try zeit.instant(.{ .source = .{ .iso8601 = data } });
    return DateTime.fromInstant(ins);
}

pub fn dateTimeToTimestamp(datetime: DateTime) !zeit.Seconds {
    return (try datetime.instant()).unixTimestamp();
}

fn printDateTime(dt: DateTime) void {
    log.debug("{:0>4}-{:0>2}-{:0>2}T{:0>2}:{:0>2}:{:0<2}Z", .{
        dt.year,
        dt.month,
        dt.day,
        dt.hour,
        dt.minute,
        dt.second,
    });
}

pub fn printNowUtc() void {
    printDateTime(timestampToDateTime(std.time.timestamp()));
}

test "Convert timestamp to datetime" {
    printDateTime(timestampToDateTime(std.time.timestamp()));
    try std.testing.expectEqual(DateTime{ .year = 2020, .month = 8, .day = 28, .hour = 9, .minute = 32, .second = 27 }, timestampToDateTime(1598607147));

    try std.testing.expectEqual(DateTime{ .year = 2020, .month = 11, .day = 1, .hour = 5, .minute = 6, .second = 7 }, timestampToDateTime(1604207167));
    // Get time for date: https://wtools.io/convert-date-time-to-unix-time
    try std.testing.expectEqual(DateTime{ .year = 2015, .month = 8, .day = 30, .hour = 12, .minute = 36, .second = 0 }, timestampToDateTime(1440938160));
}

test "Convert datetime to timestamp" {
    try std.testing.expectEqual(@as(i64, 1598607147), try dateTimeToTimestamp(DateTime{ .year = 2020, .month = 8, .day = 28, .hour = 9, .minute = 32, .second = 27 }));
    try std.testing.expectEqual(@as(i64, 1604207167), try dateTimeToTimestamp(DateTime{ .year = 2020, .month = 11, .day = 1, .hour = 5, .minute = 6, .second = 7 }));
    try std.testing.expectEqual(@as(i64, 1440938160), try dateTimeToTimestamp(DateTime{ .year = 2015, .month = 8, .day = 30, .hour = 12, .minute = 36, .second = 0 }));
}

test "Convert ISO8601 string to timestamp" {
    try std.testing.expectEqual(DateTime{ .year = 2020, .month = 8, .day = 28, .hour = 9, .minute = 32, .second = 27 }, try parseIso8601ToDateTime("20200828T093227"));
    try std.testing.expectEqual(DateTime{ .year = 2020, .month = 8, .day = 28, .hour = 9, .minute = 32, .second = 27 }, try parseIso8601ToDateTime("2020-08-28T9:32:27Z"));
    try std.testing.expectEqual(DateTime{ .year = 2020, .month = 11, .day = 1, .hour = 5, .minute = 6, .second = 7 }, try parseIso8601ToDateTime("2020-11-01T5:06:7Z"));
    try std.testing.expectEqual(DateTime{ .year = 2015, .month = 8, .day = 30, .hour = 12, .minute = 36, .second = 0 }, try parseIso8601ToDateTime("2015-08-30T12:36:00.000Z"));
}
test "Convert datetime to timestamp before 1970" {
    try std.testing.expectEqual(@as(i64, -449392815), try dateTimeToTimestamp(DateTime{ .year = 1955, .month = 10, .day = 5, .hour = 16, .minute = 39, .second = 45 }));
}

test "Convert whatever AWS is sending us to timestamp" {
    const string_date = "Fri, 03 Jun 2022 18:12:36 GMT";
    try std.testing.expectEqual(DateTime{ .year = 2022, .month = 6, .day = 3, .hour = 18, .minute = 12, .second = 36 }, try parseEnglishToDateTime(string_date));
}
