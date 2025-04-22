// From https://gist.github.com/WoodyAtHome/3ef50b17f0fa2860ac52b97af12f8d15
// Translated from German. We don't need any local time for this use case, and conversion
// really requires the TZ DB.

const std = @import("std");
const codegen_date = @import("date");

const log = std.log.scoped(.date);

pub const Timestamp = codegen_date.Timestamp;

pub const DateTime = struct { day: u8, month: u8, year: u16, hour: u8, minute: u8, second: u8 };

const SECONDS_PER_DAY = 86400; //*  24* 60 * 60 */
const DAYS_PER_YEAR = 365; //* Normal year (no leap year) */

pub fn timestampToDateTime(timestamp: i64) DateTime {

    // aus https://de.wikipedia.org/wiki/Unixzeit
    const unixtime = @as(u64, @intCast(timestamp));
    const DAYS_IN_4_YEARS = 1461; //*   4*365 +   1 */
    const DAYS_IN_100_YEARS = 36524; //* 100*365 +  25 - 1 */
    const DAYS_IN_400_YEARS = 146097; //* 400*365 + 100 - 4 + 1 */
    const DAY_NUMBER_ADJUSTED_1970_01_01 = 719468; //* Day number relates to March 1st */

    var dayN: u64 = DAY_NUMBER_ADJUSTED_1970_01_01 + unixtime / SECONDS_PER_DAY;
    const seconds_since_midnight: u64 = unixtime % SECONDS_PER_DAY;
    var temp: u64 = 0;

    // Leap year rules for Gregorian Calendars
    // Any year divisible by 100 is not a leap year unless also divisible by 400
    temp = 4 * (dayN + DAYS_IN_100_YEARS + 1) / DAYS_IN_400_YEARS - 1;
    var year = @as(u16, @intCast(100 * temp));
    dayN -= DAYS_IN_100_YEARS * temp + temp / 4;

    // For Julian calendars, each year divisible by 4 is a leap year
    temp = 4 * (dayN + DAYS_PER_YEAR + 1) / DAYS_IN_4_YEARS - 1;
    year += @as(u16, @intCast(temp));
    dayN -= DAYS_PER_YEAR * temp + temp / 4;

    // dayN calculates the days of the year in relation to March 1
    var month = @as(u8, @intCast((5 * dayN + 2) / 153));
    const day = @as(u8, @intCast(dayN - (@as(u64, @intCast(month)) * 153 + 2) / 5 + 1));
    //  153 = 31+30+31+30+31 Days for the 5 months from March through July
    //  153 = 31+30+31+30+31 Days for the 5 months from August through December
    //        31+28          Days for January and February (see below)
    //  +2: Rounding adjustment
    //  +1: The first day in March is March 1st (not March 0)

    month += 3; // Convert from the day that starts on March 1st, to a human year */
    if (month > 12) { // months 13 and 14 become 1 (January) und 2 (February) of the next year
        month -= 12;
        year += 1;
    }

    const hours = @as(u8, @intCast(seconds_since_midnight / 3600));
    const minutes = @as(u8, @intCast(seconds_since_midnight % 3600 / 60));
    const seconds = @as(u8, @intCast(seconds_since_midnight % 60));

    return DateTime{ .day = day, .month = month, .year = year, .hour = hours, .minute = minutes, .second = seconds };
}

pub fn parseEnglishToTimestamp(data: []const u8) !i64 {
    return try dateTimeToTimestamp(try parseEnglishToDateTime(data));
}

const EnglishParsingState = enum { Start, Day, Month, Year, Hour, Minute, Second, End };
/// Converts a string to a timestamp value. May not handle dates before the
/// epoch. Dates should look like "Fri, 03 Jun 2022 18:12:36 GMT"
pub fn parseEnglishToDateTime(data: []const u8) !DateTime {
    // Fri, 03 Jun 2022 18:12:36 GMT
    if (!std.mem.endsWith(u8, data, "GMT")) return error.InvalidFormat;

    var start: usize = 0;
    var state = EnglishParsingState.Start;
    // Anything not explicitly set by our string would be 0
    var rc = DateTime{ .year = 0, .month = 0, .day = 0, .hour = 0, .minute = 0, .second = 0 };
    for (data, 0..) |ch, i| {
        switch (ch) {
            ',' => {},
            ' ', ':' => {
                // State transition

                // We're going to coerce and this might not go well, but we
                // want the compiler to create checks, so we'll turn on
                // runtime safety for this block, forcing checks in ReleaseSafe
                // ReleaseFast modes.
                const next_state = try endEnglishState(state, &rc, data[start..i]);
                state = next_state;
                start = i + 1;
            },
            else => {}, // We need to be pretty trusting on this format...
        }
    }
    return rc;
}

fn endEnglishState(current_state: EnglishParsingState, date: *DateTime, prev_data: []const u8) !EnglishParsingState {
    var next_state: EnglishParsingState = undefined;
    log.debug("endEnglishState. Current state '{}', data: {s}", .{ current_state, prev_data });

    // Using two switches is slightly less efficient, but more readable
    switch (current_state) {
        .End => return error.IllegalStateTransition,
        .Start => next_state = .Day,
        .Day => next_state = .Month,
        .Month => next_state = .Year,
        .Year => next_state = .Hour,
        .Hour => next_state = .Minute,
        .Minute => next_state = .Second,
        .Second => next_state = .End,
    }

    switch (current_state) {
        .Year => date.year = try std.fmt.parseUnsigned(u16, prev_data, 10),
        .Month => date.month = try parseEnglishMonth(prev_data),
        .Day => date.day = try std.fmt.parseUnsigned(u8, prev_data, 10),
        .Hour => date.hour = try std.fmt.parseUnsigned(u8, prev_data, 10),
        .Minute => date.minute = try std.fmt.parseUnsigned(u8, prev_data, 10),
        .Second => date.second = try std.fmt.parseUnsigned(u8, prev_data, 10),
        .Start => {},
        .End => return error.InvalidState,
    }
    return next_state;
}

fn parseEnglishMonth(data: []const u8) !u8 {
    if (std.ascii.startsWithIgnoreCase(data, "Jan")) return 1;
    if (std.ascii.startsWithIgnoreCase(data, "Feb")) return 2;
    if (std.ascii.startsWithIgnoreCase(data, "Mar")) return 3;
    if (std.ascii.startsWithIgnoreCase(data, "Apr")) return 4;
    if (std.ascii.startsWithIgnoreCase(data, "May")) return 5;
    if (std.ascii.startsWithIgnoreCase(data, "Jun")) return 6;
    if (std.ascii.startsWithIgnoreCase(data, "Jul")) return 7;
    if (std.ascii.startsWithIgnoreCase(data, "Aug")) return 8;
    if (std.ascii.startsWithIgnoreCase(data, "Sep")) return 9;
    if (std.ascii.startsWithIgnoreCase(data, "Oct")) return 10;
    if (std.ascii.startsWithIgnoreCase(data, "Nov")) return 11;
    if (std.ascii.startsWithIgnoreCase(data, "Dec")) return 12;
    return error.InvalidMonth;
}
pub fn parseIso8601ToTimestamp(data: []const u8) !i64 {
    return try dateTimeToTimestamp(try parseIso8601ToDateTime(data));
}

const IsoParsingState = enum { Start, Year, Month, Day, Hour, Minute, Second, Millisecond, End };
/// Converts a string to a timestamp value. May not handle dates before the
/// epoch
pub fn parseIso8601ToDateTime(data: []const u8) !DateTime {
    // Basic format YYYYMMDDThhmmss
    if (data.len == "YYYYMMDDThhmmss".len and data[8] == 'T')
        return try parseIso8601BasicFormatToDateTime(data);
    if (data.len == "YYYYMMDDThhmmssZ".len and data[8] == 'T')
        return try parseIso8601BasicFormatToDateTime(data);

    var start: usize = 0;
    var state = IsoParsingState.Start;
    // Anything not explicitly set by our string would be 0
    var rc = DateTime{ .year = 0, .month = 0, .day = 0, .hour = 0, .minute = 0, .second = 0 };
    var zulu_time = false;
    for (data, 0..) |ch, i| {
        switch (ch) {
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' => {
                if (state == .Start) state = .Year;
            },
            '?', '~', '%' => {
                // These characters all specify the type of time (approximate, etc)
                // and we will ignore
            },
            '.', '-', ':', 'T' => {
                // State transition

                // We're going to coerce and this might not go well, but we
                // want the compiler to create checks, so we'll turn on
                // runtime safety for this block, forcing checks in ReleaseSafe
                // ReleaseFast modes.
                const next_state = try endIsoState(state, &rc, data[start..i]);
                state = next_state;
                start = i + 1;
            },
            'Z' => zulu_time = true,
            else => {
                log.err("Invalid character: {c}", .{ch});
                return error.InvalidCharacter;
            },
        }
    }
    if (!zulu_time) return error.LocalTimeNotSupported;
    // We know we have a Z at the end of this, so let's grab the last bit
    // of the string, minus the 'Z', and fly, eagles, fly!
    _ = try endIsoState(state, &rc, data[start .. data.len - 1]);
    return rc;
}

fn parseIso8601BasicFormatToDateTime(data: []const u8) !DateTime {
    return DateTime{
        .year = try std.fmt.parseUnsigned(u16, data[0..4], 10),
        .month = try std.fmt.parseUnsigned(u8, data[4..6], 10),
        .day = try std.fmt.parseUnsigned(u8, data[6..8], 10),
        .hour = try std.fmt.parseUnsigned(u8, data[9..11], 10),
        .minute = try std.fmt.parseUnsigned(u8, data[11..13], 10),
        .second = try std.fmt.parseUnsigned(u8, data[13..15], 10),
    };
}

fn endIsoState(current_state: IsoParsingState, date: *DateTime, prev_data: []const u8) !IsoParsingState {
    var next_state: IsoParsingState = undefined;
    log.debug("endIsoState. Current state '{}', data: {s}", .{ current_state, prev_data });

    // Using two switches is slightly less efficient, but more readable
    switch (current_state) {
        .Start, .End => return error.IllegalStateTransition,
        .Year => next_state = .Month,
        .Month => next_state = .Day,
        .Day => next_state = .Hour,
        .Hour => next_state = .Minute,
        .Minute => next_state = .Second,
        .Second => next_state = .Millisecond,
        .Millisecond => next_state = .End,
    }

    // TODO: This won't handle signed, which Iso supports. For now, let's fail
    // explictly
    switch (current_state) {
        .Year => date.year = try std.fmt.parseUnsigned(u16, prev_data, 10),
        .Month => date.month = try std.fmt.parseUnsigned(u8, prev_data, 10),
        .Day => date.day = try std.fmt.parseUnsigned(u8, prev_data, 10),
        .Hour => date.hour = try std.fmt.parseUnsigned(u8, prev_data, 10),
        .Minute => date.minute = try std.fmt.parseUnsigned(u8, prev_data, 10),
        .Second => date.second = try std.fmt.parseUnsigned(u8, prev_data, 10),
        .Millisecond => {}, // We'll throw that away - our granularity is 1 second
        .Start, .End => return error.InvalidState,
    }
    return next_state;
}
pub fn dateTimeToTimestamp(datetime: DateTime) !i64 {
    const epoch = DateTime{
        .year = 1970,
        .month = 1,
        .day = 1,
        .hour = 0,
        .minute = 0,
        .second = 0,
    };
    return secondsBetween(epoch, datetime);
}

const DateTimeToTimestampError = error{
    DateTimeOutOfRange,
};

fn secondsBetween(start: DateTime, end: DateTime) DateTimeToTimestampError!i64 {
    try validateDatetime(start);
    try validateDatetime(end);
    if (end.year < start.year) return -1 * try secondsBetween(end, start);
    if (start.month != 1 or
        start.day != 1 or
        start.hour != 0 or
        start.minute != 0 or
        start.second != 0)
    {
        const seconds_into_start_year = secondsFromBeginningOfYear(
            start.year,
            start.month,
            start.day,
            start.hour,
            start.minute,
            start.second,
        );
        const new_start = DateTime{
            .year = start.year,
            .month = 1,
            .day = 1,
            .hour = 0,
            .minute = 0,
            .second = 0,
        };
        return (try secondsBetween(new_start, end)) - seconds_into_start_year;
    }
    const leap_years_between = leapYearsBetween(start.year, end.year);
    const add_days: u1 = 0;
    const years_diff = end.year - start.year;
    // log.debug("Years from epoch: {d}, Leap years: {d}", .{ years_diff, leap_years_between });
    const days_diff: i32 = (years_diff * DAYS_PER_YEAR) + leap_years_between + add_days;
    // log.debug("Days with leap year, without month: {d}", .{days_diff});

    const seconds_into_year = secondsFromBeginningOfYear(
        end.year,
        end.month,
        end.day,
        end.hour,
        end.minute,
        end.second,
    );
    return (days_diff * SECONDS_PER_DAY) + @as(i64, seconds_into_year);
}

fn validateDatetime(dt: DateTime) !void {
    if (dt.month > 12 or
        dt.day > 31 or
        dt.hour >= 24 or
        dt.minute >= 60 or
        dt.second >= 60) return error.DateTimeOutOfRange;
}

fn secondsFromBeginningOfYear(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) u32 {
    const current_year_is_leap_year = isLeapYear(year);
    const leap_year_days_per_month: [12]u5 = .{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    const normal_days_per_month: [12]u5 = .{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    const days_per_month = if (current_year_is_leap_year) leap_year_days_per_month else normal_days_per_month;
    var current_month: usize = 1;
    const end_month = month;
    var days_diff: u32 = 0;
    while (current_month != end_month) {
        days_diff += days_per_month[current_month - 1]; // months are 1-based vs array is 0-based
        current_month += 1;
    }
    // log.debug("Days with month, without day: {d}. Day of month {d}, will add {d} days", .{
    //     days_diff,
    //     day,
    //     day - 1,
    // });
    // We need -1 because we're not actually including the ending day (that's up to hour/minute)
    // In other words, days in the month are 1-based, while hours/minutes are zero based
    days_diff += day - 1;
    // log.debug("Total days diff: {d}", .{days_diff});
    var seconds_diff: u32 = days_diff * SECONDS_PER_DAY;

    // From here out, we want to get everything into seconds
    seconds_diff += @as(u32, hour) * 60 * 60;
    seconds_diff += @as(u32, minute) * 60;
    seconds_diff += @as(u32, second);

    return seconds_diff;
}
fn isLeapYear(year: u16) bool {
    if (year % 4 != 0) return false;
    if (year % 400 == 0) return true;
    if (year % 100 == 0) return false;
    return true;
}

fn leapYearsBetween(start_year_inclusive: u16, end_year_exclusive: u16) u16 {
    const start = @min(start_year_inclusive, end_year_exclusive);
    const end = @max(start_year_inclusive, end_year_exclusive);
    var current = start;
    // log.debug("Leap years starting from {d}, ending at {d}", .{ start, end });
    while (current % 4 != 0 and current < end) {
        current += 1;
    }
    if (current == end) return 0; // No leap years here. E.g. 1971-1973
    // We're on a potential leap year, and now we can step by 4
    var rc: u16 = 0;
    while (current < end) {
        if (current % 4 == 0) {
            if (current % 100 != 0) {
                // log.debug("Year {d} is leap year", .{current});
                rc += 1;
                current += 4;
                continue;
            }
            // We're on a century, which is normally not a leap year, unless
            // it's divisible by 400
            if (current % 400 == 0) {
                // log.debug("Year {d} is leap year", .{current});
                rc += 1;
            }
        }
        current += 4;
    }
    return rc;
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
