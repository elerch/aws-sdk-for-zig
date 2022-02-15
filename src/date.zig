// From https://gist.github.com/WoodyAtHome/3ef50b17f0fa2860ac52b97af12f8d15
// Translated from German. We don't need any local time for this use case, and conversion
// really requires the TZ DB.

const std = @import("std");

pub const DateTime = struct { day: u8, month: u8, year: u16, hour: u8, minute: u8, second: u8 };

const SECONDS_PER_DAY = 86400; //*  24* 60 * 60 */
const DAYS_PER_YEAR = 365; //* Normal year (no leap year) */

pub fn timestampToDateTime(timestamp: i64) DateTime {

    // aus https://de.wikipedia.org/wiki/Unixzeit
    const unixtime = @intCast(u64, timestamp);
    const DAYS_IN_4_YEARS = 1461; //*   4*365 +   1 */
    const DAYS_IN_100_YEARS = 36524; //* 100*365 +  25 - 1 */
    const DAYS_IN_400_YEARS = 146097; //* 400*365 + 100 - 4 + 1 */
    const DAY_NUMBER_ADJUSTED_1970_01_01 = 719468; //* Day number relates to March 1st */

    var dayN: u64 = DAY_NUMBER_ADJUSTED_1970_01_01 + unixtime / SECONDS_PER_DAY;
    var seconds_since_midnight: u64 = unixtime % SECONDS_PER_DAY;
    var temp: u64 = 0;

    // Leap year rules for Gregorian Calendars
    // Any year divisible by 100 is not a leap year unless also divisible by 400
    temp = 4 * (dayN + DAYS_IN_100_YEARS + 1) / DAYS_IN_400_YEARS - 1;
    var year = @intCast(u16, 100 * temp);
    dayN -= DAYS_IN_100_YEARS * temp + temp / 4;

    // For Julian calendars, each year divisible by 4 is a leap year
    temp = 4 * (dayN + DAYS_PER_YEAR + 1) / DAYS_IN_4_YEARS - 1;
    year += @intCast(u16, temp);
    dayN -= DAYS_PER_YEAR * temp + temp / 4;

    // dayN calculates the days of the year in relation to March 1
    var month = @intCast(u8, (5 * dayN + 2) / 153);
    var day = @intCast(u8, dayN - (@intCast(u64, month) * 153 + 2) / 5 + 1);
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

    var hours = @intCast(u8, seconds_since_midnight / 3600);
    var minutes = @intCast(u8, seconds_since_midnight % 3600 / 60);
    var seconds = @intCast(u8, seconds_since_midnight % 60);

    return DateTime{ .day = day, .month = month, .year = year, .hour = hours, .minute = minutes, .second = seconds };
}

/// Converts a string to a timestamp value. May not handle dates before the
/// epoch
pub fn parseIso8601Timestamp(data: []const u8) !i64 {
    _ = data;
    return error.NotImplemented;

    // TODO: Use a parsing for loop with a state machine implementation
    // to tell us where we are in the string
    // if (data.len < 4) return error.NotEnoughData;
    // var year = try std.fmt.parseInt(u8, data[0..4], 10);
    //
    // var month:u4 = 0;
    // if (data.len > 5) {
    //     if (data[5] != '-') return error.InvalidCharacter;
    //     var next_dash = std.mem.indexOf(u8, data[6..], "-");
    //     if (next_dash == null)
    //         next_dash = data.len - 6;
    //     month = std.fmt.parseInt(u8, data[6..next_dash + 6], 10);
    // }
    // var day:u5 = 0;
    // var hours: u5 = 0;
    // var minutes: u6 = 0;
    // var seconds: u6 = 0;
    // var milliseconds: u9 = 0;
    // ISO 8601 is complicated. We're going
}

fn dateTimeToTimestamp(datetime: DateTime) !i64 {
    if (datetime.month > 12 or
        datetime.day > 31 or
        datetime.hour >= 24 or
        datetime.minute >= 60 or
        datetime.second >= 60) return error.DateTimeOutOfRange;
    const epoch_year = 1970;
    if (datetime.year < epoch_year) return error.DatesBeforeEpochNotImplemented;
    const leap_years_between = leapYearsBetween(epoch_year, datetime.year);
    var add_days: u1 = 0;
    const years_diff = std.math.absCast(@as(i17, datetime.year) - @as(i17, epoch_year));
    std.log.debug("Years from epoch: {d}, Leap years: {d}", .{ years_diff, leap_years_between });
    var days_diff: i32 = (years_diff * DAYS_PER_YEAR) + leap_years_between + add_days;
    std.log.debug("Days with leap year, without month: {d}", .{days_diff});

    const seconds_into_year = secondsFromBeginningOfYear(
        datetime.year,
        datetime.month,
        datetime.day,
        datetime.hour,
        datetime.minute,
        datetime.second,
    );
    return (days_diff * SECONDS_PER_DAY) + @as(i64, seconds_into_year);
}

fn secondsFromBeginningOfYear(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) u32 {
    const current_year_is_leap_year = isLeapYear(year);
    const leap_year_days_per_month: [12]u5 = .{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    const normal_days_per_month: [12]u5 = .{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    const days_per_month = if (current_year_is_leap_year) leap_year_days_per_month else normal_days_per_month;
    var current_month: usize = 1;
    var end_month = month;
    var days_diff: u32 = 0;
    while (current_month != end_month) {
        days_diff += days_per_month[current_month - 1]; // months are 1-based vs array is 0-based
        current_month += 1;
    }
    std.log.debug("Days with month, without day: {d}. Day of month {d}, will add {d} days", .{
        days_diff,
        day,
        day - 1,
    });
    // We need -1 because we're not actually including the ending day (that's up to hour/minute)
    // In other words, days in the month are 1-based, while hours/minutes are zero based
    days_diff += day - 1;
    std.log.debug("Total days diff: {d}", .{days_diff});
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
    const start = std.math.min(start_year_inclusive, end_year_exclusive);
    const end = std.math.max(start_year_inclusive, end_year_exclusive);
    var current = start;
    std.log.debug("Leap years starting from {d}, ending at {d}", .{ start, end });
    while (current % 4 != 0 and current < end) {
        current += 1;
    }
    if (current == end) return 0; // No leap years here. E.g. 1971-1973
    // We're on a potential leap year, and now we can step by 4
    var rc: u16 = 0;
    while (current < end) {
        if (current % 4 == 0) {
            if (current % 100 != 0) {
                std.log.debug("Year {d} is leap year", .{current});
                rc += 1;
                current += 4;
                continue;
            }
            // We're on a century, which is normally not a leap year, unless
            // it's divisible by 400
            if (current % 400 == 0) {
                std.log.debug("Year {d} is leap year", .{current});
                rc += 1;
            }
        }
        current += 4;
    }
    return rc;
}

fn printDateTime(dt: DateTime) void {
    std.log.debug("{:0>4}-{:0>2}-{:0>2}T{:0>2}:{:0>2}:{:0<2}Z", .{
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
    try std.testing.expectEqual(DateTime{ .year = 2015, .month = 08, .day = 30, .hour = 12, .minute = 36, .second = 00 }, timestampToDateTime(1440938160));
}

test "Convert datetime to timestamp" {
    std.testing.log_level = .debug;
    std.log.debug("\n", .{});
    try std.testing.expectEqual(@as(i64, 1598607147), try dateTimeToTimestamp(DateTime{ .year = 2020, .month = 8, .day = 28, .hour = 9, .minute = 32, .second = 27 }));
    try std.testing.expectEqual(@as(i64, 1604207167), try dateTimeToTimestamp(DateTime{ .year = 2020, .month = 11, .day = 1, .hour = 5, .minute = 6, .second = 7 }));
    try std.testing.expectEqual(@as(i64, 1440938160), try dateTimeToTimestamp(DateTime{ .year = 2015, .month = 08, .day = 30, .hour = 12, .minute = 36, .second = 00 }));
}

test "Convert ISO8601 string to timestamp" {
    try std.testing.expectEqual(@as(i64, 1598607147), try dateTimeToTimestamp(DateTime{ .year = 2020, .month = 8, .day = 28, .hour = 9, .minute = 32, .second = 27 }));
    try std.testing.expectEqual(@as(i64, 1604207167), try dateTimeToTimestamp(DateTime{ .year = 2020, .month = 11, .day = 1, .hour = 5, .minute = 6, .second = 7 }));
    try std.testing.expectEqual(@as(i64, 1440938160), try dateTimeToTimestamp(DateTime{ .year = 2015, .month = 08, .day = 30, .hour = 12, .minute = 36, .second = 00 }));
}
// TODO: I think before epoch, the best approach is to flip the epoch and the
//       input date, calculate the answer, then flip signs. However, this requires
//       re-designing the algorithm to start from something other than midnight
//       January 1st. This will require an overhaul, so for now, we'll leave
//       this unimplemented.
//
// test "Convert datetime to timestamp before 1970" {
//     std.testing.log_level = .debug;
//     std.log.debug("\n", .{});
//     try std.testing.expectEqual(@as(i64, -449392815000), try dateTimeToTimestamp(DateTime{ .year = 1955, .month = 10, .day = 05, .hour = 16, .minute = 39, .second = 45 }));
//
//
//   1955.1 - .1 + x = 1970
// }
