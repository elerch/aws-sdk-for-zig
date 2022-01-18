// From https://gist.github.com/WoodyAtHome/3ef50b17f0fa2860ac52b97af12f8d15
// Translated from German. We don't need any local time for this use case, and conversion
// really requires the TZ DB.

const std = @import("std");

pub const DateTime = struct { day: u8, month: u8, year: u16, hour: u8, minute: u8, second: u8 };

pub fn timestampToDateTime(timestamp: i64) DateTime {

    // aus https://de.wikipedia.org/wiki/Unixzeit
    const unixtime = @intCast(u64, timestamp);
    const SECONDS_PER_DAY = 86400; //*  24* 60 * 60 */
    const DAYS_PER_YEAR = 365; //* Normal year (no leap year) */
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

pub fn printDateTime(dt: DateTime) void {
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

test "GMT and localtime" {
    std.testing.log_level = .debug;
    std.log.debug("\n", .{});
    printDateTime(timestampToDateTime(std.time.timestamp()));
    try std.testing.expectEqual(DateTime{ .year = 2020, .month = 8, .day = 28, .hour = 9, .minute = 32, .second = 27 }, timestampToDateTime(1598607147));

    try std.testing.expectEqual(DateTime{ .year = 2020, .month = 11, .day = 1, .hour = 5, .minute = 6, .second = 7 }, timestampToDateTime(1604207167));
    // Get time for date: https://wtools.io/convert-date-time-to-unix-time
    try std.testing.expectEqual(DateTime{ .year = 2015, .month = 08, .day = 30, .hour = 12, .minute = 36, .second = 00 }, timestampToDateTime(1440938160));
}
