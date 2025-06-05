const std = @import("std");
const case = @import("case");

const Allocator = std.mem.Allocator;

pub fn constantName(allocator: Allocator, id: []const u8, comptime to_case: case.Case) ![]const u8 {
    // There are some ids that don't follow consistent rules, so we'll
    // look for the exceptions and, if not found, revert to the snake case
    // algorithm

    var buf = std.mem.zeroes([256]u8);
    @memcpy(buf[0..id.len], id);

    var name = try allocator.dupe(u8, id);

    const simple_replacements = &.{
        &.{ "DevOps", "Devops" },
        &.{ "IoT", "Iot" },
        &.{ "FSx", "Fsx" },
        &.{ "CloudFront", "Cloudfront" },
    };

    inline for (simple_replacements) |rep| {
        if (std.mem.indexOf(u8, name, rep[0])) |idx| @memcpy(name[idx .. idx + rep[0].len], rep[1]);
    }

    if (to_case == .snake) {
        if (std.mem.eql(u8, id, "SESv2")) return try std.fmt.allocPrint(allocator, "ses_v2", .{});
        if (std.mem.eql(u8, id, "ETag")) return try std.fmt.allocPrint(allocator, "e_tag", .{});
    }

    return try case.allocTo(allocator, to_case, name);
}
