const std = @import("std");
const expectEqualStrings = std.testing.expectEqualStrings;

pub fn snakeToCamel(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    var utf8_name = (std.unicode.Utf8View.init(name) catch unreachable).iterator();
    var target_inx: usize = 0;
    var previous_ascii: u8 = 0;
    var rc = try allocator.alloc(u8, name.len);
    while (utf8_name.nextCodepoint()) |cp| {
        if (cp > 0xff) return error.UnicodeNotSupported;
        const ascii_char: u8 = @truncate(cp);
        if (ascii_char != '_') {
            if (previous_ascii == '_' and ascii_char >= 'a' and ascii_char <= 'z') {
                const uppercase_char = ascii_char - ('a' - 'A');
                rc[target_inx] = uppercase_char;
            } else {
                rc[target_inx] = ascii_char;
            }
            target_inx = target_inx + 1;
        }
        previous_ascii = ascii_char;
    }
    // Do we care if the allocator refuses resize?
    _ = allocator.resize(rc, target_inx);
    return rc[0..target_inx];
}
pub fn snakeToPascal(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    const rc = try snakeToCamel(allocator, name);
    if (rc[0] >= 'a' and rc[0] <= 'z') {
        const uppercase_char = rc[0] - ('a' - 'A');
        rc[0] = uppercase_char;
    }
    return rc;
}

test "converts from snake to camelCase" {
    const allocator = std.testing.allocator;
    const camel = try snakeToCamel(allocator, "access_key_id");
    defer allocator.free(camel);
    try expectEqualStrings("accessKeyId", camel);
}
test "single word" {
    const allocator = std.testing.allocator;
    const camel = try snakeToCamel(allocator, "word");
    defer allocator.free(camel);
    try expectEqualStrings("word", camel);
}
