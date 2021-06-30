const std = @import("std");
const expectEqualStrings = std.testing.expectEqualStrings;

pub fn fromPascalCase(allocator: *std.mem.Allocator, name: []const u8) ![]u8 {
    var utf8_name = (std.unicode.Utf8View.init(name) catch unreachable).iterator();
    var target_inx: u64 = 0;
    var previous_codepoint: ?u21 = null;
    var cp = utf8_name.nextCodepoint();
    if (cp == null) {
        return try allocator.dupeZ(u8, name);
    } // TODO: fix bug if single letter uppercase
    var codepoint = cp.?;
    const rc = try allocator.alloc(u8, name.len * 2); // This is overkill, but is > the maximum length possibly needed
    while (utf8_name.nextCodepoint()) |next_codepoint| {
        if (codepoint > 0xff) return error{UnicodeNotSupported}.UnicodeNotSupported;
        if (next_codepoint > 0xff) return error{UnicodeNotSupported}.UnicodeNotSupported;
        const ascii_char = @truncate(u8, codepoint);
        if (next_codepoint == ' ') continue; // ignore all spaces in name
        if (ascii_char >= 'A' and ascii_char < 'Z') {
            const lowercase_char = ascii_char + ('a' - 'A');
            if (previous_codepoint == null) {
                rc[target_inx] = lowercase_char;
                target_inx = target_inx + 1;
            } else {
                if (next_codepoint >= 'A' and next_codepoint <= 'Z' and previous_codepoint.? >= 'A' and previous_codepoint.? <= 'Z') {
                    //we are in an acronym - don't snake, just lower
                    rc[target_inx] = lowercase_char;
                    target_inx = target_inx + 1;
                } else {
                    rc[target_inx] = '_';
                    rc[target_inx + 1] = lowercase_char;
                    target_inx = target_inx + 2;
                }
            }
        } else {
            // if (ascii_char == ' ') {
            //     rc[target_inx] = '_';
            // } else {
            rc[target_inx] = ascii_char;
            // }
            target_inx = target_inx + 1;
        }
        previous_codepoint = codepoint;
        codepoint = next_codepoint;
    }
    // work in the last codepoint - force lowercase
    rc[target_inx] = @truncate(u8, codepoint);
    if (rc[target_inx] >= 'A' and rc[target_inx] <= 'Z') {
        const lowercase_char = rc[target_inx] + ('a' - 'A');
        rc[target_inx] = lowercase_char;
    }
    target_inx = target_inx + 1;

    rc[target_inx] = 0;
    return rc[0..target_inx];
}

test "converts from PascalCase to snake_case" {
    const allocator = std.testing.allocator;
    const snake_case = try fromPascalCase(allocator, "MyPascalCaseThing");
    defer allocator.free(snake_case);
    try expectEqualStrings("my_pascal_case_thing", snake_case);
}
test "handles from PascalCase acronyms to snake_case" {
    const allocator = std.testing.allocator;
    const snake_case = try fromPascalCase(allocator, "SAMLMySAMLAcronymThing");
    defer allocator.free(snake_case);
    try expectEqualStrings("saml_my_saml_acronym_thing", snake_case);
}
test "spaces in the name" {
    const allocator = std.testing.allocator;
    const snake_case = try fromPascalCase(allocator, "API Gateway");
    defer allocator.free(snake_case);
    try expectEqualStrings("api_gateway", snake_case);
}
