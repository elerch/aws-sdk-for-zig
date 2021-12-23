const std = @import("std");
const expectEqualStrings = std.testing.expectEqualStrings;

pub fn fromPascalCase(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    const rc = try allocator.alloc(u8, name.len * 2); // This is overkill, but is > the maximum length possibly needed
    errdefer allocator.free(rc);
    var utf8_name = (std.unicode.Utf8View.init(name) catch unreachable).iterator();
    var target_inx: u64 = 0;
    var curr_char = (try isAscii(utf8_name.nextCodepoint())).?;
    target_inx = setNext(lowercase(curr_char), rc, target_inx);
    var prev_char = curr_char;
    if (try isAscii(utf8_name.nextCodepoint())) |ch| {
        curr_char = ch;
    } else {
        // Single character only - we're done here
        _ = setNext(0, rc, target_inx);
        return rc[0..target_inx];
    }
    while (try isAscii(utf8_name.nextCodepoint())) |next_char| {
        if (next_char == ' ') {
            // a space shouldn't be happening. But if it does, it clues us
            // in pretty well:
            //
            // MyStuff Is Awesome
            //       |^
            //       |next_char
            //       ^
            //       prev_codepoint/ascii_prev_char (and target_inx)
            target_inx = setNext(lowercase(curr_char), rc, target_inx);
            target_inx = setNext('_', rc, target_inx);
            curr_char = (try isAscii(utf8_name.nextCodepoint())).?;
            target_inx = setNext(lowercase(curr_char), rc, target_inx);
            prev_char = curr_char;
            curr_char = (try isAscii(utf8_name.nextCodepoint())).?;
            continue;
        }
        if (between(curr_char, 'A', 'Z')) {
            if (isAcronym(curr_char, next_char)) {
                // We could be in an acronym at the start of a word. This
                // is the only case where we actually need to look back at the
                // previous character, and if that's the case, throw in an
                // underscore
                // "SAMLMySAMLAcronymThing");
                if (between(prev_char, 'a', 'z'))
                    target_inx = setNext('_', rc, target_inx);

                //we are in an acronym - don't snake, just lower
                target_inx = setNext(lowercase(curr_char), rc, target_inx);
            } else {
                target_inx = setNext('_', rc, target_inx);
                target_inx = setNext(lowercase(curr_char), rc, target_inx);
            }
        } else {
            target_inx = setNext(curr_char, rc, target_inx);
        }
        prev_char = curr_char;
        curr_char = next_char;
    }
    // work in the last codepoint - force lowercase
    target_inx = setNext(lowercase(curr_char), rc, target_inx);

    rc[target_inx] = 0;
    return rc[0..target_inx];
}

fn isAcronym(char1: u8, char2: u8) bool {
    return isAcronymChar(char1) and isAcronymChar(char2);
}
fn isAcronymChar(char: u8) bool {
    return between(char, 'A', 'Z') or between(char, '0', '9');
}
fn isAscii(codepoint: ?u21) !?u8 {
    if (codepoint) |cp| {
        if (cp > 0xff) return error.UnicodeNotSupported;
        return @truncate(u8, cp);
    }
    return null;
}

fn setNext(ascii: u8, slice: []u8, inx: u64) u64 {
    slice[inx] = ascii;
    return inx + 1;
}

fn lowercase(ascii: u8) u8 {
    var lowercase_char = ascii;
    if (between(ascii, 'A', 'Z'))
        lowercase_char = ascii + ('a' - 'A');
    return lowercase_char;
}

fn between(char: u8, from: u8, to: u8) bool {
    return char >= from and char <= to;
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

test "S3" {
    const allocator = std.testing.allocator;
    const snake_case = try fromPascalCase(allocator, "S3");
    defer allocator.free(snake_case);
    try expectEqualStrings("s3", snake_case);
}

test "ec2" {
    const allocator = std.testing.allocator;
    const snake_case = try fromPascalCase(allocator, "EC2");
    defer allocator.free(snake_case);
    try expectEqualStrings("ec2", snake_case);
}

test "IoT 1Click Devices Service" {
    const allocator = std.testing.allocator;
    const snake_case = try fromPascalCase(allocator, "IoT 1Click Devices Service");
    defer allocator.free(snake_case);
    // NOTE: There is some debate amoung humans about what this should
    // turn into. Should it be iot_1click_... or iot_1_click...?
    try expectEqualStrings("iot_1_click_devices_service", snake_case);
}
