const std = @import("std");
// options is a json.Options, but since we're using our hacked json.zig we don't want to
// specifically call this out
pub fn serializeMap(map: anytype, key: []const u8, options: anytype, out_stream: anytype) !bool {
    if (map.len == 0) return true;
    // TODO: Map might be [][]struct{key, value} rather than []struct{key, value}
    var child_options = options;
    if (child_options.whitespace) |*child_ws|
        child_ws.indent_level += 1;

    try out_stream.writeByte('"');
    try out_stream.writeAll(key);
    _ = try out_stream.write("\":");
    if (options.whitespace) |ws| {
        if (ws.separator) {
            try out_stream.writeByte(' ');
        }
    }
    try out_stream.writeByte('{');
    if (options.whitespace) |_|
        try out_stream.writeByte('\n');
    for (map) |tag, i| {
        if (tag.key == null or tag.value == null) continue;
        // TODO: Deal with escaping and general "json.stringify" the values...
        if (child_options.whitespace) |ws|
            try ws.outputIndent(out_stream);
        try out_stream.writeByte('"');
        try jsonEscape(tag.key.?, child_options, out_stream);
        _ = try out_stream.write("\":");
        if (child_options.whitespace) |ws| {
            if (ws.separator) {
                try out_stream.writeByte(' ');
            }
        }
        try out_stream.writeByte('"');
        try jsonEscape(tag.value.?, child_options, out_stream);
        try out_stream.writeByte('"');
        if (i < map.len - 1) {
            try out_stream.writeByte(',');
        }
        if (child_options.whitespace) |_|
            try out_stream.writeByte('\n');
    }
    if (options.whitespace) |ws|
        try ws.outputIndent(out_stream);
    try out_stream.writeByte('}');
    return true;
}
// code within jsonEscape lifted from json.zig in stdlib
fn jsonEscape(value: []const u8, options: anytype, out_stream: anytype) !void {
    var i: usize = 0;
    while (i < value.len) : (i += 1) {
        switch (value[i]) {
            // normal ascii character
            0x20...0x21, 0x23...0x2E, 0x30...0x5B, 0x5D...0x7F => |c| try out_stream.writeByte(c),
            // only 2 characters that *must* be escaped
            '\\' => try out_stream.writeAll("\\\\"),
            '\"' => try out_stream.writeAll("\\\""),
            // solidus is optional to escape
            '/' => {
                if (options.string.String.escape_solidus) {
                    try out_stream.writeAll("\\/");
                } else {
                    try out_stream.writeByte('/');
                }
            },
            // control characters with short escapes
            // TODO: option to switch between unicode and 'short' forms?
            0x8 => try out_stream.writeAll("\\b"),
            0xC => try out_stream.writeAll("\\f"),
            '\n' => try out_stream.writeAll("\\n"),
            '\r' => try out_stream.writeAll("\\r"),
            '\t' => try out_stream.writeAll("\\t"),
            else => {
                const ulen = std.unicode.utf8ByteSequenceLength(value[i]) catch unreachable;
                // control characters (only things left with 1 byte length) should always be printed as unicode escapes
                if (ulen == 1 or options.string.String.escape_unicode) {
                    const codepoint = std.unicode.utf8Decode(value[i .. i + ulen]) catch unreachable;
                    try outputUnicodeEscape(codepoint, out_stream);
                } else {
                    try out_stream.writeAll(value[i .. i + ulen]);
                }
                i += ulen - 1;
            },
        }
    }
}
// outputUnicodeEscape and assert lifted from json.zig in stdlib
fn outputUnicodeEscape(
    codepoint: u21,
    out_stream: anytype,
) !void {
    if (codepoint <= 0xFFFF) {
        // If the character is in the Basic Multilingual Plane (U+0000 through U+FFFF),
        // then it may be represented as a six-character sequence: a reverse solidus, followed
        // by the lowercase letter u, followed by four hexadecimal digits that encode the character's code point.
        try out_stream.writeAll("\\u");
        try std.fmt.formatIntValue(codepoint, "x", std.fmt.FormatOptions{ .width = 4, .fill = '0' }, out_stream);
    } else {
        assert(codepoint <= 0x10FFFF);
        // To escape an extended character that is not in the Basic Multilingual Plane,
        // the character is represented as a 12-character sequence, encoding the UTF-16 surrogate pair.
        const high = @intCast(u16, (codepoint - 0x10000) >> 10) + 0xD800;
        const low = @intCast(u16, codepoint & 0x3FF) + 0xDC00;
        try out_stream.writeAll("\\u");
        try std.fmt.formatIntValue(high, "x", std.fmt.FormatOptions{ .width = 4, .fill = '0' }, out_stream);
        try out_stream.writeAll("\\u");
        try std.fmt.formatIntValue(low, "x", std.fmt.FormatOptions{ .width = 4, .fill = '0' }, out_stream);
    }
}

/// This function invokes undefined behavior when `ok` is `false`.
/// In Debug and ReleaseSafe modes, calls to this function are always
/// generated, and the `unreachable` statement triggers a panic.
/// In ReleaseFast and ReleaseSmall modes, calls to this function are
/// optimized away, and in fact the optimizer is able to use the assertion
/// in its heuristics.
/// Inside a test block, it is best to use the `std.testing` module rather
/// than this function, because this function may not detect a test failure
/// in ReleaseFast and ReleaseSmall mode. Outside of a test block, this assert
/// function is the correct function to use.
pub fn assert(ok: bool) void {
    if (!ok) unreachable; // assertion failure
}
