// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
// JSON parser conforming to RFC8259.
//
// https://tools.ietf.org/html/rfc8259

const std = @import("std");
const debug = std.debug;
const assert = debug.assert;
const testing = std.testing;
const mem = std.mem;
const maxInt = std.math.maxInt;

pub fn serializeMap(map: anytype, key: []const u8, options: anytype, out_stream: anytype) !void {
    if (@typeInfo(@TypeOf(map)) == .optional) {
        if (map) |m| serializeMapInternal(m, key, options, out_stream);
    } else {
        serializeMapInternal(map, key, options, out_stream);
    }
}

fn serializeMapKey(key: []const u8, options: anytype, out_stream: anytype) !void {
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
}

fn serializeMapAsObject(map: anytype, options: anytype, out_stream: anytype) !void {
    if (map.len == 0) {
        try out_stream.writeByte('{');
        try out_stream.writeByte('}');
        return;
    }

    // TODO: Map might be [][]struct{key, value} rather than []struct{key, value}
    var child_options = options;
    if (child_options.whitespace) |*whitespace| {
        whitespace.indent_level += 1;
    }

    try out_stream.writeByte('{');
    if (options.whitespace) |_|
        try out_stream.writeByte('\n');

    for (map, 0..) |tag, i| {
        // TODO: Deal with escaping and general "json.stringify" the values...
        if (child_options.whitespace) |ws|
            try ws.outputIndent(out_stream);
        try out_stream.writeByte('"');
        try jsonEscape(tag.key, child_options, out_stream);
        _ = try out_stream.write("\":");
        if (child_options.whitespace) |ws| {
            if (ws.separator) {
                try out_stream.writeByte(' ');
            }
        }
        try out_stream.writeByte('"');
        try jsonEscape(tag.value, child_options, out_stream);
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
}

fn serializeMapInternal(map: anytype, key: []const u8, options: anytype, out_stream: anytype) !bool {
    try serializeMapKey(key, options, out_stream);
    return try serializeMapAsObject(map, options, out_stream);
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

const StringEscapes = union(enum) {
    None,

    Some: struct {
        size_diff: isize,
    },
};

/// Checks to see if a string matches what it would be as a json-encoded string
/// Assumes that `encoded` is a well-formed json string
fn encodesTo(decoded: []const u8, encoded: []const u8) bool {
    var i: usize = 0;
    var j: usize = 0;
    while (i < decoded.len) {
        if (j >= encoded.len) return false;
        if (encoded[j] != '\\') {
            if (decoded[i] != encoded[j]) return false;
            j += 1;
            i += 1;
        } else {
            const escape_type = encoded[j + 1];
            if (escape_type != 'u') {
                const t: u8 = switch (escape_type) {
                    '\\' => '\\',
                    '/' => '/',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    'f' => 12,
                    'b' => 8,
                    '"' => '"',
                    else => unreachable,
                };
                if (decoded[i] != t) return false;
                j += 2;
                i += 1;
            } else {
                var codepoint = std.fmt.parseInt(u21, encoded[j + 2 .. j + 6], 16) catch unreachable;
                j += 6;
                if (codepoint >= 0xD800 and codepoint < 0xDC00) {
                    // surrogate pair
                    assert(encoded[j] == '\\');
                    assert(encoded[j + 1] == 'u');
                    const low_surrogate = std.fmt.parseInt(u21, encoded[j + 2 .. j + 6], 16) catch unreachable;
                    codepoint = 0x10000 + (((codepoint & 0x03ff) << 10) | (low_surrogate & 0x03ff));
                    j += 6;
                }
                var buf: [4]u8 = undefined;
                const len = std.unicode.utf8Encode(codepoint, &buf) catch unreachable;
                if (i + len > decoded.len) return false;
                if (!mem.eql(u8, decoded[i .. i + len], buf[0..len])) return false;
                i += len;
            }
        }
    }
    assert(i == decoded.len);
    assert(j == encoded.len);
    return true;
}

test "encodesTo" {
    // same
    try testing.expectEqual(true, encodesTo("false", "false"));
    // totally different
    try testing.expectEqual(false, encodesTo("false", "true"));
    // different lengths
    try testing.expectEqual(false, encodesTo("false", "other"));
    // with escape
    try testing.expectEqual(true, encodesTo("\\", "\\\\"));
    try testing.expectEqual(true, encodesTo("with\nescape", "with\\nescape"));
    // with unicode
    try testing.expectEqual(true, encodesTo("ą", "\\u0105"));
    try testing.expectEqual(true, encodesTo("😂", "\\ud83d\\ude02"));
    try testing.expectEqual(true, encodesTo("withąunicode😂", "with\\u0105unicode\\ud83d\\ude02"));
}

/// A single token slice into the parent string.
///
/// Use `token.slice()` on the input at the current position to get the current slice.
pub const Token = union(enum) {
    ObjectBegin,
    ObjectEnd,
    ArrayBegin,
    ArrayEnd,
    String: struct {
        /// How many bytes the token is.
        count: usize,

        /// Whether string contains an escape sequence and cannot be zero-copied
        escapes: StringEscapes,

        pub fn decodedLength(self: @This()) usize {
            return self.count +% switch (self.escapes) {
                .None => 0,
                .Some => |s| @as(usize, @bitCast(s.size_diff)),
            };
        }

        /// Slice into the underlying input string.
        pub fn slice(self: @This(), input: []const u8, i: usize) []const u8 {
            return input[i - self.count .. i];
        }
    },
    Number: struct {
        /// How many bytes the token is.
        count: usize,

        /// Whether number is simple and can be represented by an integer (i.e. no `.` or `e`)
        is_integer: bool,

        /// Slice into the underlying input string.
        pub fn slice(self: @This(), input: []const u8, i: usize) []const u8 {
            return input[i - self.count .. i];
        }
    },
    True,
    False,
    Null,
};

/// A small streaming JSON parser. This accepts input one byte at a time and returns tokens as
/// they are encountered. No copies or allocations are performed during parsing and the entire
/// parsing state requires ~40-50 bytes of stack space.
///
/// Conforms strictly to RFC8259.
///
/// For a non-byte based wrapper, consider using TokenStream instead.
pub const StreamingParser = struct {
    // Current state
    state: State,
    // How many bytes we have counted for the current token
    count: usize,
    // What state to follow after parsing a string (either property or value string)
    after_string_state: State,
    // What state to follow after parsing a value (either top-level or value end)
    after_value_state: State,
    // If we stopped now, would the complete parsed string to now be a valid json string
    complete: bool,
    // Current token flags to pass through to the next generated, see Token.
    string_escapes: StringEscapes,
    // When in .String states, was the previous character a high surrogate?
    string_last_was_high_surrogate: bool,
    // Used inside of StringEscapeHexUnicode* states
    string_unicode_codepoint: u21,
    // The first byte needs to be stored to validate 3- and 4-byte sequences.
    sequence_first_byte: u8 = undefined,
    // When in .Number states, is the number a (still) valid integer?
    number_is_integer: bool,

    // Bit-stack for nested object/map literals (max 255 nestings).
    stack: u256,
    stack_used: u8,

    const object_bit = 0;
    const array_bit = 1;
    const max_stack_size = maxInt(u8);

    pub fn init() StreamingParser {
        var p: StreamingParser = undefined;
        p.reset();
        return p;
    }

    pub fn reset(p: *StreamingParser) void {
        p.state = .TopLevelBegin;
        p.count = 0;
        // Set before ever read in main transition function
        p.after_string_state = undefined;
        p.after_value_state = .ValueEnd; // handle end of values normally
        p.stack = 0;
        p.stack_used = 0;
        p.complete = false;
        p.string_escapes = undefined;
        p.string_last_was_high_surrogate = undefined;
        p.string_unicode_codepoint = undefined;
        p.number_is_integer = undefined;
    }

    pub const State = enum(u8) {
        // These must be first with these explicit values as we rely on them for indexing the
        // bit-stack directly and avoiding a branch.
        ObjectSeparator = 0,
        ValueEnd = 1,

        TopLevelBegin,
        TopLevelEnd,

        ValueBegin,
        ValueBeginNoClosing,

        String,
        StringUtf8Byte2Of2,
        StringUtf8Byte2Of3,
        StringUtf8Byte3Of3,
        StringUtf8Byte2Of4,
        StringUtf8Byte3Of4,
        StringUtf8Byte4Of4,
        StringEscapeCharacter,
        StringEscapeHexUnicode4,
        StringEscapeHexUnicode3,
        StringEscapeHexUnicode2,
        StringEscapeHexUnicode1,

        Number,
        NumberMaybeDotOrExponent,
        NumberMaybeDigitOrDotOrExponent,
        NumberFractionalRequired,
        NumberFractional,
        NumberMaybeExponent,
        NumberExponent,
        NumberExponentDigitsRequired,
        NumberExponentDigits,

        TrueLiteral1,
        TrueLiteral2,
        TrueLiteral3,

        FalseLiteral1,
        FalseLiteral2,
        FalseLiteral3,
        FalseLiteral4,

        NullLiteral1,
        NullLiteral2,
        NullLiteral3,

        // Only call this function to generate array/object final state.
        pub fn fromInt(x: anytype) State {
            debug.assert(x == 0 or x == 1);
            const T = std.meta.Tag(State);
            return @as(State, @enumFromInt(@as(T, @intCast(x))));
        }
    };

    pub const Error = error{
        InvalidTopLevel,
        TooManyNestedItems,
        TooManyClosingItems,
        InvalidValueBegin,
        InvalidValueEnd,
        UnbalancedBrackets,
        UnbalancedBraces,
        UnexpectedClosingBracket,
        UnexpectedClosingBrace,
        InvalidNumber,
        InvalidSeparator,
        InvalidLiteral,
        InvalidEscapeCharacter,
        InvalidUnicodeHexSymbol,
        InvalidUtf8Byte,
        InvalidTopLevelTrailing,
        InvalidControlCharacter,
    };

    /// Give another byte to the parser and obtain any new tokens. This may (rarely) return two
    /// tokens. token2 is always null if token1 is null.
    ///
    /// There is currently no error recovery on a bad stream.
    pub fn feed(p: *StreamingParser, c: u8, token1: *?Token, token2: *?Token) Error!void {
        token1.* = null;
        token2.* = null;
        p.count += 1;

        // unlikely
        if (try p.transition(c, token1)) {
            _ = try p.transition(c, token2);
        }
    }

    // Perform a single transition on the state machine and return any possible token.
    fn transition(p: *StreamingParser, c: u8, token: *?Token) Error!bool {
        switch (p.state) {
            .TopLevelBegin => switch (c) {
                '{' => {
                    p.stack <<= 1;
                    p.stack |= object_bit;
                    p.stack_used += 1;

                    p.state = .ValueBegin;
                    p.after_string_state = .ObjectSeparator;

                    token.* = Token.ObjectBegin;
                },
                '[' => {
                    p.stack <<= 1;
                    p.stack |= array_bit;
                    p.stack_used += 1;

                    p.state = .ValueBegin;
                    p.after_string_state = .ValueEnd;

                    token.* = Token.ArrayBegin;
                },
                '-' => {
                    p.number_is_integer = true;
                    p.state = .Number;
                    p.after_value_state = .TopLevelEnd;
                    p.count = 0;
                },
                '0' => {
                    p.number_is_integer = true;
                    p.state = .NumberMaybeDotOrExponent;
                    p.after_value_state = .TopLevelEnd;
                    p.count = 0;
                },
                '1'...'9' => {
                    p.number_is_integer = true;
                    p.state = .NumberMaybeDigitOrDotOrExponent;
                    p.after_value_state = .TopLevelEnd;
                    p.count = 0;
                },
                '"' => {
                    p.state = .String;
                    p.after_value_state = .TopLevelEnd;
                    // We don't actually need the following since after_value_state should override.
                    p.after_string_state = .ValueEnd;
                    p.string_escapes = .None;
                    p.string_last_was_high_surrogate = false;
                    p.count = 0;
                },
                't' => {
                    p.state = .TrueLiteral1;
                    p.after_value_state = .TopLevelEnd;
                    p.count = 0;
                },
                'f' => {
                    p.state = .FalseLiteral1;
                    p.after_value_state = .TopLevelEnd;
                    p.count = 0;
                },
                'n' => {
                    p.state = .NullLiteral1;
                    p.after_value_state = .TopLevelEnd;
                    p.count = 0;
                },
                0x09, 0x0A, 0x0D, 0x20 => {
                    // whitespace
                },
                else => {
                    return error.InvalidTopLevel;
                },
            },

            .TopLevelEnd => switch (c) {
                0x09, 0x0A, 0x0D, 0x20 => {
                    // whitespace
                },
                else => {
                    return error.InvalidTopLevelTrailing;
                },
            },

            .ValueBegin => switch (c) {
                // NOTE: These are shared in ValueEnd as well, think we can reorder states to
                // be a bit clearer and avoid this duplication.
                '}' => {
                    // unlikely
                    if (p.stack & 1 != object_bit) {
                        return error.UnexpectedClosingBrace;
                    }
                    if (p.stack_used == 0) {
                        return error.TooManyClosingItems;
                    }

                    p.state = .ValueBegin;
                    p.after_string_state = State.fromInt(p.stack & 1);

                    p.stack >>= 1;
                    p.stack_used -= 1;

                    switch (p.stack_used) {
                        0 => {
                            p.complete = true;
                            p.state = .TopLevelEnd;
                        },
                        else => {
                            p.state = .ValueEnd;
                        },
                    }

                    token.* = Token.ObjectEnd;
                },
                ']' => {
                    if (p.stack & 1 != array_bit) {
                        return error.UnexpectedClosingBracket;
                    }
                    if (p.stack_used == 0) {
                        return error.TooManyClosingItems;
                    }

                    p.state = .ValueBegin;
                    p.after_string_state = State.fromInt(p.stack & 1);

                    p.stack >>= 1;
                    p.stack_used -= 1;

                    switch (p.stack_used) {
                        0 => {
                            p.complete = true;
                            p.state = .TopLevelEnd;
                        },
                        else => {
                            p.state = .ValueEnd;
                        },
                    }

                    token.* = Token.ArrayEnd;
                },
                '{' => {
                    if (p.stack_used == max_stack_size) {
                        return error.TooManyNestedItems;
                    }

                    p.stack <<= 1;
                    p.stack |= object_bit;
                    p.stack_used += 1;

                    p.state = .ValueBegin;
                    p.after_string_state = .ObjectSeparator;

                    token.* = Token.ObjectBegin;
                },
                '[' => {
                    if (p.stack_used == max_stack_size) {
                        return error.TooManyNestedItems;
                    }

                    p.stack <<= 1;
                    p.stack |= array_bit;
                    p.stack_used += 1;

                    p.state = .ValueBegin;
                    p.after_string_state = .ValueEnd;

                    token.* = Token.ArrayBegin;
                },
                '-' => {
                    p.number_is_integer = true;
                    p.state = .Number;
                    p.count = 0;
                },
                '0' => {
                    p.number_is_integer = true;
                    p.state = .NumberMaybeDotOrExponent;
                    p.count = 0;
                },
                '1'...'9' => {
                    p.number_is_integer = true;
                    p.state = .NumberMaybeDigitOrDotOrExponent;
                    p.count = 0;
                },
                '"' => {
                    p.state = .String;
                    p.string_escapes = .None;
                    p.string_last_was_high_surrogate = false;
                    p.count = 0;
                },
                't' => {
                    p.state = .TrueLiteral1;
                    p.count = 0;
                },
                'f' => {
                    p.state = .FalseLiteral1;
                    p.count = 0;
                },
                'n' => {
                    p.state = .NullLiteral1;
                    p.count = 0;
                },
                0x09, 0x0A, 0x0D, 0x20 => {
                    // whitespace
                },
                else => {
                    return error.InvalidValueBegin;
                },
            },

            // TODO: A bit of duplication here and in the following state, redo.
            .ValueBeginNoClosing => switch (c) {
                '{' => {
                    if (p.stack_used == max_stack_size) {
                        return error.TooManyNestedItems;
                    }

                    p.stack <<= 1;
                    p.stack |= object_bit;
                    p.stack_used += 1;

                    p.state = .ValueBegin;
                    p.after_string_state = .ObjectSeparator;

                    token.* = Token.ObjectBegin;
                },
                '[' => {
                    if (p.stack_used == max_stack_size) {
                        return error.TooManyNestedItems;
                    }

                    p.stack <<= 1;
                    p.stack |= array_bit;
                    p.stack_used += 1;

                    p.state = .ValueBegin;
                    p.after_string_state = .ValueEnd;

                    token.* = Token.ArrayBegin;
                },
                '-' => {
                    p.number_is_integer = true;
                    p.state = .Number;
                    p.count = 0;
                },
                '0' => {
                    p.number_is_integer = true;
                    p.state = .NumberMaybeDotOrExponent;
                    p.count = 0;
                },
                '1'...'9' => {
                    p.number_is_integer = true;
                    p.state = .NumberMaybeDigitOrDotOrExponent;
                    p.count = 0;
                },
                '"' => {
                    p.state = .String;
                    p.string_escapes = .None;
                    p.string_last_was_high_surrogate = false;
                    p.count = 0;
                },
                't' => {
                    p.state = .TrueLiteral1;
                    p.count = 0;
                },
                'f' => {
                    p.state = .FalseLiteral1;
                    p.count = 0;
                },
                'n' => {
                    p.state = .NullLiteral1;
                    p.count = 0;
                },
                0x09, 0x0A, 0x0D, 0x20 => {
                    // whitespace
                },
                else => {
                    return error.InvalidValueBegin;
                },
            },

            .ValueEnd => switch (c) {
                ',' => {
                    p.after_string_state = State.fromInt(p.stack & 1);
                    p.state = .ValueBeginNoClosing;
                },
                ']' => {
                    if (p.stack & 1 != array_bit) {
                        return error.UnexpectedClosingBracket;
                    }
                    if (p.stack_used == 0) {
                        return error.TooManyClosingItems;
                    }

                    p.state = .ValueEnd;
                    p.after_string_state = State.fromInt(p.stack & 1);

                    p.stack >>= 1;
                    p.stack_used -= 1;

                    if (p.stack_used == 0) {
                        p.complete = true;
                        p.state = .TopLevelEnd;
                    }

                    token.* = Token.ArrayEnd;
                },
                '}' => {
                    // unlikely
                    if (p.stack & 1 != object_bit) {
                        return error.UnexpectedClosingBrace;
                    }
                    if (p.stack_used == 0) {
                        return error.TooManyClosingItems;
                    }

                    p.state = .ValueEnd;
                    p.after_string_state = State.fromInt(p.stack & 1);

                    p.stack >>= 1;
                    p.stack_used -= 1;

                    if (p.stack_used == 0) {
                        p.complete = true;
                        p.state = .TopLevelEnd;
                    }

                    token.* = Token.ObjectEnd;
                },
                0x09, 0x0A, 0x0D, 0x20 => {
                    // whitespace
                },
                else => {
                    return error.InvalidValueEnd;
                },
            },

            .ObjectSeparator => switch (c) {
                ':' => {
                    p.state = .ValueBegin;
                    p.after_string_state = .ValueEnd;
                },
                0x09, 0x0A, 0x0D, 0x20 => {
                    // whitespace
                },
                else => {
                    return error.InvalidSeparator;
                },
            },

            .String => switch (c) {
                0x00...0x1F => {
                    return error.InvalidControlCharacter;
                },
                '"' => {
                    p.state = p.after_string_state;
                    if (p.after_value_state == .TopLevelEnd) {
                        p.state = .TopLevelEnd;
                        p.complete = true;
                    }

                    token.* = .{
                        .String = .{
                            .count = p.count - 1,
                            .escapes = p.string_escapes,
                        },
                    };
                    p.string_escapes = undefined;
                    p.string_last_was_high_surrogate = undefined;
                },
                '\\' => {
                    p.state = .StringEscapeCharacter;
                    switch (p.string_escapes) {
                        .None => {
                            p.string_escapes = .{ .Some = .{ .size_diff = 0 } };
                        },
                        .Some => {},
                    }
                },
                0x20, 0x21, 0x23...0x5B, 0x5D...0x7F => {
                    // non-control ascii
                    p.string_last_was_high_surrogate = false;
                },
                0xC2...0xDF => {
                    p.state = .StringUtf8Byte2Of2;
                },
                0xE0...0xEF => {
                    p.state = .StringUtf8Byte2Of3;
                    p.sequence_first_byte = c;
                },
                0xF0...0xF4 => {
                    p.state = .StringUtf8Byte2Of4;
                    p.sequence_first_byte = c;
                },
                else => {
                    return error.InvalidUtf8Byte;
                },
            },

            .StringUtf8Byte2Of2 => switch (c >> 6) {
                0b10 => p.state = .String,
                else => return error.InvalidUtf8Byte,
            },
            .StringUtf8Byte2Of3 => {
                switch (p.sequence_first_byte) {
                    0xE0 => switch (c) {
                        0xA0...0xBF => {},
                        else => return error.InvalidUtf8Byte,
                    },
                    0xE1...0xEF => switch (c) {
                        0x80...0xBF => {},
                        else => return error.InvalidUtf8Byte,
                    },
                    else => return error.InvalidUtf8Byte,
                }
                p.state = .StringUtf8Byte3Of3;
            },
            .StringUtf8Byte3Of3 => switch (c) {
                0x80...0xBF => p.state = .String,
                else => return error.InvalidUtf8Byte,
            },
            .StringUtf8Byte2Of4 => {
                switch (p.sequence_first_byte) {
                    0xF0 => switch (c) {
                        0x90...0xBF => {},
                        else => return error.InvalidUtf8Byte,
                    },
                    0xF1...0xF3 => switch (c) {
                        0x80...0xBF => {},
                        else => return error.InvalidUtf8Byte,
                    },
                    0xF4 => switch (c) {
                        0x80...0x8F => {},
                        else => return error.InvalidUtf8Byte,
                    },
                    else => return error.InvalidUtf8Byte,
                }
                p.state = .StringUtf8Byte3Of4;
            },
            .StringUtf8Byte3Of4 => switch (c) {
                0x80...0xBF => p.state = .StringUtf8Byte4Of4,
                else => return error.InvalidUtf8Byte,
            },
            .StringUtf8Byte4Of4 => switch (c) {
                0x80...0xBF => p.state = .String,
                else => return error.InvalidUtf8Byte,
            },

            .StringEscapeCharacter => switch (c) {
                // NOTE: '/' is allowed as an escaped character but it also is allowed
                // as unescaped according to the RFC. There is a reported errata which suggests
                // removing the non-escaped variant but it makes more sense to simply disallow
                // it as an escape code here.
                //
                // The current JSONTestSuite tests rely on both of this behaviour being present
                // however, so we default to the status quo where both are accepted until this
                // is further clarified.
                '"', '\\', '/', 'b', 'f', 'n', 'r', 't' => {
                    p.string_escapes.Some.size_diff -= 1;
                    p.state = .String;
                    p.string_last_was_high_surrogate = false;
                },
                'u' => {
                    p.state = .StringEscapeHexUnicode4;
                },
                else => {
                    return error.InvalidEscapeCharacter;
                },
            },

            .StringEscapeHexUnicode4 => {
                var codepoint: u21 = undefined;
                switch (c) {
                    else => return error.InvalidUnicodeHexSymbol,
                    '0'...'9' => {
                        codepoint = c - '0';
                    },
                    'A'...'F' => {
                        codepoint = c - 'A' + 10;
                    },
                    'a'...'f' => {
                        codepoint = c - 'a' + 10;
                    },
                }
                p.state = .StringEscapeHexUnicode3;
                p.string_unicode_codepoint = codepoint << 12;
            },

            .StringEscapeHexUnicode3 => {
                var codepoint: u21 = undefined;
                switch (c) {
                    else => return error.InvalidUnicodeHexSymbol,
                    '0'...'9' => {
                        codepoint = c - '0';
                    },
                    'A'...'F' => {
                        codepoint = c - 'A' + 10;
                    },
                    'a'...'f' => {
                        codepoint = c - 'a' + 10;
                    },
                }
                p.state = .StringEscapeHexUnicode2;
                p.string_unicode_codepoint |= codepoint << 8;
            },

            .StringEscapeHexUnicode2 => {
                var codepoint: u21 = undefined;
                switch (c) {
                    else => return error.InvalidUnicodeHexSymbol,
                    '0'...'9' => {
                        codepoint = c - '0';
                    },
                    'A'...'F' => {
                        codepoint = c - 'A' + 10;
                    },
                    'a'...'f' => {
                        codepoint = c - 'a' + 10;
                    },
                }
                p.state = .StringEscapeHexUnicode1;
                p.string_unicode_codepoint |= codepoint << 4;
            },

            .StringEscapeHexUnicode1 => {
                var codepoint: u21 = undefined;
                switch (c) {
                    else => return error.InvalidUnicodeHexSymbol,
                    '0'...'9' => {
                        codepoint = c - '0';
                    },
                    'A'...'F' => {
                        codepoint = c - 'A' + 10;
                    },
                    'a'...'f' => {
                        codepoint = c - 'a' + 10;
                    },
                }
                p.state = .String;
                p.string_unicode_codepoint |= codepoint;
                if (p.string_unicode_codepoint < 0xD800 or p.string_unicode_codepoint >= 0xE000) {
                    // not part of surrogate pair
                    p.string_escapes.Some.size_diff -= @as(isize, 6 - (std.unicode.utf8CodepointSequenceLength(p.string_unicode_codepoint) catch unreachable));
                    p.string_last_was_high_surrogate = false;
                } else if (p.string_unicode_codepoint < 0xDC00) {
                    // 'high' surrogate
                    // takes 3 bytes to encode a half surrogate pair into wtf8
                    p.string_escapes.Some.size_diff -= 6 - 3;
                    p.string_last_was_high_surrogate = true;
                } else {
                    // 'low' surrogate
                    p.string_escapes.Some.size_diff -= 6;
                    if (p.string_last_was_high_surrogate) {
                        // takes 4 bytes to encode a full surrogate pair into utf8
                        // 3 bytes are already reserved by high surrogate
                        p.string_escapes.Some.size_diff -= -1;
                    } else {
                        // takes 3 bytes to encode a half surrogate pair into wtf8
                        p.string_escapes.Some.size_diff -= -3;
                    }
                    p.string_last_was_high_surrogate = false;
                }
                p.string_unicode_codepoint = undefined;
            },

            .Number => {
                p.complete = p.after_value_state == .TopLevelEnd;
                switch (c) {
                    '0' => {
                        p.state = .NumberMaybeDotOrExponent;
                    },
                    '1'...'9' => {
                        p.state = .NumberMaybeDigitOrDotOrExponent;
                    },
                    else => {
                        return error.InvalidNumber;
                    },
                }
            },

            .NumberMaybeDotOrExponent => {
                p.complete = p.after_value_state == .TopLevelEnd;
                switch (c) {
                    '.' => {
                        p.number_is_integer = false;
                        p.state = .NumberFractionalRequired;
                    },
                    'e', 'E' => {
                        p.number_is_integer = false;
                        p.state = .NumberExponent;
                    },
                    else => {
                        p.state = p.after_value_state;
                        token.* = .{
                            .Number = .{
                                .count = p.count,
                                .is_integer = p.number_is_integer,
                            },
                        };
                        p.number_is_integer = undefined;
                        return true;
                    },
                }
            },

            .NumberMaybeDigitOrDotOrExponent => {
                p.complete = p.after_value_state == .TopLevelEnd;
                switch (c) {
                    '.' => {
                        p.number_is_integer = false;
                        p.state = .NumberFractionalRequired;
                    },
                    'e', 'E' => {
                        p.number_is_integer = false;
                        p.state = .NumberExponent;
                    },
                    '0'...'9' => {
                        // another digit
                    },
                    else => {
                        p.state = p.after_value_state;
                        token.* = .{
                            .Number = .{
                                .count = p.count,
                                .is_integer = p.number_is_integer,
                            },
                        };
                        return true;
                    },
                }
            },

            .NumberFractionalRequired => {
                p.complete = p.after_value_state == .TopLevelEnd;
                switch (c) {
                    '0'...'9' => {
                        p.state = .NumberFractional;
                    },
                    else => {
                        return error.InvalidNumber;
                    },
                }
            },

            .NumberFractional => {
                p.complete = p.after_value_state == .TopLevelEnd;
                switch (c) {
                    '0'...'9' => {
                        // another digit
                    },
                    'e', 'E' => {
                        p.number_is_integer = false;
                        p.state = .NumberExponent;
                    },
                    else => {
                        p.state = p.after_value_state;
                        token.* = .{
                            .Number = .{
                                .count = p.count,
                                .is_integer = p.number_is_integer,
                            },
                        };
                        return true;
                    },
                }
            },

            .NumberMaybeExponent => {
                p.complete = p.after_value_state == .TopLevelEnd;
                switch (c) {
                    'e', 'E' => {
                        p.number_is_integer = false;
                        p.state = .NumberExponent;
                    },
                    else => {
                        p.state = p.after_value_state;
                        token.* = .{
                            .Number = .{
                                .count = p.count,
                                .is_integer = p.number_is_integer,
                            },
                        };
                        return true;
                    },
                }
            },

            .NumberExponent => switch (c) {
                '-', '+' => {
                    p.complete = false;
                    p.state = .NumberExponentDigitsRequired;
                },
                '0'...'9' => {
                    p.complete = p.after_value_state == .TopLevelEnd;
                    p.state = .NumberExponentDigits;
                },
                else => {
                    return error.InvalidNumber;
                },
            },

            .NumberExponentDigitsRequired => switch (c) {
                '0'...'9' => {
                    p.complete = p.after_value_state == .TopLevelEnd;
                    p.state = .NumberExponentDigits;
                },
                else => {
                    return error.InvalidNumber;
                },
            },

            .NumberExponentDigits => {
                p.complete = p.after_value_state == .TopLevelEnd;
                switch (c) {
                    '0'...'9' => {
                        // another digit
                    },
                    else => {
                        p.state = p.after_value_state;
                        token.* = .{
                            .Number = .{
                                .count = p.count,
                                .is_integer = p.number_is_integer,
                            },
                        };
                        return true;
                    },
                }
            },

            .TrueLiteral1 => switch (c) {
                'r' => p.state = .TrueLiteral2,
                else => return error.InvalidLiteral,
            },

            .TrueLiteral2 => switch (c) {
                'u' => p.state = .TrueLiteral3,
                else => return error.InvalidLiteral,
            },

            .TrueLiteral3 => switch (c) {
                'e' => {
                    p.state = p.after_value_state;
                    p.complete = p.state == .TopLevelEnd;
                    token.* = Token.True;
                },
                else => {
                    return error.InvalidLiteral;
                },
            },

            .FalseLiteral1 => switch (c) {
                'a' => p.state = .FalseLiteral2,
                else => return error.InvalidLiteral,
            },

            .FalseLiteral2 => switch (c) {
                'l' => p.state = .FalseLiteral3,
                else => return error.InvalidLiteral,
            },

            .FalseLiteral3 => switch (c) {
                's' => p.state = .FalseLiteral4,
                else => return error.InvalidLiteral,
            },

            .FalseLiteral4 => switch (c) {
                'e' => {
                    p.state = p.after_value_state;
                    p.complete = p.state == .TopLevelEnd;
                    token.* = Token.False;
                },
                else => {
                    return error.InvalidLiteral;
                },
            },

            .NullLiteral1 => switch (c) {
                'u' => p.state = .NullLiteral2,
                else => return error.InvalidLiteral,
            },

            .NullLiteral2 => switch (c) {
                'l' => p.state = .NullLiteral3,
                else => return error.InvalidLiteral,
            },

            .NullLiteral3 => switch (c) {
                'l' => {
                    p.state = p.after_value_state;
                    p.complete = p.state == .TopLevelEnd;
                    token.* = Token.Null;
                },
                else => {
                    return error.InvalidLiteral;
                },
            },
        }

        return false;
    }
};

/// A small wrapper over a StreamingParser for full slices. Returns a stream of json Tokens.
pub const TokenStream = struct {
    i: usize,
    slice: []const u8,
    parser: StreamingParser,
    token: ?Token,

    pub const Error = StreamingParser.Error || error{UnexpectedEndOfJson};

    pub fn init(slice: []const u8) TokenStream {
        return TokenStream{
            .i = 0,
            .slice = slice,
            .parser = StreamingParser.init(),
            .token = null,
        };
    }

    pub fn next(self: *TokenStream) Error!?Token {
        if (self.token) |token| {
            self.token = null;
            return token;
        }

        var t1: ?Token = undefined;
        var t2: ?Token = undefined;

        while (self.i < self.slice.len) {
            try self.parser.feed(self.slice[self.i], &t1, &t2);
            self.i += 1;

            if (t1) |token| {
                self.token = t2;
                return token;
            }
        }

        // Without this a bare number fails, the streaming parser doesn't know the input ended
        try self.parser.feed(' ', &t1, &t2);
        self.i += 1;

        if (t1) |token| {
            return token;
        } else if (self.parser.complete) {
            return null;
        } else {
            return error.UnexpectedEndOfJson;
        }
    }
    fn stackUsed(self: *TokenStream) u8 {
        return self.parser.stack_used + if (self.token != null) @as(u8, 1) else 0;
    }
};

fn checkNext(p: *TokenStream, id: std.meta.Tag(Token)) !void {
    const token = (p.next() catch unreachable).?;
    try testing.expect(std.meta.activeTag(token) == id);
}

test "json.token" {
    const s =
        \\{
        \\  "Image": {
        \\      "Width":  800,
        \\      "Height": 600,
        \\      "Title":  "View from 15th Floor",
        \\      "Thumbnail": {
        \\          "Url":    "http://www.example.com/image/481989943",
        \\          "Height": 125,
        \\          "Width":  100
        \\      },
        \\      "Animated" : false,
        \\      "IDs": [116, 943, 234, 38793]
        \\    }
        \\}
    ;

    var p = TokenStream.init(s);

    try checkNext(&p, .ObjectBegin);
    try checkNext(&p, .String); // Image
    try checkNext(&p, .ObjectBegin);
    try checkNext(&p, .String); // Width
    try checkNext(&p, .Number);
    try checkNext(&p, .String); // Height
    try checkNext(&p, .Number);
    try checkNext(&p, .String); // Title
    try checkNext(&p, .String);
    try checkNext(&p, .String); // Thumbnail
    try checkNext(&p, .ObjectBegin);
    try checkNext(&p, .String); // Url
    try checkNext(&p, .String);
    try checkNext(&p, .String); // Height
    try checkNext(&p, .Number);
    try checkNext(&p, .String); // Width
    try checkNext(&p, .Number);
    try checkNext(&p, .ObjectEnd);
    try checkNext(&p, .String); // Animated
    try checkNext(&p, .False);
    try checkNext(&p, .String); // IDs
    try checkNext(&p, .ArrayBegin);
    try checkNext(&p, .Number);
    try checkNext(&p, .Number);
    try checkNext(&p, .Number);
    try checkNext(&p, .Number);
    try checkNext(&p, .ArrayEnd);
    try checkNext(&p, .ObjectEnd);
    try checkNext(&p, .ObjectEnd);

    try testing.expect((try p.next()) == null);
}

test "json.token mismatched close" {
    var p = TokenStream.init("[102, 111, 111 }");
    try checkNext(&p, .ArrayBegin);
    try checkNext(&p, .Number);
    try checkNext(&p, .Number);
    try checkNext(&p, .Number);
    try testing.expectError(error.UnexpectedClosingBrace, p.next());
}

/// Validate a JSON string. This does not limit number precision so a decoder may not necessarily
/// be able to decode the string even if this returns true.
pub fn validate(s: []const u8) bool {
    var p = StreamingParser.init();

    for (s) |c| {
        var token1: ?Token = undefined;
        var token2: ?Token = undefined;

        p.feed(c, &token1, &token2) catch {
            return false;
        };
    }

    return p.complete;
}

test "json.validate" {
    try testing.expectEqual(true, validate("{}"));
    try testing.expectEqual(true, validate("[]"));
    try testing.expectEqual(true, validate("[{[[[[{}]]]]}]"));
    try testing.expectEqual(false, validate("{]"));
    try testing.expectEqual(false, validate("[}"));
    try testing.expectEqual(false, validate("{{{{[]}}}]"));
}

const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const ArrayList = std.ArrayList;
const StringArrayHashMap = std.StringArrayHashMap;

pub const ValueTree = struct {
    arena: ArenaAllocator,
    root: Value,

    pub fn deinit(self: *ValueTree) void {
        self.arena.deinit();
    }
};

pub const ObjectMap = StringArrayHashMap(Value);
pub const Array = ArrayList(Value);

/// Represents a JSON value
/// Currently only supports numbers that fit into i64 or f64.
pub const Value = union(enum) {
    Null,
    Bool: bool,
    Integer: i64,
    Float: f64,
    NumberString: []const u8,
    String: []const u8,
    Array: Array,
    Object: ObjectMap,
};

/// parse tokens from a stream, returning `false` if they do not decode to `value`
fn parsesTo(comptime T: type, value: T, tokens: *TokenStream, options: ParseOptions) !bool {
    // TODO: should be able to write this function to not require an allocator
    const tmp = try parse(T, tokens, options);
    defer parseFree(T, tmp, options);

    return parsedEqual(tmp, value);
}

/// Returns if a value returned by `parse` is deep-equal to another value
fn parsedEqual(a: anytype, b: @TypeOf(a)) bool {
    switch (@typeInfo(@TypeOf(a))) {
        .Optional => {
            if (a == null and b == null) return true;
            if (a == null or b == null) return false;
            return parsedEqual(a.?, b.?);
        },
        .Union => |info| {
            if (info.tag_type) |UnionTag| {
                const tag_a = std.meta.activeTag(a);
                const tag_b = std.meta.activeTag(b);
                if (tag_a != tag_b) return false;

                inline for (info.fields) |field_info| {
                    if (@field(UnionTag, field_info.name) == tag_a) {
                        return parsedEqual(@field(a, field_info.name), @field(b, field_info.name));
                    }
                }
                return false;
            } else {
                unreachable;
            }
        },
        .Array => {
            for (a, 0..) |e, i|
                if (!parsedEqual(e, b[i])) return false;
            return true;
        },
        .Struct => |info| {
            inline for (info.fields) |field_info| {
                if (!parsedEqual(@field(a, field_info.name), @field(b, field_info.name))) return false;
            }
            return true;
        },
        .Pointer => |ptrInfo| switch (ptrInfo.size) {
            .One => return parsedEqual(a.*, b.*),
            .Slice => {
                if (a.len != b.len) return false;
                for (a, 0..) |e, i|
                    if (!parsedEqual(e, b[i])) return false;
                return true;
            },
            .Many, .C => unreachable,
        },
        else => return a == b,
    }
    unreachable;
}

pub const ParseOptions = struct {
    allocator: ?Allocator = null,

    /// Behaviour when a duplicate field is encountered.
    duplicate_field_behavior: enum {
        UseFirst,
        Error,
        UseLast,
    } = .Error,

    allow_camel_case_conversion: bool = false,
    allow_snake_case_conversion: bool = false,
    allow_unknown_fields: bool = false,
    allow_missing_fields: bool = false,
};

fn camelCaseComp(field: []const u8, key: []const u8, options: ParseOptions) !bool {
    var utf8_source_key = (std.unicode.Utf8View.init(key) catch unreachable).iterator();
    if (utf8_source_key.nextCodepoint()) |codepoint| {
        if (codepoint >= 'A' and codepoint <= 'Z') {
            const allocator = options.allocator orelse return error.AllocatorRequired;
            const source_key_camel_case = try allocator.dupeZ(u8, key);
            defer allocator.free(source_key_camel_case);
            // First codepoint is uppercase Latin char, which is all we're handling atm
            source_key_camel_case[0] = source_key_camel_case[0] + ('a' - 'A');
            // We will assume the target field is in camelCase
            return std.mem.eql(u8, field, source_key_camel_case);
        }
    }
    return std.mem.eql(u8, field, key);
}

test "snake" {
    const allocator = testing.allocator;
    const options = ParseOptions{
        .allocator = allocator,
        .allow_camel_case_conversion = true,
        .allow_snake_case_conversion = true,
        .allow_unknown_fields = true,
    };
    try std.testing.expect(try snakeCaseComp("access_key_id", "AccessKeyId", options));
}
fn snakeCaseComp(field: []const u8, key: []const u8, options: ParseOptions) !bool {
    // snake case is much more intricate. Input:
    // Field: user_id
    // Key: UserId
    // We can duplicate the field and remove all _ characters safely
    // Then take the key and lowercase all the uppercase.
    // Then compare
    var found: u32 = 0;
    for (field) |ch| {
        if (ch == '_')
            found = found + 1;
    }
    if (found == 0)
        return std.mem.eql(u8, field, key);

    // We have a snake case field. Let's do this
    const allocator = options.allocator orelse return error.AllocatorRequired;
    const comp_field = try allocator.alloc(u8, field.len - found);
    defer allocator.free(comp_field);
    var inx: u32 = 0;
    for (field) |ch| {
        if (ch != '_') {
            comp_field[inx] = ch;
            inx = inx + 1;
        }
    }
    // field = 'user_id', comp_field = 'userid'

    // We now transform the key by lowercasing. We will only deal with Latin
    var utf8_source_key = (std.unicode.Utf8View.init(key) catch unreachable).iterator();
    const normalized_key = try allocator.dupeZ(u8, key);
    defer allocator.free(normalized_key);
    inx = 0;
    while (utf8_source_key.nextCodepoint()) |codepoint| {
        if (codepoint > 255) return error.InvalidLiteral;
        if (codepoint >= 'A' and codepoint <= 'Z') {
            // First codepoint is uppercase Latin char, which is all we're handling atm
            normalized_key[inx] = normalized_key[inx] + ('a' - 'A');
            // We will assume the target field is in camelCase
        }
        inx = inx + 1;
    }
    // std.debug.print("comp_field, len {d}: {s}\n", .{ comp_field.len, comp_field });
    // std.debug.print("normalized_key, len {d}: {s}\n", .{ normalized_key.len, normalized_key });
    // std.debug.print("comp_field, last: {d}\n", .{comp_field[comp_field.len - 1]});
    // std.debug.print("normalized_key, last: {d}\n", .{normalized_key[normalized_key.len - 1]});

    return std.mem.eql(u8, comp_field, normalized_key);
}
const SkipValueError = error{UnexpectedJsonDepth} || TokenStream.Error;

fn skipValue(tokens: *TokenStream) SkipValueError!void {
    const original_depth = tokens.stackUsed();

    // Return an error if no value is found
    _ = try tokens.next();
    if (tokens.stackUsed() < original_depth) return error.UnexpectedJsonDepth;
    if (tokens.stackUsed() == original_depth) return;

    while (try tokens.next()) |_| {
        if (tokens.stackUsed() == original_depth) return;
    }
}

fn parseInternal(comptime T: type, token: Token, tokens: *TokenStream, options: ParseOptions) !T {
    switch (@typeInfo(T)) {
        .bool => {
            return switch (token) {
                .True => true,
                .False => false,
                else => error.UnexpectedToken,
            };
        },
        .float, .comptime_float => {
            const numberToken = switch (token) {
                .Number => |n| n,
                else => return error.UnexpectedToken,
            };
            return try std.fmt.parseFloat(T, numberToken.slice(tokens.slice, tokens.i - 1));
        },
        .int, .comptime_int => {
            const numberToken = switch (token) {
                .Number => |n| n,
                else => return error.UnexpectedToken,
            };
            // This is a bug. you can still potentially have an integer that has exponents
            // if (!numberToken.is_integer) return error.UnexpectedToken;
            if (numberToken.is_integer)
                return try std.fmt.parseInt(T, numberToken.slice(tokens.slice, tokens.i - 1), 10);
            const float = try std.fmt.parseFloat(f128, numberToken.slice(tokens.slice, tokens.i - 1));
            if (std.math.round(float) != float) return error.InvalidNumber;
            return @as(T, @intFromFloat(float));
        },
        .optional => |optionalInfo| {
            if (token == .Null) {
                return null;
            } else {
                return try parseInternal(optionalInfo.child, token, tokens, options);
            }
        },
        .@"enum" => |enumInfo| {
            switch (token) {
                .Number => |numberToken| {
                    if (!numberToken.is_integer) {
                        // probably is in scientific notation
                        const n = try std.fmt.parseFloat(f128, numberToken.slice(tokens.slice, tokens.i - 1));
                        return try std.meta.intToEnum(T, @as(i128, @intFromFloat(n)));
                    }

                    const n = try std.fmt.parseInt(enumInfo.tag_type, numberToken.slice(tokens.slice, tokens.i - 1), 10);
                    return try std.meta.intToEnum(T, n);
                },
                .String => |stringToken| {
                    const source_slice = stringToken.slice(tokens.slice, tokens.i - 1);

                    if (std.meta.hasFn(T, "parse")) {
                        return try T.parse(source_slice);
                    }

                    switch (stringToken.escapes) {
                        .None => return std.meta.stringToEnum(T, source_slice) orelse return error.InvalidEnumTag,
                        .Some => {
                            inline for (enumInfo.fields) |field| {
                                if (field.name.len == stringToken.decodedLength() and encodesTo(field.name, source_slice)) {
                                    return @field(T, field.name);
                                }
                            }
                            return error.InvalidEnumTag;
                        },
                    }
                },
                else => return error.UnexpectedToken,
            }
        },
        .@"union" => |unionInfo| {
            if (unionInfo.tag_type) |_| {
                // try each of the union fields until we find one that matches
                inline for (unionInfo.fields) |u_field| {
                    // take a copy of tokens so we can withhold mutations until success
                    var tokens_copy = tokens.*;
                    if (parseInternal(u_field.type, token, &tokens_copy, options)) |value| {
                        tokens.* = tokens_copy;
                        return @unionInit(T, u_field.name, value);
                    } else |err| {
                        // Bubble up error.OutOfMemory
                        // Parsing some types won't have OutOfMemory in their
                        // error-sets, for the condition to be valid, merge it in.
                        if (@as(@TypeOf(err) || error{OutOfMemory}, err) == error.OutOfMemory) return err;
                        // Bubble up AllocatorRequired, as it indicates missing option
                        if (@as(@TypeOf(err) || error{AllocatorRequired}, err) == error.AllocatorRequired) return err;
                        // otherwise continue through the `inline for`
                    }
                }
                return error.NoUnionMembersMatched;
            } else {
                @compileError("Unable to parse into untagged union '" ++ @typeName(T) ++ "'");
            }
        },
        .@"struct" => |structInfo| {
            switch (token) {
                .ObjectBegin => {},
                else => return error.UnexpectedToken,
            }
            var r: T = undefined;
            var fields_seen = [_]bool{false} ** structInfo.fields.len;
            errdefer {
                // TODO: why so high here? This was needed for ec2 describe instances
                @setEvalBranchQuota(100000);
                inline for (structInfo.fields, 0..) |field, i| {
                    if (fields_seen[i] and !field.is_comptime) {
                        parseFree(field.type, @field(r, field.name), options);
                    }
                }
            }

            while (true) {
                switch ((try tokens.next()) orelse return error.UnexpectedEndOfJson) {
                    .ObjectEnd => break,
                    .String => |stringToken| {
                        const key_source_slice = stringToken.slice(tokens.slice, tokens.i - 1);
                        var found = false;
                        inline for (structInfo.fields, 0..) |field, i| {
                            // TODO: using switches here segfault the compiler (#2727?)
                            if ((stringToken.escapes == .None and mem.eql(u8, field.name, key_source_slice)) or (stringToken.escapes == .Some and (field.name.len == stringToken.decodedLength() and encodesTo(field.name, key_source_slice))) or (stringToken.escapes == .None and options.allow_camel_case_conversion and try camelCaseComp(field.name, key_source_slice, options)) or (stringToken.escapes == .None and options.allow_snake_case_conversion and try snakeCaseComp(field.name, key_source_slice, options))) {
                                // if (switch (stringToken.escapes) {
                                //     .None => mem.eql(u8, field.name, key_source_slice),
                                //     .Some => (field.name.len == stringToken.decodedLength() and encodesTo(field.name, key_source_slice)),
                                // }) {
                                if (fields_seen[i]) {
                                    // switch (options.duplicate_field_behavior) {
                                    //     .UseFirst => {},
                                    //     .Error => {},
                                    //     .UseLast => {},
                                    // }
                                    if (options.duplicate_field_behavior == .UseFirst) {
                                        break;
                                    } else if (options.duplicate_field_behavior == .Error) {
                                        return error.DuplicateJSONField;
                                    } else if (options.duplicate_field_behavior == .UseLast) {
                                        parseFree(field.type, @field(r, field.name), options);
                                        fields_seen[i] = false;
                                    }
                                }
                                if (field.is_comptime) {
                                    // TODO: Fix this cast
                                    // if (!try parsesTo(field.type, field.default_value.?, tokens, options)) {
                                    return error.UnexpectedValue;
                                    // }
                                } else {
                                    @field(r, field.name) = try parse(field.type, tokens, options);
                                }
                                fields_seen[i] = true;
                                found = true;
                                break;
                            }
                        }
                        if (!found and !options.allow_unknown_fields) return error.UnknownField;
                        if (!found) try skipValue(tokens);
                    },
                    .ObjectBegin => {
                        if (!options.allow_unknown_fields) return error.UnknownField;
                        // At this point, we are in a struct that we do not care about. Fast forward
                        var objects: u64 = 1;
                        while (true) {
                            switch ((try tokens.next()) orelse return error.UnexpectedEndOfJson) {
                                .ObjectBegin => objects = objects + 1,
                                .ObjectEnd => {
                                    objects = objects - 1;
                                    if (objects == 0) break;
                                },
                                else => {},
                            }
                        }
                    },
                    else => return error.UnexpectedToken,
                }
            }
            inline for (structInfo.fields, 0..) |field, i| {
                if (!fields_seen[i]) {
                    if (field.default_value_ptr) |default_value_ptr| {
                        if (!field.is_comptime) {
                            const default_value = @as(*align(1) const field.type, @ptrCast(default_value_ptr)).*;
                            @field(r, field.name) = default_value;
                        }
                    } else {
                        if (!options.allow_missing_fields)
                            return error.MissingField;
                    }
                }
            }
            return r;
        },
        .array => |arrayInfo| {
            switch (token) {
                .ArrayBegin => {
                    var r: T = undefined;
                    var i: usize = 0;
                    errdefer {
                        while (true) : (i -= 1) {
                            parseFree(arrayInfo.child, r[i], options);
                            if (i == 0) break;
                        }
                    }
                    while (i < r.len) : (i += 1) {
                        r[i] = try parse(arrayInfo.child, tokens, options);
                    }
                    const tok = (try tokens.next()) orelse return error.UnexpectedEndOfJson;
                    switch (tok) {
                        .ArrayEnd => {},
                        else => return error.UnexpectedToken,
                    }
                    return r;
                },
                .String => |stringToken| {
                    if (arrayInfo.child != u8) return error.UnexpectedToken;
                    var r: T = undefined;
                    const source_slice = stringToken.slice(tokens.slice, tokens.i - 1);
                    switch (stringToken.escapes) {
                        .None => @memcpy(&r, source_slice),
                        .Some => try unescapeValidString(&r, source_slice),
                    }
                    return r;
                },
                else => return error.UnexpectedToken,
            }
        },
        .pointer => |ptrInfo| {
            const allocator = options.allocator orelse return error.AllocatorRequired;
            switch (ptrInfo.size) {
                .one => {
                    const r: T = try allocator.create(ptrInfo.child);
                    errdefer allocator.destroy(r);
                    r.* = try parseInternal(ptrInfo.child, token, tokens, options);
                    return r;
                },
                .slice => {
                    switch (token) {
                        .ArrayBegin => {
                            var arraylist = std.ArrayList(ptrInfo.child).init(allocator);
                            errdefer {
                                while (arraylist.pop()) |v| {
                                    parseFree(ptrInfo.child, v, options);
                                }
                                arraylist.deinit();
                            }

                            while (true) {
                                const tok = (try tokens.next()) orelse return error.UnexpectedEndOfJson;
                                switch (tok) {
                                    .ArrayEnd => break,
                                    else => {},
                                }

                                try arraylist.ensureTotalCapacity(arraylist.items.len + 1);
                                const v = try parseInternal(ptrInfo.child, tok, tokens, options);
                                arraylist.appendAssumeCapacity(v);
                            }
                            return arraylist.toOwnedSlice();
                        },
                        .String => |stringToken| {
                            if (ptrInfo.child != u8) return error.UnexpectedToken;
                            const source_slice = stringToken.slice(tokens.slice, tokens.i - 1);
                            switch (stringToken.escapes) {
                                .None => return allocator.dupe(u8, source_slice),
                                .Some => {
                                    const output = try allocator.alloc(u8, stringToken.decodedLength());
                                    errdefer allocator.free(output);
                                    try unescapeValidString(output, source_slice);
                                    return output;
                                },
                            }
                        },
                        .ObjectBegin => {
                            // We are parsing into a slice, but we have an
                            // ObjectBegin. This might be ok, iff the type
                            // follows this pattern: []struct { key: []const u8, value: anytype }
                            // (could key be anytype?).
                            if (!isMapPattern(T))
                                return error.UnexpectedToken;
                            const key_type = typeForField(ptrInfo.child, "key");
                            if (key_type == null) return error.UnexpectedToken;
                            const value_type = typeForField(ptrInfo.child, "value");
                            if (value_type == null) return error.UnexpectedToken;
                            var arraylist = std.ArrayList(ptrInfo.child).init(allocator);
                            errdefer {
                                while (arraylist.pop()) |v| {
                                    parseFree(ptrInfo.child, v, options);
                                }
                                arraylist.deinit();
                            }
                            while (true) {
                                const key = (try tokens.next()) orelse return error.UnexpectedEndOfJson;
                                switch (key) {
                                    .ObjectEnd => break,
                                    else => {},
                                }

                                try arraylist.ensureTotalCapacity(arraylist.items.len + 1);
                                const key_val = try parseInternal(key_type.?, key, tokens, options);
                                const val = (try tokens.next()) orelse return error.UnexpectedEndOfJson;
                                const val_val = try parseInternal(value_type.?, val, tokens, options);
                                arraylist.appendAssumeCapacity(.{ .key = key_val, .value = val_val });
                            }
                            return arraylist.toOwnedSlice();
                        },
                        else => return error.UnexpectedToken,
                    }
                },
                else => @compileError("Unable to parse into type '" ++ @typeName(T) ++ "'"),
            }
        },
        else => @compileError("Unable to parse into type '" ++ @typeName(T) ++ "'"),
    }
    unreachable;
}

fn typeForField(comptime T: type, comptime field_name: []const u8) ?type {
    const ti = @typeInfo(T);
    switch (ti) {
        .@"struct" => {
            inline for (ti.@"struct".fields) |field| {
                if (std.mem.eql(u8, field.name, field_name))
                    return field.type;
            }
        },
        else => return null, //error.TypeIsNotAStruct, // should not hit this
    }
    return null; //error.FieldNotFound;
}

fn isMapPattern(comptime T: type) bool {
    // We should be getting a type that is a pointer to a slice.
    // Let's just double check before proceeding
    const ti = @typeInfo(T);
    if (ti != .pointer) return false;
    if (ti.pointer.size != .slice) return false;
    const ti_child = @typeInfo(ti.pointer.child);
    if (ti_child != .@"struct") return false;
    if (ti_child.@"struct".fields.len != 2) return false;
    var key_found = false;
    var value_found = false;
    inline for (ti_child.@"struct".fields) |field| {
        if (std.mem.eql(u8, "key", field.name))
            key_found = true;
        if (std.mem.eql(u8, "value", field.name))
            value_found = true;
    }
    return key_found and value_found;
}

pub fn parse(comptime T: type, tokens: *TokenStream, options: ParseOptions) !T {
    // std.log.debug("parsing {s} into type {s}", .{ tokens.slice, @typeName(T) });
    const token = (try tokens.next()) orelse return error.UnexpectedEndOfJson;
    return parseInternal(T, token, tokens, options);
}

/// Releases resources created by `parse`.
/// Should be called with the same type and `ParseOptions` that were passed to `parse`
pub fn parseFree(comptime T: type, value: T, options: ParseOptions) void {
    switch (@typeInfo(T)) {
        .bool, .float, .comptime_float, .int, .comptime_int, .@"enum" => {},
        .optional => {
            if (value) |v| {
                return parseFree(@TypeOf(v), v, options);
            }
        },
        .@"union" => |unionInfo| {
            if (unionInfo.tag_type) |UnionTagType| {
                inline for (unionInfo.fields) |u_field| {
                    if (value == @field(UnionTagType, u_field.name)) {
                        parseFree(u_field.type, @field(value, u_field.name), options);
                        break;
                    }
                }
            } else {
                unreachable;
            }
        },
        .@"struct" => |structInfo| {
            inline for (structInfo.fields) |field| {
                parseFree(field.type, @field(value, field.name), options);
            }
        },
        .array => |arrayInfo| {
            for (value) |v| {
                parseFree(arrayInfo.child, v, options);
            }
        },
        .pointer => |ptrInfo| {
            const allocator = options.allocator orelse unreachable;
            switch (ptrInfo.size) {
                .one => {
                    parseFree(ptrInfo.child, value.*, options);
                    allocator.destroy(value);
                },
                .slice => {
                    for (value) |v| {
                        parseFree(ptrInfo.child, v, options);
                    }
                    allocator.free(value);
                },
                else => unreachable,
            }
        },
        else => unreachable,
    }
}

test "parse" {
    try testing.expectEqual(false, try parse(bool, @constCast(&TokenStream.init("false")), ParseOptions{}));
    try testing.expectEqual(true, try parse(bool, @constCast(&TokenStream.init("true")), ParseOptions{}));
    try testing.expectEqual(@as(u1, 1), try parse(u1, @constCast(&TokenStream.init("1")), ParseOptions{}));
    try testing.expectError(error.Overflow, parse(u1, @constCast(&TokenStream.init("50")), ParseOptions{}));
    try testing.expectEqual(@as(u64, 42), try parse(u64, @constCast(&TokenStream.init("42")), ParseOptions{}));
    try testing.expectEqual(@as(f64, 42), try parse(f64, @constCast(&TokenStream.init("42.0")), ParseOptions{}));
    try testing.expectEqual(@as(?bool, null), try parse(?bool, @constCast(&TokenStream.init("null")), ParseOptions{}));
    try testing.expectEqual(@as(?bool, true), try parse(?bool, @constCast(&TokenStream.init("true")), ParseOptions{}));

    try testing.expectEqual(@as([3]u8, "foo".*), try parse([3]u8, @constCast(&TokenStream.init("\"foo\"")), ParseOptions{}));
    try testing.expectEqual(@as([3]u8, "foo".*), try parse([3]u8, @constCast(&TokenStream.init("[102, 111, 111]")), ParseOptions{}));
}

test "parse into enum" {
    const T = enum(u32) {
        Foo = 42,
        Bar,
        @"with\\escape",
    };
    try testing.expectEqual(@as(T, .Foo), try parse(T, @constCast(&TokenStream.init("\"Foo\"")), ParseOptions{}));
    try testing.expectEqual(@as(T, .Foo), try parse(T, @constCast(&TokenStream.init("42")), ParseOptions{}));
    try testing.expectEqual(@as(T, .@"with\\escape"), try parse(T, @constCast(&TokenStream.init("\"with\\\\escape\"")), ParseOptions{}));
    try testing.expectError(error.InvalidEnumTag, parse(T, @constCast(&TokenStream.init("5")), ParseOptions{}));
    try testing.expectError(error.InvalidEnumTag, parse(T, @constCast(&TokenStream.init("\"Qux\"")), ParseOptions{}));
}

test "parse into that allocates a slice" {
    try testing.expectError(error.AllocatorRequired, parse([]u8, @constCast(&TokenStream.init("\"foo\"")), ParseOptions{}));

    const options = ParseOptions{ .allocator = testing.allocator };
    {
        const r = try parse([]u8, @constCast(&TokenStream.init("\"foo\"")), options);
        defer parseFree([]u8, r, options);
        try testing.expectEqualSlices(u8, "foo", r);
    }
    {
        const r = try parse([]u8, @constCast(&TokenStream.init("[102, 111, 111]")), options);
        defer parseFree([]u8, r, options);
        try testing.expectEqualSlices(u8, "foo", r);
    }
    {
        const r = try parse([]u8, @constCast(&TokenStream.init("\"with\\\\escape\"")), options);
        defer parseFree([]u8, r, options);
        try testing.expectEqualSlices(u8, "with\\escape", r);
    }
}

test "parse into that uses a map pattern" {
    const options = ParseOptions{ .allocator = testing.allocator };
    const Map = []struct { key: []const u8, value: []const u8 };
    const r = try parse(Map, @constCast(&TokenStream.init("{\"foo\": \"bar\"}")), options);
    defer parseFree(Map, r, options);
    try testing.expectEqualSlices(u8, "foo", r[0].key);
    try testing.expectEqualSlices(u8, "bar", r[0].value);
}

test "parse into tagged union" {
    {
        const T = union(enum) {
            int: i32,
            float: f64,
            string: []const u8,
        };
        try testing.expectEqual(T{ .float = 1.5 }, try parse(T, @constCast(&TokenStream.init("1.5")), ParseOptions{}));
    }

    { // failing allocations should be bubbled up instantly without trying next member
        var fail_alloc = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
        const options = ParseOptions{ .allocator = fail_alloc.allocator() };
        const T = union(enum) {
            // both fields here match the input
            string: []const u8,
            array: [3]u8,
        };
        try testing.expectError(error.OutOfMemory, parse(T, @constCast(&TokenStream.init("[1,2,3]")), options));
    }

    {
        // if multiple matches possible, takes first option
        const T = union(enum) {
            x: u8,
            y: u8,
        };
        try testing.expectEqual(T{ .x = 42 }, try parse(T, @constCast(&TokenStream.init("42")), ParseOptions{}));
    }

    { // needs to back out when first union member doesn't match
        const T = union(enum) {
            A: struct { x: u32 },
            B: struct { y: u32 },
        };
        try testing.expectEqual(T{ .B = .{ .y = 42 } }, try parse(T, @constCast(&TokenStream.init("{\"y\":42}")), ParseOptions{}));
    }
}

test "parse union bubbles up AllocatorRequired" {
    { // string member first in union (and not matching)
        const T = union(enum) {
            string: []const u8,
            int: i32,
        };
        try testing.expectError(error.AllocatorRequired, parse(T, @constCast(&TokenStream.init("42")), ParseOptions{}));
    }

    { // string member not first in union (and matching)
        const T = union(enum) {
            int: i32,
            float: f64,
            string: []const u8,
        };
        try testing.expectError(error.AllocatorRequired, parse(T, @constCast(&TokenStream.init("\"foo\"")), ParseOptions{}));
    }
}

test "parseFree descends into tagged union" {
    var fail_alloc = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 1 });
    const options = ParseOptions{ .allocator = fail_alloc.allocator() };
    const T = union(enum) {
        int: i32,
        float: f64,
        string: []const u8,
    };
    // use a string with unicode escape so we know result can't be a reference to global constant
    const r = try parse(T, @constCast(&TokenStream.init("\"with\\u0105unicode\"")), options);
    try testing.expectEqual(std.meta.Tag(T).string, @as(std.meta.Tag(T), r));
    try testing.expectEqualSlices(u8, "withąunicode", r.string);
    try testing.expectEqual(@as(usize, 0), fail_alloc.deallocations);
    parseFree(T, r, options);
    try testing.expectEqual(@as(usize, 1), fail_alloc.deallocations);
}

test "parse with comptime field" {
    if (true) return error.SkipZigTest; // TODO: re-enable when we work through json changes in 0.11 and see if we can move to upstream
    {
        const T = struct {
            comptime a: i32 = 0,
            b: bool,
        };
        try testing.expectEqual(T{ .a = 0, .b = true }, try parse(T, @constCast(&TokenStream.init(
            \\{
            \\  "a": 0,
            \\  "b": true
            \\}
        )), ParseOptions{}));
    }

    { // string comptime values currently require an allocator
        const T = union(enum) {
            foo: struct {
                comptime kind: []const u8 = "boolean",
                b: bool,
            },
            bar: struct {
                comptime kind: []const u8 = "float",
                b: f64,
            },
        };

        _ = try parse(T, @constCast(&TokenStream.init(
            \\{
            \\  "kind": "float",
            \\  "b": 1.0
            \\}
        )), .{
            .allocator = std.testing.allocator,
        });
    }
}

test "parse into struct with no fields" {
    const T = struct {};
    try testing.expectEqual(T{}, try parse(T, @constCast(&TokenStream.init("{}")), ParseOptions{}));
}
test "parse exponential into int" {
    const T = struct { int: i64 };
    const r = try parse(T, @constCast(&TokenStream.init("{ \"int\": 4.2e2 }")), ParseOptions{});
    try testing.expectEqual(@as(i64, 420), r.int);
}

test "parse into struct with misc fields" {
    @setEvalBranchQuota(10000);
    const options = ParseOptions{ .allocator = testing.allocator };
    const T = struct {
        int: i64,
        float: f64,
        @"with\\escape": bool,
        @"withąunicode😂": bool,
        language: []const u8,
        optional: ?bool,
        default_field: i32 = 42,
        static_array: [3]f64,
        dynamic_array: []f64,

        complex: struct {
            nested: []const u8,
        },

        veryComplex: []struct {
            foo: []const u8,
        },

        a_union: Union,
        const Union = union(enum) {
            x: u8,
            float: f64,
            string: []const u8,
        };
    };
    const r = try parse(T, @constCast(&TokenStream.init(
        \\{
        \\  "int": 420,
        \\  "float": 3.14,
        \\  "with\\escape": true,
        \\  "with\u0105unicode\ud83d\ude02": false,
        \\  "language": "zig",
        \\  "optional": null,
        \\  "static_array": [66.6, 420.420, 69.69],
        \\  "dynamic_array": [66.6, 420.420, 69.69],
        \\  "complex": {
        \\    "nested": "zig"
        \\  },
        \\  "veryComplex": [
        \\    {
        \\      "foo": "zig"
        \\    }, {
        \\      "foo": "rocks"
        \\    }
        \\  ],
        \\  "a_union": 100000
        \\}
    )), options);
    defer parseFree(T, r, options);
    try testing.expectEqual(@as(i64, 420), r.int);
    try testing.expectEqual(@as(f64, 3.14), r.float);
    try testing.expectEqual(true, r.@"with\\escape");
    try testing.expectEqual(false, r.@"withąunicode😂");
    try testing.expectEqualSlices(u8, "zig", r.language);
    try testing.expectEqual(@as(?bool, null), r.optional);
    try testing.expectEqual(@as(i32, 42), r.default_field);
    try testing.expectEqual(@as(f64, 66.6), r.static_array[0]);
    try testing.expectEqual(@as(f64, 420.420), r.static_array[1]);
    try testing.expectEqual(@as(f64, 69.69), r.static_array[2]);
    try testing.expectEqual(@as(usize, 3), r.dynamic_array.len);
    try testing.expectEqual(@as(f64, 66.6), r.dynamic_array[0]);
    try testing.expectEqual(@as(f64, 420.420), r.dynamic_array[1]);
    try testing.expectEqual(@as(f64, 69.69), r.dynamic_array[2]);
    try testing.expectEqualSlices(u8, r.complex.nested, "zig");
    try testing.expectEqualSlices(u8, "zig", r.veryComplex[0].foo);
    try testing.expectEqualSlices(u8, "rocks", r.veryComplex[1].foo);
    try testing.expectEqual(T.Union{ .float = 100000 }, r.a_union);
}

test "parse into struct with duplicate field" {
    // allow allocator to detect double frees by keeping bucket in use
    const ballast = try testing.allocator.alloc(u64, 1);
    defer testing.allocator.free(ballast);

    const options = ParseOptions{
        .allocator = testing.allocator,
        .duplicate_field_behavior = .UseLast,
    };
    const str = "{ \"a\": 1, \"a\": 0.25 }";

    const T1 = struct { a: *u64 };
    try testing.expectError(error.InvalidNumber, parse(T1, @constCast(&TokenStream.init(str)), options));

    const T2 = struct { a: f64 };
    try testing.expectEqual(T2{ .a = 0.25 }, try parse(T2, @constCast(&TokenStream.init(str)), options));
}

/// A non-stream JSON parser which constructs a tree of Value's.
pub const Parser = struct {
    allocator: Allocator,
    state: State,
    copy_strings: bool,
    // Stores parent nodes and un-combined Values.
    stack: Array,

    const State = enum {
        ObjectKey,
        ObjectValue,
        ArrayValue,
        Simple,
    };

    pub fn init(allocator: Allocator, copy_strings: bool) Parser {
        return Parser{
            .allocator = allocator,
            .state = .Simple,
            .copy_strings = copy_strings,
            .stack = Array.init(allocator),
        };
    }

    pub fn deinit(p: *Parser) void {
        p.stack.deinit();
    }

    pub fn reset(p: *Parser) void {
        p.state = .Simple;
        p.stack.shrinkRetainingCapacity(0);
    }

    pub fn parse(p: *Parser, input: []const u8) !ValueTree {
        var s = TokenStream.init(input);

        var arena = ArenaAllocator.init(p.allocator);
        errdefer arena.deinit();

        while (try s.next()) |token| {
            try p.transition(arena.allocator(), input, s.i - 1, token);
        }

        debug.assert(p.stack.items.len == 1);

        return ValueTree{
            .arena = arena,
            .root = p.stack.items[0],
        };
    }

    // Even though p.allocator exists, we take an explicit allocator so that allocation state
    // can be cleaned up on error correctly during a `parse` on call.
    fn transition(p: *Parser, allocator: Allocator, input: []const u8, i: usize, token: Token) !void {
        switch (p.state) {
            .ObjectKey => switch (token) {
                .ObjectEnd => {
                    if (p.stack.items.len == 1) {
                        return;
                    }

                    var value = p.stack.pop().?;
                    try p.pushToParent(&value);
                },
                .String => |s| {
                    try p.stack.append(try p.parseString(allocator, s, input, i));
                    p.state = .ObjectValue;
                },
                else => {
                    // The streaming parser would return an error eventually.
                    // To prevent invalid state we return an error now.
                    // TODO make the streaming parser return an error as soon as it encounters an invalid object key
                    return error.InvalidLiteral;
                },
            },
            .ObjectValue => {
                var object = &p.stack.items[p.stack.items.len - 2].Object;
                const key = p.stack.items[p.stack.items.len - 1].String;

                switch (token) {
                    .ObjectBegin => {
                        try p.stack.append(Value{ .Object = ObjectMap.init(allocator) });
                        p.state = .ObjectKey;
                    },
                    .ArrayBegin => {
                        try p.stack.append(Value{ .Array = Array.init(allocator) });
                        p.state = .ArrayValue;
                    },
                    .String => |s| {
                        try object.put(key, try p.parseString(allocator, s, input, i));
                        _ = p.stack.pop();
                        p.state = .ObjectKey;
                    },
                    .Number => |n| {
                        try object.put(key, try p.parseNumber(n, input, i));
                        _ = p.stack.pop();
                        p.state = .ObjectKey;
                    },
                    .True => {
                        try object.put(key, Value{ .Bool = true });
                        _ = p.stack.pop();
                        p.state = .ObjectKey;
                    },
                    .False => {
                        try object.put(key, Value{ .Bool = false });
                        _ = p.stack.pop();
                        p.state = .ObjectKey;
                    },
                    .Null => {
                        try object.put(key, Value.Null);
                        _ = p.stack.pop();
                        p.state = .ObjectKey;
                    },
                    .ObjectEnd, .ArrayEnd => {
                        unreachable;
                    },
                }
            },
            .ArrayValue => {
                var array = &p.stack.items[p.stack.items.len - 1].Array;

                switch (token) {
                    .ArrayEnd => {
                        if (p.stack.items.len == 1) {
                            return;
                        }

                        var value = p.stack.pop().?;
                        try p.pushToParent(&value);
                    },
                    .ObjectBegin => {
                        try p.stack.append(Value{ .Object = ObjectMap.init(allocator) });
                        p.state = .ObjectKey;
                    },
                    .ArrayBegin => {
                        try p.stack.append(Value{ .Array = Array.init(allocator) });
                        p.state = .ArrayValue;
                    },
                    .String => |s| {
                        try array.append(try p.parseString(allocator, s, input, i));
                    },
                    .Number => |n| {
                        try array.append(try p.parseNumber(n, input, i));
                    },
                    .True => {
                        try array.append(Value{ .Bool = true });
                    },
                    .False => {
                        try array.append(Value{ .Bool = false });
                    },
                    .Null => {
                        try array.append(Value.Null);
                    },
                    .ObjectEnd => {
                        unreachable;
                    },
                }
            },
            .Simple => switch (token) {
                .ObjectBegin => {
                    try p.stack.append(Value{ .Object = ObjectMap.init(allocator) });
                    p.state = .ObjectKey;
                },
                .ArrayBegin => {
                    try p.stack.append(Value{ .Array = Array.init(allocator) });
                    p.state = .ArrayValue;
                },
                .String => |s| {
                    try p.stack.append(try p.parseString(allocator, s, input, i));
                },
                .Number => |n| {
                    try p.stack.append(try p.parseNumber(n, input, i));
                },
                .True => {
                    try p.stack.append(Value{ .Bool = true });
                },
                .False => {
                    try p.stack.append(Value{ .Bool = false });
                },
                .Null => {
                    try p.stack.append(Value.Null);
                },
                .ObjectEnd, .ArrayEnd => {
                    unreachable;
                },
            },
        }
    }

    fn pushToParent(p: *Parser, value: *const Value) !void {
        switch (p.stack.items[p.stack.items.len - 1]) {
            // Object Parent -> [ ..., object, <key>, value ]
            Value.String => |key| {
                _ = p.stack.pop();

                var object = &p.stack.items[p.stack.items.len - 1].Object;
                try object.put(key, value.*);
                p.state = .ObjectKey;
            },
            // Array Parent -> [ ..., <array>, value ]
            Value.Array => |*array| {
                try array.append(value.*);
                p.state = .ArrayValue;
            },
            else => {
                unreachable;
            },
        }
    }

    fn parseString(p: *Parser, allocator: Allocator, s: std.meta.TagPayload(Token, Token.String), input: []const u8, i: usize) !Value {
        const slice = s.slice(input, i);
        switch (s.escapes) {
            .None => return Value{ .String = if (p.copy_strings) try allocator.dupe(u8, slice) else slice },
            .Some => {
                const output = try allocator.alloc(u8, s.decodedLength());
                errdefer allocator.free(output);
                try unescapeValidString(output, slice);
                return Value{ .String = output };
            },
        }
    }

    fn parseNumber(_: *Parser, n: std.meta.TagPayload(Token, Token.Number), input: []const u8, i: usize) !Value {
        return if (n.is_integer)
            Value{
                .Integer = std.fmt.parseInt(i64, n.slice(input, i), 10) catch |e| switch (e) {
                    error.Overflow => return Value{ .NumberString = n.slice(input, i) },
                    error.InvalidCharacter => |err| return err,
                },
            }
        else
            Value{ .Float = try std.fmt.parseFloat(f64, n.slice(input, i)) };
    }
};

/// Unescape a JSON string
/// Only to be used on strings already validated by the parser
/// (note the unreachable statements and lack of bounds checking)
pub fn unescapeValidString(output: []u8, input: []const u8) !void {
    var inIndex: usize = 0;
    var outIndex: usize = 0;

    while (inIndex < input.len) {
        if (input[inIndex] != '\\') {
            // not an escape sequence
            output[outIndex] = input[inIndex];
            inIndex += 1;
            outIndex += 1;
        } else if (input[inIndex + 1] != 'u') {
            // a simple escape sequence
            output[outIndex] = @as(u8, switch (input[inIndex + 1]) {
                '\\' => '\\',
                '/' => '/',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                'f' => 12,
                'b' => 8,
                '"' => '"',
                else => unreachable,
            });
            inIndex += 2;
            outIndex += 1;
        } else {
            // a unicode escape sequence
            const firstCodeUnit = std.fmt.parseInt(u16, input[inIndex + 2 .. inIndex + 6], 16) catch unreachable;

            // guess optimistically that it's not a surrogate pair
            if (std.unicode.utf8Encode(firstCodeUnit, output[outIndex..])) |byteCount| {
                outIndex += byteCount;
                inIndex += 6;
            } else |err| {
                // it might be a surrogate pair
                if (err != error.Utf8CannotEncodeSurrogateHalf) {
                    return error.InvalidUnicodeHexSymbol;
                }
                // check if a second code unit is present
                if (inIndex + 7 >= input.len or input[inIndex + 6] != '\\' or input[inIndex + 7] != 'u') {
                    return error.InvalidUnicodeHexSymbol;
                }

                const secondCodeUnit = std.fmt.parseInt(u16, input[inIndex + 8 .. inIndex + 12], 16) catch unreachable;

                const utf16le_seq = [2]u16{
                    mem.nativeToLittle(u16, firstCodeUnit),
                    mem.nativeToLittle(u16, secondCodeUnit),
                };
                if (std.unicode.utf16LeToUtf8(output[outIndex..], &utf16le_seq)) |byteCount| {
                    outIndex += byteCount;
                    inIndex += 12;
                } else |_| {
                    return error.InvalidUnicodeHexSymbol;
                }
            }
        }
    }
    assert(outIndex == output.len);
}

test "json.parser.dynamic" {
    var p = Parser.init(testing.allocator, false);
    defer p.deinit();

    const s =
        \\{
        \\  "Image": {
        \\      "Width":  800,
        \\      "Height": 600,
        \\      "Title":  "View from 15th Floor",
        \\      "Thumbnail": {
        \\          "Url":    "http://www.example.com/image/481989943",
        \\          "Height": 125,
        \\          "Width":  100
        \\      },
        \\      "Animated" : false,
        \\      "IDs": [116, 943, 234, 38793],
        \\      "ArrayOfObject": [{"n": "m"}],
        \\      "double": 1.3412,
        \\      "LargeInt": 18446744073709551615
        \\    }
        \\}
    ;

    var tree = try p.parse(s);
    defer tree.deinit();

    var root = tree.root;

    var image = root.Object.get("Image").?;

    const width = image.Object.get("Width").?;
    try testing.expect(width.Integer == 800);

    const height = image.Object.get("Height").?;
    try testing.expect(height.Integer == 600);

    const title = image.Object.get("Title").?;
    try testing.expect(mem.eql(u8, title.String, "View from 15th Floor"));

    const animated = image.Object.get("Animated").?;
    try testing.expect(animated.Bool == false);

    const array_of_object = image.Object.get("ArrayOfObject").?;
    try testing.expect(array_of_object.Array.items.len == 1);

    const obj0 = array_of_object.Array.items[0].Object.get("n").?;
    try testing.expect(mem.eql(u8, obj0.String, "m"));

    const double = image.Object.get("double").?;
    try testing.expect(double.Float == 1.3412);

    const large_int = image.Object.get("LargeInt").?;
    try testing.expect(mem.eql(u8, large_int.NumberString, "18446744073709551615"));
}

test "import more json tests" {
    // _ = @import("json/test.zig");
    // _ = @import("json/write_stream.zig");
}

// test "write json then parse it" {
//     var out_buffer: [1000]u8 = undefined;
//
//     var fixed_buffer_stream = std.io.fixedBufferStream(&out_buffer);
//     const out_stream = fixed_buffer_stream.writer();
//     var jw = writeStream(out_stream, 4);
//
//     try jw.beginObject();
//
//     try jw.objectField("f");
//     try jw.emitBool(false);
//
//     try jw.objectField("t");
//     try jw.emitBool(true);
//
//     try jw.objectField("int");
//     try jw.emitNumber(1234);
//
//     try jw.objectField("array");
//     try jw.beginArray();
//
//     try jw.arrayElem();
//     try jw.emitNull();
//
//     try jw.arrayElem();
//     try jw.emitNumber(12.34);
//
//     try jw.endArray();
//
//     try jw.objectField("str");
//     try jw.emitString("hello");
//
//     try jw.endObject();
//
//     var parser = Parser.init(testing.allocator, false);
//     defer parser.deinit();
//     var tree = try parser.parse(fixed_buffer_stream.getWritten());
//     defer tree.deinit();
//
//     try testing.expect(tree.root.Object.get("f").?.Bool == false);
//     try testing.expect(tree.root.Object.get("t").?.Bool == true);
//     try testing.expect(tree.root.Object.get("int").?.Integer == 1234);
//     try testing.expect(tree.root.Object.get("array").?.Array.items[0].Null == {});
//     try testing.expect(tree.root.Object.get("array").?.Array.items[1].Float == 12.34);
//     try testing.expect(mem.eql(u8, tree.root.Object.get("str").?.String, "hello"));
// }

fn test_parse(arena_allocator: std.mem.Allocator, json_str: []const u8) !Value {
    var p = Parser.init(arena_allocator, false);
    return (try p.parse(json_str)).root;
}

test "parsing empty string gives appropriate error" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    try testing.expectError(error.UnexpectedEndOfJson, test_parse(arena_allocator.allocator(), ""));
}

test "integer after float has proper type" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const json = try test_parse(arena_allocator.allocator(),
        \\{
        \\  "float": 3.14,
        \\  "ints": [1, 2, 3]
        \\}
    );
    try std.testing.expect(json.Object.get("ints").?.Array.items[0] == .Integer);
}

test "escaped characters" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const input =
        \\{
        \\  "backslash": "\\",
        \\  "forwardslash": "\/",
        \\  "newline": "\n",
        \\  "carriagereturn": "\r",
        \\  "tab": "\t",
        \\  "formfeed": "\f",
        \\  "backspace": "\b",
        \\  "doublequote": "\"",
        \\  "unicode": "\u0105",
        \\  "surrogatepair": "\ud83d\ude02"
        \\}
    ;

    const obj = (try test_parse(arena_allocator.allocator(), input)).Object;

    try testing.expectEqualSlices(u8, obj.get("backslash").?.String, "\\");
    try testing.expectEqualSlices(u8, obj.get("forwardslash").?.String, "/");
    try testing.expectEqualSlices(u8, obj.get("newline").?.String, "\n");
    try testing.expectEqualSlices(u8, obj.get("carriagereturn").?.String, "\r");
    try testing.expectEqualSlices(u8, obj.get("tab").?.String, "\t");
    try testing.expectEqualSlices(u8, obj.get("formfeed").?.String, "\x0C");
    try testing.expectEqualSlices(u8, obj.get("backspace").?.String, "\x08");
    try testing.expectEqualSlices(u8, obj.get("doublequote").?.String, "\"");
    try testing.expectEqualSlices(u8, obj.get("unicode").?.String, "ą");
    try testing.expectEqualSlices(u8, obj.get("surrogatepair").?.String, "😂");
}

test "string copy option" {
    const input =
        \\{
        \\  "noescape": "aą😂",
        \\  "simple": "\\\/\n\r\t\f\b\"",
        \\  "unicode": "\u0105",
        \\  "surrogatepair": "\ud83d\ude02"
        \\}
    ;

    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();

    const tree_nocopy = try @constCast(&Parser.init(arena_allocator.allocator(), false)).parse(input);
    const obj_nocopy = tree_nocopy.root.Object;

    const tree_copy = try @constCast(&Parser.init(arena_allocator.allocator(), true)).parse(input);
    const obj_copy = tree_copy.root.Object;

    for ([_][]const u8{ "noescape", "simple", "unicode", "surrogatepair" }) |field_name| {
        try testing.expectEqualSlices(u8, obj_nocopy.get(field_name).?.String, obj_copy.get(field_name).?.String);
    }

    const nocopy_addr = &obj_nocopy.get("noescape").?.String[0];
    const copy_addr = &obj_copy.get("noescape").?.String[0];

    var found_nocopy = false;
    for (input, 0..) |_, index| {
        try testing.expect(copy_addr != &input[index]);
        if (nocopy_addr == &input[index]) {
            found_nocopy = true;
        }
    }
    try testing.expect(found_nocopy);
}

pub const StringifyOptions = struct {
    pub const Whitespace = struct {
        /// How many indentation levels deep are we?
        indent_level: usize = 0,

        /// What character(s) should be used for indentation?
        indent: union(enum) {
            Space: u8,
            Tab: void,
        } = .{ .Space = 4 },

        /// After a colon, should whitespace be inserted?
        separator: bool = true,

        pub fn outputIndent(
            whitespace: @This(),
            out_stream: anytype,
        ) @TypeOf(out_stream).Error!void {
            var char: u8 = undefined;
            var n_chars: usize = undefined;
            switch (whitespace.indent) {
                .Space => |n_spaces| {
                    char = ' ';
                    n_chars = n_spaces;
                },
                .Tab => {
                    char = '\t';
                    n_chars = 1;
                },
            }
            n_chars *= whitespace.indent_level;
            try out_stream.writeByteNTimes(char, n_chars);
        }
    };

    emit_null: bool = true,

    exclude_fields: ?[][]const u8 = null,

    /// Controls the whitespace emitted
    whitespace: ?Whitespace = null,

    string: StringOptions = StringOptions{ .String = .{} },

    /// Should []u8 be serialised as a string? or an array?
    pub const StringOptions = union(enum) {
        Array,
        String: StringOutputOptions,

        /// String output options
        const StringOutputOptions = struct {
            /// Should '/' be escaped in strings?
            escape_solidus: bool = false,

            /// Should unicode characters be escaped in strings?
            escape_unicode: bool = false,
        };
    };
};

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
        const high = @as(u16, @intCast((codepoint - 0x10000) >> 10)) + 0xD800;
        const low = @as(u16, @intCast(codepoint & 0x3FF)) + 0xDC00;
        try out_stream.writeAll("\\u");
        try std.fmt.formatIntValue(high, "x", std.fmt.FormatOptions{ .width = 4, .fill = '0' }, out_stream);
        try out_stream.writeAll("\\u");
        try std.fmt.formatIntValue(low, "x", std.fmt.FormatOptions{ .width = 4, .fill = '0' }, out_stream);
    }
}
